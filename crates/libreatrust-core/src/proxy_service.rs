use crate::client::AtrClient;
use crate::error::{AtrError, AtrResult};
use crate::transport::{L3Tunnel, TcpTunnel, connect_tcp_bound};
use crate::types::RouteDecision;
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const READ_BUF_SIZE: usize = 64 * 1024;
const MAX_HEADER_SIZE: usize = 64 * 1024;
const DNS_CACHE_TTL: Duration = Duration::from_secs(30);
const DNS_CACHE_MAX_ENTRIES: usize = 1024;

// Browsers open several connections to the same host, so reuse system DNS
// answers briefly instead of re-resolving on every proxied connect.
type DnsCacheEntry = (Vec<String>, Instant);
static DNS_CACHE: LazyLock<Mutex<HashMap<String, DnsCacheEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyServiceStatus {
    Running,
    Stopped,
}

#[derive(Debug, Clone)]
pub struct ProxyServiceConfig {
    pub listen_host: String,
    pub listen_port: u16,
    pub connect_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub enable_http: bool,
    pub enable_socks5: bool,
}

impl Default for ProxyServiceConfig {
    fn default() -> Self {
        Self {
            listen_host: "127.0.0.1".into(),
            listen_port: 1080,
            connect_timeout_ms: 10_000,
            idle_timeout_ms: 0,
            enable_http: true,
            enable_socks5: true,
        }
    }
}

#[derive(Debug)]
pub struct ProxyService {
    endpoint: SocketAddr,
    stop: Arc<AtomicBool>,
    active_connections: Arc<AtomicU64>,
    total_connections: Arc<AtomicU64>,
    managed_upload_bytes: Arc<AtomicU64>,
    managed_download_bytes: Arc<AtomicU64>,
    last_error: Arc<Mutex<Option<String>>>,
    last_event: Arc<Mutex<Option<ProxyServiceEvent>>>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
    connections: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    active_sockets: Arc<Mutex<HashMap<u64, TcpStream>>>,
    keepalive_l3: Mutex<Option<L3Tunnel>>,
}

impl ProxyService {
    pub fn start(client: AtrClient, config: ProxyServiceConfig) -> AtrResult<Self> {
        if !config.enable_http && !config.enable_socks5 {
            return Err(AtrError::InvalidArgument(
                "at least one proxy protocol must be enabled".into(),
            ));
        }

        let bind_addr = format!("{}:{}", config.listen_host, config.listen_port);
        let listener = TcpListener::bind(&bind_addr)?;
        let endpoint = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let active_connections = Arc::new(AtomicU64::new(0));
        let total_connections = Arc::new(AtomicU64::new(0));
        let managed_upload_bytes = Arc::new(AtomicU64::new(0));
        let managed_download_bytes = Arc::new(AtomicU64::new(0));
        let last_error = Arc::new(Mutex::new(None));
        let last_event = Arc::new(Mutex::new(None));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let active_sockets = Arc::new(Mutex::new(HashMap::new()));
        let keepalive_l3 = match client.open_l3_tunnel() {
            Ok(tunnel) => {
                crate::diag_log("[libreatrust][proxy] dedicated L3 keepalive tunnel started");
                Some(tunnel)
            }
            Err(error) => {
                crate::diag_log(format!(
                    "[libreatrust][proxy] dedicated L3 keepalive unavailable error={error}"
                ));
                None
            }
        };

        let worker_stop = stop.clone();
        let worker_active = active_connections.clone();
        let worker_total = total_connections.clone();
        let worker_upload = managed_upload_bytes.clone();
        let worker_download = managed_download_bytes.clone();
        let worker_error = last_error.clone();
        let worker_event = last_event.clone();
        let worker_connections = connections.clone();
        let worker_sockets = active_sockets.clone();
        let worker = thread::Builder::new()
            .name("libreatrust-proxy-listener".into())
            .spawn(move || {
                run_listener(
                    listener,
                    client,
                    config,
                    worker_stop,
                    worker_active,
                    worker_total,
                    worker_upload,
                    worker_download,
                    worker_error,
                    worker_event,
                    worker_connections,
                    worker_sockets,
                )
            })
            .map_err(|err| AtrError::Internal(format!("failed to start proxy listener: {err}")))?;

        Ok(Self {
            endpoint,
            stop,
            active_connections,
            total_connections,
            managed_upload_bytes,
            managed_download_bytes,
            last_error,
            last_event,
            worker: Mutex::new(Some(worker)),
            connections,
            active_sockets,
            keepalive_l3: Mutex::new(keepalive_l3),
        })
    }

    pub fn stop(&self) -> AtrResult<()> {
        self.stop.store(true, Ordering::SeqCst);
        for stream in self.active_sockets.lock().unwrap().values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let _ = TcpStream::connect_timeout(&self.endpoint, Duration::from_millis(100));
        if let Some(worker) = self.worker.lock().unwrap().take() {
            let _ = worker.join();
        }
        let connections = std::mem::take(&mut *self.connections.lock().unwrap());
        for connection in connections {
            let _ = connection.join();
        }
        if let Some(tunnel) = self.keepalive_l3.lock().unwrap().take() {
            let _ = tunnel.close();
            crate::diag_log("[libreatrust][proxy] dedicated L3 keepalive tunnel stopped");
        }
        Ok(())
    }

    pub fn status(&self) -> ProxyServiceStatus {
        if self.stop.load(Ordering::SeqCst) {
            ProxyServiceStatus::Stopped
        } else {
            ProxyServiceStatus::Running
        }
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn stats(&self) -> ProxyServiceStats {
        ProxyServiceStats {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            managed_upload_bytes: self.managed_upload_bytes.load(Ordering::Relaxed),
            managed_download_bytes: self.managed_download_bytes.load(Ordering::Relaxed),
            last_error: self.last_error.lock().unwrap().clone(),
            last_event: self.last_event.lock().unwrap().clone(),
        }
    }

    pub fn take_event(&self) -> Option<ProxyServiceEvent> {
        self.last_event.lock().unwrap().take()
    }
}

impl Drop for ProxyService {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Debug, Clone)]
pub struct ProxyServiceStats {
    pub active_connections: u64,
    pub total_connections: u64,
    pub managed_upload_bytes: u64,
    pub managed_download_bytes: u64,
    pub last_error: Option<String>,
    pub last_event: Option<ProxyServiceEvent>,
}

#[derive(Debug, Clone)]
pub enum ProxyServiceEvent {
    SessionInvalidated { message: String },
    Error { message: String },
}

#[allow(clippy::too_many_arguments)]
fn run_listener(
    listener: TcpListener,
    client: AtrClient,
    config: ProxyServiceConfig,
    stop: Arc<AtomicBool>,
    active_connections: Arc<AtomicU64>,
    total_connections: Arc<AtomicU64>,
    managed_upload_bytes: Arc<AtomicU64>,
    managed_download_bytes: Arc<AtomicU64>,
    last_error: Arc<Mutex<Option<String>>>,
    last_event: Arc<Mutex<Option<ProxyServiceEvent>>>,
    connections: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    active_sockets: Arc<Mutex<HashMap<u64, TcpStream>>>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let client = client.clone();
                let config = config.clone();
                let active = active_connections.clone();
                let error_slot = last_error.clone();
                let event_slot = last_event.clone();
                let socket_map = active_sockets.clone();
                let upload = managed_upload_bytes.clone();
                let download = managed_download_bytes.clone();
                let connection_id = total_connections.fetch_add(1, Ordering::Relaxed) + 1;
                if let Ok(socket) = stream.try_clone() {
                    active_sockets.lock().unwrap().insert(connection_id, socket);
                }
                active.fetch_add(1, Ordering::Relaxed);
                let worker_active = active.clone();
                let connection = thread::Builder::new()
                    .name("libreatrust-proxy-conn".into())
                    .spawn(move || {
                        if let Err(err) =
                            handle_connection(stream, client, config, upload, download)
                        {
                            crate::diag_log(format!(
                                "[libreatrust][proxy] connection failed: {err}"
                            ));
                            record_proxy_error(&error_slot, &event_slot, err);
                        }
                        socket_map.lock().unwrap().remove(&connection_id);
                        worker_active.fetch_sub(1, Ordering::Relaxed);
                    });
                if let Ok(connection) = connection {
                    let mut connections = connections.lock().unwrap();
                    // Drop handles whose threads already exited so this list
                    // does not grow with the total connection count.
                    if connections.len() >= 256 {
                        connections.retain(|handle| !handle.is_finished());
                    }
                    connections.push(connection);
                } else {
                    active_sockets.lock().unwrap().remove(&connection_id);
                    active.fetch_sub(1, Ordering::Relaxed);
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                record_proxy_error(&last_error, &last_event, AtrError::from(err));
            }
        }
    }
}

fn record_proxy_error(
    last_error: &Arc<Mutex<Option<String>>>,
    last_event: &Arc<Mutex<Option<ProxyServiceEvent>>>,
    err: AtrError,
) {
    let message = err.to_string();
    *last_error.lock().unwrap() = Some(message.clone());
    let event = if is_session_invalidated_error(&message) {
        ProxyServiceEvent::SessionInvalidated { message }
    } else {
        ProxyServiceEvent::Error { message }
    };
    *last_event.lock().unwrap() = Some(event);
}

fn is_session_invalidated_error(message: &str) -> bool {
    message.contains("invalid SID")
        || message.contains("stored session is not logged in")
        || message.contains("not logged in")
        || message.contains("unauthorized")
}

fn handle_connection(
    mut client_stream: TcpStream,
    client: AtrClient,
    config: ProxyServiceConfig,
    managed_upload_bytes: Arc<AtomicU64>,
    managed_download_bytes: Arc<AtomicU64>,
) -> AtrResult<()> {
    client_stream.set_nodelay(true)?;
    if config.idle_timeout_ms > 0 {
        let timeout = Some(Duration::from_millis(config.idle_timeout_ms));
        client_stream.set_read_timeout(timeout)?;
        client_stream.set_write_timeout(timeout)?;
    }

    let first = read_some(&mut client_stream)?;
    if first.is_empty() {
        return Ok(());
    }

    match first[0] {
        0x05 if config.enable_socks5 => handle_socks5(
            client_stream,
            first,
            client,
            config,
            managed_upload_bytes,
            managed_download_bytes,
        ),
        _ if config.enable_http => handle_http(
            client_stream,
            first,
            client,
            config,
            managed_upload_bytes,
            managed_download_bytes,
        ),
        _ => Err(AtrError::InvalidArgument(
            "unsupported proxy protocol".into(),
        )),
    }
}

fn handle_socks5(
    mut client_stream: TcpStream,
    mut buffer: Vec<u8>,
    client: AtrClient,
    config: ProxyServiceConfig,
    managed_upload_bytes: Arc<AtomicU64>,
    managed_download_bytes: Arc<AtomicU64>,
) -> AtrResult<()> {
    while parse_socks5_greeting(&buffer)?.is_none() {
        append_read(&mut client_stream, &mut buffer)?;
        if buffer.len() > MAX_HEADER_SIZE {
            return Err(AtrError::InvalidArgument(
                "socks5 greeting too large".into(),
            ));
        }
    }
    client_stream.write_all(&[0x05, 0x00])?;
    client_stream.flush()?;

    buffer.clear();
    let request = loop {
        append_read(&mut client_stream, &mut buffer)?;
        if let Some(request) = parse_socks5_connect(&buffer)? {
            break request;
        }
        if buffer.len() > MAX_HEADER_SIZE {
            return Err(AtrError::InvalidArgument("socks5 request too large".into()));
        }
    };

    crate::diag_log(format!(
        "[libreatrust][proxy] socks5 connect target={}:{} leftover={}B",
        request.host,
        request.port,
        request.leftover.len()
    ));
    match open_proxy_target(&client, &request.host, request.port, &config) {
        Ok(remote) => {
            client_stream.write_all(&socks5_reply(0x00))?;
            client_stream.flush()?;
            if !request.leftover.is_empty() {
                remote.write_all(&request.leftover)?;
                if matches!(remote, ProxyRemote::Managed(_)) {
                    managed_upload_bytes
                        .fetch_add(request.leftover.len() as u64, Ordering::Relaxed);
                }
            }
            relay(
                client_stream,
                remote,
                managed_upload_bytes,
                managed_download_bytes,
            )
        }
        Err(err) => {
            let _ = client_stream.write_all(&socks5_reply(0x01));
            let _ = client_stream.flush();
            Err(err)
        }
    }
}

fn handle_http(
    mut client_stream: TcpStream,
    mut buffer: Vec<u8>,
    client: AtrClient,
    config: ProxyServiceConfig,
    managed_upload_bytes: Arc<AtomicU64>,
    managed_download_bytes: Arc<AtomicU64>,
) -> AtrResult<()> {
    while find_header_end(&buffer).is_none() {
        append_read(&mut client_stream, &mut buffer)?;
        if buffer.len() > MAX_HEADER_SIZE {
            return Err(AtrError::InvalidArgument(
                "http proxy header too large".into(),
            ));
        }
    }
    let request = parse_http_proxy_request(&buffer)?;

    if request.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(&request.target, 443)?;
        crate::diag_log(format!(
            "[libreatrust][proxy] http CONNECT target={host}:{port}"
        ));
        match open_proxy_target(&client, &host, port, &config) {
            Ok(remote) => {
                client_stream.write_all(
                    b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: NulConnect\r\n\r\n",
                )?;
                client_stream.flush()?;
                if !request.body.is_empty() {
                    remote.write_all(&request.body)?;
                    if matches!(remote, ProxyRemote::Managed(_)) {
                        managed_upload_bytes
                            .fetch_add(request.body.len() as u64, Ordering::Relaxed);
                    }
                }
                relay(
                    client_stream,
                    remote,
                    managed_upload_bytes,
                    managed_download_bytes,
                )
            }
            Err(err) => {
                let _ = client_stream.write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                );
                let _ = client_stream.flush();
                Err(err)
            }
        }
    } else {
        let (host, port, rewritten) = rewrite_http_proxy_request(request)?;
        crate::diag_log(format!(
            "[libreatrust][proxy] http request target={host}:{port} rewritten={}B",
            rewritten.len()
        ));
        let remote = open_proxy_target(&client, &host, port, &config)?;
        remote.write_all(&rewritten)?;
        if matches!(remote, ProxyRemote::Managed(_)) {
            managed_upload_bytes.fetch_add(rewritten.len() as u64, Ordering::Relaxed);
        }
        remote.flush()?;
        relay(
            client_stream,
            remote,
            managed_upload_bytes,
            managed_download_bytes,
        )
    }
}

fn open_proxy_target(
    client: &AtrClient,
    host: &str,
    port: u16,
    config: &ProxyServiceConfig,
) -> AtrResult<ProxyRemote> {
    let route = resolved_tcp_route(client, host, port)?;
    match route.decision {
        ProxyRouteDecision::Managed => {
            crate::diag_log(format!(
                "[libreatrust][proxy] route managed requested={host}:{port} connect={}:{}",
                route.connect_host, port
            ));
            Ok(ProxyRemote::Managed(
                client.open_tcp_tunnel(&route.connect_host, port)?,
            ))
        }
        ProxyRouteDecision::Direct => {
            let addr = (host, port).to_socket_addrs()?.next().ok_or_else(|| {
                AtrError::NetworkFailed(format!("failed to resolve {host}:{port}"))
            })?;
            crate::diag_log(format!(
                "[libreatrust][proxy] route direct requested={host}:{port} connect={addr}"
            ));
            let stream = connect_tcp_bound(
                &addr,
                Duration::from_millis(config.connect_timeout_ms.max(1)),
                client.client_config(),
            )?;
            stream.set_nodelay(true)?;
            Ok(ProxyRemote::Direct(stream))
        }
    }
}

#[derive(Debug)]
struct ResolvedProxyRoute {
    decision: ProxyRouteDecision,
    connect_host: String,
}

#[derive(Debug, Clone, Copy)]
enum ProxyRouteDecision {
    Direct,
    Managed,
}

fn resolved_tcp_route(client: &AtrClient, host: &str, port: u16) -> AtrResult<ResolvedProxyRoute> {
    if matches!(client.route_tcp(host, port), RouteDecision::Managed(_)) {
        crate::diag_log(format!("[libreatrust][proxy] route hit host={host}:{port}"));
        return Ok(ResolvedProxyRoute {
            decision: ProxyRouteDecision::Managed,
            connect_host: host.to_string(),
        });
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok(ResolvedProxyRoute {
            decision: ProxyRouteDecision::Direct,
            connect_host: host.to_string(),
        });
    }

    for ip in resolve_ipv4_addresses(host) {
        if matches!(client.route_tcp(&ip, port), RouteDecision::Managed(_)) {
            crate::diag_log(format!(
                "[libreatrust][proxy] route hit resolved host={host}:{port} ip={ip}"
            ));
            return Ok(ResolvedProxyRoute {
                decision: ProxyRouteDecision::Managed,
                connect_host: ip,
            });
        }
    }
    Ok(ResolvedProxyRoute {
        decision: ProxyRouteDecision::Direct,
        connect_host: host.to_string(),
    })
}

fn resolve_ipv4_addresses(host: &str) -> Vec<String> {
    if let Some((addrs, resolved)) = DNS_CACHE.lock().unwrap().get(host)
        && resolved.elapsed() < DNS_CACHE_TTL
    {
        return addrs.clone();
    }
    let addrs: Vec<String> = (host, 0)
        .to_socket_addrs()
        .map(|iter| {
            iter.filter_map(|addr| match addr {
                SocketAddr::V4(v4) => Some(v4.ip().to_string()),
                SocketAddr::V6(_) => None,
            })
            .collect()
        })
        .unwrap_or_default();
    let mut cache = DNS_CACHE.lock().unwrap();
    if cache.len() >= DNS_CACHE_MAX_ENTRIES {
        let now = Instant::now();
        cache.retain(|_, (_, resolved)| now.duration_since(*resolved) < DNS_CACHE_TTL);
        if cache.len() >= DNS_CACHE_MAX_ENTRIES {
            cache.clear();
        }
    }
    cache.insert(host.to_string(), (addrs.clone(), Instant::now()));
    addrs
}

enum ProxyRemote {
    Direct(TcpStream),
    Managed(TcpTunnel),
}

impl ProxyRemote {
    fn write_all(&self, data: &[u8]) -> AtrResult<()> {
        match self {
            Self::Direct(stream) => {
                let mut stream = stream.try_clone()?;
                stream.write_all(data)?;
                Ok(())
            }
            Self::Managed(tunnel) => {
                tunnel.write(data)?;
                Ok(())
            }
        }
    }

    fn flush(&self) -> AtrResult<()> {
        match self {
            Self::Direct(stream) => {
                let mut stream = stream.try_clone()?;
                stream.flush()?;
                Ok(())
            }
            Self::Managed(_) => Ok(()),
        }
    }
}

fn relay(
    client_stream: TcpStream,
    remote: ProxyRemote,
    managed_upload_bytes: Arc<AtomicU64>,
    managed_download_bytes: Arc<AtomicU64>,
) -> AtrResult<()> {
    let mut client_reader = client_stream.try_clone()?;
    let mut client_writer = client_stream;
    match remote {
        ProxyRemote::Direct(remote_stream) => {
            let mut remote_reader = remote_stream.try_clone()?;
            let mut remote_writer = remote_stream;
            let upstream = thread::spawn(move || {
                let result = copy_tcp_to_tcp(&mut client_reader, &mut remote_writer);
                if let Err(err) = &result {
                    crate::diag_log(format!(
                        "[libreatrust][proxy] relay direct client->remote failed: {err}"
                    ));
                }
                // Wake the peer-reading relay as well. Shutting down only the
                // write half can leave ProxyService::stop waiting forever on
                // a browser keep-alive connection.
                let _ = remote_writer.shutdown(Shutdown::Both);
                let _ = client_reader.shutdown(Shutdown::Read);
                result
            });
            let downstream = thread::spawn(move || {
                let result = copy_tcp_to_tcp(&mut remote_reader, &mut client_writer);
                if let Err(err) = &result {
                    crate::diag_log(format!(
                        "[libreatrust][proxy] relay direct remote->client failed: {err}"
                    ));
                }
                let _ = client_writer.shutdown(Shutdown::Write);
                let _ = remote_reader.shutdown(Shutdown::Read);
                result
            });
            let up = upstream.join().unwrap_or_else(|_| {
                Err(AtrError::Internal("client-to-remote relay panicked".into()))
            });
            let down = downstream.join().unwrap_or_else(|_| {
                Err(AtrError::Internal("remote-to-client relay panicked".into()))
            });
            up.and(down)
        }
        ProxyRemote::Managed(tunnel) => {
            let tunnel = Arc::new(tunnel);
            let tunnel_writer = tunnel.clone();
            let tunnel_shutdown = tunnel.clone();
            let upstream = thread::spawn(move || {
                let result = copy_tcp_to_tunnel(
                    &mut client_reader,
                    tunnel_writer.as_ref(),
                    managed_upload_bytes.as_ref(),
                );
                if let Err(err) = &result {
                    crate::diag_log(format!(
                        "[libreatrust][proxy] relay managed client->tunnel failed: {err}"
                    ));
                }
                let _ = tunnel_writer.close();
                result
            });
            let downstream = thread::spawn(move || {
                let result = copy_tunnel_to_tcp(
                    tunnel.as_ref(),
                    &mut client_writer,
                    managed_download_bytes.as_ref(),
                );
                if let Err(err) = &result {
                    crate::diag_log(format!(
                        "[libreatrust][proxy] relay managed tunnel->client failed: {err}"
                    ));
                }
                let _ = client_writer.shutdown(Shutdown::Both);
                let _ = tunnel_shutdown.close();
                result
            });
            let up = upstream.join().unwrap_or_else(|_| {
                Err(AtrError::Internal("client-to-tunnel relay panicked".into()))
            });
            let down = downstream.join().unwrap_or_else(|_| {
                Err(AtrError::Internal("tunnel-to-client relay panicked".into()))
            });
            up.and(down)
        }
    }
}

fn copy_tcp_to_tcp(reader: &mut TcpStream, writer: &mut TcpStream) -> AtrResult<()> {
    let mut buf = vec![0u8; READ_BUF_SIZE];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => {
                let _ = writer.shutdown(Shutdown::Write);
                return Ok(());
            }
            Ok(n) => n,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(AtrError::from(err)),
        };
        writer.write_all(&buf[..n])?;
    }
}

// Chunks smaller than this look like interactive traffic (keystrokes, small
// control sequences) rather than bulk transfer, so their timing is worth
// logging individually when hunting for stalls.
const INTERACTIVE_CHUNK_BYTES: usize = 512;
// A gap this long between two chunks of the same relay direction is not
// explained by normal idle time between keystrokes; log it so a stall shows
// up in the diagnostics log even without a debugger attached.
const RELAY_STALL_LOG_THRESHOLD: Duration = Duration::from_millis(80);

fn copy_tcp_to_tunnel(
    reader: &mut TcpStream,
    tunnel: &TcpTunnel,
    byte_counter: &AtomicU64,
) -> AtrResult<()> {
    let mut buf = vec![0u8; READ_BUF_SIZE];
    let mut last_chunk_at: Option<Instant> = None;
    loop {
        let read_start = Instant::now();
        let n = match reader.read(&mut buf) {
            Ok(0) => {
                let _ = tunnel.close();
                return Ok(());
            }
            Ok(n) => n,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(AtrError::from(err)),
        };
        log_relay_gap("client->tunnel", n, &mut last_chunk_at);
        let write_start = Instant::now();
        let written = tunnel.write(&buf[..n])?;
        if n <= INTERACTIVE_CHUNK_BYTES {
            crate::diag_log(format!(
                "[libreatrust][proxy][relay] client->tunnel bytes={n} wait_for_read_ms={} tunnel_write_ms={}",
                write_start.duration_since(read_start).as_millis(),
                write_start.elapsed().as_millis()
            ));
        }
        byte_counter.fetch_add(written as u64, Ordering::Relaxed);
    }
}

fn copy_tunnel_to_tcp(
    tunnel: &TcpTunnel,
    writer: &mut TcpStream,
    byte_counter: &AtomicU64,
) -> AtrResult<()> {
    let mut buf = vec![0u8; READ_BUF_SIZE];
    let mut last_chunk_at: Option<Instant> = None;
    loop {
        let read_start = Instant::now();
        let n = tunnel.read(&mut buf)?;
        if n == 0 {
            let _ = writer.shutdown(Shutdown::Write);
            return Ok(());
        }
        log_relay_gap("tunnel->client", n, &mut last_chunk_at);
        let write_start = Instant::now();
        writer.write_all(&buf[..n])?;
        if n <= INTERACTIVE_CHUNK_BYTES {
            crate::diag_log(format!(
                "[libreatrust][proxy][relay] tunnel->client bytes={n} wait_for_read_ms={} client_write_ms={}",
                write_start.duration_since(read_start).as_millis(),
                write_start.elapsed().as_millis()
            ));
        }
        byte_counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Logs when the gap since the previous chunk in this direction exceeds
/// [`RELAY_STALL_LOG_THRESHOLD`], since that is what shows up as a visible
/// stall to an interactive session (e.g. a tmux pane switch that appears to
/// not respond).  A gap while the peer is simply idle (no keys pressed) is
/// normal and not logged past the first chunk.
fn log_relay_gap(direction: &str, bytes: usize, last_chunk_at: &mut Option<Instant>) {
    let now = Instant::now();
    if let Some(previous) = last_chunk_at.replace(now) {
        let gap = now.duration_since(previous);
        if gap >= RELAY_STALL_LOG_THRESHOLD {
            crate::diag_log(format!(
                "[libreatrust][proxy][relay] {direction} gap_ms={} before bytes={bytes}",
                gap.as_millis()
            ));
        }
    }
}

fn read_some(stream: &mut TcpStream) -> AtrResult<Vec<u8>> {
    let mut buf = vec![0u8; READ_BUF_SIZE];
    let n = stream.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn append_read(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> AtrResult<()> {
    let data = read_some(stream)?;
    if data.is_empty() {
        return Err(AtrError::NetworkFailed("connection closed".into()));
    }
    buffer.extend_from_slice(&data);
    Ok(())
}

fn parse_socks5_greeting(buffer: &[u8]) -> AtrResult<Option<usize>> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    if buffer[0] != 0x05 {
        return Err(AtrError::InvalidArgument("invalid socks5 version".into()));
    }
    let len = 2 + buffer[1] as usize;
    if buffer.len() < len {
        return Ok(None);
    }
    if !buffer[2..len].contains(&0x00) {
        return Err(AtrError::Unsupported(
            "socks5 authentication is not supported".into(),
        ));
    }
    Ok(Some(len))
}

#[derive(Debug, PartialEq)]
struct Socks5ConnectRequest {
    host: String,
    port: u16,
    leftover: Vec<u8>,
}

fn parse_socks5_connect(buffer: &[u8]) -> AtrResult<Option<Socks5ConnectRequest>> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    if buffer[0] != 0x05 {
        return Err(AtrError::InvalidArgument("invalid socks5 version".into()));
    }
    if buffer[1] != 0x01 {
        return Err(AtrError::Unsupported(
            "only socks5 CONNECT is supported".into(),
        ));
    }
    let (host, cursor) = match buffer[3] {
        0x01 => {
            if buffer.len() < 10 {
                return Ok(None);
            }
            (
                std::net::Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7]).to_string(),
                8,
            )
        }
        0x03 => {
            if buffer.len() < 5 {
                return Ok(None);
            }
            let len = buffer[4] as usize;
            if buffer.len() < 5 + len + 2 {
                return Ok(None);
            }
            let host = std::str::from_utf8(&buffer[5..5 + len])
                .map_err(|err| AtrError::ParseFailed(err.to_string()))?
                .to_string();
            (host, 5 + len)
        }
        0x04 => {
            if buffer.len() < 22 {
                return Ok(None);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buffer[4..20]);
            (std::net::Ipv6Addr::from(octets).to_string(), 20)
        }
        _ => {
            return Err(AtrError::Unsupported(
                "unsupported socks5 address type".into(),
            ));
        }
    };
    if buffer.len() < cursor + 2 {
        return Ok(None);
    }
    let port = u16::from_be_bytes([buffer[cursor], buffer[cursor + 1]]);
    Ok(Some(Socks5ConnectRequest {
        host,
        port,
        leftover: buffer[cursor + 2..].to_vec(),
    }))
}

fn socks5_reply(code: u8) -> [u8; 10] {
    [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

#[derive(Debug)]
struct HttpProxyRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn parse_http_proxy_request(buffer: &[u8]) -> AtrResult<HttpProxyRequest> {
    let header_end = find_header_end(buffer)
        .ok_or_else(|| AtrError::ParseFailed("incomplete http proxy request".into()))?;
    let header = std::str::from_utf8(&buffer[..header_end])
        .map_err(|err| AtrError::ParseFailed(err.to_string()))?;
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| AtrError::ParseFailed("missing request line".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| AtrError::ParseFailed("missing method".into()))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| AtrError::ParseFailed("missing target".into()))?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| AtrError::ParseFailed("missing version".into()))?
        .to_string();

    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect();

    Ok(HttpProxyRequest {
        method,
        target,
        version,
        headers,
        body: buffer[header_end + 4..].to_vec(),
    })
}

fn rewrite_http_proxy_request(request: HttpProxyRequest) -> AtrResult<(String, u16, Vec<u8>)> {
    let (scheme, rest) = request.target.split_once("://").ok_or_else(|| {
        AtrError::InvalidArgument("http proxy request target is not absolute".into())
    })?;
    let default_port = if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    };
    let slash = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..slash];
    let path = if slash < rest.len() {
        &rest[slash..]
    } else {
        "/"
    };
    let (host, port) = parse_host_port(authority, default_port)?;
    let mut output = Vec::new();
    output.extend_from_slice(
        format!("{} {} {}\r\n", request.method, path, request.version).as_bytes(),
    );
    for (name, value) in request.headers {
        output.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&request.body);
    Ok((host, port, output))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_host_port(value: &str, default_port: u16) -> AtrResult<(String, u16)> {
    if let Some(stripped) = value.strip_prefix('[') {
        let (host, rest) = stripped
            .split_once(']')
            .ok_or_else(|| AtrError::InvalidArgument("invalid bracketed host".into()))?;
        let port = rest
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Ok((host.to_string(), port));
    }

    if let Some((host, port)) = value.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return Ok((host.to_string(), port));
    }
    Ok((value.to_string(), default_port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{DomainResource, ResourceSnapshot};
    use crate::types::ClientConfig;
    use std::io::{Read, Write};
    use std::net::Ipv6Addr;
    use std::sync::mpsc;

    fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn direct_relay_stops_when_client_socket_is_shutdown() {
        let (browser, proxy_client) = connected_pair();
        let stop_socket = proxy_client.try_clone().unwrap();
        let (proxy_remote, remote_peer) = connected_pair();
        let (done_tx, done_rx) = mpsc::channel();

        let worker = thread::spawn(move || {
            let result = relay(
                proxy_client,
                ProxyRemote::Direct(proxy_remote),
                Arc::new(AtomicU64::new(0)),
                Arc::new(AtomicU64::new(0)),
            );
            let _ = done_tx.send(result);
        });

        // Keep both peers alive, just as a browser and an HTTP keep-alive
        // server would. Proxy shutdown must still wake both relay directions.
        let _browser = browser;
        let _remote_peer = remote_peer;
        stop_socket.shutdown(Shutdown::Both).unwrap();

        let result = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("direct relay did not stop after client shutdown");
        assert!(result.is_ok());
        worker.join().unwrap();
    }

    fn test_client() -> AtrClient {
        AtrClient::new(ClientConfig {
            server_host: "127.0.0.1".into(),
            server_port: 443,
            auto_detect_interface: false,
            ..Default::default()
        })
        .unwrap()
    }

    fn start_test_proxy(config: ProxyServiceConfig) -> ProxyService {
        ProxyService::start(test_client(), config).unwrap()
    }

    fn wait_until_idle(service: &ProxyService) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if service.stats().active_connections == 0 {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "proxy connection did not drain in time"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn socks5_greeting_accepts_no_auth_method() {
        assert_eq!(parse_socks5_greeting(&[0x05, 0x01, 0x00]).unwrap(), Some(3));
    }

    #[test]
    fn socks5_greeting_waits_for_remaining_method_bytes() {
        assert_eq!(parse_socks5_greeting(&[0x05]).unwrap(), None);
        assert_eq!(parse_socks5_greeting(&[0x05, 0x02]).unwrap(), None);
        assert_eq!(parse_socks5_greeting(&[0x05, 0x02, 0x00]).unwrap(), None);
    }

    #[test]
    fn socks5_greeting_rejects_wrong_version() {
        assert!(parse_socks5_greeting(&[0x04, 0x01, 0x00]).is_err());
    }

    #[test]
    fn socks5_greeting_rejects_auth_only_methods() {
        assert!(parse_socks5_greeting(&[0x05, 0x01, 0x02]).is_err());
    }

    #[test]
    fn socks5_connect_parses_ipv4_and_keeps_leftover() {
        let mut buffer = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        buffer.extend_from_slice(&443u16.to_be_bytes());
        buffer.extend_from_slice(b"XY");
        let request = parse_socks5_connect(&buffer).unwrap().unwrap();
        assert_eq!(request.host, "127.0.0.1");
        assert_eq!(request.port, 443);
        assert_eq!(request.leftover, b"XY");
    }

    #[test]
    fn socks5_connect_parses_domain_name() {
        let mut buffer = vec![0x05, 0x01, 0x00, 0x03, 5];
        buffer.extend_from_slice(b"abcde");
        buffer.extend_from_slice(&8080u16.to_be_bytes());
        let request = parse_socks5_connect(&buffer).unwrap().unwrap();
        assert_eq!(request.host, "abcde");
        assert_eq!(request.port, 8080);
        assert!(request.leftover.is_empty());
    }

    #[test]
    fn socks5_connect_parses_ipv6() {
        let mut buffer = vec![0x05, 0x01, 0x00, 0x04];
        buffer.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        buffer.extend_from_slice(&1080u16.to_be_bytes());
        let request = parse_socks5_connect(&buffer).unwrap().unwrap();
        assert_eq!(request.host, "::1");
        assert_eq!(request.port, 1080);
    }

    #[test]
    fn socks5_connect_requests_more_bytes_when_incomplete() {
        assert_eq!(parse_socks5_connect(&[0x05, 0x01]).unwrap(), None);
        assert_eq!(
            parse_socks5_connect(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4]).unwrap(),
            None
        );
        assert_eq!(
            parse_socks5_connect(&[0x05, 0x01, 0x00, 0x03, 5, b'a', b'b']).unwrap(),
            None
        );
    }

    #[test]
    fn socks5_connect_rejects_non_connect_command() {
        assert!(parse_socks5_connect(&[0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80]).is_err());
    }

    #[test]
    fn socks5_reply_has_fixed_shape() {
        assert_eq!(
            socks5_reply(0x00),
            [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(socks5_reply(0x01)[1], 0x01);
    }

    #[test]
    fn http_connect_request_parses_target_headers_and_empty_body() {
        let buffer = b"CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\nProxy-Connection: keep-alive\r\n\r\n";
        let request = parse_http_proxy_request(buffer).unwrap();
        assert_eq!(request.method, "CONNECT");
        assert_eq!(request.target, "example.com:8443");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(
            request.headers,
            vec![
                ("Host".to_string(), "example.com:8443".to_string()),
                ("Proxy-Connection".to_string(), "keep-alive".to_string()),
            ]
        );
        assert!(request.body.is_empty());
    }

    #[test]
    fn http_get_request_keeps_body_after_header_end() {
        let buffer =
            b"GET http://example.com/p?q=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody";
        let request = parse_http_proxy_request(buffer).unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "http://example.com/p?q=1");
        assert_eq!(request.body, b"body");
    }

    #[test]
    fn http_rewrite_converts_absolute_form_to_origin_form() {
        let request = parse_http_proxy_request(
            b"GET http://example.com:8080/p?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
        )
        .unwrap();
        let (host, port, rewritten) = rewrite_http_proxy_request(request).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(
            rewritten,
            b"GET /p?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
        );
    }

    #[test]
    fn http_rewrite_applies_default_ports_per_scheme() {
        let http = parse_http_proxy_request(b"GET http://example.com/ HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(rewrite_http_proxy_request(http).unwrap().1, 80);
        let https = parse_http_proxy_request(b"GET https://example.com/ HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(rewrite_http_proxy_request(https).unwrap().1, 443);
    }

    #[test]
    fn http_rewrite_rejects_origin_form_target() {
        let request =
            parse_http_proxy_request(b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert!(rewrite_http_proxy_request(request).is_err());
    }

    #[test]
    fn parse_host_port_handles_brackets_and_defaults() {
        assert_eq!(
            parse_host_port("example.com", 443).unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("example.com:8080", 443).unwrap(),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            parse_host_port("[::1]", 443).unwrap(),
            ("::1".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("[::1]:8443", 443).unwrap(),
            ("::1".to_string(), 8443)
        );
    }

    #[test]
    fn find_header_end_locates_terminator() {
        assert_eq!(find_header_end(b"a: b\r\n\r\nc"), Some(4));
        assert_eq!(find_header_end(b"a: b\r\n"), None);
    }

    #[test]
    fn resolved_route_uses_managed_decision_for_configured_domain() {
        let mut snapshot = ResourceSnapshot::default();
        snapshot.domain_resources.insert(
            "example.com".into(),
            DomainResource {
                port_min: 443,
                port_max: 443,
                protocol: "tcp".into(),
                app_id: "app".into(),
                node_group_id: "group".into(),
            },
        );
        let mut client = test_client();
        client.set_resource(snapshot);
        let route = resolved_tcp_route(&client, "example.com", 443).unwrap();
        assert!(matches!(route.decision, ProxyRouteDecision::Managed));
        assert_eq!(route.connect_host, "example.com");
    }

    #[test]
    fn resolved_route_sends_ip_literals_direct() {
        let client = test_client();
        let route = resolved_tcp_route(&client, "10.1.2.3", 80).unwrap();
        assert!(matches!(route.decision, ProxyRouteDecision::Direct));
        assert_eq!(route.connect_host, "10.1.2.3");
    }

    #[test]
    fn resolved_route_resolves_unmanaged_host_ips() {
        let client = test_client();
        let route = resolved_tcp_route(&client, "localhost", 80).unwrap();
        assert!(matches!(route.decision, ProxyRouteDecision::Direct));
    }

    #[test]
    fn dns_cache_reuses_answers_and_evicts_expired_entries() {
        let fresh = resolve_ipv4_addresses("127.0.0.1");
        assert_eq!(fresh, vec!["127.0.0.1".to_string()]);
        assert_eq!(resolve_ipv4_addresses("127.0.0.1"), fresh);
        assert!(DNS_CACHE.lock().unwrap().contains_key("127.0.0.1"));

        let stale = Instant::now()
            .checked_sub(Duration::from_secs(DNS_CACHE_TTL.as_secs() + 1))
            .unwrap_or_else(Instant::now);
        {
            let mut cache = DNS_CACHE.lock().unwrap();
            for index in 0..DNS_CACHE_MAX_ENTRIES {
                cache.insert(format!("filler-{index}.invalid"), (Vec::new(), stale));
            }
            // Drop the fresh entry so the next resolve misses and takes the
            // eviction path instead of returning from cache.
            cache.remove("127.0.0.1");
        }
        resolve_ipv4_addresses("127.0.0.1");

        let mut cache = DNS_CACHE.lock().unwrap();
        assert!(cache.values().all(|(_, at)| at.elapsed() < DNS_CACHE_TTL));
        assert!(cache.contains_key("127.0.0.1"));
        cache.remove("127.0.0.1");
    }

    #[test]
    fn proxy_relays_socks5_connect_in_both_directions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_port = listener.local_addr().unwrap().port();
        let target = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 4];
            socket.read_exact(&mut greeting).unwrap();
            assert_eq!(&greeting, b"ping");
            socket.write_all(b"PONG-OK").unwrap();
            let mut drain = [0u8; 64];
            while socket.read(&mut drain).unwrap() > 0 {}
        });

        let service = start_test_proxy(ProxyServiceConfig {
            listen_host: "127.0.0.1".into(),
            listen_port: 0,
            ..Default::default()
        });

        let mut client = TcpStream::connect(service.endpoint()).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).unwrap();
        assert_eq!(&greeting, &[0x05, 0x00]);

        let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        request.extend_from_slice(&target_port.to_be_bytes());
        client.write_all(&request).unwrap();
        client.write_all(b"ping").unwrap();

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00);

        let mut echoed = [0u8; 7];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"PONG-OK");

        client.write_all(b"tail").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        drop(client);
        target.join().unwrap();

        wait_until_idle(&service);
        let stats = service.stats();
        assert_eq!(stats.total_connections, 1);

        service.stop().unwrap();
        assert_eq!(service.status(), ProxyServiceStatus::Stopped);
    }

    #[test]
    fn proxy_relays_http_connect_in_both_directions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_port = listener.local_addr().unwrap().port();
        let target = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 5];
            socket.read_exact(&mut greeting).unwrap();
            assert_eq!(&greeting, b"http-");
            socket.write_all(b"HTTP-DONE").unwrap();
            let mut drain = [0u8; 64];
            while socket.read(&mut drain).unwrap() > 0 {}
        });

        let service = start_test_proxy(ProxyServiceConfig {
            listen_host: "127.0.0.1".into(),
            listen_port: 0,
            enable_socks5: false,
            ..Default::default()
        });

        let mut client = TcpStream::connect(service.endpoint()).unwrap();
        let request = format!(
            "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
        );
        client.write_all(request.as_bytes()).unwrap();

        let mut response = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            assert!(
                client.read(&mut byte).unwrap() > 0,
                "closed before response"
            );
            response.push(byte[0]);
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        assert!(response.starts_with(b"HTTP/1.1 200 Connection Established"));

        client.write_all(b"http-").unwrap();
        let mut echoed = [0u8; 9];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"HTTP-DONE");

        client.write_all(b"bye").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        drop(client);
        target.join().unwrap();

        wait_until_idle(&service);
        service.stop().unwrap();
        assert_eq!(service.status(), ProxyServiceStatus::Stopped);
    }

    #[test]
    fn proxy_closes_connection_for_unsupported_protocol() {
        let service = start_test_proxy(ProxyServiceConfig {
            listen_host: "127.0.0.1".into(),
            listen_port: 0,
            enable_http: false,
            ..Default::default()
        });

        let mut client = TcpStream::connect(service.endpoint()).unwrap();
        client.write_all(&[0x04]).unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).unwrap(), 0);

        let stats = service.stats();
        assert!(
            stats
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("unsupported proxy protocol")
        );
        service.stop().unwrap();
    }

    #[test]
    fn proxy_idle_timeout_closes_quiescent_socks5_client() {
        let service = start_test_proxy(ProxyServiceConfig {
            listen_host: "127.0.0.1".into(),
            listen_port: 0,
            enable_http: false,
            idle_timeout_ms: 200,
            ..Default::default()
        });

        let mut client = TcpStream::connect(service.endpoint()).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).unwrap();
        assert_eq!(&greeting, &[0x05, 0x00]);

        // Going idle must trip the read timeout and close the connection.
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        service.stop().unwrap();
    }
}
