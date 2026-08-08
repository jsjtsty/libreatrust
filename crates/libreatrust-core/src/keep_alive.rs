use crate::client::AtrClient;
use crate::error::{AtrError, AtrResult};
use crate::transport::{TcpTunnel, client_tls_config};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;
use url::Url;

const DEFAULT_INTERVAL_MS: u64 = 60_000;
const DNS_NAME: &[u8] = b"www.baidu.com";

#[derive(Debug, Clone)]
pub struct KeepAliveConfig {
    pub interval_ms: u64,
    pub url: Option<String>,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            interval_ms: DEFAULT_INTERVAL_MS,
            url: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct KeepAliveStatus {
    pub probe_count: u64,
    pub last_error: Option<String>,
}

#[derive(Debug)]
pub struct KeepAliveService {
    stop: Arc<AtomicBool>,
    probe_count: Arc<AtomicU64>,
    last_error: Arc<Mutex<Option<String>>>,
    wake: Arc<(Mutex<()>, Condvar)>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}

impl KeepAliveService {
    pub fn start(client: AtrClient, config: KeepAliveConfig) -> AtrResult<Self> {
        let interval = Duration::from_millis(config.interval_ms.max(1));
        let stop = Arc::new(AtomicBool::new(false));
        let probe_count = Arc::new(AtomicU64::new(0));
        let last_error = Arc::new(Mutex::new(None));
        let wake = Arc::new((Mutex::new(()), Condvar::new()));

        let worker_stop = stop.clone();
        let worker_count = probe_count.clone();
        let worker_error = last_error.clone();
        let worker_wake = wake.clone();
        let worker = thread::Builder::new()
            .name("libreatrust-keep-alive".into())
            .spawn(move || {
                while !worker_stop.load(Ordering::SeqCst) {
                    let result = if let Some(url) = config.url.as_deref().filter(|v| !v.is_empty())
                    {
                        probe_http(&client, url)
                    } else {
                        probe_dns(&client)
                    };

                    worker_count.fetch_add(1, Ordering::Relaxed);
                    if let Err(err) = result {
                        crate::diag_log(format!("[libreatrust][keep-alive] probe failed: {err}"));
                        *worker_error.lock().unwrap() = Some(err.to_string());
                    } else {
                        *worker_error.lock().unwrap() = None;
                        crate::diag_log("[libreatrust][keep-alive] probe succeeded");
                    }

                    let (lock, wake) = &*worker_wake;
                    let guard = lock.lock().unwrap();
                    let _ = wake
                        .wait_timeout_while(guard, interval, |_| {
                            !worker_stop.load(Ordering::SeqCst)
                        })
                        .unwrap();
                }
            })
            .map_err(|err| AtrError::Internal(format!("failed to start keep-alive: {err}")))?;

        Ok(Self {
            stop,
            probe_count,
            last_error,
            wake,
            worker: Mutex::new(Some(worker)),
        })
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.wake.1.notify_all();
        if let Some(worker) = self.worker.lock().unwrap().take() {
            let _ = worker.join();
        }
    }

    pub fn status(&self) -> KeepAliveStatus {
        KeepAliveStatus {
            probe_count: self.probe_count.load(Ordering::Relaxed),
            last_error: self.last_error.lock().unwrap().clone(),
        }
    }
}

impl Drop for KeepAliveService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.wake.1.notify_all();
        if let Some(worker) = self.worker.get_mut().unwrap().take() {
            let _ = worker.join();
        }
    }
}

fn probe_dns(client: &AtrClient) -> AtrResult<()> {
    let dns_server = client
        .resource()
        .and_then(|resource| resource.dns_server.clone())
        .ok_or_else(|| AtrError::NotFound("remote DNS server is not configured".into()))?;
    let packet = build_dns_query(0x4c41);
    match probe_dns_udp(client, &dns_server, &packet) {
        Ok(()) => Ok(()),
        Err(udp_err) => {
            crate::diag_log(format!("[libreatrust][keep-alive] UDP DNS probe failed, trying TCP: {udp_err}"));
            probe_dns_tcp(client, &dns_server, &packet).map_err(|tcp_err| {
                AtrError::NetworkFailed(format!("DNS keep-alive failed over UDP ({udp_err}) and TCP ({tcp_err})"))
            })
        }
    }
}

fn probe_dns_udp(client: &AtrClient, dns_server: &str, packet: &[u8]) -> AtrResult<()> {
    let tunnel = Arc::new(client.open_udp_tunnel(dns_server, 53)?);
    tunnel.write(packet)?;
    let response = read_udp_with_timeout(tunnel.clone(), 10_000)?;
    tunnel.close()?;
    validate_dns_response(packet, &response)
}

fn probe_dns_tcp(client: &AtrClient, dns_server: &str, packet: &[u8]) -> AtrResult<()> {
    let tunnel = Arc::new(client.open_tcp_tunnel(dns_server, 53)?);
    let framed_len = u16::try_from(packet.len())
        .map_err(|_| AtrError::InvalidArgument("DNS query is too large".into()))?;
    let mut framed = Vec::with_capacity(packet.len() + 2);
    framed.extend_from_slice(&framed_len.to_be_bytes());
    framed.extend_from_slice(packet);
    tunnel.write(&framed)?;
    let response = read_tcp_dns_with_timeout(tunnel.clone(), 10_000)?;
    tunnel.close()?;
    validate_dns_response(packet, &response)
}

fn validate_dns_response(query: &[u8], response: &[u8]) -> AtrResult<()> {
    if response.len() < 12 {
        return Err(AtrError::NetworkFailed("DNS response is too short".into()));
    }
    if response[..2] != query[..2] {
        return Err(AtrError::NetworkFailed("DNS response ID does not match query".into()));
    }
    Ok(())
}

fn read_udp_with_timeout(tunnel: Arc<crate::transport::UdpTunnel>, timeout_ms: u64) -> AtrResult<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    let reader_tunnel = tunnel.clone();
    thread::spawn(move || {
        let mut response = vec![0u8; 4096];
        let result = reader_tunnel.read(&mut response).map(|len| {
            response.truncate(len);
            response
        });
        let _ = tx.send(result);
    });
    match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
        Ok(result) => result,
        Err(_) => {
            let _ = tunnel.close();
            Err(AtrError::NetworkFailed(format!("DNS UDP response timed out after {timeout_ms}ms")))
        }
    }
}

fn read_tcp_dns_with_timeout(tunnel: Arc<TcpTunnel>, timeout_ms: u64) -> AtrResult<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    let reader_tunnel = tunnel.clone();
    thread::spawn(move || {
        let result = (|| {
            let mut length = [0u8; 2];
            read_tunnel_exact(&reader_tunnel, &mut length)?;
            let response_len = u16::from_be_bytes(length) as usize;
            let mut response = vec![0u8; response_len];
            read_tunnel_exact(&reader_tunnel, &mut response)?;
            Ok(response)
        })();
        let _ = tx.send(result);
    });
    match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
        Ok(result) => result,
        Err(_) => {
            let _ = tunnel.close();
            Err(AtrError::NetworkFailed(format!("DNS TCP response timed out after {timeout_ms}ms")))
        }
    }
}

fn read_tunnel_exact(tunnel: &TcpTunnel, buffer: &mut [u8]) -> AtrResult<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        let count = tunnel.read(&mut buffer[offset..])?;
        if count == 0 {
            return Err(AtrError::NetworkFailed("TCP tunnel closed while reading DNS response".into()));
        }
        offset += count;
    }
    Ok(())
}

fn probe_http(client: &AtrClient, target: &str) -> AtrResult<()> {
    let url = Url::parse(target)?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(AtrError::Unsupported(
            "keep-alive URL must use http or https".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| AtrError::InvalidArgument("keep-alive URL has no host".into()))?
        .to_string();
    let is_https = url.scheme() == "https";
    let port = url.port_or_known_default().unwrap_or(80);
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let path = match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: libreatrust-keep-alive\r\n\r\n"
    );
    let tunnel = Arc::new(client.open_tcp_tunnel(&host, port)?);
    let (tx, rx) = mpsc::channel();
    let worker_tunnel = tunnel.clone();
    let worker = thread::spawn(move || {
        let result = (|| -> AtrResult<()> {
            if is_https {
                let server_name = ServerName::try_from(host.to_string())
                    .map_err(|_| AtrError::InvalidArgument(format!("invalid HTTPS host {host}")))?;
                let conn = ClientConnection::new(client_tls_config(), server_name)
                    .map_err(|err| AtrError::NetworkFailed(format!("HTTPS handshake setup failed: {err}")))?;
                let mut tls = StreamOwned::new(conn, TunnelIo { tunnel: worker_tunnel.clone() });
                tls.write_all(request.as_bytes())?;
                tls.flush()?;
                let mut response = [0u8; 1024];
                let count = tls.read(&mut response)?;
                validate_http_response(&response[..count])
            } else {
                worker_tunnel.write(request.as_bytes())?;
                let mut response = [0u8; 1024];
                let count = worker_tunnel.read(&mut response)?;
                validate_http_response(&response[..count])
            }
        })();
        let _ = tx.send(result);
    });
    let result = match rx.recv_timeout(Duration::from_millis(10_000)) {
        Ok(result) => result,
        Err(_) => Err(AtrError::NetworkFailed("HTTP keep-alive response timed out after 10000ms".into())),
    };
    if result.is_err() {
        let _ = tunnel.close();
    }
    let _ = worker.join();
    result
}

fn validate_http_response(response: &[u8]) -> AtrResult<()> {
    let header = String::from_utf8_lossy(response);
    if header.starts_with("HTTP/") {
        Ok(())
    } else {
        Err(AtrError::NetworkFailed("HTTP keep-alive returned an invalid response".into()))
    }
}

struct TunnelIo {
    tunnel: Arc<TcpTunnel>,
}

impl Read for TunnelIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.tunnel.read(buf).map_err(std::io::Error::other)
    }
}

impl Write for TunnelIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tunnel.write(buf).map_err(std::io::Error::other)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn build_dns_query(id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in DNS_NAME.split(|byte| *byte == b'.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label);
    }
    packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    packet
}

#[cfg(test)]
mod tests {
    use super::build_dns_query;

    #[test]
    fn builds_dns_query_for_keep_alive() {
        let packet = build_dns_query(0x1234);
        assert_eq!(&packet[..2], &[0x12, 0x34]);
        assert_eq!(&packet[2..4], &[0x01, 0x00]);
        assert!(packet.windows(3).any(|part| part == b"www"));
        assert!(packet.windows(5).any(|part| part == b"baidu"));
        assert_eq!(&packet[packet.len() - 4..], &[0x00, 0x01, 0x00, 0x01]);
    }
}
