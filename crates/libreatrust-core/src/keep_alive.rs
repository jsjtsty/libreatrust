use crate::client::AtrClient;
use crate::error::{AtrError, AtrResult};
use crate::transport::{TcpTunnel, client_tls_config};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}

impl KeepAliveService {
    pub fn start(client: AtrClient, config: KeepAliveConfig) -> AtrResult<Self> {
        let interval = Duration::from_millis(config.interval_ms.max(1));
        let stop = Arc::new(AtomicBool::new(false));
        let probe_count = Arc::new(AtomicU64::new(0));
        let last_error = Arc::new(Mutex::new(None));

        let worker_stop = stop.clone();
        let worker_count = probe_count.clone();
        let worker_error = last_error.clone();
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

                    let mut remaining = interval;
                    while remaining > Duration::ZERO && !worker_stop.load(Ordering::SeqCst) {
                        let slice = remaining.min(Duration::from_millis(250));
                        thread::sleep(slice);
                        remaining = remaining.saturating_sub(slice);
                    }
                }
            })
            .map_err(|err| AtrError::Internal(format!("failed to start keep-alive: {err}")))?;

        Ok(Self {
            stop,
            probe_count,
            last_error,
            worker: Mutex::new(Some(worker)),
        })
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
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
    let tunnel = client.open_udp_tunnel(&dns_server, 53)?;
    let packet = build_dns_query(0x4c41);
    tunnel.write(&packet)?;
    tunnel.close()
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
        .ok_or_else(|| AtrError::InvalidArgument("keep-alive URL has no host".into()))?;
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
    let tunnel = client.open_tcp_tunnel(host, port)?;
    if url.scheme() == "https" {
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| AtrError::InvalidArgument(format!("invalid HTTPS host {host}")))?;
        let conn = ClientConnection::new(client_tls_config(), server_name).map_err(|err| {
            AtrError::NetworkFailed(format!("HTTPS handshake setup failed: {err}"))
        })?;
        let mut tls = StreamOwned::new(conn, TunnelIo { tunnel: &tunnel });
        tls.write_all(request.as_bytes())?;
        tls.flush()?;
    } else {
        tunnel.write(request.as_bytes())?;
    }
    tunnel.close()
}

struct TunnelIo<'a> {
    tunnel: &'a TcpTunnel,
}

impl Read for TunnelIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.tunnel.read(buf).map_err(std::io::Error::other)
    }
}

impl Write for TunnelIo<'_> {
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
