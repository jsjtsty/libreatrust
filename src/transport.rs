use crate::client::AtrClient;
use crate::error::{AtrError, AtrResult};
use crate::sign::calc_request_sig;
use crate::types::{ProtocolKind, RouteDecision};
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig as TlsClientConfig, ClientConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Digest;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, SystemTime};

#[derive(Debug)]
pub struct TcpTunnel {
    stream: Arc<Mutex<StreamOwned<ClientConnection, TcpStream>>>,
    read_buf: Mutex<VecDeque<u8>>,
    closed: AtomicBool,
}

#[derive(Debug)]
pub struct UdpTunnel {
    l3: Arc<L3Tunnel>,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    incoming_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    close_flag: Arc<AtomicBool>,
}

impl TcpTunnel {
    pub fn connect(client: &AtrClient, host: &str, port: u16) -> AtrResult<Self> {
        let hit = match client.route_tcp(host, port) {
            RouteDecision::Managed(hit) => hit,
            RouteDecision::Direct => {
                return Err(AtrError::NotFound(format!(
                    "resource not managed for {host}:{port}"
                )));
            }
        };
        let node_addr = client.best_node_for(&hit.node_group_id).ok_or_else(|| {
            AtrError::NotFound(format!("no node for group {}", hit.node_group_id))
        })?;
        let session = client
            .session()
            .ok_or_else(|| AtrError::InvalidState("session not set".into()))?;
        let stream = connect_tls(&node_addr, client.client_config())?;
        stream.sock.set_read_timeout(Some(Duration::from_millis(250)))?;
        let tunnel = Self {
            stream: Arc::new(Mutex::new(stream)),
            read_buf: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
        };
        tunnel.send_init(session, &hit.app_id, host, port)?;
        tunnel.send_dest(host, port)?;
        Ok(tunnel)
    }

    pub fn read(&self, buf: &mut [u8]) -> AtrResult<usize> {
        let mut copied = 0usize;
        {
            let mut cached = self.read_buf.lock().unwrap();
            while copied < buf.len() {
                if let Some(b) = cached.pop_front() {
                    buf[copied] = b;
                    copied += 1;
                } else {
                    break;
                }
            }
            if copied == buf.len() {
                return Ok(copied);
            }
        }

        let data = self.read_frame()?;
        let mut cached = self.read_buf.lock().unwrap();
        for b in data {
            cached.push_back(b);
        }
        while copied < buf.len() {
            if let Some(b) = cached.pop_front() {
                buf[copied] = b;
                copied += 1;
            } else {
                break;
            }
        }
        Ok(copied)
    }

    pub fn write(&self, data: &[u8]) -> AtrResult<usize> {
        if data.len() > u16::MAX as usize {
            return Err(AtrError::InvalidArgument("tcp payload too large".into()));
        }
        let mut frame = Vec::with_capacity(4 + data.len());
        frame.extend_from_slice(&[0x01, 0x00]);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        let mut stream = self.stream.lock().unwrap();
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(data.len())
    }

    pub fn close(&self) -> AtrResult<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let mut stream = self.stream.lock().unwrap();
        let _ = stream.write_all(&[0x01, 0x01, 0x00, 0x00]);
        let _ = stream.flush();
        let _ = stream.sock.shutdown(Shutdown::Both);
        Ok(())
    }

    fn send_init(
        &self,
        session: &crate::types::SessionMaterial,
        app_id: &str,
        dest_addr: &str,
        port: u16,
    ) -> AtrResult<()> {
        let proc_path = if port == 22 {
            "/usr/bin/ssh"
        } else {
            "/usr/bin/libreatrust"
        };
        let proc_name = if port == 22 { "ssh" } else { "libreatrust" };
        let proc_hash = format!("{:X}", sha2::Sha256::digest(proc_path.as_bytes()));
        let msg = format!(
            r#"{{"sid":"{}","appId":"{}","url":"tcp://{}:{}","deviceId":"{}","connectionId":"{}","procHash":"{}","userName":"{}","rcAppliedInfo":0,"lang":"en-US","destAddr":"{}:{}","env":{{"application":{{"runtime":{{"process":{{"name":"{}","digital_signature":"TrustAppClosed","platform":"Linux","fingerprint":"{}","description":"TrustAppClosed","path":"{}","version":"TrustAppClosed","security_env":"normal"}},"process_trusted":"TRUSTED"}}}}}},"xRequestSig":""}}"#,
            session.sid,
            app_id,
            dest_addr,
            port,
            session.device_id,
            session.connection_id,
            proc_hash,
            session.username,
            dest_addr,
            port,
            proc_name,
            proc_hash,
            proc_path
        );
        let key = hex::decode(&session.sign_key_hex)
            .map_err(|e| AtrError::CryptoFailed(e.to_string()))?;
        let sig = calc_request_sig(&key, msg.as_bytes());
        let final_msg = msg.replace(
            r#""xRequestSig":"""#,
            &format!(r#""xRequestSig":"{}""#, sig),
        );
        let mut frame = Vec::with_capacity(5 + 2 + final_msg.len());
        frame.extend_from_slice(&[0x05, 0x01, 0x81, 0x53, 0x03]);
        frame.extend_from_slice(&(final_msg.len() as u16).to_be_bytes());
        frame.extend_from_slice(final_msg.as_bytes());
        let mut stream = self.stream.lock().unwrap();
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }

    fn send_dest(&self, host: &str, port: u16) -> AtrResult<()> {
        let mut frame = Vec::new();
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            frame.extend_from_slice(&[0x05, 0x01, 0x01, 0x01]);
            frame.extend_from_slice(&ip.octets());
        } else {
            let bytes = host.as_bytes();
            if bytes.len() > u8::MAX as usize {
                return Err(AtrError::InvalidArgument(format!(
                    "domain too long: {host}"
                )));
            }
            frame.extend_from_slice(&[0x05, 0x01, 0x01, 0x03, bytes.len() as u8]);
            frame.extend_from_slice(bytes);
        }
        frame.extend_from_slice(&port.to_be_bytes());
        let mut stream = self.stream.lock().unwrap();
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }

    fn read_frame(&self) -> AtrResult<Vec<u8>> {
        loop {
            let mut header = [0u8; 2];
            let mut stream = self.stream.lock().unwrap();
            if !read_exact_or_empty(&mut *stream, &mut header)? {
                return Ok(Vec::new());
            }
            match header {
                [0x01, 0x00] => {
                    let mut len_bytes = [0u8; 2];
                    if !read_exact_or_empty(&mut *stream, &mut len_bytes)? {
                        return Ok(Vec::new());
                    }
                    let len = u16::from_be_bytes(len_bytes) as usize;
                    let mut data = vec![0u8; len];
                    if !read_exact_or_empty(&mut *stream, &mut data)? {
                        return Ok(Vec::new());
                    }
                    return Ok(data);
                }
                [0x01, 0x01] => {
                    let mut tail = [0u8; 2];
                    if !read_exact_or_empty(&mut *stream, &mut tail)? {
                        return Ok(Vec::new());
                    }
                    if tail == [0x30, 0x30] {
                        return Err(AtrError::NetworkFailed(
                            "connection closed by server".into(),
                        ));
                    }
                }
                [0x53, 0x00] => {
                    let mut len_bytes = [0u8; 2];
                    if !read_exact_or_empty(&mut *stream, &mut len_bytes)? {
                        return Ok(Vec::new());
                    }
                    let len = u16::from_be_bytes(len_bytes) as usize;
                    let mut payload = vec![0u8; len];
                    if !read_exact_or_empty(&mut *stream, &mut payload)? {
                        return Ok(Vec::new());
                    }
                    if !String::from_utf8_lossy(&payload).contains("OK") {
                        return Err(AtrError::NetworkFailed(
                            String::from_utf8_lossy(&payload).into_owned(),
                        ));
                    }
                }
                [0x05, 0x81] => {
                    let mut marker = [0u8; 2];
                    if !read_exact_or_empty(&mut *stream, &mut marker)? {
                        return Ok(Vec::new());
                    }
                    if marker != [0x53, 0x00] {
                        eprintln!(
                            "[libreatrust][tcp] ignoring tunnel auth marker {:02x?}",
                            marker
                        );
                        continue;
                    }

                    let mut len_bytes = [0u8; 2];
                    if !read_exact_or_empty(&mut *stream, &mut len_bytes)? {
                        return Ok(Vec::new());
                    }
                    let len = u16::from_be_bytes(len_bytes) as usize;
                    let mut payload = vec![0u8; len];
                    if !read_exact_or_empty(&mut *stream, &mut payload)? {
                        return Ok(Vec::new());
                    }
                    let text = String::from_utf8_lossy(&payload);
                    eprintln!("[libreatrust][tcp] tunnel auth response {}", text);
                    if !text.contains(r#""message":"OK""#)
                        && !text.contains(r#""message":"Succeeded""#)
                    {
                        return Err(AtrError::NetworkFailed(text.into_owned()));
                    }
                }
                [0x05, status] => {
                    let mut tail = [0u8; 8];
                    if !read_exact_or_empty(&mut *stream, &mut tail)? {
                        return Ok(Vec::new());
                    }
                    eprintln!(
                        "[libreatrust][tcp] ignoring tunnel control status={:02x} tail={:02x?}",
                        status, tail
                    );
                }
                _ => {
                    eprintln!(
                        "[libreatrust][tcp] ignoring tunnel header {:02x} {:02x}",
                        header[0], header[1]
                    );
                }
            }
        }
    }
}

fn read_exact_or_empty<R: Read>(reader: &mut R, buf: &mut [u8]) -> AtrResult<bool> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(false),
        Err(err) => Err(AtrError::from(err)),
    }
}

impl UdpTunnel {
    pub fn connect(client: &AtrClient, host: &str, port: u16) -> AtrResult<Self> {
        match client.route_udp(host, port) {
            RouteDecision::Managed(_) => {}
            RouteDecision::Direct => {
                return Err(AtrError::NotFound(format!(
                    "resource not managed for {host}:{port}"
                )));
            }
        };
        let l3 = Arc::new(L3Tunnel::new(client.clone())?);
        let remote_ip = resolve_ipv4(host)?;
        let local_ip = pick_local_ip(remote_ip);
        let local_port = pick_local_port(host, port);
        let (tx, rx) = mpsc::channel();
        let close_flag = Arc::new(AtomicBool::new(false));

        {
            let l3_reader = l3.clone();
            let close_flag_reader = close_flag.clone();
            let tx_reader = tx.clone();
            thread::spawn(move || {
                loop {
                    if close_flag_reader.load(Ordering::SeqCst) {
                        break;
                    }
                    let packet = match l3_reader.read_packet() {
                        Ok(pkt) => pkt,
                        Err(_) => break,
                    };
                    if let Some(payload) =
                        udp_payload_if_match(&packet, local_ip, local_port, remote_ip, port)
                    {
                        let _ = tx_reader.send(payload);
                    }
                }
            });
        }

        Ok(Self {
            l3,
            local_ip,
            local_port,
            remote_ip,
            remote_port: port,
            incoming_rx: Mutex::new(rx),
            close_flag,
        })
    }

    pub fn read(&self, buf: &mut [u8]) -> AtrResult<usize> {
        loop {
            if self.close_flag.load(Ordering::SeqCst) {
                return Err(AtrError::NetworkFailed("udp tunnel closed".into()));
            }
            match self
                .incoming_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_millis(250))
            {
                Ok(payload) => {
                    let n = buf.len().min(payload.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    return Ok(n);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(AtrError::NetworkFailed("udp tunnel closed".into()));
                }
            }
        }
    }

    pub fn write(&self, data: &[u8]) -> AtrResult<usize> {
        if self.close_flag.load(Ordering::SeqCst) {
            return Err(AtrError::InvalidState("udp tunnel closed".into()));
        }
        let packet = build_udp_ipv4_packet(
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port,
            data,
        )?;
        self.l3.write_packet(&packet)?;
        Ok(data.len())
    }

    pub fn close(&self) -> AtrResult<()> {
        if self.close_flag.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.l3.close()?;
        Ok(())
    }
}

impl Drop for UdpTunnel {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[derive(Debug)]
pub struct L3Tunnel {
    client: AtrClient,
    incoming_tx: mpsc::Sender<Vec<u8>>,
    incoming_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    remotes: Mutex<HashMap<String, Arc<L3Remote>>>,
    close_flag: Arc<AtomicBool>,
    vip_list: Arc<Mutex<Vec<Ipv4Addr>>>,
}

impl L3Tunnel {
    pub fn new(client: AtrClient) -> AtrResult<Self> {
        let (tx, rx) = mpsc::channel();
        Ok(Self {
            client,
            incoming_tx: tx,
            incoming_rx: Mutex::new(rx),
            remotes: Mutex::new(HashMap::new()),
            close_flag: Arc::new(AtomicBool::new(false)),
            vip_list: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn read_packet(&self) -> AtrResult<Vec<u8>> {
        loop {
            if self.close_flag.load(Ordering::SeqCst) {
                return Err(AtrError::NetworkFailed("l3 tunnel closed".into()));
            }
            match self
                .incoming_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_millis(250))
            {
                Ok(pkt) => return Ok(pkt),
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(AtrError::NetworkFailed("l3 tunnel closed".into()));
                }
            }
        }
    }

    pub fn write_packet(&self, packet: &[u8]) -> AtrResult<usize> {
        let meta = parse_packet_meta(packet)?;
        let decision = match meta.protocol {
            ProtocolKind::Tcp => self
                .client
                .route_tcp(&meta.dst_ip.to_string(), meta.dst_port),
            ProtocolKind::Udp => self
                .client
                .route_udp(&meta.dst_ip.to_string(), meta.dst_port),
            ProtocolKind::Icmp => self.client.route_icmp(&meta.dst_ip.to_string()),
        };
        let hit = match decision {
            RouteDecision::Managed(hit) => hit,
            RouteDecision::Direct => {
                return Err(AtrError::NotFound(format!(
                    "resource not managed for {}",
                    meta.dst_ip
                )));
            }
        };

        let remote = self.remote_for(&hit.node_group_id)?;
        remote.write_packet(meta, &hit.app_id, &hit.node_group_id, packet)?;
        Ok(packet.len())
    }

    pub fn close(&self) -> AtrResult<()> {
        if self.close_flag.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        for remote in self.remotes.lock().unwrap().values() {
            remote.close_flag.store(true, Ordering::SeqCst);
        }
        self.remotes.lock().unwrap().clear();
        Ok(())
    }

    pub fn virtual_ips(&self) -> Vec<Ipv4Addr> {
        self.vip_list.lock().unwrap().clone()
    }

    fn remote_for(&self, node_group_id: &str) -> AtrResult<Arc<L3Remote>> {
        if let Some(existing) = self.remotes.lock().unwrap().get(node_group_id).cloned() {
            return Ok(existing);
        }
        let node_addr = self
            .client
            .best_node_for(node_group_id)
            .ok_or_else(|| AtrError::NotFound(format!("no node for group {node_group_id}")))?;
        let session = self
            .client
            .session()
            .ok_or_else(|| AtrError::InvalidState("session not set".into()))?
            .clone();
        let remote = Arc::new(L3Remote::connect(
            self.client.clone(),
            session,
            node_addr,
            self.incoming_tx.clone(),
            self.vip_list.clone(),
        )?);
        self.remotes
            .lock()
            .unwrap()
            .insert(node_group_id.to_string(), remote.clone());
        Ok(remote)
    }
}

impl Drop for L3Tunnel {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[derive(Debug)]
struct Conntrack {
    key: String,
    auth_id: u64,
    connect_token: Mutex<Option<String>>,
    app_id: String,
    auth_started: AtomicBool,
    auth_result: Mutex<Option<AtrResult<()>>>,
    auth_cv: Condvar,
}

#[derive(Debug)]
struct ConntrackMgr {
    next_auth_id: AtomicU64,
    by_key: Mutex<HashMap<String, Arc<Conntrack>>>,
    by_id: Mutex<HashMap<u64, Arc<Conntrack>>>,
}

impl ConntrackMgr {
    fn new() -> Self {
        Self {
            next_auth_id: AtomicU64::new(0),
            by_key: Mutex::new(HashMap::new()),
            by_id: Mutex::new(HashMap::new()),
        }
    }

    fn get_or_create(&self, key: &str, app_id: &str, _node_group_id: &str) -> Arc<Conntrack> {
        if let Some(ct) = self.by_key.lock().unwrap().get(key).cloned() {
            return ct;
        }
        let auth_id = self.next_auth_id.fetch_add(1, Ordering::SeqCst) + 1;
        let ct = Arc::new(Conntrack {
            key: key.to_string(),
            auth_id,
            connect_token: Mutex::new(None),
            app_id: app_id.to_string(),
            auth_started: AtomicBool::new(false),
            auth_result: Mutex::new(None),
            auth_cv: Condvar::new(),
        });
        self.by_key
            .lock()
            .unwrap()
            .insert(key.to_string(), ct.clone());
        self.by_id.lock().unwrap().insert(auth_id, ct.clone());
        ct
    }

    fn by_id(&self, auth_id: u64) -> Option<Arc<Conntrack>> {
        self.by_id.lock().unwrap().get(&auth_id).cloned()
    }
}

#[derive(Debug, Clone)]
struct L3ClientInfo {
    sid: String,
    device_id: String,
    connection_id: String,
}

#[derive(Debug)]
struct L3Remote {
    stream: Arc<Mutex<StreamOwned<ClientConnection, TcpStream>>>,
    info: L3ClientInfo,
    sign_key: Vec<u8>,
    conntracks: Arc<ConntrackMgr>,
    close_flag: Arc<AtomicBool>,
    vip_list: Arc<Mutex<Vec<Ipv4Addr>>>,
}

#[derive(Debug, Clone, Copy)]
struct PacketMeta {
    atype: u8,
    protocol: ProtocolKind,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

impl L3Remote {
    fn connect(
        client: AtrClient,
        session: crate::types::SessionMaterial,
        addr: String,
        incoming_tx: mpsc::Sender<Vec<u8>>,
        vip_list: Arc<Mutex<Vec<Ipv4Addr>>>,
    ) -> AtrResult<Self> {
        let stream = connect_tls(&addr, client.client_config())?;
        let remote = Self {
            stream: Arc::new(Mutex::new(stream)),
            info: L3ClientInfo {
                sid: session.sid,
                device_id: session.device_id,
                connection_id: session.connection_id,
            },
            sign_key: hex::decode(session.sign_key_hex)
                .map_err(|e| AtrError::CryptoFailed(e.to_string()))?,
            conntracks: Arc::new(ConntrackMgr::new()),
            close_flag: Arc::new(AtomicBool::new(false)),
            vip_list,
        };
        remote.auth_tunnel()?;
        remote.spawn_loops(incoming_tx);
        Ok(remote)
    }

    fn spawn_loops(&self, incoming_tx: mpsc::Sender<Vec<u8>>) {
        let reader = self.stream.clone();
        let conntracks = self.conntracks.clone();
        let close = self.close_flag.clone();
        let heartbeat_stream = self.stream.clone();
        let heartbeat_close = self.close_flag.clone();
        let vip_list = self.vip_list.clone();

        thread::spawn(move || {
            loop {
                if close.load(Ordering::SeqCst) {
                    break;
                }
                let frame = {
                    let mut stream = reader.lock().unwrap();
                    read_l3_frame(&mut *stream)
                };
                let frame = match frame {
                    Ok(v) => v,
                    Err(_) => break,
                };
                match frame.cmd {
                    0x94 => {
                        if frame.data_mode == DataMode::Len {
                            let _ = incoming_tx.send(frame.payload);
                        } else if let Ok(packets) = parse_data_payload(&frame.payload) {
                            for pkt in packets {
                                let _ = incoming_tx.send(pkt);
                            }
                        }
                    }
                    0x93 => {
                        let _ = handle_auth_resp(&conntracks, frame.status, &frame.payload);
                    }
                    0x95 => {}
                    0x96 => {
                        if let Some(ips) = parse_virtual_ip_bytes(&frame.payload) {
                            *vip_list.lock().unwrap() = ips;
                        }
                    }
                    _ => {}
                }
            }
        });

        thread::spawn(move || {
            while !heartbeat_close.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(25));
                let mut stream = heartbeat_stream.lock().unwrap();
                let _ = stream.write_all(&[0x05, 0x15, 0x00, 0x00]);
                let _ = stream.flush();
            }
        });
    }

    fn auth_tunnel(&self) -> AtrResult<()> {
        let req = serde_json::to_vec(&json!({ "sid": self.info.sid }))?;
        let packet = wrap_auth_req_data(&req, 1);
        {
            let mut stream = self.stream.lock().unwrap();
            stream.write_all(&packet)?;
            stream.flush()?;
        }

        let mut stream = self.stream.lock().unwrap();
        let mut method = [0u8; 2];
        stream.read_exact(&mut method)?;
        if method != [0x05, 0xD0] {
            return Err(AtrError::NetworkFailed(format!(
                "unexpected auth method {:?}",
                method
            )));
        }

        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;
        if header[0] != 0x53 {
            return Err(AtrError::NetworkFailed(format!(
                "unexpected auth header {:02x?}",
                header
            )));
        }
        let status = header[1];
        let len = u16::from_be_bytes([header[2], header[3]]) as usize;
        let mut payload = vec![0u8; len];
        if len > 0 {
            stream.read_exact(&mut payload)?;
        }
        if status != 0 {
            return Err(AtrError::Unauthorized(
                String::from_utf8_lossy(&payload).into_owned(),
            ));
        }
        if !payload.is_empty() {
            let resp: AuthResponseSid = serde_json::from_slice(&payload)?;
            if resp.code != 0 {
                return Err(AtrError::Unauthorized(format!(
                    "tunnel auth failed: {}",
                    resp.message
                )));
            }
        }
        let mut vip_header = [0u8; 4];
        if stream.read_exact(&mut vip_header).is_ok() && vip_header[0] == 0x05 {
            let data_len = vip_payload_length(vip_header[3]);
            if data_len > 0 {
                let mut vip_data = vec![0u8; data_len];
                stream.read_exact(&mut vip_data)?;
                if let Some(ips) = parse_virtual_ip_bytes(&vip_data) {
                    *self.vip_list.lock().unwrap() = ips;
                }
            }
        }
        Ok(())
    }

    fn write_packet(
        &self,
        meta: PacketMeta,
        app_id: &str,
        node_group_id: &str,
        pkt: &[u8],
    ) -> AtrResult<()> {
        let ct = self
            .conntracks
            .get_or_create(&conn_track_key(&meta), app_id, node_group_id);
        self.ensure_auth(&ct, meta)?;
        let token = ct
            .connect_token
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| AtrError::InvalidState("missing connect token".into()))?;
        let payload = build_data_payload(&token, &[pkt.to_vec()]);
        let mut stream = self.stream.lock().unwrap();
        stream.write_all(&payload)?;
        stream.flush()?;
        Ok(())
    }

    fn ensure_auth(&self, ct: &Arc<Conntrack>, meta: PacketMeta) -> AtrResult<()> {
        if let Some(result) = ct.auth_result.lock().unwrap().clone() {
            return result;
        }
        if ct
            .auth_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.send_auth_request(ct, meta)?;
        }
        let mut guard = ct.auth_result.lock().unwrap();
        let deadline = SystemTime::now() + Duration::from_secs(8);
        loop {
            if let Some(result) = guard.clone() {
                return result;
            }
            let now = SystemTime::now();
            if now >= deadline {
                return Err(AtrError::NetworkFailed(format!(
                    "l3 auth timeout for {}",
                    ct.key
                )));
            }
            let remaining = deadline
                .duration_since(now)
                .unwrap_or(Duration::from_secs(0));
            let (next, _) = ct.auth_cv.wait_timeout(guard, remaining).unwrap();
            guard = next;
        }
    }

    fn send_auth_request(&self, ct: &Arc<Conntrack>, meta: PacketMeta) -> AtrResult<()> {
        let req = build_auth_request(&self.info, &self.sign_key, meta, ct)?;
        let packet = wrap_auth_req_data(&req, 1);
        let mut stream = self.stream.lock().unwrap();
        stream.write_all(&packet)?;
        stream.flush()?;
        Ok(())
    }
}

#[derive(Debug)]
struct Frame {
    cmd: u8,
    status: u8,
    payload: Vec<u8>,
    data_mode: DataMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataMode {
    Token,
    Len,
}

fn connect_tls(
    addr: &str,
    cfg: &crate::types::ClientConfig,
) -> AtrResult<StreamOwned<ClientConnection, TcpStream>> {
    let tcp = TcpStream::connect(addr).map_err(|e| AtrError::NetworkFailed(e.to_string()))?;
    tcp.set_write_timeout(Some(Duration::from_millis(cfg.io_timeout_ms)))?;
    let host = addr.split(':').next().unwrap_or(addr);
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| AtrError::InvalidArgument(format!("invalid host {host}")))?;
    let client_cfg = TlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let conn = ClientConnection::new(Arc::new(client_cfg), server_name)
        .map_err(|e| AtrError::NetworkFailed(e.to_string()))?;
    Ok(StreamOwned::new(conn, tcp))
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn read_l3_frame(stream: &mut StreamOwned<ClientConnection, TcpStream>) -> AtrResult<Frame> {
    loop {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header)?;
        match header {
            [0x05, cmd] if cmd == 0x93 || cmd == 0x96 => {
                let mut status_len = [0u8; 3];
                stream.read_exact(&mut status_len)?;
                let status = status_len[0];
                let len = u16::from_be_bytes([status_len[1], status_len[2]]) as usize;
                let mut payload = vec![0u8; len];
                if len > 0 {
                    stream.read_exact(&mut payload)?;
                }
                return Ok(Frame {
                    cmd,
                    status,
                    payload,
                    data_mode: DataMode::Len,
                });
            }
            [0x05, 0x94] => {
                let (payload, mode) = read_data_resp_payload(stream)?;
                return Ok(Frame {
                    cmd: 0x94,
                    status: 0,
                    payload,
                    data_mode: mode,
                });
            }
            [0x05, cmd] => {
                let mut len_bytes = [0u8; 2];
                stream.read_exact(&mut len_bytes)?;
                let len = u16::from_be_bytes(len_bytes) as usize;
                let mut payload = vec![0u8; len];
                if len > 0 {
                    stream.read_exact(&mut payload)?;
                }
                return Ok(Frame {
                    cmd,
                    status: 0,
                    payload,
                    data_mode: DataMode::Len,
                });
            }
            [0x53, 0x00] => {
                let mut len_bytes = [0u8; 2];
                stream.read_exact(&mut len_bytes)?;
                let len = u16::from_be_bytes(len_bytes) as usize;
                let mut payload = vec![0u8; len];
                if len > 0 {
                    stream.read_exact(&mut payload)?;
                }
                continue;
            }
            _ => {
                return Err(AtrError::ParseFailed(format!(
                    "unexpected frame header {:02x} {:02x}",
                    header[0], header[1]
                )));
            }
        }
    }
}

fn read_data_resp_payload(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
) -> AtrResult<(Vec<u8>, DataMode)> {
    let mut peek = [0u8; 2];
    stream.read_exact(&mut peek)?;
    let payload_len = u16::from_be_bytes(peek) as usize;
    if payload_len > 0 && payload_len <= 4096 {
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            stream.read_exact(&mut payload)?;
        }
        return Ok((payload, DataMode::Len));
    }

    let token_len = peek[0] as usize;
    let mut payload = vec![peek[0]];
    if token_len > 0 {
        let mut token = vec![0u8; token_len];
        stream.read_exact(&mut token)?;
        payload.extend_from_slice(&token);
    }
    let mut reserved = [0u8; 2];
    stream.read_exact(&mut reserved)?;
    payload.extend_from_slice(&reserved);
    let mut count = [0u8; 1];
    stream.read_exact(&mut count)?;
    payload.extend_from_slice(&count);
    for _ in 0..count[0] {
        let mut len_bytes = [0u8; 2];
        stream.read_exact(&mut len_bytes)?;
        payload.extend_from_slice(&len_bytes);
        let plen = u16::from_be_bytes(len_bytes) as usize;
        if plen > 0 {
            let mut pkt = vec![0u8; plen];
            stream.read_exact(&mut pkt)?;
            payload.extend_from_slice(&pkt);
        }
    }
    Ok((payload, DataMode::Token))
}

fn build_auth_request(
    info: &L3ClientInfo,
    sign_key: &[u8],
    meta: PacketMeta,
    ct: &Arc<Conntrack>,
) -> AtrResult<Vec<u8>> {
    let url = format!(
        "{}:{}:{}",
        proto_name(meta.protocol),
        meta.dst_ip,
        meta.dst_port
    );
    let env = default_env();
    let req = AuthRequestIp {
        sid: info.sid.clone(),
        app_id: ct.app_id.clone(),
        url,
        device_id: info.device_id.clone(),
        connection_id: info.connection_id.clone(),
        env: Some(env.clone()),
        conntrack_hash: ct.auth_id,
        lang: lang_from_env(),
        ip: AuthIp {
            atype: auth_ip_type(meta.atype),
            protocol: meta.protocol as i32,
            dest_addr: meta.dst_ip.to_string(),
            dest_port: meta.dst_port,
            src_addr: meta.src_ip.to_string(),
            src_port: meta.src_port,
        },
        domain: String::new(),
        proc_hash: env.process_fingerprint(),
        x_request_sig: String::new(),
    };
    let unsigned = serde_json::to_vec(&req)?;
    let sig = calc_request_sig(sign_key, &unsigned);
    let mut req = req;
    req.x_request_sig = sig;
    Ok(serde_json::to_vec(&req)?)
}

#[derive(Debug, Serialize)]
struct AuthRequestIp {
    sid: String,
    #[serde(rename = "appId")]
    app_id: String,
    #[serde(rename = "url")]
    url: String,
    #[serde(rename = "deviceId")]
    device_id: String,
    #[serde(rename = "connectionId")]
    connection_id: String,
    env: Option<TrustEnv>,
    #[serde(rename = "conntrackHash")]
    conntrack_hash: u64,
    lang: String,
    ip: AuthIp,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    domain: String,
    #[serde(rename = "procHash")]
    proc_hash: String,
    #[serde(rename = "xRequestSig")]
    x_request_sig: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AuthIp {
    atype: i32,
    protocol: i32,
    #[serde(rename = "destAddr")]
    dest_addr: String,
    #[serde(rename = "destPort")]
    dest_port: u16,
    #[serde(rename = "srcAddr")]
    src_addr: String,
    #[serde(rename = "srcPort")]
    src_port: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TrustEnv {
    application: TrustApp,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TrustApp {
    runtime: TrustRuntime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TrustRuntime {
    process: TrustProcess,
    #[serde(rename = "process_trusted")]
    process_trusted: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TrustProcess {
    name: String,
    #[serde(rename = "digital_signature")]
    digital_signature: String,
    platform: String,
    fingerprint: String,
    description: String,
    path: String,
    version: String,
    #[serde(rename = "security_env")]
    security_env: String,
}

impl TrustEnv {
    fn process_fingerprint(&self) -> String {
        self.application.runtime.process.fingerprint.clone()
    }
}

fn default_env() -> TrustEnv {
    let proc_path = "/usr/bin/libreatrust";
    let fingerprint = format!("{:X}", sha2::Sha256::digest(proc_path.as_bytes()));
    TrustEnv {
        application: TrustApp {
            runtime: TrustRuntime {
                process: TrustProcess {
                    name: "libreatrust".into(),
                    digital_signature: "TrustAppClosed".into(),
                    platform: "Linux".into(),
                    fingerprint,
                    description: "TrustAppClosed".into(),
                    path: proc_path.into(),
                    version: "TrustAppClosed".into(),
                    security_env: "normal".into(),
                },
                process_trusted: "TRUSTED".into(),
            },
        },
    }
}

fn wrap_auth_req_data(payload: &[u8], addr_type: u8) -> Vec<u8> {
    let mut header = Vec::with_capacity(4 + payload.len());
    header.extend_from_slice(&[0x53, 0x00]);
    header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    header.extend_from_slice(payload);
    let mut buf = Vec::with_capacity(3 + header.len() + 10);
    buf.extend_from_slice(&[0x05, 0x01, 0xD0]);
    buf.extend_from_slice(&header);
    buf.extend_from_slice(&[
        0x05, 0x04, 0x00, addr_type, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    buf
}

fn build_data_payload(token: &str, packets: &[Vec<u8>]) -> Vec<u8> {
    let token_bytes = token.as_bytes();
    let mut payload_len = 1 + token_bytes.len() + 2 + 1;
    for pkt in packets {
        payload_len += 2 + pkt.len();
    }
    let mut payload = Vec::with_capacity(payload_len + 2);
    payload.extend_from_slice(&[0x05, 0x14]);
    payload.push(token_bytes.len() as u8);
    payload.extend_from_slice(token_bytes);
    payload.extend_from_slice(&[0x00, 0x00]);
    payload.push(packets.len() as u8);
    for pkt in packets {
        payload.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
        payload.extend_from_slice(pkt);
    }
    payload
}

fn parse_data_payload(payload: &[u8]) -> AtrResult<Vec<Vec<u8>>> {
    if payload.len() < 4 {
        return Err(AtrError::ParseFailed("payload too short".into()));
    }
    let token_len = payload[0] as usize;
    let mut idx = 1 + token_len;
    if payload.len() < idx + 3 {
        return Err(AtrError::ParseFailed("payload token overflow".into()));
    }
    idx += 2;
    let count = payload[idx] as usize;
    idx += 1;
    let mut packets = Vec::with_capacity(count);
    for _ in 0..count {
        if idx + 2 > payload.len() {
            return Err(AtrError::ParseFailed("packet length overflow".into()));
        }
        let plen = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
        idx += 2;
        if idx + plen > payload.len() {
            return Err(AtrError::ParseFailed("packet data overflow".into()));
        }
        packets.push(payload[idx..idx + plen].to_vec());
        idx += plen;
    }
    Ok(packets)
}

fn handle_auth_resp(conntracks: &Arc<ConntrackMgr>, status: u8, payload: &[u8]) -> AtrResult<()> {
    if status != 0 {
        return Ok(());
    }
    let resp: AuthResponseIp = serde_json::from_slice(payload)?;
    let ct = conntracks
        .by_id(resp.data.conntrack_hash)
        .ok_or_else(|| AtrError::NotFound("conntrack missing".into()))?;
    let token = if !resp.data.connect_token.trim().is_empty() {
        resp.data.connect_token.trim().to_string()
    } else {
        resp.data.token.trim().to_string()
    };
    let result = if resp.code == 0 && !token.is_empty() {
        *ct.connect_token.lock().unwrap() = Some(token);
        Ok(())
    } else {
        Err(AtrError::Unauthorized(format!(
            "auth failed: {} {}",
            resp.code, resp.message
        )))
    };
    *ct.auth_result.lock().unwrap() = Some(result.clone());
    ct.auth_cv.notify_all();
    result
}

#[derive(Debug, Deserialize)]
struct AuthResponseIp {
    code: i64,
    message: String,
    data: AuthResponseIpData,
}

#[derive(Debug, Deserialize)]
struct AuthResponseSid {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct AuthResponseIpData {
    #[serde(rename = "conntrackHash")]
    conntrack_hash: u64,
    #[serde(rename = "connectToken", default)]
    connect_token: String,
    #[serde(default)]
    token: String,
}

fn parse_packet_meta(packet: &[u8]) -> AtrResult<PacketMeta> {
    if packet.len() < 20 {
        return Err(AtrError::ParseFailed("packet too short".into()));
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return Err(AtrError::Unsupported("only ipv4 is supported".into()));
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if packet.len() < ihl {
        return Err(AtrError::ParseFailed("invalid ipv4 header".into()));
    }
    let proto = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let (src_port, dst_port) = match proto {
        6 | 17 => {
            if packet.len() < ihl + 4 {
                return Err(AtrError::ParseFailed("transport header too short".into()));
            }
            (
                u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
                u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
            )
        }
        1 => (0, 0),
        _ => {
            return Err(AtrError::Unsupported(format!(
                "protocol {proto} unsupported"
            )));
        }
    };
    Ok(PacketMeta {
        atype: 4,
        protocol: match proto {
            6 => ProtocolKind::Tcp,
            17 => ProtocolKind::Udp,
            _ => ProtocolKind::Icmp,
        },
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    })
}

fn resolve_ipv4(host: &str) -> AtrResult<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let mut iter = (host, 0u16)
        .to_socket_addrs()
        .map_err(|e| AtrError::NetworkFailed(e.to_string()))?;
    for addr in iter.by_ref() {
        if let std::net::SocketAddr::V4(v4) = addr {
            return Ok(*v4.ip());
        }
    }
    Err(AtrError::NotFound(format!("no ipv4 address for {host}")))
}

fn pick_local_ip(remote_ip: Ipv4Addr) -> Ipv4Addr {
    let octets = remote_ip.octets();
    Ipv4Addr::new(10, octets[1], octets[2], octets[3])
}

fn pick_local_port(host: &str, port: u16) -> u16 {
    let mut hash = 0u32;
    for byte in host.as_bytes() {
        hash = hash.wrapping_mul(16777619) ^ u32::from(*byte);
    }
    let mixed = hash ^ u32::from(port);
    40_000 + (mixed % 20_000) as u16
}

fn udp_payload_if_match(
    packet: &[u8],
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Option<Vec<u8>> {
    let (src_ip, dst_ip, src_port, dst_port, payload) = parse_ipv4_udp_packet(packet).ok()?;
    if src_ip == remote_ip
        && src_port == remote_port
        && dst_ip == local_ip
        && dst_port == local_port
    {
        Some(payload)
    } else {
        None
    }
}

fn build_udp_ipv4_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> AtrResult<Vec<u8>> {
    let udp_len = 8usize + payload.len();
    if udp_len > u16::MAX as usize {
        return Err(AtrError::InvalidArgument("udp payload too large".into()));
    }
    let total_len = 20usize + udp_len;
    if total_len > u16::MAX as usize {
        return Err(AtrError::InvalidArgument("ipv4 packet too large".into()));
    }

    let mut packet = vec![0u8; total_len];
    packet[0] = (4 << 4) | 5;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());
    let ip_checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[6..8].copy_from_slice(&0u16.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let checksum = udp_checksum(src_ip, dst_ip, udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

fn parse_ipv4_udp_packet(packet: &[u8]) -> AtrResult<(Ipv4Addr, Ipv4Addr, u16, u16, Vec<u8>)> {
    if packet.len() < 28 {
        return Err(AtrError::ParseFailed("udp packet too short".into()));
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return Err(AtrError::Unsupported("only ipv4 is supported".into()));
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if packet.len() < ihl + 8 {
        return Err(AtrError::ParseFailed("udp header too short".into()));
    }
    if packet[9] != 17 {
        return Err(AtrError::Unsupported("not a udp packet".into()));
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    let udp_len = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]) as usize;
    if packet.len() < ihl + udp_len || udp_len < 8 {
        return Err(AtrError::ParseFailed("invalid udp length".into()));
    }
    let payload = packet[ihl + 8..ihl + udp_len].to_vec();
    Ok((src_ip, dst_ip, src_port, dst_port, payload))
}

fn vip_payload_length(addr_type: u8) -> usize {
    match addr_type {
        1 => 6,
        4 => 18,
        5 => 22,
        _ => 0,
    }
}

fn parse_virtual_ip_bytes(data: &[u8]) -> Option<Vec<Ipv4Addr>> {
    match data.len() {
        6 => Some(vec![Ipv4Addr::new(data[0], data[1], data[2], data[3])]),
        18 => Some(vec![Ipv4Addr::new(data[0], data[1], data[2], data[3])]),
        22 => Some(vec![Ipv4Addr::new(data[0], data[1], data[2], data[3])]),
        _ => None,
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    checksum_words(header)
}

fn udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len() + (udp.len() % 2));
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }
    let sum = checksum_words(&pseudo);
    if sum == 0 { 0xFFFF } else { sum }
}

fn checksum_words(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn proto_name(proto: ProtocolKind) -> &'static str {
    match proto {
        ProtocolKind::Tcp => "tcp",
        ProtocolKind::Udp => "udp",
        ProtocolKind::Icmp => "icmp",
    }
}

fn auth_ip_type(atype: u8) -> i32 {
    match atype {
        6 => 0x86DD,
        _ => 0x0800,
    }
}

fn lang_from_env() -> String {
    let value = [
        env::var("ATR_LANG").ok(),
        env::var("LC_ALL").ok(),
        env::var("LC_MESSAGES").ok(),
        env::var("LANG").ok(),
    ]
    .into_iter()
    .flatten()
    .find(|s| !s.is_empty())
    .unwrap_or_else(|| "en-US".to_string());
    let mut lang = value;
    if let Some(idx) = lang.find('.') {
        lang.truncate(idx);
    }
    lang = lang.replace('_', "-");
    if lang.len() == 2 {
        let lower = lang.to_lowercase();
        return format!("{lower}-{upper}", upper = lower.to_uppercase());
    }
    if let Some((a, b)) = lang.split_once('-') {
        return format!("{}-{}", a.to_lowercase(), b.to_uppercase());
    }
    lang
}

fn conn_track_key(meta: &PacketMeta) -> String {
    format!(
        "{}:{}-{}:{}",
        meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port
    )
}

impl AtrClient {
    pub fn open_tcp_tunnel(&self, host: &str, port: u16) -> AtrResult<TcpTunnel> {
        TcpTunnel::connect(self, host, port)
    }

    pub fn open_udp_tunnel(&self, host: &str, port: u16) -> AtrResult<UdpTunnel> {
        UdpTunnel::connect(self, host, port)
    }

    pub fn open_l3_tunnel(&self) -> AtrResult<L3Tunnel> {
        L3Tunnel::new(self.clone())
    }
}

impl fmt::Display for PacketMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "atype={} proto={} {}:{} -> {}:{}",
            self.atype,
            proto_name(self.protocol),
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port
        )
    }
}
