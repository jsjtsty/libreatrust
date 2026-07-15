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
#[cfg(target_family = "unix")]
use std::ffi::CStr;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(target_family = "unix")]
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, SystemTime};

#[derive(Debug)]
pub struct TcpTunnel {
    incoming_rx: Mutex<mpsc::Receiver<AtrResult<Vec<u8>>>>,
    write_tx: mpsc::Sender<TcpTunnelCommand>,
    wake_tx: Mutex<TcpStream>,
    read_buf: Mutex<VecDeque<u8>>,
    closed: AtomicBool,
}

#[derive(Debug)]
enum TcpTunnelCommand {
    Write(Vec<u8>, mpsc::Sender<AtrResult<usize>>),
    Close,
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
        crate::diag_log(format!(
            "[libreatrust][tcp] connect begin target={host}:{port} app={} node_group={} node={node_addr}",
            hit.app_id, hit.node_group_id
        ));
        let session = client
            .session()
            .ok_or_else(|| AtrError::InvalidState("session not set".into()))?;
        let mut stream = connect_tls(&node_addr, client.client_config())?;
        stream.sock.set_read_timeout(Some(Duration::from_millis(
            client.client_config().io_timeout_ms,
        )))?;
        send_tcp_init(&mut stream, session, &hit.app_id, host, port)?;
        validate_tcp_tunnel_auth(&mut stream)?;
        send_tcp_dest(&mut stream, host, port)?;
        stream.sock.set_read_timeout(None)?;
        crate::diag_log(format!(
            "[libreatrust][tcp] connect ready target={host}:{port}"
        ));

        let (incoming_tx, incoming_rx) = mpsc::channel();
        let (write_tx, write_rx) = mpsc::channel();
        let (wake_rx, wake_tx) = tcp_stream_pair()?;
        wake_rx.set_nonblocking(true)?;
        wake_tx.set_nonblocking(true)?;
        thread::spawn(move || run_tcp_tunnel_worker(stream, incoming_tx, write_rx, wake_rx));

        Ok(Self {
            incoming_rx: Mutex::new(incoming_rx),
            write_tx,
            wake_tx: Mutex::new(wake_tx),
            read_buf: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
        })
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

        let data = match self.incoming_rx.lock().unwrap().recv() {
            Ok(result) => result?,
            Err(_) => return Ok(0),
        };
        let remaining = buf.len() - copied;
        let direct = remaining.min(data.len());
        buf[copied..copied + direct].copy_from_slice(&data[..direct]);
        copied += direct;

        if direct < data.len() {
            let mut cached = self.read_buf.lock().unwrap();
            cached.extend(data[direct..].iter().copied());
        }
        Ok(copied)
    }

    pub fn write(&self, data: &[u8]) -> AtrResult<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(AtrError::InvalidState("tcp tunnel closed".into()));
        }
        let (ack_tx, ack_rx) = mpsc::channel();
        self.write_tx
            .send(TcpTunnelCommand::Write(data.to_vec(), ack_tx))
            .map_err(|_| AtrError::NetworkFailed("tcp tunnel worker stopped".into()))?;
        self.wake_worker();
        ack_rx
            .recv()
            .map_err(|_| AtrError::NetworkFailed("tcp tunnel worker stopped".into()))?
    }

    pub fn close(&self) -> AtrResult<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let _ = self.write_tx.send(TcpTunnelCommand::Close);
        self.wake_worker();
        Ok(())
    }

    fn wake_worker(&self) {
        if let Ok(mut wake_tx) = self.wake_tx.lock() {
            let _ = wake_tx.write_all(&[1]);
        }
    }
}

fn run_tcp_tunnel_worker(
    mut stream: StreamOwned<ClientConnection, TcpStream>,
    incoming_tx: mpsc::Sender<AtrResult<Vec<u8>>>,
    write_rx: mpsc::Receiver<TcpTunnelCommand>,
    mut wake_rx: TcpStream,
) {
    loop {
        if !drain_tcp_tunnel_commands(&mut stream, &write_rx) {
            return;
        }

        let event = match wait_for_tcp_tunnel_event(&stream.sock, &wake_rx) {
            Ok(event) => event,
            Err(error) => {
                let _ = incoming_tx.send(Err(error));
                let _ = stream.sock.shutdown(Shutdown::Both);
                return;
            }
        };

        if event.wake_readable {
            drain_wake_stream(&mut wake_rx);
            if !drain_tcp_tunnel_commands(&mut stream, &write_rx) {
                return;
            }
        }

        if event.socket_readable {
            if !drain_tcp_tunnel_frames(&mut stream, &incoming_tx) {
                return;
            }
        }
    }
}

fn drain_tcp_tunnel_frames(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    incoming_tx: &mpsc::Sender<AtrResult<Vec<u8>>>,
) -> bool {
    // One socket readiness event may decrypt multiple aTrust frames into rustls'
    // internal buffer. Drain the already-available frames so interactive streams
    // do not wait for the next client keystroke to flush buffered output.
    let _ = stream.sock.set_read_timeout(Some(Duration::from_millis(1)));
    let result = loop {
        match read_tcp_frame(stream) {
            Ok(Some(data)) => {
                if incoming_tx.send(Ok(data)).is_err() {
                    break false;
                }
            }
            Ok(None) => break true,
            Err(error) => {
                let _ = incoming_tx.send(Err(error));
                break false;
            }
        }
    };
    let _ = stream.sock.set_read_timeout(None);
    if !result {
        let _ = stream.sock.shutdown(Shutdown::Both);
    }
    result
}

fn drain_tcp_tunnel_commands(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    write_rx: &mpsc::Receiver<TcpTunnelCommand>,
) -> bool {
    while let Ok(command) = write_rx.try_recv() {
        match command {
            TcpTunnelCommand::Write(data, ack_tx) => {
                let result = write_tcp_payload(stream, &data);
                let should_stop = result.is_err();
                let _ = ack_tx.send(result);
                if should_stop {
                    let _ = stream.sock.shutdown(Shutdown::Both);
                    return false;
                }
            }
            TcpTunnelCommand::Close => {
                let _ = stream.write_all(&[0x01, 0x01, 0x00, 0x00]);
                let _ = stream.flush();
                let _ = stream.sock.shutdown(Shutdown::Both);
                return false;
            }
        }
    }
    true
}

#[derive(Debug, Clone, Copy)]
struct TcpTunnelEvent {
    socket_readable: bool,
    wake_readable: bool,
}

fn wait_for_tcp_tunnel_event(socket: &TcpStream, wake: &TcpStream) -> AtrResult<TcpTunnelEvent> {
    use mio::event::Event;
    use mio::net::TcpStream as MioTcpStream;
    use mio::{Events, Interest, Poll, Token};

    let mut socket = MioTcpStream::from_std(socket.try_clone()?);
    let mut wake = MioTcpStream::from_std(wake.try_clone()?);
    let mut poll = Poll::new().map_err(AtrError::from)?;
    poll.registry()
        .register(&mut socket, Token(0), Interest::READABLE)?;
    poll.registry()
        .register(&mut wake, Token(1), Interest::READABLE)?;
    let mut events = Events::with_capacity(2);
    poll.poll(&mut events, None).map_err(AtrError::from)?;
    Ok(TcpTunnelEvent {
        socket_readable: events.iter().any(|event: &Event| event.token() == Token(0)),
        wake_readable: events.iter().any(|event: &Event| event.token() == Token(1)),
    })
}

fn drain_wake_stream(wake_rx: &mut TcpStream) {
    let mut buf = [0u8; 64];
    loop {
        match wake_rx.read(&mut buf) {
            Ok(0) => return,
            Ok(_) => continue,
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                return;
            }
            Err(_) => return,
        }
    }
}

fn tcp_stream_pair() -> AtrResult<(TcpStream, TcpStream)> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let sender = TcpStream::connect(address)?;
    let (receiver, _) = listener.accept()?;
    receiver.set_nonblocking(true)?;
    sender.set_nonblocking(true)?;
    Ok((receiver, sender))
}

#[cfg(target_family = "unix")]
fn set_no_sigpipe(fd: i32) {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    unsafe {
        let value: libc::c_int = 1;
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        );
    }
}

#[cfg(target_family = "unix")]
pub(crate) fn connect_tcp_bound(addr: &SocketAddr, timeout: Duration) -> AtrResult<TcpStream> {
    let fd = unsafe { libc::socket(socket_domain(addr), libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(AtrError::from(std::io::Error::last_os_error()));
    }

    if let Err(err) = set_bound_interface(fd, addr) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    set_no_sigpipe(fd);
    if let Err(err) = set_nonblocking(fd, true) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    let (storage, len) = sockaddr_storage(addr);
    let connect_result = unsafe {
        libc::connect(
            fd,
            &storage as *const _ as *const libc::sockaddr,
            len as libc::socklen_t,
        )
    };
    if connect_result != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() != ErrorKind::WouldBlock
            && err.raw_os_error() != Some(libc::EINPROGRESS)
            && err.raw_os_error() != Some(libc::EALREADY)
        {
            unsafe {
                libc::close(fd);
            }
            return Err(AtrError::from(err));
        }
    }

    if let Err(err) = wait_for_connect(fd, timeout) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    if let Err(err) = set_nonblocking(fd, false) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    Ok(stream)
}

#[cfg(target_os = "windows")]
pub(crate) fn connect_tcp_bound(addr: &SocketAddr, timeout: Duration) -> AtrResult<TcpStream> {
    // Windows has no portable equivalent of the Unix interface-binding code below.
    // The OS routing table still selects the appropriate active interface.
    Ok(TcpStream::connect_timeout(addr, timeout)?)
}

#[cfg(target_family = "unix")]
fn socket_domain(addr: &SocketAddr) -> libc::c_int {
    match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    }
}

#[cfg(target_family = "unix")]
static PHYSICAL_INTERFACE_INDEX: OnceLock<u32> = OnceLock::new();

#[cfg(target_family = "unix")]
fn set_bound_interface(fd: libc::c_int, addr: &SocketAddr) -> AtrResult<()> {
    let Some(interface_index) = default_physical_interface_index(addr) else {
        crate::diag_log(
            "[libreatrust][transport] no physical interface available for bound socket",
        );
        return Ok(());
    };
    let value = interface_index as libc::c_int;
    let (level, option) = match addr {
        SocketAddr::V4(_) => (libc::IPPROTO_IP, 25),
        SocketAddr::V6(_) => (libc::IPPROTO_IPV6, 125),
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(AtrError::from(std::io::Error::last_os_error()));
    }
    crate::diag_log(format!(
        "[libreatrust][transport] bound outbound socket to if_index={interface_index}"
    ));
    Ok(())
}

#[cfg(target_family = "unix")]
fn default_physical_interface_index(addr: &SocketAddr) -> Option<u32> {
    if let Some(index) = PHYSICAL_INTERFACE_INDEX.get().copied() {
        return Some(index);
    }
    let index = route_default_physical_interface(addr).or_else(|| active_physical_interface(addr));
    if let Some(index) = index {
        let _ = PHYSICAL_INTERFACE_INDEX.set(index);
    }
    index
}

#[cfg(target_family = "unix")]
fn route_default_physical_interface(addr: &SocketAddr) -> Option<u32> {
    let family_flag = match addr {
        SocketAddr::V4(_) => "-inet",
        SocketAddr::V6(_) => "-inet6",
    };
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "get", family_flag, "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let interface = route_field(&text, "interface")?;
    if !is_physical_interface_name(&interface) {
        return None;
    }
    let c_name = std::ffi::CString::new(interface).ok()?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 { None } else { Some(index) }
}

#[cfg(target_family = "unix")]
fn active_physical_interface(addr: &SocketAddr) -> Option<u32> {
    let family = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return None;
    }

    let mut best: Option<(i32, u32, String)> = None;
    let mut current = ifaddrs;
    while !current.is_null() {
        let ifaddr = unsafe { &*current };
        if !ifaddr.ifa_addr.is_null() {
            let sockaddr = unsafe { &*ifaddr.ifa_addr };
            if sockaddr.sa_family as libc::c_int == family
                && interface_flags_are_usable(ifaddr.ifa_flags)
            {
                let name = unsafe { CStr::from_ptr(ifaddr.ifa_name) }
                    .to_string_lossy()
                    .into_owned();
                if is_physical_interface_name(&name) {
                    if let Ok(c_name) = std::ffi::CString::new(name.as_str()) {
                        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
                        if index != 0 {
                            let score = physical_interface_score(&name);
                            if best
                                .as_ref()
                                .map_or(true, |(best_score, _, _)| score > *best_score)
                            {
                                best = Some((score, index, name));
                            }
                        }
                    }
                }
            }
        }
        current = ifaddr.ifa_next;
    }
    unsafe {
        libc::freeifaddrs(ifaddrs);
    }

    best.map(|(_, index, name)| {
        crate::diag_log(format!(
            "[libreatrust][transport] selected active physical interface {name} if_index={index}"
        ));
        index
    })
}

#[cfg(target_family = "unix")]
fn interface_flags_are_usable(flags: libc::c_uint) -> bool {
    flags & (libc::IFF_UP as libc::c_uint) != 0
        && flags & (libc::IFF_RUNNING as libc::c_uint) != 0
        && flags & (libc::IFF_LOOPBACK as libc::c_uint) == 0
        && flags & (libc::IFF_POINTOPOINT as libc::c_uint) == 0
}

#[cfg(target_family = "unix")]
fn is_physical_interface_name(name: &str) -> bool {
    !(name.starts_with("utun")
        || name.starts_with("lo")
        || name.starts_with("awdl")
        || name.starts_with("llw")
        || name.starts_with("bridge")
        || name.starts_with("gif")
        || name.starts_with("stf")
        || name.starts_with("vmnet")
        || name.starts_with("vmenet"))
}

#[cfg(target_family = "unix")]
fn physical_interface_score(name: &str) -> i32 {
    if name.starts_with("en") {
        100
    } else if name.starts_with("pdp_ip") {
        80
    } else {
        10
    }
}

#[cfg(target_family = "unix")]
fn route_field(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() == name {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

#[cfg(target_family = "unix")]
fn set_nonblocking(fd: libc::c_int, enabled: bool) -> AtrResult<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(AtrError::from(std::io::Error::last_os_error()));
    }
    let new_flags = if enabled {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) } < 0 {
        return Err(AtrError::from(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_family = "unix")]
fn wait_for_connect(fd: libc::c_int, timeout: Duration) -> AtrResult<()> {
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if result > 0 {
            break;
        }
        if result == 0 {
            return Err(AtrError::NetworkFailed("connect timed out".into()));
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == ErrorKind::Interrupted {
            continue;
        }
        return Err(AtrError::from(err));
    }

    let mut error: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&error) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut error as *mut _ as *mut libc::c_void,
            &mut len,
        )
    } != 0
    {
        return Err(AtrError::from(std::io::Error::last_os_error()));
    }
    if error != 0 {
        return Err(AtrError::from(std::io::Error::from_raw_os_error(error)));
    }
    Ok(())
}

#[cfg(target_family = "unix")]
fn sockaddr_storage(addr: &SocketAddr) -> (libc::sockaddr_storage, usize) {
    match addr {
        SocketAddr::V4(v4) => {
            let mut storage = unsafe { std::mem::zeroed::<libc::sockaddr_storage>() };
            let raw = libc::sockaddr_in {
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as u8,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in, raw);
            }
            (storage, std::mem::size_of::<libc::sockaddr_in>())
        }
        SocketAddr::V6(v6) => {
            let mut storage = unsafe { std::mem::zeroed::<libc::sockaddr_storage>() };
            let raw = libc::sockaddr_in6 {
                sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as u8,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in6, raw);
            }
            (storage, std::mem::size_of::<libc::sockaddr_in6>())
        }
    }
}

fn send_tcp_init(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    session: &crate::types::SessionMaterial,
    app_id: &str,
    dest_addr: &str,
    port: u16,
) -> AtrResult<()> {
    let proc_path = if cfg!(target_os = "windows") {
        if port == 22 {
            "ssh.exe"
        } else {
            "libreatrust.exe"
        }
    } else if port == 22 {
        "/usr/bin/ssh"
    } else {
        "/usr/bin/libreatrust"
    };
    let proc_name = if port == 22 { "ssh" } else { "libreatrust" };
    let platform = current_platform_name();
    let proc_hash = format!("{:X}", sha2::Sha256::digest(proc_path.as_bytes()));
    let msg = format!(
        r#"{{"sid":"{}","appId":"{}","url":"tcp://{}:{}","deviceId":"{}","connectionId":"{}","procHash":"{}","userName":"{}","rcAppliedInfo":0,"lang":"en-US","destAddr":"{}:{}","env":{{"application":{{"runtime":{{"process":{{"name":"{}","digital_signature":"TrustAppClosed","platform":"{}","fingerprint":"{}","description":"TrustAppClosed","path":"{}","version":"TrustAppClosed","security_env":"normal"}},"process_trusted":"TRUSTED"}}}}}},"xRequestSig":""}}"#,
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
        platform,
        proc_hash,
        proc_path
    );
    let key =
        hex::decode(&session.sign_key_hex).map_err(|e| AtrError::CryptoFailed(e.to_string()))?;
    let sig = calc_request_sig(&key, msg.as_bytes());
    let final_msg = msg.replace(
        r#""xRequestSig":"""#,
        &format!(r#""xRequestSig":"{}""#, sig),
    );
    let mut frame = Vec::with_capacity(5 + 2 + final_msg.len());
    frame.extend_from_slice(&[0x05, 0x01, 0x81, 0x53, 0x03]);
    frame.extend_from_slice(&(final_msg.len() as u16).to_be_bytes());
    frame.extend_from_slice(final_msg.as_bytes());
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn send_tcp_dest(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    host: &str,
    port: u16,
) -> AtrResult<()> {
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
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn validate_tcp_tunnel_auth(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
) -> AtrResult<()> {
    loop {
        let mut header = [0u8; 2];
        read_tunnel_exact_blocking(stream, &mut header)?;
        match header {
            [0x53, 0x00] => {
                let mut len_bytes = [0u8; 2];
                read_tunnel_exact_blocking(stream, &mut len_bytes)?;
                let len = u16::from_be_bytes(len_bytes) as usize;
                let mut payload = vec![0u8; len];
                read_tunnel_exact_blocking(stream, &mut payload)?;
                let text = String::from_utf8_lossy(&payload);
                if text.contains("OK") || text.contains("Succeeded") {
                    return Ok(());
                }
                return Err(AtrError::NetworkFailed(text.into_owned()));
            }
            [0x05, 0x81] => {
                let mut marker = [0u8; 2];
                read_tunnel_exact_blocking(stream, &mut marker)?;
                if marker != [0x53, 0x00] {
                    crate::diag_log(format!(
                        "[libreatrust][tcp] ignoring tunnel auth marker {:02x?}",
                        marker
                    ));
                    continue;
                }

                let mut len_bytes = [0u8; 2];
                read_tunnel_exact_blocking(stream, &mut len_bytes)?;
                let len = u16::from_be_bytes(len_bytes) as usize;
                let mut payload = vec![0u8; len];
                read_tunnel_exact_blocking(stream, &mut payload)?;
                let text = String::from_utf8_lossy(&payload);
                crate::diag_log(format!("[libreatrust][tcp] tunnel auth response {}", text));
                if text.contains(r#""message":"OK""#) || text.contains(r#""message":"Succeeded""#) {
                    return Ok(());
                }
                return Err(AtrError::NetworkFailed(text.into_owned()));
            }
            [0x05, status] => {
                let mut tail = [0u8; 8];
                read_tunnel_exact_blocking(stream, &mut tail)?;
                crate::diag_log(format!(
                    "[libreatrust][tcp] ignoring tunnel control status={:02x} tail={:02x?}",
                    status, tail
                ));
            }
            [0x01, 0x00] => {
                return Err(AtrError::NetworkFailed(
                    "unexpected application data during tcp tunnel auth".into(),
                ));
            }
            [0x01, 0x01] => {
                let mut tail = [0u8; 2];
                read_tunnel_exact_blocking(stream, &mut tail)?;
                return Err(AtrError::NetworkFailed(format!(
                    "tcp tunnel closed during auth: {:02x?}",
                    tail
                )));
            }
            _ => {
                crate::diag_log(format!(
                    "[libreatrust][tcp] ignoring tunnel auth header {:02x} {:02x}",
                    header[0], header[1]
                ));
            }
        }
    }
}

fn write_tcp_payload(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    data: &[u8],
) -> AtrResult<usize> {
    if data.len() > u16::MAX as usize {
        return Err(AtrError::InvalidArgument("tcp payload too large".into()));
    }
    let mut frame = Vec::with_capacity(4 + data.len());
    frame.extend_from_slice(&[0x01, 0x00]);
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(data.len())
}

fn read_tcp_frame(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
) -> AtrResult<Option<Vec<u8>>> {
    let mut header = [0u8; 2];
    if !read_tunnel_exact(stream, &mut header)? {
        return Ok(None);
    }
    match header {
        [0x01, 0x00] => {
            let mut len_bytes = [0u8; 2];
            read_tunnel_exact_blocking(stream, &mut len_bytes)?;
            let len = u16::from_be_bytes(len_bytes) as usize;
            let mut data = vec![0u8; len];
            read_tunnel_exact_blocking(stream, &mut data)?;
            Ok(Some(data))
        }
        [0x01, 0x01] => {
            let mut tail = [0u8; 2];
            read_tunnel_exact_blocking(stream, &mut tail)?;
            if tail == [0x30, 0x30] {
                return Err(AtrError::NetworkFailed(
                    "connection closed by server".into(),
                ));
            }
            Ok(None)
        }
        [0x53, 0x00] => {
            let mut len_bytes = [0u8; 2];
            read_tunnel_exact_blocking(stream, &mut len_bytes)?;
            let len = u16::from_be_bytes(len_bytes) as usize;
            let mut payload = vec![0u8; len];
            read_tunnel_exact_blocking(stream, &mut payload)?;
            if !String::from_utf8_lossy(&payload).contains("OK") {
                return Err(AtrError::NetworkFailed(
                    String::from_utf8_lossy(&payload).into_owned(),
                ));
            }
            Ok(None)
        }
        [0x05, 0x81] => {
            let mut marker = [0u8; 2];
            read_tunnel_exact_blocking(stream, &mut marker)?;
            if marker != [0x53, 0x00] {
                crate::diag_log(format!(
                    "[libreatrust][tcp] ignoring tunnel auth marker {:02x?}",
                    marker
                ));
                return Ok(None);
            }

            let mut len_bytes = [0u8; 2];
            read_tunnel_exact_blocking(stream, &mut len_bytes)?;
            let len = u16::from_be_bytes(len_bytes) as usize;
            let mut payload = vec![0u8; len];
            read_tunnel_exact_blocking(stream, &mut payload)?;
            let text = String::from_utf8_lossy(&payload);
            crate::diag_log(format!("[libreatrust][tcp] tunnel auth response {}", text));
            if !text.contains(r#""message":"OK""#) && !text.contains(r#""message":"Succeeded""#) {
                return Err(AtrError::NetworkFailed(text.into_owned()));
            }
            Ok(None)
        }
        [0x05, status] => {
            let mut tail = [0u8; 8];
            read_tunnel_exact_blocking(stream, &mut tail)?;
            crate::diag_log(format!(
                "[libreatrust][tcp] ignoring tunnel control status={:02x} tail={:02x?}",
                status, tail
            ));
            Ok(None)
        }
        _ => {
            crate::diag_log(format!(
                "[libreatrust][tcp] ignoring tunnel header {:02x} {:02x}",
                header[0], header[1]
            ));
            Ok(None)
        }
    }
}

fn read_tunnel_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> AtrResult<bool> {
    let mut offset = 0usize;
    while offset < buf.len() {
        match reader.read(&mut buf[offset..]) {
            Ok(0) => {
                return if offset == 0 {
                    Err(AtrError::NetworkFailed(
                        "connection closed by server".into(),
                    ))
                } else {
                    Err(AtrError::NetworkFailed(
                        "unexpected eof in tcp tunnel frame".into(),
                    ))
                };
            }
            Ok(n) => offset += n,
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if offset == 0 {
                    return Ok(false);
                }
            }
            Err(err) => return Err(AtrError::from(err)),
        }
    }
    Ok(true)
}

fn read_tunnel_exact_blocking<R: Read>(reader: &mut R, buf: &mut [u8]) -> AtrResult<()> {
    while !read_tunnel_exact(reader, buf)? {}
    Ok(())
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
        let remotes: Vec<_> = self
            .remotes
            .lock()
            .unwrap()
            .drain()
            .map(|(_, remote)| remote)
            .collect();
        for remote in remotes {
            remote.close();
        }
        Ok(())
    }

    pub fn virtual_ips(&self) -> Vec<Ipv4Addr> {
        self.vip_list.lock().unwrap().clone()
    }

    fn remote_for(&self, node_group_id: &str) -> AtrResult<Arc<L3Remote>> {
        if self.close_flag.load(Ordering::SeqCst) {
            return Err(AtrError::InvalidState("l3 tunnel closed".into()));
        }
        let existing = self.remotes.lock().unwrap().get(node_group_id).cloned();
        if let Some(existing) = existing {
            if !existing.close_flag.load(Ordering::SeqCst) {
                return Ok(existing);
            }
            self.remotes.lock().unwrap().remove(node_group_id);
            existing.close();
        }
        let node_addr = self
            .client
            .best_node_for(node_group_id)
            .ok_or_else(|| AtrError::NotFound(format!("no node for group {node_group_id}")))?;
        crate::diag_log(format!(
            "[libreatrust][l3] remote connect begin node_group={node_group_id} node={node_addr}"
        ));
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
        crate::diag_log(format!(
            "[libreatrust][l3] remote connect ready node_group={node_group_id}"
        ));
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
    write_interest: Arc<AtomicUsize>,
    vip_list: Arc<Mutex<Vec<Ipv4Addr>>>,
    close_notify: Arc<(Mutex<bool>, Condvar)>,
    workers: Mutex<Vec<thread::JoinHandle<()>>>,
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
        stream.sock.set_read_timeout(Some(Duration::from_millis(
            client.client_config().io_timeout_ms,
        )))?;
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
            write_interest: Arc::new(AtomicUsize::new(0)),
            vip_list,
            close_notify: Arc::new((Mutex::new(false), Condvar::new())),
            workers: Mutex::new(Vec::new()),
        };
        remote.auth_tunnel()?;
        {
            let stream = remote.stream.lock().unwrap();
            stream
                .sock
                .set_read_timeout(Some(Duration::from_millis(5)))?;
        }
        remote.spawn_loops(incoming_tx);
        Ok(remote)
    }

    fn spawn_loops(&self, incoming_tx: mpsc::Sender<Vec<u8>>) {
        let reader = self.stream.clone();
        let conntracks = self.conntracks.clone();
        let close = self.close_flag.clone();
        let write_interest = self.write_interest.clone();
        let heartbeat_stream = self.stream.clone();
        let heartbeat_close = self.close_flag.clone();
        let heartbeat_write_interest = self.write_interest.clone();
        let vip_list = self.vip_list.clone();
        let close_notify = self.close_notify.clone();
        let reader_notify = self.close_notify.clone();

        let reader_stream = reader.clone();
        let reader_close = close.clone();
        let reader_worker = thread::Builder::new()
            .name("libreatrust-l3-reader".into())
            .spawn(move || {
                loop {
                    if close.load(Ordering::SeqCst) {
                        break;
                    }
                    if write_interest.load(Ordering::SeqCst) > 0 {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    let frame = {
                        let mut stream = reader.lock().unwrap();
                        read_l3_frame_available(&mut *stream)
                    };
                    let frame = match frame {
                        Ok(Some(v)) => v,
                        Ok(None) => continue,
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
                reader_close.store(true, Ordering::SeqCst);
                let (closed, notify) = &*reader_notify;
                *closed.lock().unwrap() = true;
                notify.notify_all();
                if let Ok(stream) = reader_stream.lock() {
                    let _ = stream.sock.shutdown(Shutdown::Both);
                }
            })
            .expect("failed to spawn L3 reader");

        let heartbeat_worker = thread::Builder::new()
            .name("libreatrust-l3-heartbeat".into())
            .spawn(move || {
                while !heartbeat_close.load(Ordering::SeqCst) {
                    let (closed, notify) = &*close_notify;
                    let guard = closed.lock().unwrap();
                    if *guard {
                        break;
                    }
                    let (guard, _) = notify.wait_timeout(guard, Duration::from_secs(25)).unwrap();
                    if *guard || heartbeat_close.load(Ordering::SeqCst) {
                        break;
                    }
                    heartbeat_write_interest.fetch_add(1, Ordering::SeqCst);
                    let mut stream = heartbeat_stream.lock().unwrap();
                    let _ = stream.write_all(&[0x05, 0x15, 0x00, 0x00]);
                    let _ = stream.flush();
                    heartbeat_write_interest.fetch_sub(1, Ordering::SeqCst);
                }
            })
            .expect("failed to spawn L3 heartbeat");

        self.workers
            .lock()
            .unwrap()
            .extend([reader_worker, heartbeat_worker]);
    }

    fn close(&self) {
        self.close_flag.store(true, Ordering::SeqCst);
        let (closed, notify) = &*self.close_notify;
        *closed.lock().unwrap() = true;
        notify.notify_all();
        if let Ok(stream) = self.stream.lock() {
            let _ = stream.sock.shutdown(Shutdown::Both);
        }
        let workers = std::mem::take(&mut *self.workers.lock().unwrap());
        for worker in workers {
            let _ = worker.join();
        }
    }

    fn auth_tunnel(&self) -> AtrResult<()> {
        let req = serde_json::to_vec(&json!({ "sid": self.info.sid }))?;
        let packet = wrap_auth_req_data(&req, 1);
        {
            let mut stream = self.stream.lock().unwrap();
            crate::diag_log("[libreatrust][l3] tunnel auth send sid".to_string());
            stream.write_all(&packet)?;
            stream.flush()?;
        }

        let mut stream = self.stream.lock().unwrap();
        let mut method = [0u8; 2];
        stream.read_exact(&mut method)?;
        crate::diag_log(format!(
            "[libreatrust][l3] tunnel auth method={method:02x?}"
        ));
        if method != [0x05, 0xD0] {
            return Err(AtrError::NetworkFailed(format!(
                "unexpected auth method {:?}",
                method
            )));
        }

        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;
        crate::diag_log(format!(
            "[libreatrust][l3] tunnel auth header={header:02x?}"
        ));
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
        if !payload.is_empty() {
            crate::diag_log(format!(
                "[libreatrust][l3] tunnel auth payload {}",
                String::from_utf8_lossy(&payload)
            ));
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
        if read_tunnel_exact(&mut *stream, &mut vip_header)? && vip_header[0] == 0x05 {
            crate::diag_log(format!(
                "[libreatrust][l3] tunnel auth optional vip header={vip_header:02x?}"
            ));
            let data_len = vip_payload_length(vip_header[3]);
            if data_len > 0 {
                let mut vip_data = vec![0u8; data_len];
                read_tunnel_exact_blocking(&mut *stream, &mut vip_data)?;
                if let Some(ips) = parse_virtual_ip_bytes(&vip_data) {
                    crate::diag_log(format!(
                        "[libreatrust][l3] tunnel auth vip={}",
                        ips.iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    ));
                    *self.vip_list.lock().unwrap() = ips;
                }
            }
        }
        crate::diag_log("[libreatrust][l3] tunnel auth ready".to_string());
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
        self.write_interest.fetch_add(1, Ordering::SeqCst);
        let write_result = {
            let mut stream = self.stream.lock().unwrap();
            stream.write_all(&payload).and_then(|_| stream.flush())
        };
        self.write_interest.fetch_sub(1, Ordering::SeqCst);
        write_result?;
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
        let packet = build_l3_auth_request_payload(&req)?;
        self.write_interest.fetch_add(1, Ordering::SeqCst);
        crate::diag_log(format!("[libreatrust][l3] auth request key={}", ct.key));
        let write_result = {
            let mut stream = self.stream.lock().unwrap();
            stream.write_all(&packet).and_then(|_| stream.flush())
        };
        self.write_interest.fetch_sub(1, Ordering::SeqCst);
        write_result?;
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
    let socket_addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| AtrError::NetworkFailed(format!("failed to resolve {addr}")))?;
    let tcp = connect_tcp_bound(
        &socket_addr,
        Duration::from_millis(cfg.connect_timeout_ms.max(1)),
    )?;
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

fn read_l3_frame_available(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
) -> AtrResult<Option<Frame>> {
    loop {
        let mut header = [0u8; 2];
        if !read_tunnel_exact(stream, &mut header)? {
            return Ok(None);
        }
        match header {
            [0x05, cmd] if cmd == 0x93 || cmd == 0x96 => {
                let mut status_len = [0u8; 3];
                read_tunnel_exact_blocking(stream, &mut status_len)?;
                let status = status_len[0];
                let len = u16::from_be_bytes([status_len[1], status_len[2]]) as usize;
                let mut payload = vec![0u8; len];
                if len > 0 {
                    read_tunnel_exact_blocking(stream, &mut payload)?;
                }
                return Ok(Some(Frame {
                    cmd,
                    status,
                    payload,
                    data_mode: DataMode::Len,
                }));
            }
            [0x05, 0x94] => {
                let (payload, mode) = read_data_resp_payload(stream)?;
                return Ok(Some(Frame {
                    cmd: 0x94,
                    status: 0,
                    payload,
                    data_mode: mode,
                }));
            }
            [0x05, cmd] => {
                let mut len_bytes = [0u8; 2];
                read_tunnel_exact_blocking(stream, &mut len_bytes)?;
                let len = u16::from_be_bytes(len_bytes) as usize;
                let mut payload = vec![0u8; len];
                if len > 0 {
                    read_tunnel_exact_blocking(stream, &mut payload)?;
                }
                return Ok(Some(Frame {
                    cmd,
                    status: 0,
                    payload,
                    data_mode: DataMode::Len,
                }));
            }
            [0x53, 0x00] => {
                let mut len_bytes = [0u8; 2];
                read_tunnel_exact_blocking(stream, &mut len_bytes)?;
                let len = u16::from_be_bytes(len_bytes) as usize;
                let mut payload = vec![0u8; len];
                if len > 0 {
                    read_tunnel_exact_blocking(stream, &mut payload)?;
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
    read_tunnel_exact_blocking(stream, &mut peek)?;
    let payload_len = u16::from_be_bytes(peek) as usize;
    if payload_len > 0 && payload_len <= 4096 {
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            read_tunnel_exact_blocking(stream, &mut payload)?;
        }
        return Ok((payload, DataMode::Len));
    }

    let token_len = peek[0] as usize;
    let mut payload = vec![peek[0]];
    if token_len > 0 {
        let mut token = vec![0u8; token_len];
        read_tunnel_exact_blocking(stream, &mut token)?;
        payload.extend_from_slice(&token);
    }
    let mut reserved = [0u8; 2];
    read_tunnel_exact_blocking(stream, &mut reserved)?;
    payload.extend_from_slice(&reserved);
    let mut count = [0u8; 1];
    read_tunnel_exact_blocking(stream, &mut count)?;
    payload.extend_from_slice(&count);
    for _ in 0..count[0] {
        let mut len_bytes = [0u8; 2];
        read_tunnel_exact_blocking(stream, &mut len_bytes)?;
        payload.extend_from_slice(&len_bytes);
        let plen = u16::from_be_bytes(len_bytes) as usize;
        if plen > 0 {
            let mut pkt = vec![0u8; plen];
            read_tunnel_exact_blocking(stream, &mut pkt)?;
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
            protocol: protocol_number(meta.protocol),
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
    // Match the reference client identity. The aTrust gateway evaluates these
    // fields during L3 conntrack authorization.
    let proc_path = "/usr/bin/zju-connect";
    let fingerprint = format!("{:X}", sha2::Sha256::digest(proc_path.as_bytes()));
    TrustEnv {
        application: TrustApp {
            runtime: TrustRuntime {
                process: TrustProcess {
                    name: "zju-connect".into(),
                    digital_signature: "TrustAppClosed".into(),
                    platform: current_platform_name().into(),
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

fn current_platform_name() -> &'static str {
    match env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        other => other,
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

fn build_l3_auth_request_payload(req: &[u8]) -> AtrResult<Vec<u8>> {
    if req.len() > u16::MAX as usize {
        return Err(AtrError::InvalidArgument(
            "l3 auth request too large".into(),
        ));
    }
    let mut payload = Vec::with_capacity(4 + req.len());
    payload.extend_from_slice(&[0x05, 0x13]);
    payload.extend_from_slice(&(req.len() as u16).to_be_bytes());
    payload.extend_from_slice(req);
    Ok(payload)
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

fn protocol_number(proto: ProtocolKind) -> i32 {
    match proto {
        ProtocolKind::Tcp => 6,
        ProtocolKind::Udp => 17,
        ProtocolKind::Icmp => 1,
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
        "{}:{}:{}-{}:{}",
        meta.atype, meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port
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

    pub fn request_l3_virtual_ips(&self) -> AtrResult<Vec<Ipv4Addr>> {
        let session = self
            .session()
            .ok_or_else(|| AtrError::InvalidState("session not set".into()))?;
        let addr = self
            .best_node()
            .ok_or_else(|| AtrError::NotFound("no node for l3 virtual ip request".into()))?;
        crate::diag_log(format!("[libreatrust][l3] virtual ip request node={addr}"));

        let mut stream = connect_tls(&addr, self.client_config())?;
        stream.sock.set_read_timeout(Some(Duration::from_millis(
            self.client_config().io_timeout_ms,
        )))?;

        let req = serde_json::to_vec(&json!({ "sid": session.sid }))?;
        let packet = wrap_auth_req_data(&req, 1);
        stream.write_all(&packet)?;
        stream.flush()?;

        let mut method = [0u8; 2];
        stream.read_exact(&mut method)?;
        if method != [0x05, 0xD0] {
            return Err(AtrError::NetworkFailed(format!(
                "unexpected virtual ip method {:?}",
                method
            )));
        }

        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;
        if header[0] != 0x53 {
            return Err(AtrError::NetworkFailed(format!(
                "unexpected virtual ip header {:02x?}",
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
                    "virtual ip request failed: {}",
                    resp.message
                )));
            }
        }

        let mut vip_header = [0u8; 4];
        stream.read_exact(&mut vip_header)?;
        if vip_header[0] != 0x05 {
            return Err(AtrError::NetworkFailed(format!(
                "unexpected virtual ip payload header {:02x?}",
                vip_header
            )));
        }
        let data_len = vip_payload_length(vip_header[3]);
        if data_len == 0 {
            return Err(AtrError::NetworkFailed(
                "virtual ip response had empty payload".into(),
            ));
        }
        let mut vip_data = vec![0u8; data_len];
        stream.read_exact(&mut vip_data)?;
        let ips = parse_virtual_ip_bytes(&vip_data)
            .filter(|ips| !ips.is_empty())
            .ok_or_else(|| AtrError::ParseFailed("virtual ip response had no ipv4".into()))?;
        crate::diag_log(format!(
            "[libreatrust][l3] virtual ip ready {}",
            ips.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ));
        Ok(ips)
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
