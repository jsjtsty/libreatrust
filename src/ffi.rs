#![allow(non_camel_case_types)]

use libreatrust_core::{
    AtrClient, AtrError, AtrResult, AuthChallenge, AuthChallengeKind, AuthConfig, AuthSession,
    CallbackTarget, ClientConfig, CookieRecord, DomainResource, ErrorCode, IpResource, L3Tunnel,
    PasswordLoginInput, ProxyService, ProxyServiceConfig, ProxyServiceEvent, ProxyServiceStatus,
    ResourceSnapshot, SessionMaterial, SmsLoginInput, TcpTunnel, UdpTunnel, parse_resource_bytes,
};
use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::os::raw::c_char;
use std::ptr;

#[repr(C)]
pub struct atr_client_t {
    inner: AtrClient,
}

#[repr(C)]
pub struct atr_auth_session_t {
    inner: AuthSession,
}

#[repr(C)]
pub struct atr_tcp_tunnel_t {
    inner: TcpTunnel,
}

#[repr(C)]
pub struct atr_udp_tunnel_t {
    inner: UdpTunnel,
}

#[repr(C)]
pub struct atr_l3_tunnel_t {
    inner: L3Tunnel,
}

#[repr(C)]
pub struct atr_proxy_service_t {
    inner: ProxyService,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_string_list_t {
    pub items: *mut *mut c_char,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_ip_resource_t {
    pub ip_min: *mut c_char,
    pub ip_max: *mut c_char,
    pub port_min: u16,
    pub port_max: u16,
    pub protocol: *mut c_char,
    pub app_id: *mut c_char,
    pub node_group_id: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_ip_resource_list_t {
    pub items: *mut atr_ip_resource_t,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_domain_resource_t {
    pub domain: *mut c_char,
    pub port_min: u16,
    pub port_max: u16,
    pub protocol: *mut c_char,
    pub app_id: *mut c_char,
    pub node_group_id: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_domain_resource_list_t {
    pub items: *mut atr_domain_resource_t,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_dns_resource_t {
    pub domain: *mut c_char,
    pub ip: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_dns_resource_list_t {
    pub items: *mut atr_dns_resource_t,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_node_group_t {
    pub group_id: *mut c_char,
    pub addresses: atr_string_list_t,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_node_group_list_t {
    pub items: *mut atr_node_group_t,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_resource_snapshot_t {
    pub resource_bytes: atr_blob_t,
    pub dns_server: *mut c_char,
    pub major_node_group: *mut c_char,
    pub ip_resources: atr_ip_resource_list_t,
    pub domain_resources: atr_domain_resource_list_t,
    pub dns_resources: atr_dns_resource_list_t,
    pub node_groups: atr_node_group_list_t,
    pub excluded_ips: atr_string_list_t,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_blob_t {
    pub data: *mut u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_cookie_input_t {
    pub host: *const c_char,
    pub scheme: *const c_char,
    pub name: *const c_char,
    pub value: *const c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_cookie_list_input_t {
    pub items: *const atr_cookie_input_t,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_cookie_record_t {
    pub host: *mut c_char,
    pub scheme: *mut c_char,
    pub name: *mut c_char,
    pub value: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_cookie_list_t {
    pub items: *mut atr_cookie_record_t,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_client_config_t {
    pub server_host: *const c_char,
    pub server_port: u16,
    pub user_agent: *const c_char,
    pub connect_timeout_ms: u64,
    pub io_timeout_ms: u64,
    pub node_probe_timeout_ms: u64,
    pub allow_insecure_tls: bool,
    pub bind_interface: *const c_char,
    pub auto_detect_interface: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_auth_config_t {
    pub server_host: *const c_char,
    pub server_port: u16,
    pub user_agent: *const c_char,
    pub client_type: *const c_char,
    pub platform: *const c_char,
    pub login_domain: *const c_char,
    pub preferred_auth_type: *const c_char,
    pub io_timeout_ms: u64,
    pub allow_insecure_tls: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_auth_method_info_t {
    pub login_domain: *mut c_char,
    pub auth_type: *mut c_char,
    pub auth_name: *mut c_char,
    pub login_url: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_auth_method_list_t {
    pub items: *mut atr_auth_method_info_t,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_password_login_input_t {
    pub username: *const c_char,
    pub password: *const c_char,
    pub login_domain: *const c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_sms_login_input_t {
    pub phone: *const c_char,
    pub login_domain: *const c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_callback_target_t {
    pub callback_url: *const c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_session_material_input_t {
    pub username: *const c_char,
    pub sid: *const c_char,
    pub device_id: *const c_char,
    pub connection_id: *const c_char,
    pub sign_key_hex: *const c_char,
    pub cookies: atr_cookie_list_input_t,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_session_material_t {
    pub username: *mut c_char,
    pub sid: *mut c_char,
    pub device_id: *mut c_char,
    pub connection_id: *mut c_char,
    pub sign_key_hex: *mut c_char,
    pub cookies: atr_cookie_list_t,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum atr_auth_challenge_kind_t {
    ATR_AUTH_CHALLENGE_CAPTCHA = 0,
    ATR_AUTH_CHALLENGE_SMS_CODE = 1,
    ATR_AUTH_CHALLENGE_CALLBACK_URL = 2,
    ATR_AUTH_CHALLENGE_DONE = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum atr_proxy_service_status_t {
    ATR_PROXY_SERVICE_RUNNING = 0,
    ATR_PROXY_SERVICE_STOPPED = 1,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum atr_proxy_service_event_kind_t {
    ATR_PROXY_SERVICE_EVENT_NONE = 0,
    ATR_PROXY_SERVICE_EVENT_ERROR = 1,
    ATR_PROXY_SERVICE_EVENT_SESSION_INVALIDATED = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_proxy_service_config_t {
    pub listen_host: *const c_char,
    pub listen_port: u16,
    pub connect_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub enable_http: bool,
    pub enable_socks5: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_proxy_service_endpoint_t {
    pub host: *mut c_char,
    pub port: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_proxy_service_stats_t {
    pub active_connections: u64,
    pub total_connections: u64,
    pub last_error: *mut c_char,
    pub last_event_kind: atr_proxy_service_event_kind_t,
    pub last_event_message: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_proxy_service_traffic_stats_t {
    pub managed_upload_bytes: u64,
    pub managed_download_bytes: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct atr_auth_challenge_t {
    pub kind: atr_auth_challenge_kind_t,
    pub image: atr_blob_t,
    pub auth_id: *mut c_char,
    pub auth_url: *mut c_char,
    pub callback_kind: atr_auth_challenge_kind_t,
    pub session: atr_session_material_t,
}

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

fn store_error(err: &AtrError) -> ErrorCode {
    let text = CString::new(err.to_string()).unwrap_or_else(|_| CString::new("error").unwrap());
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(text));
    err.code()
}

fn cstr_to_string(ptr: *const c_char, field: &'static str) -> Result<String, AtrError> {
    if ptr.is_null() {
        return Err(AtrError::InvalidArgument(format!("{field} is null")));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map(|s| s.to_string())
        .map_err(|e| AtrError::ParseFailed(e.to_string()))
}

fn set_string_out(out: *mut *mut c_char, value: String) -> Result<(), AtrError> {
    if out.is_null() {
        return Err(AtrError::InvalidArgument("out is null".into()));
    }
    let cstr = CString::new(value).map_err(|e| AtrError::Internal(e.to_string()))?;
    unsafe {
        *out = cstr.into_raw();
    }
    Ok(())
}

fn leak_boxed_slice<T>(values: Vec<T>) -> (*mut T, usize) {
    let mut boxed = values.into_boxed_slice();
    let len = boxed.len();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    (ptr, len)
}

unsafe fn free_boxed_slice<T>(ptr: *mut T, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

fn set_blob_out(out: *mut atr_blob_t, data: Vec<u8>) -> Result<(), AtrError> {
    if out.is_null() {
        return Err(AtrError::InvalidArgument("out is null".into()));
    }
    let (data, len) = leak_boxed_slice(data);
    let blob = atr_blob_t { len, data };
    unsafe {
        *out = blob;
    }
    Ok(())
}

fn copy_blob(data: &[u8]) -> atr_blob_t {
    let (data, len) = leak_boxed_slice(data.to_vec());
    atr_blob_t { len, data }
}

fn set_string_list_out(out: *mut atr_string_list_t, values: Vec<String>) -> Result<(), AtrError> {
    if out.is_null() {
        return Err(AtrError::InvalidArgument("out is null".into()));
    }
    let mut items: Vec<*mut c_char> = Vec::with_capacity(values.len());
    for value in values {
        items.push(
            CString::new(value)
                .map_err(|e| AtrError::Internal(e.to_string()))?
                .into_raw(),
        );
    }
    let (items, len) = leak_boxed_slice(items);
    unsafe {
        *out = atr_string_list_t { len, items };
    }
    Ok(())
}

fn set_ipaddr_string_list(
    out: *mut atr_string_list_t,
    values: Vec<Ipv4Addr>,
) -> Result<(), AtrError> {
    set_string_list_out(out, values.into_iter().map(|ip| ip.to_string()).collect())
}

fn copy_cookie_record(cookie: &CookieRecord) -> Result<atr_cookie_record_t, AtrError> {
    Ok(atr_cookie_record_t {
        host: CString::new(cookie.host.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        scheme: CString::new(cookie.scheme.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        name: CString::new(cookie.name.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        value: CString::new(cookie.value.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
    })
}

fn copy_session_material(session: &SessionMaterial) -> Result<atr_session_material_t, AtrError> {
    let mut cookies: Vec<atr_cookie_record_t> = Vec::with_capacity(session.cookies.len());
    for cookie in &session.cookies {
        cookies.push(copy_cookie_record(cookie)?);
    }
    let mut cookies = cookies;
    let list = atr_cookie_list_t {
        len: cookies.len(),
        items: cookies.as_mut_ptr(),
    };
    std::mem::forget(cookies);
    Ok(atr_session_material_t {
        username: CString::new(session.username.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        sid: CString::new(session.sid.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        device_id: CString::new(session.device_id.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        connection_id: CString::new(session.connection_id.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        sign_key_hex: CString::new(session.sign_key_hex.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        cookies: list,
    })
}

fn challenge_to_ffi(challenge: AuthChallenge) -> Result<atr_auth_challenge_t, AtrError> {
    let mut out = atr_auth_challenge_t {
        kind: atr_auth_challenge_kind_t::ATR_AUTH_CHALLENGE_DONE,
        image: atr_blob_t {
            data: ptr::null_mut(),
            len: 0,
        },
        auth_id: ptr::null_mut(),
        auth_url: ptr::null_mut(),
        callback_kind: atr_auth_challenge_kind_t::ATR_AUTH_CHALLENGE_DONE,
        session: atr_session_material_t {
            username: ptr::null_mut(),
            sid: ptr::null_mut(),
            device_id: ptr::null_mut(),
            connection_id: ptr::null_mut(),
            sign_key_hex: ptr::null_mut(),
            cookies: atr_cookie_list_t {
                items: ptr::null_mut(),
                len: 0,
            },
        },
    };
    match challenge {
        AuthChallenge::NeedCaptcha { image } => {
            out.kind = atr_auth_challenge_kind_t::ATR_AUTH_CHALLENGE_CAPTCHA;
            set_blob_out(&mut out.image, image)?;
        }
        AuthChallenge::NeedSmsCode { auth_id } => {
            out.kind = atr_auth_challenge_kind_t::ATR_AUTH_CHALLENGE_SMS_CODE;
            out.auth_id = CString::new(auth_id)
                .map_err(|e| AtrError::Internal(e.to_string()))?
                .into_raw();
        }
        AuthChallenge::NeedCallbackUrl { auth_url, kind } => {
            out.kind = atr_auth_challenge_kind_t::ATR_AUTH_CHALLENGE_CALLBACK_URL;
            out.auth_url = CString::new(auth_url)
                .map_err(|e| AtrError::Internal(e.to_string()))?
                .into_raw();
            out.callback_kind = match kind {
                AuthChallengeKind::Captcha => atr_auth_challenge_kind_t::ATR_AUTH_CHALLENGE_CAPTCHA,
                AuthChallengeKind::SmsCode => {
                    atr_auth_challenge_kind_t::ATR_AUTH_CHALLENGE_SMS_CODE
                }
                AuthChallengeKind::CallbackUrl => {
                    atr_auth_challenge_kind_t::ATR_AUTH_CHALLENGE_CALLBACK_URL
                }
            };
        }
        AuthChallenge::Done(session) => {
            out.kind = atr_auth_challenge_kind_t::ATR_AUTH_CHALLENGE_DONE;
            out.session = copy_session_material(&session)?;
        }
    }
    Ok(out)
}

fn free_c_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

fn free_blob(blob: &mut atr_blob_t) {
    unsafe {
        free_boxed_slice(blob.data, blob.len);
    }
    blob.data = ptr::null_mut();
    blob.len = 0;
}

fn free_string_list(list: &mut atr_string_list_t) {
    if !list.items.is_null() && list.len > 0 {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(list.items, list.len);
            for item in slice {
                free_c_string(*item);
                *item = ptr::null_mut();
            }
            free_boxed_slice(list.items, list.len);
        }
    }
    list.items = ptr::null_mut();
    list.len = 0;
}

fn free_ip_resource_list(list: &mut atr_ip_resource_list_t) {
    if !list.items.is_null() && list.len > 0 {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(list.items, list.len);
            for item in slice {
                free_c_string(item.ip_min);
                free_c_string(item.ip_max);
                free_c_string(item.protocol);
                free_c_string(item.app_id);
                free_c_string(item.node_group_id);
                item.ip_min = ptr::null_mut();
                item.ip_max = ptr::null_mut();
                item.protocol = ptr::null_mut();
                item.app_id = ptr::null_mut();
                item.node_group_id = ptr::null_mut();
            }
            free_boxed_slice(list.items, list.len);
        }
    }
    list.items = ptr::null_mut();
    list.len = 0;
}

fn free_domain_resource_list(list: &mut atr_domain_resource_list_t) {
    if !list.items.is_null() && list.len > 0 {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(list.items, list.len);
            for item in slice {
                free_c_string(item.domain);
                free_c_string(item.protocol);
                free_c_string(item.app_id);
                free_c_string(item.node_group_id);
                item.domain = ptr::null_mut();
                item.protocol = ptr::null_mut();
                item.app_id = ptr::null_mut();
                item.node_group_id = ptr::null_mut();
            }
            free_boxed_slice(list.items, list.len);
        }
    }
    list.items = ptr::null_mut();
    list.len = 0;
}

fn free_dns_resource_list(list: &mut atr_dns_resource_list_t) {
    if !list.items.is_null() && list.len > 0 {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(list.items, list.len);
            for item in slice {
                free_c_string(item.domain);
                free_c_string(item.ip);
                item.domain = ptr::null_mut();
                item.ip = ptr::null_mut();
            }
            free_boxed_slice(list.items, list.len);
        }
    }
    list.items = ptr::null_mut();
    list.len = 0;
}

fn free_node_group_list(list: &mut atr_node_group_list_t) {
    if !list.items.is_null() && list.len > 0 {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(list.items, list.len);
            for item in slice {
                free_c_string(item.group_id);
                free_string_list(&mut item.addresses);
                item.group_id = ptr::null_mut();
            }
            free_boxed_slice(list.items, list.len);
        }
    }
    list.items = ptr::null_mut();
    list.len = 0;
}

fn copy_ip_resource(resource: &IpResource) -> Result<atr_ip_resource_t, AtrError> {
    Ok(atr_ip_resource_t {
        ip_min: CString::new(resource.ip_min.to_string())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        ip_max: CString::new(resource.ip_max.to_string())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        port_min: resource.port_min,
        port_max: resource.port_max,
        protocol: CString::new(resource.protocol.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        app_id: CString::new(resource.app_id.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        node_group_id: CString::new(resource.node_group_id.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
    })
}

fn copy_domain_resource(
    domain: &str,
    resource: &DomainResource,
) -> Result<atr_domain_resource_t, AtrError> {
    Ok(atr_domain_resource_t {
        domain: CString::new(domain)
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        port_min: resource.port_min,
        port_max: resource.port_max,
        protocol: CString::new(resource.protocol.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        app_id: CString::new(resource.app_id.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        node_group_id: CString::new(resource.node_group_id.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
    })
}

fn copy_dns_resource(domain: &str, ip: &Ipv4Addr) -> Result<atr_dns_resource_t, AtrError> {
    Ok(atr_dns_resource_t {
        domain: CString::new(domain)
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        ip: CString::new(ip.to_string())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
    })
}

fn copy_node_groups(
    groups: &std::collections::HashMap<String, Vec<String>>,
) -> Result<atr_node_group_list_t, AtrError> {
    let mut group_items = Vec::with_capacity(groups.len());
    for (group_id, addresses) in groups {
        let mut addresses_out = Vec::with_capacity(addresses.len());
        for addr in addresses {
            addresses_out.push(
                CString::new(addr.as_str())
                    .map_err(|e| AtrError::Internal(e.to_string()))?
                    .into_raw(),
            );
        }
        let (addr_items, addr_len) = leak_boxed_slice(addresses_out);
        let addr_list = atr_string_list_t {
            len: addr_len,
            items: addr_items,
        };
        group_items.push(atr_node_group_t {
            group_id: CString::new(group_id.as_str())
                .map_err(|e| AtrError::Internal(e.to_string()))?
                .into_raw(),
            addresses: addr_list,
        });
    }
    let (items, len) = leak_boxed_slice(group_items);
    Ok(atr_node_group_list_t { len, items })
}

fn copy_resource_snapshot(
    snapshot: &ResourceSnapshot,
    resource_bytes: Option<&[u8]>,
) -> Result<atr_resource_snapshot_t, AtrError> {
    let mut ip_items = Vec::with_capacity(snapshot.ip_resources.len());
    for resource in &snapshot.ip_resources {
        ip_items.push(copy_ip_resource(resource)?);
    }
    let mut domain_items = Vec::with_capacity(snapshot.domain_resources.len());
    for (domain, resource) in &snapshot.domain_resources {
        domain_items.push(copy_domain_resource(domain, resource)?);
    }
    let mut dns_items = Vec::with_capacity(snapshot.dns_resource.len());
    for (domain, ip) in &snapshot.dns_resource {
        dns_items.push(copy_dns_resource(domain, ip)?);
    }

    Ok(atr_resource_snapshot_t {
        resource_bytes: resource_bytes.map(copy_blob).unwrap_or(atr_blob_t {
            data: ptr::null_mut(),
            len: 0,
        }),
        dns_server: match &snapshot.dns_server {
            Some(value) => CString::new(value.as_str())
                .map_err(|e| AtrError::Internal(e.to_string()))?
                .into_raw(),
            None => ptr::null_mut(),
        },
        major_node_group: CString::new(snapshot.major_node_group.clone())
            .map_err(|e| AtrError::Internal(e.to_string()))?
            .into_raw(),
        ip_resources: {
            let (items, len) = leak_boxed_slice(ip_items);
            atr_ip_resource_list_t { len, items }
        },
        domain_resources: {
            let (items, len) = leak_boxed_slice(domain_items);
            atr_domain_resource_list_t { len, items }
        },
        dns_resources: {
            let (items, len) = leak_boxed_slice(dns_items);
            atr_dns_resource_list_t { len, items }
        },
        node_groups: copy_node_groups(&snapshot.node_groups)?,
        excluded_ips: {
            let excluded = snapshot
                .excluded_ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>();
            let mut list = Vec::with_capacity(excluded.len());
            for item in excluded {
                list.push(
                    CString::new(item)
                        .map_err(|e| AtrError::Internal(e.to_string()))?
                        .into_raw(),
                );
            }
            let (items, len) = leak_boxed_slice(list);
            atr_string_list_t { len, items }
        },
    })
}

fn free_cookie_record(record: &mut atr_cookie_record_t) {
    free_c_string(record.host);
    free_c_string(record.scheme);
    free_c_string(record.name);
    free_c_string(record.value);
    record.host = ptr::null_mut();
    record.scheme = ptr::null_mut();
    record.name = ptr::null_mut();
    record.value = ptr::null_mut();
}

fn free_cookie_list(list: &mut atr_cookie_list_t) {
    if !list.items.is_null() && list.len > 0 {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(list.items, list.len);
            for item in slice {
                free_cookie_record(item);
            }
            free_boxed_slice(list.items, list.len);
        }
    }
    list.items = ptr::null_mut();
    list.len = 0;
}

fn free_session_material(session: &mut atr_session_material_t) {
    free_c_string(session.username);
    free_c_string(session.sid);
    free_c_string(session.device_id);
    free_c_string(session.connection_id);
    free_c_string(session.sign_key_hex);
    free_cookie_list(&mut session.cookies);
    session.username = ptr::null_mut();
    session.sid = ptr::null_mut();
    session.device_id = ptr::null_mut();
    session.connection_id = ptr::null_mut();
    session.sign_key_hex = ptr::null_mut();
}

fn free_challenge(challenge: &mut atr_auth_challenge_t) {
    free_blob(&mut challenge.image);
    free_c_string(challenge.auth_id);
    free_c_string(challenge.auth_url);
    free_session_material(&mut challenge.session);
    challenge.kind = atr_auth_challenge_kind_t::ATR_AUTH_CHALLENGE_DONE;
    challenge.callback_kind = atr_auth_challenge_kind_t::ATR_AUTH_CHALLENGE_DONE;
    challenge.auth_id = ptr::null_mut();
    challenge.auth_url = ptr::null_mut();
}

fn free_resource_snapshot(snapshot: &mut atr_resource_snapshot_t) {
    free_blob(&mut snapshot.resource_bytes);
    free_c_string(snapshot.dns_server);
    free_c_string(snapshot.major_node_group);
    free_ip_resource_list(&mut snapshot.ip_resources);
    free_domain_resource_list(&mut snapshot.domain_resources);
    free_dns_resource_list(&mut snapshot.dns_resources);
    free_node_group_list(&mut snapshot.node_groups);
    free_string_list(&mut snapshot.excluded_ips);
    snapshot.dns_server = ptr::null_mut();
    snapshot.major_node_group = ptr::null_mut();
}

fn client_config_from_ffi(cfg: &atr_client_config_t) -> AtrResult<ClientConfig> {
    Ok(ClientConfig {
        server_host: cstr_to_string(cfg.server_host, "server_host")?,
        server_port: cfg.server_port,
        user_agent: cstr_to_string(cfg.user_agent, "user_agent")?,
        connect_timeout_ms: cfg.connect_timeout_ms,
        io_timeout_ms: cfg.io_timeout_ms,
        node_probe_timeout_ms: cfg.node_probe_timeout_ms,
        allow_insecure_tls: cfg.allow_insecure_tls,
        bind_interface: if cfg.bind_interface.is_null() {
            None
        } else {
            Some(cstr_to_string(cfg.bind_interface, "bind_interface")?)
        },
        auto_detect_interface: cfg.auto_detect_interface,
    })
}

fn auth_config_from_ffi(cfg: &atr_auth_config_t) -> AtrResult<AuthConfig> {
    Ok(AuthConfig {
        server_host: cstr_to_string(cfg.server_host, "server_host")?,
        server_port: cfg.server_port,
        user_agent: cstr_to_string(cfg.user_agent, "user_agent")?,
        client_type: cstr_to_string(cfg.client_type, "client_type")?,
        platform: cstr_to_string(cfg.platform, "platform")?,
        login_domain: cstr_to_string(cfg.login_domain, "login_domain")?,
        preferred_auth_type: if cfg.preferred_auth_type.is_null() {
            None
        } else {
            Some(cstr_to_string(
                cfg.preferred_auth_type,
                "preferred_auth_type",
            )?)
        },
        io_timeout_ms: cfg.io_timeout_ms,
        allow_insecure_tls: cfg.allow_insecure_tls,
    })
}

fn password_input_from_ffi(input: &atr_password_login_input_t) -> AtrResult<PasswordLoginInput> {
    Ok(PasswordLoginInput {
        username: cstr_to_string(input.username, "username")?,
        password: cstr_to_string(input.password, "password")?,
        login_domain: cstr_to_string(input.login_domain, "login_domain")?,
    })
}

fn sms_input_from_ffi(input: &atr_sms_login_input_t) -> AtrResult<SmsLoginInput> {
    Ok(SmsLoginInput {
        phone: cstr_to_string(input.phone, "phone")?,
        login_domain: cstr_to_string(input.login_domain, "login_domain")?,
    })
}

fn callback_target_from_ffi(input: &atr_callback_target_t) -> AtrResult<CallbackTarget> {
    Ok(CallbackTarget {
        callback_url: cstr_to_string(input.callback_url, "callback_url")?,
    })
}

fn session_material_from_ffi(input: &atr_session_material_input_t) -> AtrResult<SessionMaterial> {
    let mut cookies = Vec::with_capacity(input.cookies.len);
    if !input.cookies.items.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(input.cookies.items, input.cookies.len) };
        for item in slice {
            cookies.push(CookieRecord {
                host: cstr_to_string(item.host, "cookie.host")?,
                scheme: cstr_to_string(item.scheme, "cookie.scheme")?,
                name: cstr_to_string(item.name, "cookie.name")?,
                value: cstr_to_string(item.value, "cookie.value")?,
            });
        }
    }
    Ok(SessionMaterial {
        username: cstr_to_string(input.username, "username")?,
        sid: cstr_to_string(input.sid, "sid")?,
        device_id: cstr_to_string(input.device_id, "device_id")?,
        connection_id: cstr_to_string(input.connection_id, "connection_id")?,
        sign_key_hex: cstr_to_string(input.sign_key_hex, "sign_key_hex")?,
        cookies,
    })
}

fn proxy_service_config_from_ffi(
    input: &atr_proxy_service_config_t,
) -> AtrResult<ProxyServiceConfig> {
    let mut config = ProxyServiceConfig::default();
    config.listen_host = cstr_to_string(input.listen_host, "listen_host")?;
    config.listen_port = input.listen_port;
    config.connect_timeout_ms = if input.connect_timeout_ms == 0 {
        config.connect_timeout_ms
    } else {
        input.connect_timeout_ms
    };
    config.idle_timeout_ms = input.idle_timeout_ms;
    config.enable_http = input.enable_http;
    config.enable_socks5 = input.enable_socks5;
    Ok(config)
}

fn proxy_service_status_to_ffi(status: ProxyServiceStatus) -> atr_proxy_service_status_t {
    match status {
        ProxyServiceStatus::Running => atr_proxy_service_status_t::ATR_PROXY_SERVICE_RUNNING,
        ProxyServiceStatus::Stopped => atr_proxy_service_status_t::ATR_PROXY_SERVICE_STOPPED,
    }
}

fn free_proxy_service_endpoint(endpoint: &mut atr_proxy_service_endpoint_t) {
    free_c_string(endpoint.host);
    endpoint.host = ptr::null_mut();
    endpoint.port = 0;
}

fn free_proxy_service_stats(stats: &mut atr_proxy_service_stats_t) {
    free_c_string(stats.last_error);
    free_c_string(stats.last_event_message);
    stats.last_error = ptr::null_mut();
    stats.last_event_message = ptr::null_mut();
    stats.last_event_kind = atr_proxy_service_event_kind_t::ATR_PROXY_SERVICE_EVENT_NONE;
    stats.active_connections = 0;
    stats.total_connections = 0;
}

fn proxy_service_event_to_ffi(
    event: Option<ProxyServiceEvent>,
) -> AtrResult<(atr_proxy_service_event_kind_t, *mut c_char)> {
    match event {
        Some(ProxyServiceEvent::SessionInvalidated { message }) => Ok((
            atr_proxy_service_event_kind_t::ATR_PROXY_SERVICE_EVENT_SESSION_INVALIDATED,
            CString::new(message)
                .map_err(|err| AtrError::Internal(err.to_string()))?
                .into_raw(),
        )),
        Some(ProxyServiceEvent::Error { message }) => Ok((
            atr_proxy_service_event_kind_t::ATR_PROXY_SERVICE_EVENT_ERROR,
            CString::new(message)
                .map_err(|err| AtrError::Internal(err.to_string()))?
                .into_raw(),
        )),
        None => Ok((
            atr_proxy_service_event_kind_t::ATR_PROXY_SERVICE_EVENT_NONE,
            ptr::null_mut(),
        )),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_last_error_message() -> *const c_char {
    LAST_ERROR.with(|slot| match &*slot.borrow() {
        Some(s) => s.as_ptr(),
        None => ptr::null(),
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_new(
    config: *const atr_client_config_t,
    out: *mut *mut atr_client_t,
) -> i32 {
    if config.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let cfg = client_config_from_ffi(unsafe { &*config })?;
        let client = AtrClient::new(cfg)?;
        let boxed = Box::new(atr_client_t { inner: client });
        unsafe {
            *out = Box::into_raw(boxed);
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_free(client: *mut atr_client_t) {
    if !client.is_null() {
        unsafe {
            drop(Box::from_raw(client));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_set_session(
    client: *mut atr_client_t,
    session: *const atr_session_material_input_t,
) -> i32 {
    if client.is_null() || session.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let material = session_material_from_ffi(unsafe { &*session })?;
        unsafe { &mut *client }.inner.set_session(material);
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_set_resource(
    client: *mut atr_client_t,
    resource_bytes: *const u8,
    resource_len: usize,
    service_host: *const c_char,
) -> i32 {
    if client.is_null() || resource_bytes.is_null() || service_host.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let resource = unsafe { std::slice::from_raw_parts(resource_bytes, resource_len) };
        let host = unsafe { CStr::from_ptr(service_host) }
            .to_str()
            .map_err(|e| AtrError::ParseFailed(e.to_string()))?;
        let snapshot = parse_resource_bytes(resource, host)?;
        let client = unsafe { &mut *client };
        client.inner.set_resource(snapshot);
        client.inner.set_resource_bytes(resource.to_vec());
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_route_tcp(
    client: *const atr_client_t,
    host: *const c_char,
    port: u16,
    managed: *mut bool,
) -> i32 {
    route(
        client,
        host,
        port,
        managed,
        libreatrust_core::ProtocolKind::Tcp,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_route_udp(
    client: *const atr_client_t,
    host: *const c_char,
    port: u16,
    managed: *mut bool,
) -> i32 {
    route(
        client,
        host,
        port,
        managed,
        libreatrust_core::ProtocolKind::Udp,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_route_icmp(
    client: *const atr_client_t,
    host: *const c_char,
    managed: *mut bool,
) -> i32 {
    route(
        client,
        host,
        0,
        managed,
        libreatrust_core::ProtocolKind::Icmp,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_get_resource_bytes(
    client: *const atr_client_t,
    out: *mut atr_blob_t,
) -> i32 {
    if client.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let bytes = unsafe { &*client }
            .inner
            .resource_bytes()
            .ok_or_else(|| AtrError::InvalidState("resource bytes not set".into()))?;
        unsafe {
            *out = copy_blob(bytes);
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_get_dns_server(
    client: *const atr_client_t,
    out: *mut *mut c_char,
) -> i32 {
    if client.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let dns = unsafe { &*client }
            .inner
            .resource()
            .and_then(|r| r.dns_server.clone())
            .ok_or_else(|| AtrError::InvalidState("dns server not set".into()))?;
        set_string_out(out, dns)
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_get_major_node_group(
    client: *const atr_client_t,
    out: *mut *mut c_char,
) -> i32 {
    if client.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let major = unsafe { &*client }
            .inner
            .resource()
            .map(|r| r.major_node_group.clone())
            .ok_or_else(|| AtrError::InvalidState("resource not set".into()))?;
        set_string_out(out, major)
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_get_resource_snapshot(
    client: *const atr_client_t,
    out: *mut atr_resource_snapshot_t,
) -> i32 {
    if client.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let client_ref = unsafe { &*client };
        let snapshot = client_ref
            .inner
            .resource()
            .ok_or_else(|| AtrError::InvalidState("resource not set".into()))?;
        let bytes = client_ref.inner.resource_bytes();
        unsafe {
            *out = copy_resource_snapshot(snapshot, bytes)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

fn route(
    client: *const atr_client_t,
    host: *const c_char,
    port: u16,
    managed: *mut bool,
    kind: libreatrust_core::ProtocolKind,
) -> i32 {
    if client.is_null() || host.is_null() || managed.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    unsafe {
        *managed = false;
    }
    let result = (|| -> Result<(), AtrError> {
        let host = unsafe { CStr::from_ptr(host) }
            .to_str()
            .map_err(|e| AtrError::ParseFailed(e.to_string()))?;
        let decision = match kind {
            libreatrust_core::ProtocolKind::Tcp => unsafe { &*client }.inner.route_tcp(host, port),
            libreatrust_core::ProtocolKind::Udp => unsafe { &*client }.inner.route_udp(host, port),
            libreatrust_core::ProtocolKind::Icmp => unsafe { &*client }.inner.route_icmp(host),
        };
        unsafe {
            *managed = matches!(decision, libreatrust_core::RouteDecision::Managed(_));
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_new(
    config: *const atr_auth_config_t,
    out: *mut *mut atr_auth_session_t,
) -> i32 {
    if config.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let cfg = auth_config_from_ffi(unsafe { &*config })?;
        let session = AuthSession::new(cfg)?;
        let boxed = Box::new(atr_auth_session_t { inner: session });
        unsafe { *out = Box::into_raw(boxed) };
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_free(session: *mut atr_auth_session_t) {
    if !session.is_null() {
        unsafe {
            drop(Box::from_raw(session));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_string_free(ptr: *mut c_char) {
    free_c_string(ptr);
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_available_methods(
    session: *mut atr_auth_session_t,
    out: *mut atr_auth_method_list_t,
) -> i32 {
    if session.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let methods = unsafe { &mut *session }.inner.available_methods()?;
        let mut out_items: Vec<atr_auth_method_info_t> = Vec::with_capacity(methods.len());
        for method in methods {
            out_items.push(atr_auth_method_info_t {
                login_domain: CString::new(method.login_domain)
                    .map_err(|e| AtrError::Internal(e.to_string()))?
                    .into_raw(),
                auth_type: CString::new(method.auth_type)
                    .map_err(|e| AtrError::Internal(e.to_string()))?
                    .into_raw(),
                auth_name: CString::new(method.auth_name)
                    .map_err(|e| AtrError::Internal(e.to_string()))?
                    .into_raw(),
                login_url: CString::new(method.login_url)
                    .map_err(|e| AtrError::Internal(e.to_string()))?
                    .into_raw(),
            });
        }
        let mut out_items = out_items;
        unsafe {
            *out = atr_auth_method_list_t {
                len: out_items.len(),
                items: out_items.as_mut_ptr(),
            };
        }
        std::mem::forget(out_items);
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_resolve_login_url(
    session: *const atr_auth_session_t,
    login_url: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    if session.is_null() || login_url.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let login_url = unsafe { CStr::from_ptr(login_url) }
            .to_str()
            .map_err(|e| AtrError::ParseFailed(e.to_string()))?;
        let resolved = unsafe { &*session }.inner.resolve_login_url(login_url)?;
        set_string_out(out, resolved)
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_login_password(
    session: *mut atr_auth_session_t,
    input: *const atr_password_login_input_t,
    device_id: *const c_char,
    out: *mut atr_auth_challenge_t,
) -> i32 {
    if session.is_null() || input.is_null() || device_id.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let input = password_input_from_ffi(unsafe { &*input })?;
        let device_id = unsafe { CStr::from_ptr(device_id) }
            .to_str()
            .map_err(|e| AtrError::ParseFailed(e.to_string()))?;
        let challenge = unsafe { &mut *session }
            .inner
            .login_with_password(input, device_id.to_string())?;
        unsafe {
            *out = challenge_to_ffi(challenge)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_login_sms(
    session: *mut atr_auth_session_t,
    input: *const atr_sms_login_input_t,
    device_id: *const c_char,
    out: *mut atr_auth_challenge_t,
) -> i32 {
    if session.is_null() || input.is_null() || device_id.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let input = sms_input_from_ffi(unsafe { &*input })?;
        let device_id = unsafe { CStr::from_ptr(device_id) }
            .to_str()
            .map_err(|e| AtrError::ParseFailed(e.to_string()))?;
        let challenge = unsafe { &mut *session }
            .inner
            .login_with_sms(input, device_id.to_string())?;
        unsafe {
            *out = challenge_to_ffi(challenge)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_submit_captcha(
    session: *mut atr_auth_session_t,
    captcha: *const c_char,
    out: *mut atr_auth_challenge_t,
) -> i32 {
    if session.is_null() || captcha.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let captcha = unsafe { CStr::from_ptr(captcha) }
            .to_str()
            .map_err(|e| AtrError::ParseFailed(e.to_string()))?;
        let challenge = unsafe { &mut *session }.inner.submit_captcha(captcha)?;
        unsafe {
            *out = challenge_to_ffi(challenge)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_submit_sms_code(
    session: *mut atr_auth_session_t,
    code: *const c_char,
    out: *mut atr_auth_challenge_t,
) -> i32 {
    if session.is_null() || code.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let code = unsafe { CStr::from_ptr(code) }
            .to_str()
            .map_err(|e| AtrError::ParseFailed(e.to_string()))?;
        let challenge = unsafe { &mut *session }.inner.submit_sms_code(code)?;
        unsafe {
            *out = challenge_to_ffi(challenge)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_complete_callback(
    session: *mut atr_auth_session_t,
    target: *const atr_callback_target_t,
    out: *mut atr_auth_challenge_t,
) -> i32 {
    if session.is_null() || target.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let target = callback_target_from_ffi(unsafe { &*target })?;
        let challenge = unsafe { &mut *session }.inner.complete_callback(target)?;
        unsafe {
            *out = challenge_to_ffi(challenge)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_prepare_callback_login(
    session: *mut atr_auth_session_t,
    device_id: *const c_char,
) -> i32 {
    if session.is_null() || device_id.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let device_id = unsafe { CStr::from_ptr(device_id) }
            .to_str()
            .map_err(|e| AtrError::ParseFailed(e.to_string()))?;
        unsafe { &mut *session }
            .inner
            .prepare_callback_login(device_id.to_string());
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_complete_callback_with_device(
    session: *mut atr_auth_session_t,
    target: *const atr_callback_target_t,
    device_id: *const c_char,
    out: *mut atr_auth_challenge_t,
) -> i32 {
    if session.is_null() || target.is_null() || device_id.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let target = callback_target_from_ffi(unsafe { &*target })?;
        let device_id = unsafe { CStr::from_ptr(device_id) }
            .to_str()
            .map_err(|e| AtrError::ParseFailed(e.to_string()))?;
        let challenge = unsafe { &mut *session }
            .inner
            .complete_callback_with_device(target, device_id.to_string())?;
        unsafe {
            *out = challenge_to_ffi(challenge)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_fetch_client_resource(
    session: *mut atr_auth_session_t,
    out: *mut atr_blob_t,
) -> i32 {
    if session.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let bytes = unsafe { &mut *session }.inner.client_resource_bytes()?;
        set_blob_out(out, bytes)
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_get_client_resource(
    session: *mut atr_auth_session_t,
    out: *mut atr_blob_t,
) -> i32 {
    atr_auth_session_fetch_client_resource(session, out)
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_import_session(
    session: *mut atr_auth_session_t,
    material: *const atr_session_material_input_t,
) -> i32 {
    if session.is_null() || material.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let material = session_material_from_ffi(unsafe { &*material })?;
        unsafe { &mut *session }.inner.import_session(material);
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_resume_session(
    session: *mut atr_auth_session_t,
    material: *const atr_session_material_input_t,
    out: *mut atr_session_material_t,
) -> i32 {
    if session.is_null() || material.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let material = session_material_from_ffi(unsafe { &*material })?;
        let refreshed = unsafe { &mut *session }.inner.resume_session(material)?;
        unsafe {
            *out = copy_session_material(&refreshed)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_session_export_session(
    session: *const atr_auth_session_t,
    out: *mut atr_session_material_t,
) -> i32 {
    if session.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let material = unsafe { &*session }.inner.session_material();
        unsafe {
            *out = copy_session_material(&material)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_open_tcp(
    client: *const atr_client_t,
    host: *const c_char,
    port: u16,
    out: *mut *mut atr_tcp_tunnel_t,
) -> i32 {
    if client.is_null() || host.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let host = unsafe { CStr::from_ptr(host) }
            .to_str()
            .map_err(|e| AtrError::ParseFailed(e.to_string()))?;
        let tunnel = unsafe { &*client }.inner.open_tcp_tunnel(host, port)?;
        unsafe {
            *out = Box::into_raw(Box::new(atr_tcp_tunnel_t { inner: tunnel }));
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_open_udp(
    client: *const atr_client_t,
    host: *const c_char,
    port: u16,
    out: *mut *mut atr_udp_tunnel_t,
) -> i32 {
    if client.is_null() || host.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let host = unsafe { CStr::from_ptr(host) }
            .to_str()
            .map_err(|e| AtrError::ParseFailed(e.to_string()))?;
        let tunnel = unsafe { &*client }.inner.open_udp_tunnel(host, port)?;
        unsafe {
            *out = Box::into_raw(Box::new(atr_udp_tunnel_t { inner: tunnel }));
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_tcp_tunnel_free(tunnel: *mut atr_tcp_tunnel_t) {
    if !tunnel.is_null() {
        unsafe {
            drop(Box::from_raw(tunnel));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_tcp_tunnel_close(tunnel: *mut atr_tcp_tunnel_t) -> i32 {
    if tunnel.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    match unsafe { &*tunnel }.inner.close() {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_tcp_tunnel_read(
    tunnel: *const atr_tcp_tunnel_t,
    buf: *mut u8,
    len: usize,
    out_len: *mut usize,
) -> i32 {
    if tunnel.is_null() || buf.is_null() || out_len.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
        let n = unsafe { &*tunnel }.inner.read(slice)?;
        unsafe { *out_len = n };
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_tcp_tunnel_write(
    tunnel: *const atr_tcp_tunnel_t,
    buf: *const u8,
    len: usize,
    out_len: *mut usize,
) -> i32 {
    if tunnel.is_null() || buf.is_null() || out_len.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let slice = unsafe { std::slice::from_raw_parts(buf, len) };
        let n = unsafe { &*tunnel }.inner.write(slice)?;
        unsafe { *out_len = n };
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_udp_tunnel_free(tunnel: *mut atr_udp_tunnel_t) {
    if !tunnel.is_null() {
        unsafe {
            drop(Box::from_raw(tunnel));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_udp_tunnel_close(tunnel: *mut atr_udp_tunnel_t) -> i32 {
    if tunnel.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    match unsafe { &*tunnel }.inner.close() {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_udp_tunnel_read(
    tunnel: *const atr_udp_tunnel_t,
    buf: *mut u8,
    len: usize,
    out_len: *mut usize,
) -> i32 {
    if tunnel.is_null() || buf.is_null() || out_len.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
        let n = unsafe { &*tunnel }.inner.read(slice)?;
        unsafe { *out_len = n };
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_udp_tunnel_write(
    tunnel: *const atr_udp_tunnel_t,
    buf: *const u8,
    len: usize,
    out_len: *mut usize,
) -> i32 {
    if tunnel.is_null() || buf.is_null() || out_len.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let slice = unsafe { std::slice::from_raw_parts(buf, len) };
        let n = unsafe { &*tunnel }.inner.write(slice)?;
        unsafe { *out_len = n };
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_open_l3(
    client: *const atr_client_t,
    out: *mut *mut atr_l3_tunnel_t,
) -> i32 {
    if client.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let tunnel = unsafe { &*client }.inner.open_l3_tunnel()?;
        unsafe {
            *out = Box::into_raw(Box::new(atr_l3_tunnel_t { inner: tunnel }));
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_l3_tunnel_free(tunnel: *mut atr_l3_tunnel_t) {
    if !tunnel.is_null() {
        unsafe {
            drop(Box::from_raw(tunnel));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_l3_tunnel_close(tunnel: *const atr_l3_tunnel_t) -> i32 {
    if tunnel.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    match unsafe { &*tunnel }.inner.close() {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_l3_tunnel_send_heartbeat(tunnel: *const atr_l3_tunnel_t) -> i32 {
    if tunnel.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    match unsafe { &*tunnel }.inner.send_heartbeat() {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_l3_tunnel_read_packet(
    tunnel: *const atr_l3_tunnel_t,
    buf: *mut u8,
    len: usize,
    out_len: *mut usize,
) -> i32 {
    if tunnel.is_null() || buf.is_null() || out_len.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
        let packet = unsafe { &*tunnel }.inner.read_packet()?;
        if packet.len() > slice.len() {
            return Err(AtrError::InvalidArgument(
                "buffer too small for packet".into(),
            ));
        }
        slice[..packet.len()].copy_from_slice(&packet);
        unsafe { *out_len = packet.len() };
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_l3_tunnel_write_packet(
    tunnel: *const atr_l3_tunnel_t,
    buf: *const u8,
    len: usize,
    out_len: *mut usize,
) -> i32 {
    if tunnel.is_null() || buf.is_null() || out_len.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let slice = unsafe { std::slice::from_raw_parts(buf, len) };
        let n = unsafe { &*tunnel }.inner.write_packet(slice)?;
        unsafe { *out_len = n };
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_resource_snapshot_free(snapshot: *mut atr_resource_snapshot_t) {
    if snapshot.is_null() {
        return;
    }
    unsafe {
        free_resource_snapshot(&mut *snapshot);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_l3_tunnel_get_virtual_ips(
    tunnel: *const atr_l3_tunnel_t,
    out: *mut atr_string_list_t,
) -> i32 {
    if tunnel.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let ips = unsafe { &*tunnel }.inner.virtual_ips();
        set_ipaddr_string_list(out, ips)
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_client_start_proxy_service(
    client: *const atr_client_t,
    config: *const atr_proxy_service_config_t,
    out: *mut *mut atr_proxy_service_t,
) -> i32 {
    if client.is_null() || config.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let config = proxy_service_config_from_ffi(unsafe { &*config })?;
        let service = ProxyService::start(unsafe { &*client }.inner.clone(), config)?;
        unsafe {
            *out = Box::into_raw(Box::new(atr_proxy_service_t { inner: service }));
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_proxy_service_stop(service: *const atr_proxy_service_t) -> i32 {
    if service.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    match unsafe { &*service }.inner.stop() {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_proxy_service_status(
    service: *const atr_proxy_service_t,
    out: *mut atr_proxy_service_status_t,
) -> i32 {
    if service.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    unsafe {
        *out = proxy_service_status_to_ffi((&*service).inner.status());
    }
    ErrorCode::Ok as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_proxy_service_get_endpoint(
    service: *const atr_proxy_service_t,
    out: *mut atr_proxy_service_endpoint_t,
) -> i32 {
    if service.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let endpoint = unsafe { &*service }.inner.endpoint();
        let host = CString::new(endpoint.ip().to_string())
            .map_err(|err| AtrError::Internal(err.to_string()))?;
        unsafe {
            *out = atr_proxy_service_endpoint_t {
                host: host.into_raw(),
                port: endpoint.port(),
            };
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_proxy_service_get_stats(
    service: *const atr_proxy_service_t,
    out: *mut atr_proxy_service_stats_t,
) -> i32 {
    if service.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let stats = unsafe { &*service }.inner.stats();
        let (last_event_kind, last_event_message) = proxy_service_event_to_ffi(stats.last_event)?;
        let last_error = match stats.last_error {
            Some(error) => CString::new(error)
                .map_err(|err| AtrError::Internal(err.to_string()))?
                .into_raw(),
            None => ptr::null_mut(),
        };
        unsafe {
            *out = atr_proxy_service_stats_t {
                active_connections: stats.active_connections,
                total_connections: stats.total_connections,
                last_error,
                last_event_kind,
                last_event_message,
            };
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_proxy_service_get_traffic_stats(
    service: *const atr_proxy_service_t,
    out: *mut atr_proxy_service_traffic_stats_t,
) -> i32 {
    if service.is_null() || out.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let stats = unsafe { &*service }.inner.stats();
    unsafe {
        *out = atr_proxy_service_traffic_stats_t {
            managed_upload_bytes: stats.managed_upload_bytes,
            managed_download_bytes: stats.managed_download_bytes,
        };
    }
    ErrorCode::Ok as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_proxy_service_take_event(
    service: *const atr_proxy_service_t,
    out_kind: *mut atr_proxy_service_event_kind_t,
    out_message: *mut *mut c_char,
) -> i32 {
    if service.is_null() || out_kind.is_null() || out_message.is_null() {
        return ErrorCode::InvalidArgument as i32;
    }
    let result = (|| -> Result<(), AtrError> {
        let (kind, message) = proxy_service_event_to_ffi(unsafe { &*service }.inner.take_event())?;
        unsafe {
            *out_kind = kind;
            *out_message = message;
        }
        Ok(())
    })();
    match result {
        Ok(()) => ErrorCode::Ok as i32,
        Err(err) => store_error(&err) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_proxy_service_endpoint_free(endpoint: *mut atr_proxy_service_endpoint_t) {
    if endpoint.is_null() {
        return;
    }
    unsafe {
        free_proxy_service_endpoint(&mut *endpoint);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_proxy_service_stats_free(stats: *mut atr_proxy_service_stats_t) {
    if stats.is_null() {
        return;
    }
    unsafe {
        free_proxy_service_stats(&mut *stats);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_proxy_service_free(service: *mut atr_proxy_service_t) {
    if !service.is_null() {
        unsafe {
            drop(Box::from_raw(service));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_blob_free(blob: *mut atr_blob_t) {
    if blob.is_null() {
        return;
    }
    unsafe {
        free_blob(&mut *blob);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_string_list_free(list: *mut atr_string_list_t) {
    if list.is_null() {
        return;
    }
    unsafe {
        free_string_list(&mut *list);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_method_list_free(list: *mut atr_auth_method_list_t) {
    if list.is_null() {
        return;
    }
    unsafe {
        let list = &mut *list;
        if !list.items.is_null() && list.len > 0 {
            let slice = std::slice::from_raw_parts_mut(list.items, list.len);
            for item in slice {
                free_c_string(item.login_domain);
                free_c_string(item.auth_type);
                free_c_string(item.auth_name);
                free_c_string(item.login_url);
                item.login_domain = ptr::null_mut();
                item.auth_type = ptr::null_mut();
                item.auth_name = ptr::null_mut();
                item.login_url = ptr::null_mut();
            }
            free_boxed_slice(list.items, list.len);
        }
        list.items = ptr::null_mut();
        list.len = 0;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_session_material_free(session: *mut atr_session_material_t) {
    if session.is_null() {
        return;
    }
    unsafe {
        free_session_material(&mut *session);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn atr_auth_challenge_free(challenge: *mut atr_auth_challenge_t) {
    if challenge.is_null() {
        return;
    }
    unsafe {
        free_challenge(&mut *challenge);
    }
}
