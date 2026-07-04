use crate::error::{AtrError, AtrResult};
use crate::types::{ProtocolKind, RouteDecision, RouteHit};
use ipnet::Ipv4Net;
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpResource {
    pub ip_min: Ipv4Addr,
    pub ip_max: Ipv4Addr,
    pub port_min: u16,
    pub port_max: u16,
    pub protocol: String,
    pub app_id: String,
    pub node_group_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainResource {
    pub port_min: u16,
    pub port_max: u16,
    pub protocol: String,
    pub app_id: String,
    pub node_group_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceSnapshot {
    pub ip_resources: Vec<IpResource>,
    pub domain_resources: HashMap<String, DomainResource>,
    pub dns_resource: HashMap<String, Ipv4Addr>,
    pub dns_server: Option<String>,
    pub major_node_group: String,
    pub node_groups: HashMap<String, Vec<String>>,
    pub best_nodes: HashMap<String, String>,
    pub excluded_ips: Vec<Ipv4Addr>,
}

#[derive(Debug, Deserialize)]
struct ClientResourceResponse {
    data: ClientResourceData,
}

#[derive(Debug, Deserialize)]
struct ClientResourceData {
    #[serde(rename = "appList")]
    app_list: AppListResponse,
    #[serde(default, rename = "sdpPolicy")]
    sdp_policy: Option<SdpPolicyResponse>,
}

#[derive(Debug, Deserialize)]
struct AppListResponse {
    data: AppListData,
}

#[derive(Debug, Deserialize)]
struct SdpPolicyResponse {
    data: SdpPolicyData,
}

#[derive(Debug, Deserialize)]
struct AppListData {
    #[serde(rename = "appInfo")]
    app_info: Vec<AppInfo>,
    config: AppConfig,
}

#[derive(Debug, Deserialize)]
struct AppInfo {
    apps: Vec<AppEntry>,
}

#[derive(Debug, Deserialize)]
struct AppEntry {
    id: String,
    #[serde(rename = "nodeGroupId")]
    node_group_id: String,
    #[serde(rename = "addressList")]
    address_list: Vec<AddressEntry>,
}

#[derive(Debug, Deserialize)]
struct AddressEntry {
    protocol: String,
    port: String,
    host: String,
    #[serde(default)]
    ip: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AppConfig {
    #[serde(rename = "nodeGroupConf")]
    node_group_conf: NodeGroupConf,
}

#[derive(Debug, Deserialize)]
struct NodeGroupConf {
    #[serde(rename = "majorNodeGroup")]
    major_node_group: MajorNodeGroup,
    #[serde(rename = "nodeGroupList")]
    node_group_list: Vec<NodeGroupEntry>,
}

#[derive(Debug, Deserialize)]
struct MajorNodeGroup {
    id: String,
}

#[derive(Debug, Deserialize)]
struct NodeGroupEntry {
    id: String,
    #[serde(rename = "addressInfo")]
    address_info: Vec<NodeAddress>,
}

#[derive(Debug, Deserialize)]
struct NodeAddress {
    address: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Debug, Deserialize)]
struct SdpPolicyData {
    #[serde(rename = "clientOption")]
    client_option: ClientOption,
}

#[derive(Debug, Deserialize)]
struct ClientOption {
    #[serde(rename = "dnsOption")]
    dns_option: DnsOption,
    #[serde(rename = "dnsOptionV2")]
    dns_option_v2: DnsOption,
}

#[derive(Debug, Deserialize, Default)]
struct DnsOption {
    #[serde(default, rename = "firstDNS")]
    first_dns: String,
}

pub fn parse_resource_bytes(resource: &[u8], service_host: &str) -> AtrResult<ResourceSnapshot> {
    let parsed: ClientResourceResponse = serde_json::from_slice(resource)?;
    let mut snapshot = ResourceSnapshot::default();
    let mut excluded = Vec::new();

    let app_list = parsed.data.app_list.data;
    let sdp_policy = match parsed.data.sdp_policy {
        Some(policy) => policy.data,
        None => SdpPolicyData {
            client_option: ClientOption {
                dns_option: DnsOption::default(),
                dns_option_v2: DnsOption::default(),
            },
        },
    };

    for app in app_list.app_info {
        for app_item in app.apps {
            for addr in app_item.address_list {
                let (port_min, port_max) = parse_port_range(&addr.port)?;
                if let Some(entry) = parse_host_entry(
                    &addr.host,
                    &addr.protocol,
                    port_min,
                    port_max,
                    &app_item.id,
                    &app_item.node_group_id,
                )? {
                    match entry {
                        HostEntry::Ip(resource) => snapshot.ip_resources.push(resource),
                        HostEntry::Domain(domain, resource) => {
                            snapshot.domain_resources.insert(domain, resource);
                        }
                    }
                }

                if !addr.ip.is_empty() {
                    if is_domain_like(&addr.host) {
                        for ip_str in addr.ip {
                            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                                snapshot.dns_resource.insert(addr.host.clone(), ip);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    snapshot.dns_server = if !sdp_policy.client_option.dns_option.first_dns.is_empty() {
        Some(sdp_policy.client_option.dns_option.first_dns)
    } else if !sdp_policy.client_option.dns_option_v2.first_dns.is_empty() {
        Some(sdp_policy.client_option.dns_option_v2.first_dns)
    } else {
        None
    };

    snapshot.major_node_group = app_list.config.node_group_conf.major_node_group.id;
    for group in app_list.config.node_group_conf.node_group_list {
        let mut addresses = Vec::new();
        for addr in group.address_info {
            if addr.kind == "wan" {
                let mut normalized = addr.address;
                if normalized == "{{sdpcHost}}" {
                    normalized = service_host.to_string();
                }
                if !normalized.contains(':') {
                    normalized.push_str(":441");
                }
                if let Some(host) = normalized.split(':').next()
                    && let Ok(ip) = host.parse::<Ipv4Addr>()
                {
                    excluded.push(ip);
                }
                addresses.push(normalized);
            }
        }
        snapshot.node_groups.insert(group.id, addresses);
    }
    snapshot.excluded_ips = excluded;
    snapshot.best_nodes = snapshot
        .node_groups
        .iter()
        .filter_map(|(k, v)| v.first().map(|addr| (k.clone(), addr.clone())))
        .collect();
    Ok(snapshot)
}

pub fn route(
    snapshot: &ResourceSnapshot,
    host: &str,
    port: u16,
    protocol: ProtocolKind,
) -> RouteDecision {
    if is_node_endpoint(snapshot, host, port) {
        return RouteDecision::Direct;
    }

    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        if let Some(hit) = match_ip(snapshot, ip, port, protocol) {
            return RouteDecision::Managed(hit);
        }
        return RouteDecision::Direct;
    }

    if let Some(hit) = match_domain(snapshot, host, port, protocol) {
        return RouteDecision::Managed(hit);
    }
    RouteDecision::Direct
}

fn is_node_endpoint(snapshot: &ResourceSnapshot, host: &str, port: u16) -> bool {
    let host = host.trim().trim_matches(['[', ']']);
    snapshot.node_groups.values().flatten().any(|endpoint| {
        let Some((node_host, node_port)) = split_host_port(endpoint) else {
            return false;
        };
        node_port == port && node_host.eq_ignore_ascii_case(host)
    })
}

fn split_host_port(endpoint: &str) -> Option<(&str, u16)> {
    let endpoint = endpoint.trim();
    let (host, port) = endpoint.rsplit_once(':')?;
    let host = host.trim().trim_matches(['[', ']']);
    if host.is_empty() {
        return None;
    }
    let port = port.trim().parse::<u16>().ok()?;
    Some((host, port))
}

#[allow(dead_code)]
pub fn ip_in_resources(
    snapshot: &ResourceSnapshot,
    ip: Ipv4Addr,
    port: u16,
    protocol: ProtocolKind,
) -> Option<RouteHit> {
    match_ip(snapshot, ip, port, protocol)
}

fn match_domain(
    snapshot: &ResourceSnapshot,
    host: &str,
    port: u16,
    protocol: ProtocolKind,
) -> Option<RouteHit> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    for (domain, resource) in &snapshot.domain_resources {
        if !protocol_matches(&resource.protocol, protocol)
            || resource.port_min > port
            || port > resource.port_max
        {
            continue;
        }

        let domain = domain
            .replace('*', "")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let bare_domain = domain.trim_start_matches('.');
        let matched = if domain.starts_with('.') {
            host.ends_with(&domain) || host == bare_domain
        } else {
            host == domain || host.ends_with(&format!(".{domain}"))
        };
        if matched {
            return Some(RouteHit {
                app_id: resource.app_id.clone(),
                node_group_id: resource.node_group_id.clone(),
            });
        }
    }
    None
}

fn match_ip(
    snapshot: &ResourceSnapshot,
    ip: Ipv4Addr,
    port: u16,
    protocol: ProtocolKind,
) -> Option<RouteHit> {
    for resource in &snapshot.ip_resources {
        if ip_between(ip, resource.ip_min, resource.ip_max)
            && protocol_matches(&resource.protocol, protocol)
            && resource.port_min <= port
            && port <= resource.port_max
        {
            return Some(RouteHit {
                app_id: resource.app_id.clone(),
                node_group_id: resource.node_group_id.clone(),
            });
        }
    }
    None
}

fn protocol_matches(rule: &str, protocol: ProtocolKind) -> bool {
    match (rule, protocol) {
        ("all", _) => true,
        ("tcp", ProtocolKind::Tcp) => true,
        ("udp", ProtocolKind::Udp) => true,
        ("icmp", ProtocolKind::Icmp) => true,
        _ => false,
    }
}

fn parse_port_range(port: &str) -> AtrResult<(u16, u16)> {
    if let Some((start, end)) = port.split_once('-') {
        let start = start
            .parse::<u16>()
            .map_err(|_| AtrError::ParseFailed(format!("invalid port range: {port}")))?;
        let end = end
            .parse::<u16>()
            .map_err(|_| AtrError::ParseFailed(format!("invalid port range: {port}")))?;
        Ok((start, end))
    } else {
        let value = port
            .parse::<u16>()
            .map_err(|_| AtrError::ParseFailed(format!("invalid port: {port}")))?;
        Ok((value, value))
    }
}

enum HostEntry {
    Ip(IpResource),
    Domain(String, DomainResource),
}

fn parse_host_entry(
    host: &str,
    protocol: &str,
    port_min: u16,
    port_max: u16,
    app_id: &str,
    node_group_id: &str,
) -> AtrResult<Option<HostEntry>> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(Some(HostEntry::Ip(IpResource {
            ip_min: ip,
            ip_max: ip,
            port_min,
            port_max,
            protocol: protocol.to_string(),
            app_id: app_id.to_string(),
            node_group_id: node_group_id.to_string(),
        })));
    }

    if let Ok(net) = host.parse::<Ipv4Net>() {
        let first = net.network();
        let last = net.broadcast();
        return Ok(Some(HostEntry::Ip(IpResource {
            ip_min: first,
            ip_max: last,
            port_min,
            port_max,
            protocol: protocol.to_string(),
            app_id: app_id.to_string(),
            node_group_id: node_group_id.to_string(),
        })));
    }

    if let Some((start, end)) = parse_ip_range(host)? {
        return Ok(Some(HostEntry::Ip(IpResource {
            ip_min: start,
            ip_max: end,
            port_min,
            port_max,
            protocol: protocol.to_string(),
            app_id: app_id.to_string(),
            node_group_id: node_group_id.to_string(),
        })));
    }

    if is_domain_like(host) {
        let domain = host.replace('*', "");
        return Ok(Some(HostEntry::Domain(
            domain,
            DomainResource {
                port_min,
                port_max,
                protocol: protocol.to_string(),
                app_id: app_id.to_string(),
                node_group_id: node_group_id.to_string(),
            },
        )));
    }

    Ok(None)
}

fn parse_ip_range(host: &str) -> AtrResult<Option<(Ipv4Addr, Ipv4Addr)>> {
    if let Some((start, end)) = host.split_once('-') {
        let start = start
            .parse::<Ipv4Addr>()
            .map_err(|_| AtrError::ParseFailed(format!("invalid ip range: {host}")))?;
        let end = end
            .parse::<Ipv4Addr>()
            .map_err(|_| AtrError::ParseFailed(format!("invalid ip range: {host}")))?;
        return Ok(Some((start, end)));
    }
    Ok(None)
}

fn is_domain_like(host: &str) -> bool {
    host.chars()
        .any(|c| !matches!(c, '0'..='9' | '.' | ':' | '-'))
        || host.contains('*')
}

fn ip_between(value: Ipv4Addr, min: Ipv4Addr, max: Ipv4Addr) -> bool {
    ip_order(value).cmp(&ip_order(min)) != Ordering::Less
        && ip_order(value).cmp(&ip_order(max)) != Ordering::Greater
}

fn ip_order(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_ipv4_range() {
        let mut snapshot = ResourceSnapshot::default();
        snapshot.ip_resources.push(IpResource {
            ip_min: "10.0.0.1".parse().unwrap(),
            ip_max: "10.0.0.10".parse().unwrap(),
            port_min: 80,
            port_max: 80,
            protocol: "tcp".into(),
            app_id: "app".into(),
            node_group_id: "group".into(),
        });
        let hit = route(&snapshot, "10.0.0.2", 80, ProtocolKind::Tcp);
        assert!(matches!(hit, RouteDecision::Managed(_)));
    }

    #[test]
    fn routes_domain_suffix_resource() {
        let mut snapshot = ResourceSnapshot::default();
        snapshot.domain_resources.insert(
            ".cnki.net".into(),
            DomainResource {
                port_min: 1,
                port_max: 65535,
                protocol: "tcp".into(),
                app_id: "app".into(),
                node_group_id: "group".into(),
            },
        );

        let apex = route(&snapshot, "cnki.net", 443, ProtocolKind::Tcp);
        let subdomain = route(&snapshot, "www.cnki.net", 443, ProtocolKind::Tcp);
        let unrelated = route(&snapshot, "notcnki.net", 443, ProtocolKind::Tcp);

        assert!(matches!(apex, RouteDecision::Managed(_)));
        assert!(matches!(subdomain, RouteDecision::Managed(_)));
        assert!(matches!(unrelated, RouteDecision::Direct));
    }

    #[test]
    fn routes_node_endpoint_directly() {
        let mut snapshot = ResourceSnapshot::default();
        snapshot.node_groups.insert(
            "group".into(),
            vec!["202.118.253.228:441".into(), "node.example.com:441".into()],
        );
        snapshot.ip_resources.push(IpResource {
            ip_min: "202.118.253.1".parse().unwrap(),
            ip_max: "202.118.253.254".parse().unwrap(),
            port_min: 1,
            port_max: u16::MAX,
            protocol: "tcp".into(),
            app_id: "app".into(),
            node_group_id: "group".into(),
        });

        let node_ip = route(&snapshot, "202.118.253.228", 441, ProtocolKind::Tcp);
        let node_host = route(&snapshot, "node.example.com", 441, ProtocolKind::Tcp);
        let managed = route(&snapshot, "202.118.253.10", 441, ProtocolKind::Tcp);

        assert!(matches!(node_ip, RouteDecision::Direct));
        assert!(matches!(node_host, RouteDecision::Direct));
        assert!(matches!(managed, RouteDecision::Managed(_)));
    }
}
