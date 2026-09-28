//! Proxy auto-config (PAC) generation for the local proxy service.
//!
//! With a PAC file, the system only sends hosts that belong to managed
//! resources to the local proxy; everything else goes out directly. Ordinary
//! traffic then no longer depends on the proxy process staying alive.

use crate::resource::ResourceSnapshot;
use std::net::{IpAddr, SocketAddr};

/// Builds a PAC script that routes managed TCP destinations through
/// `proxy` and everything else directly.
pub fn generate_pac(snapshot: &ResourceSnapshot, proxy: SocketAddr) -> String {
    let mut domains: Vec<String> = snapshot
        .domain_resources
        .iter()
        .filter(|(_, resource)| carries_tcp(&resource.protocol))
        .filter_map(|(domain, _)| normalize_domain(domain))
        .collect();
    domains.sort();
    domains.dedup();

    let mut ranges: Vec<(u32, u32)> = snapshot
        .ip_resources
        .iter()
        .filter(|resource| carries_tcp(&resource.protocol))
        .map(|resource| (u32::from(resource.ip_min), u32::from(resource.ip_max)))
        .filter(|(min, max)| min <= max)
        .collect();
    ranges.sort_unstable();
    ranges.dedup();

    let host = match proxy.ip() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let proxy_line = format!(
        "PROXY {host}:{port}; SOCKS5 {host}:{port}; DIRECT",
        port = proxy.port()
    );

    let domain_table = domains
        .iter()
        .map(|domain| format!("{}:1", js_string(domain)))
        .collect::<Vec<_>>()
        .join(",");
    let range_table = ranges
        .iter()
        .map(|(min, max)| format!("[{min},{max}]"))
        .collect::<Vec<_>>()
        .join(",");

    // All data lives inside the function so that nothing leaks into the
    // global scope of whatever evaluates the script.
    format!(
        r#"function FindProxyForURL(url, host) {{
  var PROXY = {proxy};
  var DOMAINS = {{{domain_table}}};
  var RANGES = [{range_table}];
  function ipToNumber(value) {{
    var parts = value.split(".");
    if (parts.length != 4) return -1;
    var number = 0;
    for (var i = 0; i < 4; i++) {{
      if (!/^[0-9]{{1,3}}$/.test(parts[i])) return -1;
      var octet = parseInt(parts[i], 10);
      if (octet > 255) return -1;
      number = number * 256 + octet;
    }}
    return number;
  }}
  function inRanges(number) {{
    for (var i = 0; i < RANGES.length; i++) {{
      if (number >= RANGES[i][0] && number <= RANGES[i][1]) return true;
    }}
    return false;
  }}
  host = host.toLowerCase();
  if (host.charAt(host.length - 1) == ".") host = host.substring(0, host.length - 1);
  var suffix = host;
  while (true) {{
    if (DOMAINS.hasOwnProperty(suffix)) return PROXY;
    var dot = suffix.indexOf(".");
    if (dot < 0) break;
    suffix = suffix.substring(dot + 1);
  }}
  if (RANGES.length == 0) return "DIRECT";
  var number = ipToNumber(host);
  if (number < 0) {{
    if (isPlainHostName(host)) return "DIRECT";
    var resolved = dnsResolve(host);
    if (!resolved) return "DIRECT";
    number = ipToNumber(resolved);
  }}
  if (number >= 0 && inRanges(number)) return PROXY;
  return "DIRECT";
}}
"#,
        proxy = js_string(&proxy_line),
    )
}

fn carries_tcp(protocol: &str) -> bool {
    matches!(protocol, "all" | "tcp")
}

/// Mirrors the matching in `resource::match_domain`: wildcards are dropped
/// and a rule matches the domain itself and all of its subdomains.
fn normalize_domain(domain: &str) -> Option<String> {
    let normalized = domain
        .replace('*', "")
        .trim_matches('.')
        .trim()
        .to_ascii_lowercase();
    let valid = !normalized.is_empty()
        && normalized
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'));
    valid.then_some(normalized)
}

fn js_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{DomainResource, IpResource};
    use std::net::Ipv4Addr;

    fn domain(protocol: &str) -> DomainResource {
        DomainResource {
            port_min: 1,
            port_max: 65535,
            protocol: protocol.into(),
            app_id: "app".into(),
            node_group_id: "group".into(),
        }
    }

    #[test]
    fn pac_lists_tcp_domains_and_ranges() {
        let mut snapshot = ResourceSnapshot::default();
        snapshot
            .domain_resources
            .insert("*.Intranet.Example.edu.".into(), domain("all"));
        snapshot
            .domain_resources
            .insert("udp-only.example".into(), domain("udp"));
        snapshot
            .domain_resources
            .insert("bad\"domain".into(), domain("tcp"));
        snapshot.ip_resources.push(IpResource {
            ip_min: Ipv4Addr::new(10, 0, 0, 0),
            ip_max: Ipv4Addr::new(10, 0, 0, 255),
            port_min: 1,
            port_max: 65535,
            protocol: "tcp".into(),
            app_id: "app".into(),
            node_group_id: "group".into(),
        });

        let pac = generate_pac(&snapshot, "127.0.0.1:1920".parse().unwrap());
        assert!(pac.contains(r#""intranet.example.edu":1"#));
        assert!(!pac.contains("udp-only"));
        assert!(!pac.contains("bad"));
        assert!(pac.contains("[167772160,167772415]"));
        assert!(pac.contains("PROXY 127.0.0.1:1920; SOCKS5 127.0.0.1:1920; DIRECT"));
    }

    #[test]
    fn pac_brackets_ipv6_proxy_host() {
        let pac = generate_pac(&ResourceSnapshot::default(), "[::1]:1920".parse().unwrap());
        assert!(pac.contains("PROXY [::1]:1920"));
    }
}
