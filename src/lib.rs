pub use libreatrust_core::{
    AtrClient, AtrError, AtrResult, AuthChallenge, AuthChallengeKind, AuthConfig, AuthMethodInfo,
    AuthSession, CallbackTarget, ClientConfig, CookieRecord, DomainResource, ErrorCode, IpResource,
    L3Tunnel, PasswordLoginInput, ProtocolKind, ProxyService, ProxyServiceConfig,
    ProxyServiceEvent, ProxyServiceStats, ProxyServiceStatus, ResourceSnapshot, RouteDecision,
    RouteHit, SessionMaterial, SmsLoginInput, TcpTunnel, UdpTunnel, log_file_path, log_write,
    parse_resource_bytes, set_log_directory, set_verbose_logging, verbose_logging_enabled,
};

mod ffi;

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_ascii() {
        assert!(env!("CARGO_PKG_VERSION").is_ascii());
    }
}
