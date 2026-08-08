pub use libreatrust_core::{
    AtrClient, AtrError, AtrResult, AuthChallenge, AuthChallengeKind, AuthConfig, AuthMethodInfo,
    AuthSession, CallbackTarget, ClientConfig, CookieRecord, DomainResource, ErrorCode, IpResource,
    L3Tunnel, PasswordLoginInput, ProtocolKind, ProxyService, ProxyServiceConfig,
    ProxyServiceEvent, ProxyServiceStats, ProxyServiceStatus, ResourceSnapshot, RouteDecision,
    RouteHit, SessionMaterial, SmsLoginInput, TcpTunnel, UdpTunnel, parse_resource_bytes,
};

mod ffi;

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_ascii() {
        assert!(env!("CARGO_PKG_VERSION").is_ascii());
    }
}
