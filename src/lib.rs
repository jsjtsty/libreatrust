mod auth;
mod client;
mod error;
mod ffi;
mod proxy_service;
mod resource;
mod sign;
mod transport;
mod types;

pub use auth::AuthSession;
pub use client::AtrClient;
pub use error::{AtrError, AtrResult, ErrorCode};
pub use proxy_service::{ProxyService, ProxyServiceConfig, ProxyServiceStats, ProxyServiceStatus};
pub use resource::{DomainResource, IpResource, ResourceSnapshot};
pub use transport::{L3Tunnel, TcpTunnel, UdpTunnel};
pub use types::{
    AuthChallenge, AuthChallengeKind, AuthConfig, AuthMethodInfo, CallbackTarget, ClientConfig,
    PasswordLoginInput, ProtocolKind, RouteDecision, RouteHit, SessionMaterial, SmsLoginInput,
};

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_ascii() {
        assert!(env!("CARGO_PKG_VERSION").is_ascii());
    }
}
