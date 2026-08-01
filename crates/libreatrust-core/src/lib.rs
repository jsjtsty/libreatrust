mod auth;
mod client;
mod error;
mod keep_alive;
mod proxy_service;
mod resource;
mod sign;
mod transport;
mod types;

#[cfg(any(debug_assertions, feature = "verbose-logs"))]
pub(crate) fn diag_log(message: impl AsRef<str>) {
    let message = message.as_ref();
    eprintln!("{message}");
}

#[cfg(not(any(debug_assertions, feature = "verbose-logs")))]
pub(crate) fn diag_log(_message: impl AsRef<str>) {}

pub use auth::AuthSession;
pub use client::AtrClient;
pub use error::{AtrError, AtrResult, ErrorCode};
pub use keep_alive::{KeepAliveConfig, KeepAliveService, KeepAliveStatus};
pub use proxy_service::{
    ProxyService, ProxyServiceConfig, ProxyServiceEvent, ProxyServiceStats, ProxyServiceStatus,
};
pub use resource::{DomainResource, IpResource, ResourceSnapshot, parse_resource_bytes};
pub use transport::{L3Tunnel, TcpTunnel, UdpTunnel};
pub use types::{
    AuthChallenge, AuthChallengeKind, AuthConfig, AuthMethodInfo, CallbackTarget, ClientConfig,
    CookieRecord, PasswordLoginInput, ProtocolKind, RouteDecision, RouteHit, SessionMaterial,
    SmsLoginInput,
};

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_ascii() {
        assert!(env!("CARGO_PKG_VERSION").is_ascii());
    }
}
