mod auth;
mod client;
mod error;
mod log;
mod pac;
mod proxy_service;
mod resource;
mod sign;
mod transport;
mod types;

pub use auth::AuthSession;
pub use client::AtrClient;
pub use error::{AtrError, AtrResult, ErrorCode};
pub use log::{
    MAX_LOG_BYTES, log_file_path, log_write, set_log_directory, set_verbose_logging,
    verbose_logging_enabled,
};
pub use pac::generate_pac;
pub use proxy_service::{
    ProxyService, ProxyServiceConfig, ProxyServiceEvent, ProxyServiceEventListener,
    ProxyServiceStats, ProxyServiceStatus,
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
