mod auth;
mod client;
mod error;
mod proxy_service;
mod resource;
mod sign;
mod transport;
mod types;

#[cfg(feature = "verbose-logs")]
pub(crate) fn diag_log(message: impl AsRef<str>) {
    let message = message.as_ref();
    eprintln!("{message}");

    let log_path = std::env::var_os("HOME")
        .filter(|home| home != "/var/root")
        .map(|home| {
            std::path::PathBuf::from(home)
                .join("Library/Application Support/NulConnect/NulConnect.log")
        })
        .unwrap_or_else(|| {
            std::path::PathBuf::from(
                "/Library/Application Support/NulConnect/nulconnect-helper.log",
            )
        });

    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        use std::io::Write as _;
        let _ = writeln!(file, "{message}");
    }
}

#[cfg(not(feature = "verbose-logs"))]
pub(crate) fn diag_log(_message: impl AsRef<str>) {}

pub use auth::AuthSession;
pub use client::AtrClient;
pub use error::{AtrError, AtrResult, ErrorCode};
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
