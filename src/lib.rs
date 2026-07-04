mod auth;
mod client;
mod error;
mod ffi;
mod proxy_service;
mod resource;
mod sign;
mod transport;
mod types;

pub(crate) fn diag_log(message: impl AsRef<str>) {
    let message = message.as_ref();
    eprintln!("{message}");

    let Ok(home) = std::env::var("HOME") else {
        return;
    };
    let log_dir = std::path::Path::new(&home).join("Library/Logs/NulConnect");
    let _ = std::fs::create_dir_all(&log_dir);

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("app.log"))
    {
        use std::io::Write;
        let _ = writeln!(file, "{message}");
    }
}

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
