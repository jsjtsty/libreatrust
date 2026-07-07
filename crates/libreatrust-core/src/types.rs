use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_host: String,
    pub server_port: u16,
    pub user_agent: String,
    pub connect_timeout_ms: u64,
    pub io_timeout_ms: u64,
    pub node_probe_timeout_ms: u64,
    pub allow_insecure_tls: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_host: String::new(),
            server_port: 443,
            user_agent: String::from("Mozilla/5.0"),
            connect_timeout_ms: 20_000,
            io_timeout_ms: 20_000,
            node_probe_timeout_ms: 3_000,
            allow_insecure_tls: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMaterial {
    pub username: String,
    pub sid: String,
    pub device_id: String,
    pub connection_id: String,
    pub sign_key_hex: String,
    pub cookies: Vec<CookieRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieRecord {
    pub host: String,
    pub scheme: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub server_host: String,
    pub server_port: u16,
    pub user_agent: String,
    pub client_type: String,
    pub platform: String,
    pub login_domain: String,
    pub preferred_auth_type: Option<String>,
    pub io_timeout_ms: u64,
    pub allow_insecure_tls: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            server_host: String::new(),
            server_port: 443,
            user_agent: String::from("Mozilla/5.0"),
            client_type: String::from("SDPClient"),
            platform: String::from("Linux"),
            login_domain: String::new(),
            preferred_auth_type: None,
            io_timeout_ms: 20_000,
            allow_insecure_tls: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthMethodInfo {
    #[serde(rename = "loginDomain")]
    pub login_domain: String,
    #[serde(rename = "authType")]
    pub auth_type: String,
    #[serde(rename = "authName")]
    pub auth_name: String,
    #[serde(rename = "loginUrl")]
    pub login_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordLoginInput {
    pub username: String,
    pub password: String,
    pub login_domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsLoginInput {
    pub phone: String,
    pub login_domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackTarget {
    pub callback_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthChallengeKind {
    Captcha,
    SmsCode,
    CallbackUrl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthChallenge {
    NeedCaptcha {
        image: Vec<u8>,
    },
    NeedSmsCode {
        auth_id: String,
    },
    NeedCallbackUrl {
        auth_url: String,
        kind: AuthChallengeKind,
    },
    Done(SessionMaterial),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolKind {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteHit {
    pub app_id: String,
    pub node_group_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RouteDecision {
    Direct,
    Managed(RouteHit),
}
