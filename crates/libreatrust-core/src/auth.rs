use crate::error::{AtrError, AtrResult};
use crate::types::{
    AuthChallenge, AuthConfig, AuthMethodInfo, CallbackTarget, CookieRecord, PasswordLoginInput,
    SessionMaterial, SmsLoginInput,
};
use base64::Engine as _;
use rand::RngCore;
use reqwest::StatusCode;
use reqwest::blocking::{Client, Response};
use reqwest::cookie::Jar;
use reqwest::header::{HeaderValue, SET_COOKIE};
use rsa::{BigUint, RsaPublicKey, pkcs1v15::Pkcs1v15Encrypt};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

#[derive(Debug, Clone)]
enum PendingFlow {
    Password(PasswordLoginInput),
    AuthStep(AuthStep),
    SmsLogin(SmsLoginInput),
    SmsVerify {
        phone: String,
        login_domain: String,
        code: String,
    },
}

#[derive(Debug)]
pub struct AuthSession {
    config: AuthConfig,
    client: Client,
    cookie_jar: Arc<Jar>,
    base_url: Url,
    base_host: String,
    csrf_token: String,
    pub_key: String,
    pub_key_exp: String,
    anti_replay_rand: String,
    device_id: String,
    sign_key_hex: String,
    connection_id: String,
    env: String,
    ticket: String,
    sid: String,
    username: String,
    client_resource_bytes: Option<Vec<u8>>,
    cookies: HashMap<String, CookieRecord>,
    pending: Option<PendingFlow>,
}

#[derive(Debug, Deserialize)]
struct AuthConfigResponse {
    data: AuthConfigData,
}

#[derive(Debug, Deserialize)]
struct AuthConfigData {
    #[serde(rename = "authServerInfoList")]
    auth_server_info_list: Vec<AuthMethodInfo>,
    #[serde(rename = "isLogin")]
    is_login: i32,
    #[serde(default, rename = "csrfToken")]
    csrf_token: String,
    #[serde(rename = "pubKey")]
    pub_key: String,
    #[serde(rename = "pubKeyExp")]
    pub_key_exp: String,
    #[serde(rename = "antiReplayRand")]
    anti_replay_rand: String,
    #[serde(default)]
    security: Option<AuthConfigSecurity>,
}

#[derive(Debug, Deserialize)]
struct AuthConfigSecurity {
    #[serde(default, rename = "csrfToken")]
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct CodeResponse {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct PasswordResponse {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
    #[serde(default)]
    data: PasswordResponseData,
}

#[derive(Debug, Default, Deserialize)]
struct PasswordResponseData {
    #[serde(default)]
    ticket: String,
    #[serde(default, rename = "graphCheckCodeEnable")]
    graph_check_code_enable: i32,
}

#[derive(Debug, Deserialize)]
struct AuthCheckResponse {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
    #[serde(default)]
    data: AuthCheckData,
}

#[derive(Debug, Default, Deserialize)]
struct AuthCheckData {
    #[serde(default, rename = "nextServiceList")]
    next_service_list: Vec<AuthIdItem>,
    #[serde(default, rename = "nextService")]
    next_service: String,
}

#[derive(Debug, Deserialize)]
struct AuthIdItem {
    #[serde(default, rename = "authId")]
    auth_id: String,
    #[serde(default, rename = "authType")]
    auth_type: String,
}

#[derive(Debug, Deserialize)]
struct AuthStepResponse {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
    #[serde(default)]
    data: AuthStepData,
}

#[derive(Debug, Default, Deserialize)]
struct AuthStepData {
    #[serde(default, rename = "nextService")]
    next_service: String,
    #[serde(default, rename = "nextServiceList")]
    next_service_list: Vec<AuthIdItem>,
}

#[derive(Debug, Deserialize)]
struct CustomSmsResponse {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
    #[serde(default)]
    data: CustomSmsData,
}

#[derive(Debug, Default, Deserialize)]
struct CustomSmsData {
    #[serde(default)]
    tips: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmsMode {
    WithAuthId,
    WithoutAuthId,
    Custom,
}

#[derive(Debug, Clone)]
struct AuthStep {
    service: String,
    auth_id: String,
    sms_mode: Option<SmsMode>,
}

fn auth_step_from_data(data: AuthStepData) -> AuthStep {
    let mut service = data.next_service;
    let selected = data
        .next_service_list
        .iter()
        .find(|item| !service.is_empty() && item.auth_type == service)
        .or_else(|| data.next_service_list.first());
    let auth_id = selected
        .map(|item| item.auth_id.clone())
        .unwrap_or_default();
    if service.is_empty() {
        service = selected
            .map(|item| item.auth_type.clone())
            .unwrap_or_default();
    }
    if service.is_empty() && !auth_id.is_empty() {
        service = "auth/sms".into();
    }
    let sms_mode = match service.as_str() {
        "auth/sms" => Some(if auth_id.is_empty() {
            SmsMode::WithoutAuthId
        } else {
            SmsMode::WithAuthId
        }),
        "auth/customSms" => Some(SmsMode::Custom),
        _ => None,
    };
    AuthStep {
        service,
        auth_id,
        sms_mode,
    }
}

#[derive(Debug, Deserialize)]
struct SmsResponse {
    code: i64,
    message: String,
    data: SmsResponseData,
}

#[derive(Debug, Deserialize)]
struct SmsResponseData {
    #[serde(default, rename = "graphCheckCodeEnable")]
    graph_check_code_enable: i32,
    #[serde(default)]
    ticket: String,
}

#[derive(Debug, Deserialize)]
struct OnlineInfoResponse {
    data: OnlineInfoData,
}

#[derive(Debug, Deserialize)]
struct OnlineInfoData {
    username: String,
}

impl AuthSession {
    pub fn new(config: AuthConfig) -> AtrResult<Self> {
        if config.server_host.is_empty() {
            return Err(AtrError::InvalidArgument("server_host is empty".into()));
        }
        let base_host = if config.server_port == 443 {
            config.server_host.clone()
        } else {
            format!("{}:{}", config.server_host, config.server_port)
        };
        let base_url = Url::parse(&format!("https://{}", base_host))?;
        let jar = Arc::new(Jar::default());
        let client = Client::builder()
            .cookie_provider(jar.clone())
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(config.allow_insecure_tls)
            .timeout(Duration::from_millis(config.io_timeout_ms.max(1)))
            .build()?;

        Ok(Self {
            config,
            client,
            cookie_jar: jar,
            base_url,
            base_host,
            csrf_token: String::new(),
            pub_key: String::new(),
            pub_key_exp: String::new(),
            anti_replay_rand: String::new(),
            device_id: String::new(),
            sign_key_hex: random_hex(64),
            connection_id: String::new(),
            env: String::new(),
            ticket: String::new(),
            sid: String::new(),
            username: String::new(),
            client_resource_bytes: None,
            cookies: HashMap::new(),
            pending: None,
        })
    }

    pub fn available_methods(&mut self) -> AtrResult<Vec<AuthMethodInfo>> {
        let (_, methods) = self.auth_config_init()?;
        Ok(methods)
    }

    pub fn resolve_login_url(&self, login_url: &str) -> AtrResult<String> {
        Ok(self.base_url.join(login_url)?.to_string())
    }

    pub fn login_with_password(
        &mut self,
        input: PasswordLoginInput,
        device_id: String,
    ) -> AtrResult<AuthChallenge> {
        self.reset_identity(device_id);
        self.pending = Some(PendingFlow::Password(input.clone()));
        self.run_password(&input, "")
    }

    pub fn login_with_sms(
        &mut self,
        input: SmsLoginInput,
        device_id: String,
    ) -> AtrResult<AuthChallenge> {
        self.reset_identity(device_id);
        self.pending = Some(PendingFlow::SmsLogin(input.clone()));
        self.run_sms_send(&input, "")
    }

    pub fn submit_captcha(&mut self, captcha: &str) -> AtrResult<AuthChallenge> {
        let pending = self
            .pending
            .clone()
            .ok_or_else(|| AtrError::InvalidState("no pending challenge".into()))?;
        match pending {
            PendingFlow::Password(input) => self.run_password(&input, captcha),
            PendingFlow::SmsLogin(input) => self.run_sms_send(&input, captcha),
            PendingFlow::SmsVerify {
                phone,
                login_domain,
                code,
            } => self.run_sms_verify(&phone, &login_domain, &code, captcha),
            PendingFlow::AuthStep(_) => Err(AtrError::InvalidState(
                "captcha is not expected here".into(),
            )),
        }
    }

    pub fn submit_sms_code(&mut self, code: &str) -> AtrResult<AuthChallenge> {
        let pending = self
            .pending
            .clone()
            .ok_or_else(|| AtrError::InvalidState("no pending sms flow".into()))?;
        match pending {
            PendingFlow::AuthStep(step) => {
                let (code, skip_secondary_auth) = code
                    .strip_prefix('$')
                    .map_or((code, false), |code| (code, true));
                let next = self.complete_auth_step(&step, code, skip_secondary_auth)?;
                self.continue_auth(next)
            }
            PendingFlow::SmsLogin(input) => {
                self.pending = Some(PendingFlow::SmsVerify {
                    phone: input.phone,
                    login_domain: input.login_domain,
                    code: code.to_string(),
                });
                let (phone, login_domain, stored_code) = match self.pending.clone() {
                    Some(PendingFlow::SmsVerify {
                        phone,
                        login_domain,
                        code,
                    }) => (phone, login_domain, code),
                    _ => return Err(AtrError::InvalidState("sms flow lost".into())),
                };
                self.run_sms_verify(&phone, &login_domain, &stored_code, "")
            }
            PendingFlow::SmsVerify {
                phone,
                login_domain,
                ..
            } => self.run_sms_verify(&phone, &login_domain, code, ""),
            PendingFlow::Password(_) => Err(AtrError::InvalidState(
                "pending password flow, not sms".into(),
            )),
        }
    }

    pub fn complete_callback(&mut self, target: CallbackTarget) -> AtrResult<AuthChallenge> {
        let callback = Url::parse(&target.callback_url)?;
        let ticket = self.extract_ticket_from_callback(&callback)?;
        self.ticket = ticket;
        self.finish_login(true)
    }

    pub fn complete_callback_with_device(
        &mut self,
        target: CallbackTarget,
        device_id: String,
    ) -> AtrResult<AuthChallenge> {
        self.reset_identity(device_id);
        self.complete_callback(target)
    }

    pub fn prepare_callback_login(&mut self, device_id: String) {
        self.reset_identity(device_id);
    }

    pub fn import_session(&mut self, session: SessionMaterial) {
        self.device_id = session.device_id;
        self.connection_id = self.build_connection_id(&self.device_id);
        self.sign_key_hex = random_hex(64);
        self.username = session.username;
        self.ticket.clear();
        self.sid = session.sid;
        self.cookies.clear();
        for cookie in session.cookies {
            self.install_cookie(&cookie);
            self.cookies.insert(cookie.name.clone(), cookie);
        }
        self.env = self.build_env(&self.device_id);
    }

    pub fn resume_session(&mut self, session: SessionMaterial) -> AtrResult<SessionMaterial> {
        self.import_session(session);
        let (is_login, _) = self.auth_config_init()?;
        if !is_login {
            return Err(AtrError::Unauthorized(
                "stored session is not logged in".into(),
            ));
        }
        let username = self.online_info()?;
        self.username = username;
        self.sync_sid_from_cookies();
        Ok(self.session_material())
    }

    pub fn session_material(&self) -> SessionMaterial {
        SessionMaterial {
            username: self.username.clone(),
            sid: self.sid.clone(),
            device_id: self.device_id.clone(),
            connection_id: self.connection_id.clone(),
            sign_key_hex: self.sign_key_hex.clone(),
            cookies: self.collect_cookies(),
        }
    }

    pub fn client_resource_bytes(&mut self) -> AtrResult<Vec<u8>> {
        if let Some(bytes) = self.client_resource_bytes.clone() {
            return Ok(bytes);
        }
        let bytes = self.fetch_client_resource()?;
        self.client_resource_bytes = Some(bytes.clone());
        Ok(bytes)
    }

    fn reset_identity(&mut self, device_id: String) {
        self.device_id = device_id;
        self.connection_id = self.build_connection_id(&self.device_id);
        self.sign_key_hex = random_hex(64);
        self.env = self.build_env(&self.device_id);
        self.ticket.clear();
        self.sid.clear();
        self.username.clear();
        self.pending = None;
    }

    fn run_password(
        &mut self,
        input: &PasswordLoginInput,
        captcha: &str,
    ) -> AtrResult<AuthChallenge> {
        let _ = self.auth_config_init()?;
        let response = self.post_password(input, captcha)?;
        if response.data.graph_check_code_enable != 0 {
            let image = self.fetch_captcha()?;
            self.pending = Some(PendingFlow::Password(input.clone()));
            return Ok(AuthChallenge::NeedCaptcha { image });
        }
        self.ticket = response.data.ticket;
        self.sync_sid_from_cookies();
        self.finish_login(false)
    }

    fn run_sms_send(&mut self, input: &SmsLoginInput, captcha: &str) -> AtrResult<AuthChallenge> {
        let _ = self.auth_config_init()?;
        let captcha_enabled = self.send_sms(input, captcha)?;
        if captcha_enabled != 0 && captcha.is_empty() {
            let image = self.fetch_captcha()?;
            self.pending = Some(PendingFlow::SmsLogin(input.clone()));
            return Ok(AuthChallenge::NeedCaptcha { image });
        }
        let step = self.auth_check()?;
        self.continue_auth(step)
    }

    fn run_sms_verify(
        &mut self,
        phone: &str,
        login_domain: &str,
        code: &str,
        captcha: &str,
    ) -> AtrResult<AuthChallenge> {
        let response = self.post_sms_verify(phone, login_domain, code, captcha)?;
        if response.data.graph_check_code_enable != 0 && captcha.is_empty() {
            let image = self.fetch_captcha()?;
            self.pending = Some(PendingFlow::SmsVerify {
                phone: phone.to_string(),
                login_domain: login_domain.to_string(),
                code: code.to_string(),
            });
            return Ok(AuthChallenge::NeedCaptcha { image });
        }
        self.ticket = response.data.ticket;
        self.sync_sid_from_cookies();
        self.finish_login(false)
    }

    fn finish_login(&mut self, update_mod: bool) -> AtrResult<AuthChallenge> {
        if update_mod {
            let _ = self.auth_config_mod()?;
        }
        self.report_env()?;
        let step = self.auth_check()?;
        return self.continue_auth(step);
    }

    fn complete_login(&mut self) -> AtrResult<AuthChallenge> {
        self.pending = None;
        let username = self.online_info()?;
        self.username = username.clone();
        self.sync_sid_from_cookies();
        Ok(AuthChallenge::Done(SessionMaterial {
            username,
            sid: self.sid.clone(),
            device_id: self.device_id.clone(),
            connection_id: self.connection_id.clone(),
            sign_key_hex: self.sign_key_hex.clone(),
            cookies: self.collect_cookies(),
        }))
    }

    fn continue_auth(&mut self, mut step: AuthStep) -> AtrResult<AuthChallenge> {
        for _ in 0..8 {
            match step.service.as_str() {
                "" => return self.complete_login(),
                "auth/authCheck" => step = self.auth_check()?,
                "auth/sms" => return self.begin_sms(step),
                "auth/customSms" => return self.begin_custom_sms(),
                service => {
                    return Err(AtrError::Unsupported(format!(
                        "unsupported next authentication service: {service}"
                    )));
                }
            }
        }
        Err(AtrError::Unauthorized(
            "authentication chain exceeded 8 steps".into(),
        ))
    }

    fn begin_sms(&mut self, step: AuthStep) -> AtrResult<AuthChallenge> {
        let mode = step
            .sms_mode
            .ok_or_else(|| AtrError::InvalidState("missing SMS authentication mode".into()))?;
        if mode == SmsMode::WithAuthId {
            let _ = self.auth_config_refresh()?;
        }
        self.log_phone_number(&step.auth_id);
        self.trigger_password_sms_step(&step)?;
        if mode == SmsMode::WithoutAuthId {
            let _ = self.auth_config_refresh()?;
        }
        let auth_id = step.auth_id.clone();
        self.pending = Some(PendingFlow::AuthStep(step));
        Ok(AuthChallenge::NeedSmsCode { auth_id })
    }

    fn begin_custom_sms(&mut self) -> AtrResult<AuthChallenge> {
        self.send_custom_sms()?;
        self.pending = Some(PendingFlow::AuthStep(AuthStep {
            service: "auth/customSms".into(),
            auth_id: String::new(),
            sms_mode: Some(SmsMode::Custom),
        }));
        Ok(AuthChallenge::NeedSmsCode {
            auth_id: String::new(),
        })
    }

    fn complete_auth_step(
        &mut self,
        step: &AuthStep,
        code: &str,
        skip_secondary_auth: bool,
    ) -> AtrResult<AuthStep> {
        match step.sms_mode {
            Some(SmsMode::Custom) => self.custom_sms_check_code(code, skip_secondary_auth),
            Some(SmsMode::WithAuthId) | Some(SmsMode::WithoutAuthId) => {
                self.password_sms_check(step, code, skip_secondary_auth)
            }
            None => Err(AtrError::InvalidState("invalid authentication step".into())),
        }
    }

    fn fetch_client_resource(&mut self) -> AtrResult<Vec<u8>> {
        if self.ticket.is_empty() {
            let (is_login, _) = self.auth_config_init()?;
            if !is_login {
                return Err(AtrError::Unauthorized(
                    "stored session is not logged in".into(),
                ));
            }
        }
        let mut url = self.base_url.join("/controller/v1/user/clientResource")?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in self.shared_params() {
                qp.append_pair(&k, &v);
            }
        }
        let payload = json!({
            "resourceType": {
                "sdpPolicy": {},
                "appList": {},
                "favoriteAppList": {},
                "featureCenter": {},
                "uemSpace": { "params": { "action": "login" } }
            }
        });
        let resp = self
            .client
            .post(url)
            .header("User-Agent", &self.config.user_agent)
            .header("Content-Type", "application/json;charset=utf-8")
            .header("x-csrf-token", &self.csrf_token)
            .header("x-sdp-traceid", self.trace_id())
            .body(payload.to_string())
            .send()?;
        self.capture_cookies(&resp)?;
        let status = resp.status();
        let bytes = resp.bytes()?.to_vec();
        validate_client_resource_response(status, &bytes)?;
        Ok(bytes)
    }

    fn auth_config_init(&mut self) -> AtrResult<(bool, Vec<AuthMethodInfo>)> {
        self.auth_config_impl(&[("needTicket", "1")])
    }

    fn auth_config_mod(&mut self) -> AtrResult<(bool, Vec<AuthMethodInfo>)> {
        self.auth_config_impl(&[("mod", "1")])
            .map(|(is_login, methods)| (is_login, methods))
    }

    fn auth_config_refresh(&mut self) -> AtrResult<(bool, Vec<AuthMethodInfo>)> {
        self.auth_config_impl(&[("mod", "1"), ("needTicket", "1")])
    }

    fn auth_config_impl(
        &mut self,
        extra: &[(&str, &str)],
    ) -> AtrResult<(bool, Vec<AuthMethodInfo>)> {
        let mut url = self.base_url.join("/passport/v1/public/authConfig")?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in self.shared_params() {
                qp.append_pair(&k, &v);
            }
            for (k, v) in extra {
                qp.append_pair(k, v);
            }
        }
        crate::diag_log(format!("[libreatrust][auth] GET {}", url));
        let resp = self
            .client
            .get(url)
            .header("User-Agent", &self.config.user_agent)
            .header("x-csrf-token", &self.csrf_token)
            .header("x-sdp-rid", self.base64_rid())
            .header("x-sdp-traceid", self.trace_id())
            .send()
            .map_err(|err| {
                crate::diag_log(format!(
                    "[libreatrust][auth] authConfig request failed: {}",
                    err
                ));
                err
            })?;
        let status = resp.status();
        self.capture_cookies(&resp)?;
        let body = resp.text()?;
        crate::diag_log(format!(
            "[libreatrust][auth] authConfig response status={} body={}",
            status, body
        ));
        let parsed: AuthConfigResponse = serde_json::from_str(&body).map_err(|err| {
            crate::diag_log(format!(
                "[libreatrust][auth] authConfig parse failed: {}",
                err
            ));
            err
        })?;
        self.csrf_token = if parsed.data.csrf_token.is_empty() {
            parsed
                .data
                .security
                .as_ref()
                .map(|security| security.csrf_token.clone())
                .unwrap_or_default()
        } else {
            parsed.data.csrf_token
        };
        self.pub_key = parsed.data.pub_key;
        self.pub_key_exp = parsed.data.pub_key_exp;
        self.anti_replay_rand = parsed.data.anti_replay_rand;
        Ok((parsed.data.is_login == 1, parsed.data.auth_server_info_list))
    }

    fn post_password(
        &mut self,
        input: &PasswordLoginInput,
        captcha: &str,
    ) -> AtrResult<PasswordResponse> {
        let body = self.password_payload(input, captcha)?;
        let url = self.base_url.join("/passport/v1/auth/psw")?;
        let resp = self
            .client
            .post(url_with_params(url, &self.shared_params())?)
            .header("User-Agent", &self.config.user_agent)
            .header("Content-Type", "application/json;charset=utf-8")
            .header("x-csrf-token", &self.csrf_token)
            .header("x-sdp-env", &self.env)
            .header("x-sdp-traceid", self.trace_id())
            .body(body)
            .send()?;
        self.capture_cookies(&resp)?;
        let response: PasswordResponse = serde_json::from_str(&resp.text()?)?;
        let captcha_challenge = response.data.graph_check_code_enable != 0;
        if response.code != 0 && !captcha_challenge {
            return Err(AtrError::Unauthorized(if response.message.is_empty() {
                format!("password authentication failed with code {}", response.code)
            } else {
                response.message.clone()
            }));
        }
        Ok(response)
    }

    fn password_payload(&self, input: &PasswordLoginInput, captcha: &str) -> AtrResult<String> {
        let key_bytes =
            hex::decode(&self.pub_key).map_err(|e| AtrError::CryptoFailed(e.to_string()))?;
        let n = BigUint::from_bytes_be(&key_bytes);
        let e = BigUint::from(
            self.pub_key_exp
                .parse::<u32>()
                .map_err(|e| AtrError::ParseFailed(e.to_string()))?,
        );
        let pub_key = RsaPublicKey::new(n, e)?;
        let msg = format!("{}_{}", input.password, self.anti_replay_rand);
        let cipher =
            pub_key.encrypt(&mut rsa::rand_core::OsRng, Pkcs1v15Encrypt, msg.as_bytes())?;
        let mut payload = json!({
            "username": format!("{}@{}", input.username, input.login_domain),
            "password": hex::encode(cipher),
            "rememberPwd": "0"
        });
        if !captcha.is_empty() {
            payload["graphCheckCode"] = json!(captcha);
        }
        Ok(payload.to_string())
    }

    fn send_sms(&mut self, input: &SmsLoginInput, captcha: &str) -> AtrResult<i32> {
        let mut url = self.base_url.join("/passport/v1/public/sendSms")?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in self.shared_params() {
                qp.append_pair(&k, &v);
            }
        }
        let mut payload = json!({
            "phone": format!("{}@{}", input.phone, input.login_domain),
            "graphCheckCode": captcha
        });
        if captcha.is_empty() {
            payload["graphCheckCode"] = json!("");
        }
        let resp = self
            .client
            .post(url)
            .header("User-Agent", &self.config.user_agent)
            .header("Content-Type", "application/json;charset=utf-8")
            .header("x-csrf-token", &self.csrf_token)
            .header("x-sdp-env", &self.env)
            .header("x-sdp-traceid", self.trace_id())
            .body(payload.to_string())
            .send()?;
        self.capture_cookies(&resp)?;
        let parsed: SmsResponse = serde_json::from_str(&resp.text()?)?;
        if parsed.code != 0 && parsed.code != 75_500_401 {
            return Err(AtrError::Unauthorized(format!(
                "sendSms failed: {}",
                parsed.message
            )));
        }
        Ok(parsed.data.graph_check_code_enable)
    }

    fn post_sms_verify(
        &mut self,
        phone: &str,
        login_domain: &str,
        code: &str,
        captcha: &str,
    ) -> AtrResult<SmsResponse> {
        let mut url = self.base_url.join("/passport/v1/auth/smsCheckCode")?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in self.shared_params() {
                qp.append_pair(&k, &v);
            }
        }
        let mut payload = json!({
            "code": code,
            "phone": format!("{}@{}", phone, login_domain)
        });
        if !captcha.is_empty() {
            payload["graphCheckCode"] = json!(captcha);
        }
        let resp = self
            .client
            .post(url)
            .header("User-Agent", &self.config.user_agent)
            .header("Content-Type", "application/json;charset=utf-8")
            .header("x-csrf-token", &self.csrf_token)
            .header("x-sdp-env", &self.env)
            .header("x-sdp-traceid", self.trace_id())
            .body(payload.to_string())
            .send()?;
        self.capture_cookies(&resp)?;
        Ok(serde_json::from_str(&resp.text()?)?)
    }

    fn log_phone_number(&mut self, auth_id: &str) {
        let result = (|| -> AtrResult<()> {
            let mut url = self.base_url.join("/passport/v1/public/phoneNumber")?;
            {
                let mut qp = url.query_pairs_mut();
                for (k, v) in self.shared_params() {
                    qp.append_pair(&k, &v);
                }
                if !auth_id.is_empty() {
                    qp.append_pair("authId", auth_id);
                }
            }
            let resp = self
                .client
                .get(url)
                .header("User-Agent", &self.config.user_agent)
                .header("x-csrf-token", &self.csrf_token)
                .header("x-sdp-traceid", self.trace_id())
                .send()?;
            self.capture_cookies(&resp)?;
            let value: Value = serde_json::from_str(&resp.text()?)?;
            let numbers = value
                .get("data")
                .and_then(|data| data.get("phoneNumber"))
                .and_then(|value| match value {
                    Value::Array(values) => {
                        Some(values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                    }
                    Value::String(value) if !value.is_empty() => Some(vec![value.as_str()]),
                    _ => None,
                })
                .unwrap_or_default();
            if !numbers.is_empty() {
                crate::diag_log(format!(
                    "[libreatrust][auth] available phone numbers: {}",
                    numbers.join(", ")
                ));
            }
            Ok(())
        })();
        if let Err(error) = result {
            crate::diag_log(format!(
                "[libreatrust][auth] phone number lookup skipped: {error}"
            ));
        }
    }

    fn trigger_password_sms_step(&mut self, step: &AuthStep) -> AtrResult<()> {
        let mut url = self.base_url.join("/passport/v1/auth/sms")?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in self.shared_params() {
                qp.append_pair(&k, &v);
            }
            qp.append_pair("action", "sendsms");
            if step.sms_mode == Some(SmsMode::WithAuthId) {
                qp.append_pair("isPrevEffect", "0");
                qp.append_pair("taskId", "");
                qp.append_pair("authId", &step.auth_id);
            }
        }
        let resp = self
            .client
            .get(url)
            .header("User-Agent", &self.config.user_agent)
            .header("x-csrf-token", &self.csrf_token)
            .header("x-sdp-traceid", self.trace_id())
            .send()?;
        self.capture_cookies(&resp)?;
        let body = resp.text()?;
        let parsed: SmsResponse = serde_json::from_str(&body)?;
        if parsed.code != 0 && parsed.code != 75_500_401 {
            return Err(AtrError::Unauthorized(format!(
                "authSms failed: {}",
                parsed.message
            )));
        }
        Ok(())
    }

    fn password_sms_check(
        &mut self,
        step: &AuthStep,
        code: &str,
        skip_secondary_auth: bool,
    ) -> AtrResult<AuthStep> {
        let mut url = self.base_url.join("/passport/v1/auth/sms")?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in self.shared_params() {
                qp.append_pair(&k, &v);
            }
            qp.append_pair("action", "checkcode");
        }
        let skip = if skip_secondary_auth { "1" } else { "0" };
        let resp = if step.sms_mode == Some(SmsMode::WithoutAuthId) {
            let payload = [("code", code), ("skipSecondaryAuth", skip)];
            self.client
                .post(url)
                .header("User-Agent", &self.config.user_agent)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("x-csrf-token", &self.csrf_token)
                .header("x-sdp-traceid", self.trace_id())
                .form(&payload)
                .send()?
        } else {
            let payload = json!({
                "isPrevEffect": false,
                "code": code,
                "skipSecondaryAuth": skip,
                "taskId": "",
                "authId": step.auth_id
            });
            self.client
                .post(url)
                .header("User-Agent", &self.config.user_agent)
                .header("Content-Type", "application/json;charset=utf-8")
                .header("x-csrf-token", &self.csrf_token)
                .header("x-sdp-traceid", self.trace_id())
                .body(payload.to_string())
                .send()?
        };
        self.capture_cookies(&resp)?;
        let parsed: AuthStepResponse = serde_json::from_str(&resp.text()?)?;
        if parsed.code != 0 {
            return Err(AtrError::Unauthorized(format!(
                "smsCheckCode failed: {} {}",
                parsed.code, parsed.message
            )));
        }
        Ok(auth_step_from_data(parsed.data))
    }

    fn send_custom_sms(&mut self) -> AtrResult<()> {
        let url = self.base_url.join("/passport/v1/auth/customSms")?;
        let mut params = self.shared_params();
        params.push(("action".into(), "sendcustomsms".into()));
        let url = url_with_params(url, &params)?;
        let payload = json!({
            "isPrevEffect": "0",
            "taskId": ""
        });
        let resp = self
            .client
            .post(url)
            .header("User-Agent", &self.config.user_agent)
            .header("Content-Type", "application/json;charset=utf-8")
            .header("x-csrf-token", &self.csrf_token)
            .header("x-sdp-traceid", self.trace_id())
            .body(payload.to_string())
            .send()?;
        self.capture_cookies(&resp)?;
        let parsed: CustomSmsResponse = serde_json::from_str(&resp.text()?)?;
        if parsed.code != 0 {
            return Err(AtrError::Unauthorized(format!(
                "sendCustomSMS failed: {} {}",
                parsed.code, parsed.message
            )));
        }
        crate::diag_log(format!(
            "[libreatrust][auth] custom SMS: {}",
            parsed.data.tips
        ));
        Ok(())
    }

    fn custom_sms_check_code(
        &mut self,
        code: &str,
        skip_secondary_auth: bool,
    ) -> AtrResult<AuthStep> {
        let url = self.base_url.join("/passport/v1/auth/customSms")?;
        let mut params = self.shared_params();
        params.push(("action".into(), "checkcustomcode".into()));
        let url = url_with_params(url, &params)?;
        let payload = json!({
            "isPrevEffect": false,
            "customCode": code,
            "skipSecondaryAuth": if skip_secondary_auth { "1" } else { "0" },
            "taskId": ""
        });
        let resp = self
            .client
            .post(url)
            .header("User-Agent", &self.config.user_agent)
            .header("Content-Type", "application/json;charset=utf-8")
            .header("x-csrf-token", &self.csrf_token)
            .header("x-sdp-traceid", self.trace_id())
            .body(payload.to_string())
            .send()?;
        self.capture_cookies(&resp)?;
        let parsed: AuthStepResponse = serde_json::from_str(&resp.text()?)?;
        if parsed.code != 0 {
            return Err(AtrError::Unauthorized(format!(
                "customSMSCheckCode failed: {} {}",
                parsed.code, parsed.message
            )));
        }
        Ok(auth_step_from_data(parsed.data))
    }

    fn auth_check(&mut self) -> AtrResult<AuthStep> {
        let mut url = self.base_url.join("/passport/v1/auth/authCheck")?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in self.shared_params() {
                qp.append_pair(&k, &v);
            }
        }
        let resp = self
            .client
            .get(url)
            .header("User-Agent", &self.config.user_agent)
            .header("x-csrf-token", &self.csrf_token)
            .header("x-sdp-traceid", self.trace_id())
            .send()?;
        self.capture_cookies(&resp)?;
        let parsed: AuthCheckResponse = serde_json::from_str(&resp.text()?)?;
        if parsed.code != 0 {
            return Err(AtrError::Unauthorized(format!(
                "authCheck failed: {} {}",
                parsed.code, parsed.message
            )));
        }
        Ok(auth_step_from_data(AuthStepData {
            next_service: parsed.data.next_service,
            next_service_list: parsed.data.next_service_list,
        }))
    }

    fn report_env(&mut self) -> AtrResult<()> {
        if self.ticket.is_empty() {
            return Err(AtrError::InvalidState("ticket is empty".into()));
        }
        let mut url = self.base_url.join("/controller/v1/public/reportEnv")?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in self.shared_params() {
                qp.append_pair(&k, &v);
            }
        }
        let payload = json!({
            "ticket": self.ticket,
            "deviceId": self.device_id,
            "env": {
                "endpoint": {
                    "device_id": self.device_id,
                    "device": { "type": "browser" }
                }
            }
        });
        let resp = self
            .client
            .post(url)
            .header("User-Agent", &self.config.user_agent)
            .header("Content-Type", "application/json;charset=utf-8")
            .header("x-csrf-token", &self.csrf_token)
            .header("x-sdp-traceid", self.trace_id())
            .body(payload.to_string())
            .send()?;
        self.capture_cookies(&resp)?;
        let parsed: CodeResponse = serde_json::from_str(&resp.text()?)?;
        if parsed.code != 0 {
            return Err(AtrError::Unauthorized(format!(
                "reportEnv failed: {}",
                parsed.message
            )));
        }
        Ok(())
    }

    fn online_info(&mut self) -> AtrResult<String> {
        let mut url = self.base_url.join("/passport/v1/user/onlineInfo")?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in self.shared_params() {
                qp.append_pair(&k, &v);
            }
        }
        let resp = self
            .client
            .get(url)
            .header("User-Agent", &self.config.user_agent)
            .header("x-csrf-token", &self.csrf_token)
            .header("x-sdp-traceid", self.trace_id())
            .send()?;
        self.capture_cookies(&resp)?;
        let parsed: OnlineInfoResponse = serde_json::from_str(&resp.text()?)?;
        Ok(parsed.data.username)
    }

    fn fetch_captcha(&mut self) -> AtrResult<Vec<u8>> {
        let mut url = self.base_url.join("/passport/v1/public/checkCode")?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in self.shared_params() {
                qp.append_pair(&k, &v);
            }
            qp.append_pair("rnd", &self.millis().to_string());
        }
        let mut resp = self
            .client
            .get(url)
            .header("User-Agent", &self.config.user_agent)
            .header("Accept", "image/webp,image/apng,image/*,*/*;q=0.8")
            .send()?;
        self.capture_cookies(&resp)?;
        let mut buf = Vec::new();
        resp.copy_to(&mut buf)?;
        Ok(buf)
    }

    fn capture_cookies(&mut self, response: &Response) -> AtrResult<()> {
        for value in response.headers().get_all(SET_COOKIE).iter() {
            if let Ok(cookie) = parse_set_cookie(value, &self.base_host) {
                self.install_cookie(&cookie);
                self.cookies.insert(cookie.name.clone(), cookie);
            }
        }
        Ok(())
    }

    fn install_cookie(&self, cookie: &CookieRecord) {
        let host = if cookie.host.is_empty() {
            &self.base_host
        } else {
            &cookie.host
        };
        let scheme = if cookie.scheme.is_empty() {
            "https"
        } else {
            &cookie.scheme
        };
        let Ok(url) = Url::parse(&format!("{scheme}://{host}")) else {
            return;
        };
        self.cookie_jar
            .add_cookie_str(&format!("{}={}", cookie.name, cookie.value), &url);
    }

    fn collect_cookies(&self) -> Vec<CookieRecord> {
        self.cookies.values().cloned().collect()
    }

    fn sync_sid_from_cookies(&mut self) {
        if let Some(cookie) = self.cookies.get("sid") {
            self.sid = cookie.value.clone();
        }
    }

    fn extract_ticket_from_callback(&mut self, callback: &Url) -> AtrResult<String> {
        let response = self
            .client
            .get(callback.clone())
            .header("User-Agent", &self.config.user_agent)
            .header("x-csrf-token", &self.csrf_token)
            .header("x-sdp-traceid", self.trace_id())
            .send()?;
        self.capture_cookies(&response)?;
        if response.status().is_redirection() {
            if let Some(location) = response.headers().get("Location") {
                let location = location.to_str().unwrap_or_default();
                if let Some(ticket) = self.extract_ticket_from_redirect(location)? {
                    return Ok(ticket);
                }
            }
        }
        let ticket = callback
            .query_pairs()
            .find(|(k, _)| k == "ticket")
            .map(|(_, v)| v.to_string())
            .ok_or_else(|| AtrError::ParseFailed("ticket missing".into()))?;
        Ok(ticket)
    }

    fn extract_ticket_from_redirect(&self, location: &str) -> AtrResult<Option<String>> {
        let url = Url::parse(location)?;
        if let Some(ticket) = url
            .query_pairs()
            .find(|(k, _)| k == "ticket")
            .map(|(_, v)| v.to_string())
        {
            return Ok(Some(ticket));
        }
        if let Some(data) = url
            .query_pairs()
            .find(|(k, _)| k == "data")
            .map(|(_, v)| v.to_string())
        {
            let payload: serde_json::Value = serde_json::from_str(&data)?;
            if let Some(ticket) = payload.get("ticket").and_then(|v| v.as_str()) {
                return Ok(Some(ticket.to_string()));
            }
        }
        Ok(None)
    }

    fn shared_params(&self) -> Vec<(String, String)> {
        vec![
            ("clientType".into(), self.config.client_type.clone()),
            ("platform".into(), self.config.platform.clone()),
            ("lang".into(), "en-US".into()),
        ]
    }

    fn build_env(&self, device_id: &str) -> String {
        let payload = json!({ "deviceId": device_id }).to_string();
        base64::engine::general_purpose::STANDARD.encode(payload.as_bytes())
    }

    fn build_connection_id(&self, device_id: &str) -> String {
        let digest = md5::compute(device_id.as_bytes());
        format!("{:X}-{}", digest, self.micros())
    }

    fn base64_rid(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.base_host.as_bytes())
    }

    fn trace_id(&self) -> String {
        format!("{:x}", self.millis())
    }

    fn millis(&self) -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    }

    fn micros(&self) -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros()
    }
}

fn parse_set_cookie(value: &HeaderValue, host: &str) -> AtrResult<CookieRecord> {
    let raw = value
        .to_str()
        .map_err(|e| AtrError::ParseFailed(e.to_string()))?;
    let first = raw
        .split(';')
        .next()
        .ok_or_else(|| AtrError::ParseFailed("set-cookie missing cookie pair".into()))?;
    let (name, value) = first
        .split_once('=')
        .ok_or_else(|| AtrError::ParseFailed("invalid set-cookie".into()))?;
    Ok(CookieRecord {
        host: host.to_string(),
        scheme: "https".into(),
        name: name.trim().to_string(),
        value: value.trim().to_string(),
    })
}

fn url_with_params(mut url: Url, params: &[(String, String)]) -> AtrResult<Url> {
    {
        let mut qp = url.query_pairs_mut();
        for (k, v) in params {
            qp.append_pair(k, v);
        }
    }
    Ok(url)
}

fn validate_client_resource_response(status: StatusCode, body: &[u8]) -> AtrResult<()> {
    if !status.is_success() {
        let detail = short_response_body(body);
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(AtrError::Unauthorized(format!(
                "clientResource http status {}: {detail}",
                status.as_u16()
            )));
        }
        return Err(AtrError::NetworkFailed(format!(
            "clientResource http status {}: {detail}",
            status.as_u16()
        )));
    }

    let Ok(payload) = serde_json::from_slice::<Value>(body) else {
        return Ok(());
    };
    if payload.get("data").is_some() {
        return Ok(());
    }

    let code = json_i64(&payload, &["code", "Code", "errCode", "errorCode"]);
    let message = json_str(
        &payload,
        &["message", "Message", "msg", "error", "errorMessage"],
    )
    .unwrap_or("empty error message");
    if let Some(code) = code {
        if code != 0 {
            return Err(AtrError::Unauthorized(format!(
                "clientResource failed: code {code}: {message}"
            )));
        }
    } else if payload.get("success").and_then(Value::as_bool) == Some(false) {
        return Err(AtrError::Unauthorized(format!(
            "clientResource failed: {message}"
        )));
    }

    Ok(())
}

fn json_i64(payload: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| {
        payload
            .get(*key)
            .and_then(|value| value.as_i64().or_else(|| value.as_str()?.parse().ok()))
    })
}

fn json_str<'a>(payload: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_str))
}

fn short_response_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body).replace(['\r', '\n', '\t'], " ");
    let text = text.trim();
    if text.is_empty() {
        return "<empty body>".into();
    }
    const MAX_LEN: usize = 512;
    if text.chars().count() <= MAX_LEN {
        return text.to_string();
    }
    format!("{}...", text.chars().take(MAX_LEN).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::{AuthIdItem, AuthStepData, PasswordResponse, SmsMode, auth_step_from_data};

    #[test]
    fn password_captcha_response_allows_missing_ticket() {
        let response: PasswordResponse = serde_json::from_str(
            r#"{"code":1,"message":"captcha required","data":{"graphCheckCodeEnable":1}}"#,
        )
        .expect("captcha response should parse before a ticket is issued");

        assert_eq!(response.code, 1);
        assert_eq!(response.message, "captcha required");
        assert_eq!(response.data.graph_check_code_enable, 1);
        assert!(response.data.ticket.is_empty());
    }

    #[test]
    fn maps_auth_steps_and_sms_modes() {
        let with_id = auth_step_from_data(AuthStepData {
            next_service: String::new(),
            next_service_list: vec![AuthIdItem {
                auth_id: "auth-1".into(),
                auth_type: "auth/sms".into(),
            }],
        });
        assert_eq!(with_id.service, "auth/sms");
        assert_eq!(with_id.auth_id, "auth-1");
        assert_eq!(with_id.sms_mode, Some(SmsMode::WithAuthId));

        let without_id = auth_step_from_data(AuthStepData {
            next_service: "auth/sms".into(),
            next_service_list: Vec::new(),
        });
        assert_eq!(without_id.sms_mode, Some(SmsMode::WithoutAuthId));

        let custom = auth_step_from_data(AuthStepData {
            next_service: "auth/customSms".into(),
            next_service_list: Vec::new(),
        });
        assert_eq!(custom.sms_mode, Some(SmsMode::Custom));
    }
}

fn random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; (len + 1) / 2];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let hex = hex::encode(bytes);
    hex[..len].to_string()
}
