use crate::store::Platform;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum PushError {
    NotConfigured,
    Config(String),
    Upstream(String),
}

/// Optional metadata included in VoIP pushes so PushKit can report the call
/// to CallKit immediately without waiting for the app to poll.
#[derive(Debug, Default)]
pub struct VoipPayload<'a> {
    pub caller: &'a str,
    pub is_video: bool,
    pub call_id: &'a str,
}

pub trait Pusher: Send + Sync {
    fn send(&self, platform: Platform, token: &str) -> Result<(), PushError>;
    /// Send a PushKit VoIP push (iOS only). Returns `NotConfigured` by default
    /// so implementations that don't support it degrade gracefully.
    fn send_voip(&self, token: &str, payload: &VoipPayload<'_>) -> Result<(), PushError> {
        let _ = (token, payload);
        Err(PushError::NotConfigured)
    }
}

pub struct NoopPusher;

impl Pusher for NoopPusher {
    fn send(&self, _platform: Platform, _token: &str) -> Result<(), PushError> {
        Err(PushError::NotConfigured)
    }
}

#[derive(Clone)]
pub struct ApnsConfig {
    pub key_pem: String,
    pub key_id: String,
    pub team_id: String,
    pub topic: String,
    /// APNs topic for PushKit VoIP pushes. Defaults to `{topic}.voip`.
    /// Override with `APNS_VOIP_TOPIC` env var if needed.
    pub voip_topic: String,
    pub sandbox: bool,
}

impl ApnsConfig {
    pub fn from_env() -> Result<Option<Self>, PushError> {
        let path = env_opt("APNS_KEY_PATH");
        if path.is_empty() {
            return Ok(None);
        }
        let key_pem = fs::read_to_string(&path).map_err(|e| PushError::Config(e.to_string()))?;
        let key_id = env_req("APNS_KEY_ID")?;
        let team_id = env_req("APNS_TEAM_ID")?;
        let topic = env_opt("APNS_TOPIC");
        let topic = if topic.is_empty() {
            "com.julienlhk.horus".into()
        } else {
            topic
        };
        let voip_topic = env_opt("APNS_VOIP_TOPIC");
        let voip_topic = if voip_topic.is_empty() {
            format!("{topic}.voip")
        } else {
            voip_topic
        };
        let sandbox = env_opt("APNS_SANDBOX").eq_ignore_ascii_case("true");
        Ok(Some(Self {
            key_pem,
            key_id,
            team_id,
            topic,
            voip_topic,
            sandbox,
        }))
    }
}

#[derive(Clone)]
pub struct FcmConfig {
    pub project_id: String,
    pub client_email: String,
    pub private_key: String,
    pub token_uri: String,
}

impl FcmConfig {
    pub fn from_env() -> Result<Option<Self>, PushError> {
        let path = env_opt("FCM_SERVICE_ACCOUNT_JSON");
        if path.is_empty() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path).map_err(|e| PushError::Config(e.to_string()))?;
        let sa: ServiceAccount = serde_json::from_str(&raw)
            .map_err(|e| PushError::Config(format!("fcm json: {e}")))?;
        let project_id = {
            let from_env = env_opt("FCM_PROJECT_ID");
            if from_env.is_empty() {
                sa.project_id
            } else {
                from_env
            }
        };
        Ok(Some(Self {
            project_id,
            client_email: sa.client_email,
            private_key: sa.private_key,
            token_uri: if sa.token_uri.is_empty() {
                "https://oauth2.googleapis.com/token".into()
            } else {
                sa.token_uri
            },
        }))
    }
}

#[derive(Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
    #[serde(default)]
    token_uri: String,
}

pub struct HttpPusher {
    client: reqwest::blocking::Client,
    apns: Option<ApnsConfig>,
    fcm: Option<FcmConfig>,
    apns_jwt: Mutex<Option<CachedToken>>,
    fcm_oauth: Mutex<Option<CachedToken>>,
}

struct CachedToken {
    value: String,
    exp: u64,
}

impl HttpPusher {
    pub fn new(apns: Option<ApnsConfig>, fcm: Option<FcmConfig>) -> Result<Self, PushError> {
        let client = reqwest::blocking::Client::builder()
            .http2_prior_knowledge()
            .use_rustls_tls()
            .build()
            .map_err(|e| PushError::Config(e.to_string()))?;
        // FCM OAuth is HTTP/1.1; a second client without prior knowledge is used there.
        drop(client);
        let client = reqwest::blocking::Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(|e| PushError::Config(e.to_string()))?;
        Ok(Self {
            client,
            apns,
            fcm,
            apns_jwt: Mutex::new(None),
            fcm_oauth: Mutex::new(None),
        })
    }

    fn apns_jwt(&self, cfg: &ApnsConfig) -> Result<String, PushError> {
        let now = unix_now();
        {
            let cache = self.apns_jwt.lock().expect("jwt");
            if let Some(c) = cache.as_ref() {
                if c.exp > now + 60 {
                    return Ok(c.value.clone());
                }
            }
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(cfg.key_id.clone());
        header.typ = Some("JWT".into());
        #[derive(Serialize)]
        struct Claims {
            iss: String,
            iat: u64,
        }
        let claims = Claims {
            iss: cfg.team_id.clone(),
            iat: now,
        };
        let key = EncodingKey::from_ec_pem(cfg.key_pem.as_bytes())
            .map_err(|e| PushError::Config(format!("apns pem: {e}")))?;
        let jwt = encode(&header, &claims, &key)
            .map_err(|e| PushError::Config(format!("apns jwt: {e}")))?;
        *self.apns_jwt.lock().expect("jwt") = Some(CachedToken {
            value: jwt.clone(),
            exp: now + 50 * 60,
        });
        Ok(jwt)
    }

    fn send_voip_apns(&self, token: &str, payload: &VoipPayload<'_>) -> Result<(), PushError> {
        let cfg = self.apns.as_ref().ok_or(PushError::NotConfigured)?;
        let jwt = self.apns_jwt(cfg)?;
        // VoIP push payload — no `aps` key; custom keys are delivered verbatim
        // to the PKPushRegistryDelegate on the device.
        let body = serde_json::json!({
            "caller":   if payload.caller.is_empty() { "Incoming call" } else { payload.caller },
            "is_video": payload.is_video,
            "call_id":  if payload.call_id.is_empty() { "unknown" } else { payload.call_id }
        });
        let hosts = if cfg.sandbox {
            ["https://api.sandbox.push.apple.com", "https://api.push.apple.com"]
        } else {
            ["https://api.push.apple.com", "https://api.sandbox.push.apple.com"]
        };
        let mut last = PushError::Upstream("apns-voip".into());
        for host in hosts {
            let url = format!("{host}/3/device/{token}");
            let resp = self
                .client
                .post(&url)
                .bearer_auth(&jwt)
                .header("apns-topic", &cfg.voip_topic)
                .header("apns-push-type", "voip")
                .header("apns-priority", "10")
                .json(&body)
                .send();
            match resp {
                Ok(r) if r.status().is_success() => return Ok(()),
                Ok(r) => {
                    let code = r.status().as_u16();
                    let text = r.text().unwrap_or_default();
                    if code == 400 && text.contains("BadDeviceToken") {
                        last = PushError::Upstream(format!("apns-voip {code}"));
                        continue;
                    }
                    return Err(PushError::Upstream(format!("apns-voip {code}")));
                }
                Err(e) => last = PushError::Upstream(e.to_string()),
            }
        }
        Err(last)
    }

    fn send_apns(&self, token: &str) -> Result<(), PushError> {
        let cfg = self.apns.as_ref().ok_or(PushError::NotConfigured)?;
        let jwt = self.apns_jwt(cfg)?;
        let body = serde_json::json!({
            "aps": {
                "content-available": 1
            }
        });
        let hosts = if cfg.sandbox {
            [
                "https://api.sandbox.push.apple.com",
                "https://api.push.apple.com",
            ]
        } else {
            [
                "https://api.push.apple.com",
                "https://api.sandbox.push.apple.com",
            ]
        };
        let mut last = PushError::Upstream("apns".into());
        for host in hosts {
            let url = format!("{host}/3/device/{token}");
            let resp = self
                .client
                .post(&url)
                .bearer_auth(&jwt)
                .header("apns-topic", &cfg.topic)
                .header("apns-push-type", "background")
                .header("apns-priority", "5")
                .json(&body)
                .send();
            match resp {
                Ok(r) if r.status().is_success() => return Ok(()),
                Ok(r) => {
                    let code = r.status().as_u16();
                    let text = r.text().unwrap_or_default();
                    if code == 400 && text.contains("BadDeviceToken") {
                        last = PushError::Upstream(format!("apns {code}"));
                        continue;
                    }
                    return Err(PushError::Upstream(format!("apns {code}")));
                }
                Err(e) => last = PushError::Upstream(e.to_string()),
            }
        }
        Err(last)
    }

    fn fcm_access_token(&self, cfg: &FcmConfig) -> Result<String, PushError> {
        let now = unix_now();
        {
            let cache = self.fcm_oauth.lock().expect("oauth");
            if let Some(c) = cache.as_ref() {
                if c.exp > now + 60 {
                    return Ok(c.value.clone());
                }
            }
        }
        #[derive(Serialize)]
        struct Claims {
            iss: String,
            scope: String,
            aud: String,
            iat: u64,
            exp: u64,
        }
        let claims = Claims {
            iss: cfg.client_email.clone(),
            scope: "https://www.googleapis.com/auth/firebase.messaging".into(),
            aud: cfg.token_uri.clone(),
            iat: now,
            exp: now + 3600,
        };
        let key = EncodingKey::from_rsa_pem(cfg.private_key.as_bytes())
            .map_err(|e| PushError::Config(format!("fcm pem: {e}")))?;
        let jwt = encode(&Header::new(Algorithm::RS256), &claims, &key)
            .map_err(|e| PushError::Config(format!("fcm jwt: {e}")))?;
        let form = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", jwt.as_str()),
        ];
        let resp = self
            .client
            .post(&cfg.token_uri)
            .form(&form)
            .send()
            .map_err(|e| PushError::Upstream(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(PushError::Upstream(format!(
                "fcm oauth {}",
                resp.status().as_u16()
            )));
        }
        #[derive(Deserialize)]
        struct Tok {
            access_token: String,
            #[serde(default)]
            expires_in: u64,
        }
        let tok: Tok = resp
            .json()
            .map_err(|e| PushError::Upstream(e.to_string()))?;
        let exp = now + tok.expires_in.max(60).min(3600);
        *self.fcm_oauth.lock().expect("oauth") = Some(CachedToken {
            value: tok.access_token.clone(),
            exp,
        });
        Ok(tok.access_token)
    }

    fn send_fcm(&self, token: &str) -> Result<(), PushError> {
        let cfg = self.fcm.as_ref().ok_or(PushError::NotConfigured)?;
        let access = self.fcm_access_token(cfg)?;
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            cfg.project_id
        );
        let body = serde_json::json!({
            "message": {
                "token": token,
                "android": { "priority": "high" },
                "data": { "t": "1" }
            }
        });
        let resp = self
            .client
            .post(url)
            .bearer_auth(access)
            .json(&body)
            .send()
            .map_err(|e| PushError::Upstream(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(PushError::Upstream(format!(
                "fcm {}",
                resp.status().as_u16()
            )))
        }
    }
}

impl Pusher for HttpPusher {
    fn send(&self, platform: Platform, token: &str) -> Result<(), PushError> {
        match platform {
            Platform::Ios => self.send_apns(token),
            Platform::Android => self.send_fcm(token),
        }
    }

    fn send_voip(&self, token: &str, payload: &VoipPayload<'_>) -> Result<(), PushError> {
        self.send_voip_apns(token, payload)
    }
}

fn env_opt(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

fn env_req(key: &str) -> Result<String, PushError> {
    let v = env_opt(key);
    if v.is_empty() {
        Err(PushError::Config(format!("missing {key}")))
    } else {
        Ok(v)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
