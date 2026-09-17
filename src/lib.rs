//! Content-free wake relay: `wake_id` → APNs/FCM token. No message bodies.

mod auth;
mod push;
mod rate;
mod store;

pub use push::{ApnsConfig, FcmConfig, HttpPusher, NoopPusher, PushError, Pusher, VoipPayload};
pub use rate::RateLimiter;
pub use store::{Platform, TokenRow, TokenStore};

use auth::{decode_b64url, hash_key, verify_register_hmac, verify_wake_hmac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_WAKE_PER_HOUR: u32 = 30;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<TokenStore>>,
    pub rate: Arc<Mutex<RateLimiter>>,
    pub pusher: Arc<dyn Pusher>,
}

#[derive(Debug, Deserialize)]
pub struct AuthBootstrap {
    pub v: u32,
    pub key: String,
    #[serde(default)]
    pub wake_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterBody {
    pub wake_id: String,
    pub platform: String,
    pub token: String,
    #[serde(default)]
    pub auth: Option<AuthBootstrap>,
}

#[derive(Debug, Deserialize)]
pub struct WakeBody {
    pub wake_id: String,
}

#[derive(Debug, Deserialize)]
pub struct WakeCallBody {
    pub wake_id: String,
    #[serde(default)]
    pub caller: String,
    #[serde(default)]
    pub is_video: bool,
    #[serde(default)]
    pub call_id: String,
}

#[derive(Debug, Deserialize)]
pub struct VoipRegisterBody {
    pub wake_id: String,
    pub voip_token: String,
    #[serde(default)]
    pub auth: Option<AuthBootstrap>,
}

#[derive(Debug, Deserialize)]
pub struct UnregisterBody {
    pub wake_id: String,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub code: u16,
    pub body: String,
}

impl HttpResponse {
    fn json(code: u16, body: &str) -> Self {
        Self {
            code,
            body: body.to_string(),
        }
    }
}

pub fn validate_wake_id(id: &str) -> bool {
    let id = id.trim();
    if id.len() < 32 || id.len() > 86 {
        return false;
    }
    id.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn validate_token(token: &str) -> bool {
    let t = token.trim();
    if t.len() < 16 || t.len() > 4096 {
        return false;
    }
    !t.chars().any(|c| c.is_whitespace() || c.is_control())
}

pub fn parse_platform(raw: &str) -> Option<Platform> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "ios" => Some(Platform::Ios),
        "android" => Some(Platform::Android),
        _ => None,
    }
}

/// First 8 hex chars of SHA-256 — safe for logs (not the capability).
pub fn wake_log_id(wake_id: &str) -> String {
    let digest = Sha256::digest(wake_id.as_bytes());
    hex_encode(&digest[..4])
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub fn handle(
    state: &AppState,
    method: &str,
    path: &str,
    body: &str,
    auth_header: Option<&str>,
    wake_auth_header: Option<&str>,
) -> HttpResponse {
    match (method, path) {
        ("GET", "/health") => HttpResponse::json(200, "{\"ok\":true}"),
        ("POST", "/register") => register(state, body, auth_header),
        ("POST", "/register-voip") => register_voip(state, body, auth_header),
        ("DELETE", "/register") => unregister(state, body, auth_header),
        ("POST", "/wake") => wake(state, body, wake_auth_header),
        ("POST", "/wake-call") => wake_call(state, body, wake_auth_header),
        _ => HttpResponse::json(404, "{\"error\":\"not found\"}"),
    }
}

fn require_auth_new() -> bool {
    std::env::var("HORUS_WAKE_REQUIRE_AUTH")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn register(state: &AppState, body: &str, _auth_header: Option<&str>) -> HttpResponse {
    let parsed: RegisterBody = match serde_json::from_str(body.trim()) {
        Ok(v) => v,
        Err(_) => return HttpResponse::json(400, "{\"error\":\"bad json\"}"),
    };
    if !validate_wake_id(&parsed.wake_id) {
        return HttpResponse::json(400, "{\"error\":\"bad wake_id\"}");
    }
    if !validate_token(&parsed.token) {
        return HttpResponse::json(400, "{\"error\":\"bad token\"}");
    }
    let Some(platform) = parse_platform(&parsed.platform) else {
        return HttpResponse::json(400, "{\"error\":\"bad platform\"}");
    };
    let wake_id = parsed.wake_id.trim();
    let token = parsed.token.trim();
    let mut store = state.store.lock().expect("store");
    let existing_auth = store.get_auth(wake_id).ok().flatten();

    if let Some(auth) = &parsed.auth {
        if auth.v != 1 {
            return HttpResponse::json(400, "{\"error\":\"bad auth version\"}");
        }
        let Some(key) = decode_b64url(&auth.key) else {
            return HttpResponse::json(400, "{\"error\":\"bad auth key\"}");
        };
        if key.len() < 16 {
            return HttpResponse::json(400, "{\"error\":\"bad auth key\"}");
        }
        let rh = hash_key(&key);
        if let Some(existing) = existing_auth.as_ref().and_then(|a| a.register_key_hash) {
            if existing != rh {
                return HttpResponse::json(401, "{\"error\":\"unauthorized\"}");
            }
        }
        let ws = if auth.wake_secret.is_empty() {
            None
        } else {
            decode_b64url(&auth.wake_secret).and_then(|b| {
                if b.len() != 32 {
                    return None;
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                Some(a)
            })
        };
        match store.upsert_auth(wake_id, platform, token, Some(rh), ws) {
            Ok(()) => {
                eprintln!("register {} platform={}", wake_log_id(wake_id), platform.as_str());
                HttpResponse::json(200, "{\"ok\":true}")
            }
            Err(_) => HttpResponse::json(500, "{\"error\":\"store\"}"),
        }
    } else if existing_auth
        .as_ref()
        .and_then(|a| a.register_key_hash)
        .is_some()
    {
        HttpResponse::json(401, "{\"error\":\"unauthorized\"}")
    } else if require_auth_new() && existing_auth.is_none() {
        HttpResponse::json(401, "{\"error\":\"auth required\"}")
    } else {
        match store.upsert(wake_id, platform, token) {
            Ok(()) => {
                eprintln!("register {} platform={}", wake_log_id(wake_id), platform.as_str());
                HttpResponse::json(200, "{\"ok\":true}")
            }
            Err(_) => HttpResponse::json(500, "{\"error\":\"store\"}"),
        }
    }
}

fn unregister(state: &AppState, body: &str, _auth_header: Option<&str>) -> HttpResponse {
    let parsed: UnregisterBody = match serde_json::from_str(body.trim()) {
        Ok(v) => v,
        Err(_) => return HttpResponse::json(400, "{\"error\":\"bad json\"}"),
    };
    if !validate_wake_id(&parsed.wake_id) || !validate_token(&parsed.token) {
        return HttpResponse::json(400, "{\"error\":\"bad request\"}");
    }
    let mut store = state.store.lock().expect("store");
    match store.delete_if_token(&parsed.wake_id, parsed.token.trim()) {
        Ok(true) => {
            eprintln!("unregister {}", wake_log_id(&parsed.wake_id));
            HttpResponse::json(200, "{\"ok\":true}")
        }
        Ok(false) => HttpResponse::json(404, "{\"error\":\"not found\"}"),
        Err(_) => HttpResponse::json(500, "{\"error\":\"store\"}"),
    }
}

fn wake(state: &AppState, body: &str, wake_auth_header: Option<&str>) -> HttpResponse {
    let parsed: WakeBody = match serde_json::from_str(body.trim()) {
        Ok(v) => v,
        Err(_) => return HttpResponse::json(400, "{\"error\":\"bad json\"}"),
    };
    if !validate_wake_id(&parsed.wake_id) {
        return HttpResponse::json(400, "{\"error\":\"bad wake_id\"}");
    }
    {
        let mut rate = state.rate.lock().expect("rate");
        if rate.check(&parsed.wake_id).is_err() {
            eprintln!("wake {} 429", wake_log_id(&parsed.wake_id));
            return HttpResponse::json(429, "{\"error\":\"rate limited\"}");
        }
    }
    let row = {
        let store = state.store.lock().expect("store");
        if let Ok(Some(auth)) = store.get_auth(&parsed.wake_id) {
            if let Some(secret) = auth.wake_secret {
                let Some(hdr) = wake_auth_header else {
                    return HttpResponse::json(401, "{\"error\":\"wake auth required\"}");
                };
                if !verify_wake_hmac(&secret, &parsed.wake_id, "POST", "/wake", body, hdr) {
                    return HttpResponse::json(401, "{\"error\":\"unauthorized\"}");
                }
            }
        }
        match store.get(&parsed.wake_id) {
            Ok(Some(row)) => row,
            Ok(None) => {
                eprintln!("wake {} 404", wake_log_id(&parsed.wake_id));
                return HttpResponse::json(404, "{\"error\":\"unknown\"}");
            }
            Err(_) => return HttpResponse::json(500, "{\"error\":\"store\"}"),
        }
    };
    match state.pusher.send(row.platform, &row.token) {
        Ok(()) => {
            eprintln!(
                "wake {} platform={} 200",
                wake_log_id(&parsed.wake_id),
                row.platform.as_str()
            );
            HttpResponse::json(200, "{\"ok\":true}")
        }
        Err(PushError::NotConfigured) => HttpResponse::json(501, "{\"error\":\"push not configured\"}"),
        Err(_) => HttpResponse::json(502, "{\"error\":\"push failed\"}"),
    }
}

/// Register a PushKit VoIP push token for an existing wake_id.
/// The regular /register call must happen first so that platform is known.
/// Protected rows (register_key_hash set) require the same register key + HMAC.
fn register_voip(state: &AppState, body: &str, auth_header: Option<&str>) -> HttpResponse {
    let parsed: VoipRegisterBody = match serde_json::from_str(body.trim()) {
        Ok(v) => v,
        Err(_) => return HttpResponse::json(400, "{\"error\":\"bad json\"}"),
    };
    if !validate_wake_id(&parsed.wake_id) {
        return HttpResponse::json(400, "{\"error\":\"bad wake_id\"}");
    }
    if !validate_token(&parsed.voip_token) {
        return HttpResponse::json(400, "{\"error\":\"bad voip_token\"}");
    }
    let mut store = state.store.lock().expect("store");
    let existing_auth = store.get_auth(&parsed.wake_id).ok().flatten();
    if existing_auth.is_none() {
        return HttpResponse::json(404, "{\"error\":\"wake_id unknown — register first\"}");
    }
    if let Some(hash) = existing_auth.as_ref().and_then(|a| a.register_key_hash) {
        let Some(auth) = &parsed.auth else {
            return HttpResponse::json(401, "{\"error\":\"unauthorized\"}");
        };
        let Some(key) = decode_b64url(&auth.key) else {
            return HttpResponse::json(400, "{\"error\":\"bad auth key\"}");
        };
        if hash_key(&key) != hash {
            return HttpResponse::json(401, "{\"error\":\"unauthorized\"}");
        }
        let Some(hdr) = auth_header else {
            return HttpResponse::json(401, "{\"error\":\"auth required\"}");
        };
        if !verify_register_hmac(&key, &parsed.wake_id, "POST", "/register-voip", body, hdr) {
            return HttpResponse::json(401, "{\"error\":\"unauthorized\"}");
        }
    }
    match store.upsert_voip(&parsed.wake_id, parsed.voip_token.trim()) {
        Ok(true) => {
            eprintln!("register-voip {}", wake_log_id(&parsed.wake_id));
            HttpResponse::json(200, "{\"ok\":true}")
        }
        Ok(false) => HttpResponse::json(404, "{\"error\":\"wake_id unknown — register first\"}"),
        Err(_) => HttpResponse::json(500, "{\"error\":\"store\"}"),
    }
}

/// Send a VoIP-type APNs push to wake a killed iOS app for an incoming call.
/// Falls back to a regular alert push if no VoIP token is stored.
fn wake_call(state: &AppState, body: &str, wake_auth_header: Option<&str>) -> HttpResponse {
    let parsed: WakeCallBody = match serde_json::from_str(body.trim()) {
        Ok(v) => v,
        Err(_) => return HttpResponse::json(400, "{\"error\":\"bad json\"}"),
    };
    if !validate_wake_id(&parsed.wake_id) {
        return HttpResponse::json(400, "{\"error\":\"bad wake_id\"}");
    }
    {
        let mut rate = state.rate.lock().expect("rate");
        if rate.check(&parsed.wake_id).is_err() {
            eprintln!("wake-call {} 429", wake_log_id(&parsed.wake_id));
            return HttpResponse::json(429, "{\"error\":\"rate limited\"}");
        }
    }
    let row = {
        let store = state.store.lock().expect("store");
        if let Ok(Some(auth)) = store.get_auth(&parsed.wake_id) {
            if let Some(secret) = auth.wake_secret {
                let Some(hdr) = wake_auth_header else {
                    return HttpResponse::json(401, "{\"error\":\"wake auth required\"}");
                };
                if !verify_wake_hmac(&secret, &parsed.wake_id, "POST", "/wake-call", body, hdr) {
                    return HttpResponse::json(401, "{\"error\":\"unauthorized\"}");
                }
            }
        }
        match store.get(&parsed.wake_id) {
            Ok(Some(row)) => row,
            Ok(None) => {
                eprintln!("wake-call {} 404", wake_log_id(&parsed.wake_id));
                return HttpResponse::json(404, "{\"error\":\"unknown\"}");
            }
            Err(_) => return HttpResponse::json(500, "{\"error\":\"store\"}"),
        }
    };
    let payload = VoipPayload {
        caller: &parsed.caller,
        is_video: parsed.is_video,
        call_id: &parsed.call_id,
    };
    // Prefer VoIP push (wakes killed app via PushKit + CallKit native UI).
    // Fall back to regular alert push if no VoIP token is stored yet.
    if let Some(ref voip_token) = row.voip_token {
        match state.pusher.send_voip(voip_token, &payload) {
            Ok(()) => {
                eprintln!("wake-call {} voip 200", wake_log_id(&parsed.wake_id));
                return HttpResponse::json(200, "{\"ok\":true,\"via\":\"voip\"}");
            }
            Err(PushError::NotConfigured) => {
                // APNs not configured — fall through to alert push
            }
            Err(_) => {
                // VoIP push failed — fall through to alert push as best-effort
                eprintln!("wake-call {} voip failed, fallback", wake_log_id(&parsed.wake_id));
            }
        }
    }
    // Alert push fallback (works for foreground/background; cannot wake killed app).
    match state.pusher.send(row.platform, &row.token) {
        Ok(()) => {
            eprintln!("wake-call {} alert 200", wake_log_id(&parsed.wake_id));
            HttpResponse::json(200, "{\"ok\":true,\"via\":\"alert\"}")
        }
        Err(PushError::NotConfigured) => HttpResponse::json(501, "{\"error\":\"push not configured\"}"),
        Err(_) => HttpResponse::json(502, "{\"error\":\"push failed\"}"),
    }
}

pub fn default_rate_limiter() -> RateLimiter {
    RateLimiter::new(Duration::from_secs(60 * 60), DEFAULT_WAKE_PER_HOUR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct RecPusher {
        calls: Mutex<Vec<(Platform, String)>>,
        fail: bool,
    }

    impl Pusher for RecPusher {
        fn send(&self, platform: Platform, token: &str) -> Result<(), PushError> {
            if self.fail {
                return Err(PushError::Upstream("no".into()));
            }
            self.calls
                .lock()
                .unwrap()
                .push((platform, token.to_string()));
            Ok(())
        }
    }

    fn state(pusher: RecPusher) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.sqlite");
        let store = TokenStore::open(db.to_str().unwrap()).unwrap();
        let app = AppState {
            store: Arc::new(Mutex::new(store)),
            rate: Arc::new(Mutex::new(RateLimiter::new(Duration::from_secs(3600), 2))),
            pusher: Arc::new(pusher),
        };
        (app, dir)
    }

    #[test]
    fn wake_id_rules() {
        assert!(validate_wake_id(
            "abcdefghijklmnopqrstuvwxyzABCDEF"
        ));
        assert!(!validate_wake_id("short"));
        assert!(!validate_wake_id("has space in the id which is bad!!!!"));
        assert!(!validate_wake_id("slash/not/allowed________________"));
    }

    #[test]
    fn register_wake_unregister() {
        let rec = RecPusher {
            calls: Mutex::new(vec![]),
            fail: false,
        };
        let (app, _dir) = state(rec);
        let body = r#"{"wake_id":"abcdefghijklmnopqrstuvwxyzABCDEF","platform":"ios","token":"0123456789abcdef0123456789abcdef"}"#;
        assert_eq!(handle(&app, "POST", "/register", body, None, None).code, 200);
        let w = handle(
            &app,
            "POST",
            "/wake",
            r#"{"wake_id":"abcdefghijklmnopqrstuvwxyzABCDEF"}"#,
            None,
            None,
        );
        assert_eq!(w.code, 200);
        let del = handle(
            &app,
            "DELETE",
            "/register",
            r#"{"wake_id":"abcdefghijklmnopqrstuvwxyzABCDEF","token":"0123456789abcdef0123456789abcdef"}"#,
            None,
            None,
        );
        assert_eq!(del.code, 200);
        let miss = handle(
            &app,
            "POST",
            "/wake",
            r#"{"wake_id":"abcdefghijklmnopqrstuvwxyzABCDEF"}"#,
            None,
            None,
        );
        assert_eq!(miss.code, 404);
    }

    #[test]
    fn rate_limit_wake() {
        let rec = RecPusher {
            calls: Mutex::new(vec![]),
            fail: false,
        };
        let (app, _dir) = state(rec);
        let body = r#"{"wake_id":"abcdefghijklmnopqrstuvwxyzABCDEF","platform":"android","token":"0123456789abcdef0123456789abcdef"}"#;
        assert_eq!(handle(&app, "POST", "/register", body, None, None).code, 200);
        let wake = r#"{"wake_id":"abcdefghijklmnopqrstuvwxyzABCDEF"}"#;
        assert_eq!(handle(&app, "POST", "/wake", wake, None, None).code, 200);
        assert_eq!(handle(&app, "POST", "/wake", wake, None, None).code, 200);
        assert_eq!(handle(&app, "POST", "/wake", wake, None, None).code, 429);
    }

    #[test]
    fn never_stores_message_fields() {
        let rec = RecPusher {
            calls: Mutex::new(vec![]),
            fail: false,
        };
        let (app, _dir) = state(rec);
        let sneaky = r#"{"wake_id":"abcdefghijklmnopqrstuvwxyzABCDEF","platform":"ios","token":"0123456789abcdef0123456789abcdef","text":"hello"}"#;
        assert_eq!(handle(&app, "POST", "/register", sneaky, None, None).code, 200);
        let store = app.store.lock().unwrap();
        let row = store
            .get("abcdefghijklmnopqrstuvwxyzABCDEF")
            .unwrap()
            .unwrap();
        assert_eq!(row.token, "0123456789abcdef0123456789abcdef");
        assert!(!format!("{row:?}").contains("hello"));
    }

    #[test]
    fn health_and_404() {
        let rec = RecPusher {
            calls: Mutex::new(vec![]),
            fail: false,
        };
        let (app, _dir) = state(rec);
        assert_eq!(handle(&app, "GET", "/health", "", None, None).code, 200);
        assert_eq!(handle(&app, "POST", "/nope", "{}", None, None).code, 404);
        assert_eq!(handle(&app, "POST", "/register", "not-json", None, None).code, 400);
    }

    #[test]
    fn log_id_is_not_wake_id() {
        let id = "abcdefghijklmnopqrstuvwxyzABCDEF";
        let h = wake_log_id(id);
        assert_eq!(h.len(), 8);
        assert!(!id.to_ascii_lowercase().contains(&h));
    }

    #[test]
    fn register_voip_requires_register_key() {
        let rec = RecPusher {
            calls: Mutex::new(vec![]),
            fail: false,
        };
        let (app, _dir) = state(rec);
        let key = b"register-key-32-bytes-long!!!!!";
        use base64::Engine;
        let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
        let secret = [7u8; 32];
        let secret_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
        let body = format!(
            r#"{{"wake_id":"abcdefghijklmnopqrstuvwxyzABCDEF","platform":"ios","token":"0123456789abcdef0123456789abcdef","auth":{{"v":1,"key":"{key_b64}","wake_secret":"{secret_b64}"}}}}"#
        );
        assert_eq!(handle(&app, "POST", "/register", &body, None, None).code, 200);

        let voip = r#"{"wake_id":"abcdefghijklmnopqrstuvwxyzABCDEF","voip_token":"0123456789abcdef0123456789abcdef"}"#;
        assert_eq!(
            handle(&app, "POST", "/register-voip", voip, None, None).code,
            401
        );

        let voip_auth = format!(
            r#"{{"wake_id":"abcdefghijklmnopqrstuvwxyzABCDEF","voip_token":"0123456789abcdef0123456789abcdef","auth":{{"v":1,"key":"{key_b64}"}}}}"#
        );
        let hdr = auth::sign_hmac_header(
            key,
            "abcdefghijklmnopqrstuvwxyzABCDEF",
            "POST",
            "/register-voip",
            &voip_auth,
        )
        .unwrap();
        assert_eq!(
            handle(
                &app,
                "POST",
                "/register-voip",
                &voip_auth,
                Some(&hdr),
                None
            )
            .code,
            200
        );
    }
}
