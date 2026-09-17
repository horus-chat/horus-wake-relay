use horus_wake_relay::{
    default_rate_limiter, handle, ApnsConfig, AppState, FcmConfig, HttpPusher, NoopPusher, Pusher,
    TokenStore,
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

fn main() -> std::io::Result<()> {
    let addr = std::env::var("HORUS_WAKE_ADDR").unwrap_or_else(|_| "127.0.0.1:8789".into());
    let db = std::env::var("HORUS_WAKE_DB").unwrap_or_else(|_| "wake_tokens.sqlite".into());

    let store = TokenStore::open(&db).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
    })?;
    let apns = ApnsConfig::from_env().unwrap_or_else(|e| {
        eprintln!("apns config error: {e:?}");
        None
    });
    let fcm = FcmConfig::from_env().unwrap_or_else(|e| {
        eprintln!("fcm config error: {e:?}");
        None
    });
    let pusher: Arc<dyn Pusher> = match HttpPusher::new(apns.clone(), fcm.clone()) {
        Ok(p) => {
            eprintln!(
                "push backends apns={} fcm={}",
                apns.is_some(),
                fcm.is_some()
            );
            Arc::new(p)
        }
        Err(e) => {
            eprintln!("push client failed ({e:?}); /wake will return 501");
            Arc::new(NoopPusher)
        }
    };

    let state = AppState {
        store: Arc::new(Mutex::new(store)),
        rate: Arc::new(Mutex::new(default_rate_limiter())),
        pusher,
    };

    let listener = TcpListener::bind(&addr)?;
    eprintln!("horus-wake-relay listening on http://{addr} db={db}");
    eprintln!("put Caddy or nginx on :443 → this port; never log request bodies");

    for stream in listener.incoming().flatten() {
        let state = state.clone();
        std::thread::spawn(move || {
            let _ = serve(stream, &state);
        });
    }
    Ok(())
}

fn serve(mut stream: TcpStream, state: &AppState) -> std::io::Result<()> {
    let raw = read_http(&mut stream)?;
    let (method, path, body, auth, wake_auth) = parse_request(&raw);
    let res = handle(state, &method, &path, &body, auth.as_deref(), wake_auth.as_deref());
    respond(&mut stream, res.code, res.body.as_bytes())
}

fn read_http(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_headers_end(&buf) {
            let header_end = end + 4;
            if let Some(len) = content_length(&buf[..end]) {
                while buf.len() < header_end + len {
                    let n = stream.read(&mut chunk)?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
            break;
        }
        if buf.len() > 256 * 1024 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn content_length(headers: &[u8]) -> Option<usize> {
    let s = String::from_utf8_lossy(headers);
    for line in s.lines() {
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            return v.trim().parse().ok();
        }
    }
    None
}

fn parse_request(raw: &str) -> (String, String, String, Option<String>, Option<String>) {
    let mut lines = raw.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let path = path.split('?').next().unwrap_or(&path).to_string();
    let body = if let Some(i) = raw.find("\r\n\r\n") {
        raw[i + 4..].to_string()
    } else {
        String::new()
    };
    let auth = header_value(raw, "x-horus-auth");
    let wake_auth = header_value(raw, "x-horus-wake-auth");
    (method, path, body, auth, wake_auth)
}

fn header_value(raw: &str, name: &str) -> Option<String> {
    let head = raw.split("\r\n\r\n").next()?;
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn respond(stream: &mut TcpStream, code: u16, body: &[u8]) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}
