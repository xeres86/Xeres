fn reason(code: u16) -> &'static str {
    match code { 200 => "OK", 302 => "Found", 403 => "Forbidden", 404 => "Not Found", 501 => "Not Implemented", _ => "OK" }
}

fn serve_static(path: &str) -> (u16, &'static str, String) {
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    let full = format!("static/{}", rel);
    let ctype = if full.ends_with(".js") { "text/javascript" }
        else if full.ends_with(".css") { "text/css" }
        else { "text/html; charset=utf-8" };
    match std::fs::read_to_string(&full) {
        Ok(c) => (200, ctype, c),
        // SPA fallback (P2 router): an extension-less path is a client route, not
        // a real file — serve index.html so a deep link / reload boots the app and
        // the router resolves the URL. Missing assets (with a `.`) stay a 404.
        Err(_) if !rel.contains('.') => match std::fs::read_to_string("static/index.html") {
            Ok(c) => (200, "text/html; charset=utf-8", c),
            Err(_) => (404, "text/html", String::from("<h1>404 - not found</h1>")),
        },
        Err(_) => (404, "text/html", String::from("<h1>404 - not found</h1>")),
    }
}

fn dispatch(method: &str, path: &str, body: &str) -> (u16, &'static str, String) {
    if method == "POST" && path.starts_with("/__xeres/sync/") {
        let coll = &path["/__xeres/sync/".len()..];
        return (200, "application/json", sync_dispatch(coll, body));
    }
    if method == "POST" && path.starts_with("/__xeres/") {
        return match route(path, body) {
            Some((code, json)) => (code, "application/json", json),
            None => (404, "application/json", String::from("{\"error\":\"no such rpc\"}")),
        };
    }
    //__XERES_API__
    //__XERES_GUARD__
    serve_static(path)
}

fn cookie_value(req: &str, name: &str) -> Option<String> {
    for line in req.lines() {
        if line.get(..7).map_or(false, |p| p.eq_ignore_ascii_case("cookie:")) {
            for pair in line[7..].split(';') {
                if let Some(v) = pair.trim().strip_prefix(&format!("{}=", name)) { return Some(v.to_string()); }
            }
        }
    }
    None
}

fn header_value(req: &str, name: &str) -> Option<String> {
    let key = format!("{}:", name);
    for line in req.lines() {
        if line.get(..key.len()).map_or(false, |p| p.eq_ignore_ascii_case(&key)) {
            return Some(line[key.len()..].trim().to_string());
        }
    }
    None
}

fn rand_token() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mk = || std::collections::hash_map::RandomState::new().build_hasher().finish();
    format!("{:016x}{:016x}", mk(), mk())
}

// Default S1/S2 security headers, always emitted. HSTS is honored once TLS is
// terminated in front; no Access-Control-Allow-Origin (the app is same-origin).
const SECURITY_HEADERS: &str = "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nStrict-Transport-Security: max-age=63072000; includeSubDomains\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\n";

// First occurrence of `needle` in `hay` (finds the \r\n\r\n header terminator).
fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() { return None; }
    hay.windows(needle.len()).position(|w| w == needle)
}
// Parse Content-Length from a request head (0 if absent/invalid).
fn content_length(head: &str) -> usize {
    for line in head.lines() {
        if line.len() > 15 && line[..15].eq_ignore_ascii_case("content-length:") {
            return line[15..].trim().parse().unwrap_or(0);
        }
    }
    0
}
// A read that timed out (idle keep-alive connection) vs a real I/O error.
fn is_idle(e: &std::io::Error) -> bool { matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) }

fn write_response<S: Write>(stream: &mut S, code: u16, ctype: &str, payload: &str, cookies: &str, keep: bool) -> std::io::Result<()> {
    let conn = if keep { "keep-alive" } else { "close" };
    if code == 302 {
        let resp = format!("HTTP/1.1 302 Found\r\nLocation: {}\r\n{}{}Content-Length: 0\r\nConnection: {}\r\n\r\n", payload, SECURITY_HEADERS, cookies, conn);
        stream.write_all(resp.as_bytes())?;
        return stream.flush();
    }
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n{}{}Content-Length: {}\r\nConnection: {}\r\n\r\n{}",
        code, reason(code), ctype, SECURITY_HEADERS, cookies, payload.as_bytes().len(), conn, payload
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

// Keep-alive: a request/response loop reusing the socket until the client opts
// out, an idle read times out (reaping the thread), or the per-connection cap is
// hit. HTTP/1.1 framing: full headers, then exactly Content-Length body bytes;
// any pipelined remainder stays buffered for the next iteration.
fn handle_conn<S: Read + Write>(stream: &mut S) -> std::io::Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 16384];
    let mut served: u32 = 0;
    loop {
        let head_end = loop {
            if let Some(pos) = find_subseq(&buf, b"\r\n\r\n") { break pos + 4; }
            if buf.len() > 1 << 20 { return Ok(()); }
            match stream.read(&mut tmp) {
                Ok(0) => return Ok(()),
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) if is_idle(&e) => return Ok(()),
                Err(e) => return Err(e),
            }
        };
        let need = { let head = String::from_utf8_lossy(&buf[..head_end]); head_end + content_length(&head) };
        while buf.len() < need {
            match stream.read(&mut tmp) {
                Ok(0) => return Ok(()),
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) if is_idle(&e) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        let req_bytes: Vec<u8> = buf.drain(..need).collect();
        let req = String::from_utf8_lossy(&req_bytes);
        let body = String::from_utf8_lossy(&req_bytes[head_end..]);
        let first = req.lines().next().unwrap_or("");
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("/");
        let version = parts.next().unwrap_or("HTTP/1.1");
        served += 1;
        let conn_hdr = header_value(&req, "connection").unwrap_or_default().to_ascii_lowercase();
        let client_keep = if version.eq_ignore_ascii_case("HTTP/1.0") { conn_hdr.contains("keep-alive") } else { !conn_hdr.contains("close") };
        let keep = client_keep && served < MAX_REQUESTS_PER_CONN;
        let csrf_cookie = cookie_value(&req, "xeres_csrf");
        // Default S1 CSRF: a state-changing RPC fn call must echo the double-submit
        // token (xeres_csrf cookie value resent as X-CSRF-Token). Sync is exempt.
        if method == "POST" && path.starts_with("/__xeres/") && !path.starts_with("/__xeres/sync/") {
            let header = header_value(&req, "x-csrf-token");
            let ok = matches!((&csrf_cookie, &header), (Some(c), Some(h)) if !c.is_empty() && c == h);
            if !ok {
                write_response(stream, 403, "application/json", "{\"error\":\"csrf token missing or invalid\"}", "", keep)?;
                if keep { continue; } else { return Ok(()); }
            }
        }
    //__XERES_RECOVER__
        let (code, ctype, payload) = dispatch(method, path, &body);
        let mut cookies = String::new();
    //__XERES_SETCOOKIE__
        if csrf_cookie.is_none() {
            cookies.push_str(&format!("Set-Cookie: xeres_csrf={}; Secure; SameSite=Strict; Path=/\r\n", rand_token()));
        }
        write_response(stream, code, ctype, &payload, &cookies, keep)?;
        if !keep { return Ok(()); }
    }
}

// Plain-HTTP accept loop (the default). One thread per connection so an idle or
// slow socket can't block accept.
fn serve_plain(listener: TcpListener, addr: &str) {
    println!("xeres app serving http://{}", addr);
    for stream in listener.incoming() {
        if let Ok(mut s) = stream {
            let _ = s.set_read_timeout(Some(KEEPALIVE_IDLE));
            std::thread::spawn(move || { let _ = handle_conn(&mut s); });
        }
    }
}

// Build a rustls ServerConfig from PEM cert-chain + key files (startup-only;
// panics loud on a bad cert so it fails before the accept loop).
#[cfg(feature = "tls")]
fn load_tls(cert: &str, key: &str) -> rustls::ServerConfig {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let cert_file = std::fs::File::open(cert).unwrap_or_else(|e| panic!("xeres: cannot open TLS_CERT {} ({})", cert, e));
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
        .collect::<Result<_, _>>().expect("xeres: cannot parse TLS_CERT PEM");
    let key_file = std::fs::File::open(key).unwrap_or_else(|e| panic!("xeres: cannot open TLS_KEY {} ({})", key, e));
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
        .expect("xeres: cannot read TLS_KEY PEM").expect("xeres: no private key in TLS_KEY");
    rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)
        .expect("xeres: invalid certificate/key pair")
}

// With `tls` on and TLS_CERT/TLS_KEY set, terminate HTTPS directly: each accepted
// TcpStream is wrapped in a rustls stream and handed to the same generic
// handle_conn. Otherwise (or unset env) fall back to plain HTTP.
#[cfg(feature = "tls")]
fn serve_loop(listener: TcpListener, addr: &str) {
    if let (Ok(cert), Ok(key)) = (std::env::var("TLS_CERT"), std::env::var("TLS_KEY")) {
        let config = std::sync::Arc::new(load_tls(&cert, &key));
        println!("xeres app serving https://{}", addr);
        for stream in listener.incoming() {
            if let Ok(s) = stream {
                let _ = s.set_read_timeout(Some(KEEPALIVE_IDLE));
                let config = config.clone();
                std::thread::spawn(move || {
                    if let Ok(conn) = rustls::ServerConnection::new(config) {
                        let mut tls = rustls::StreamOwned::new(conn, s);
                        let _ = handle_conn(&mut tls);
                    }
                });
            }
        }
        return;
    }
    serve_plain(listener, addr);
}

#[cfg(not(feature = "tls"))]
fn serve_loop(listener: TcpListener, addr: &str) {
    serve_plain(listener, addr);
}

fn main() {
    let addr = "127.0.0.1:8080";
    let listener = TcpListener::bind(addr).expect("xeres: cannot bind 127.0.0.1:8080");
    serve_loop(listener, addr);
}
