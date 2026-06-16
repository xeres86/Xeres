// In-process HTTP runtime for `xeres serve`: serves the client bundle, runs
// server fns through the interpreter (secret-stripping the response), and
// handles local-first sync — all with no generated Rust and no cargo.

use crate::interp::{json_str, Interp, Value};
use crate::parser::{EnvModifier, XeresProgram};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Mutex, OnceLock};

/// Paths to a PEM cert chain + private key for `xeres serve --tls`.
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
}

pub fn serve(program: &XeresProgram, static_dir: &str, port: u16, tls: Option<TlsConfig>) {
    let addr = format!("127.0.0.1:{}", port);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("xeres serve: cannot bind {} ({})", addr, e);
            return;
        }
    };

    // With --tls we terminate HTTPS directly: each accepted TcpStream is wrapped
    // in a rustls server stream and handed to the same `handle_conn` (it only
    // needs `Read + Write`). The security headers we already send (HSTS, Secure
    // cookies) finally become truthful. Without --tls it's today's plain path.
    if let Some(tls) = tls {
        let config = std::sync::Arc::new(load_tls(&tls.cert, &tls.key));
        println!("xeres serve: https://{}", addr);
        std::thread::scope(|s| {
            for stream in listener.incoming().flatten() {
                let config = config.clone();
                s.spawn(move || match rustls::ServerConnection::new(config) {
                    Ok(conn) => {
                        let _ = handle_conn(rustls::StreamOwned::new(conn, stream), program, static_dir);
                    }
                    Err(e) => eprintln!("xeres serve: tls connection setup failed ({})", e),
                });
            }
        });
        return;
    }

    println!("xeres serve: http://{}", addr);

    // Scoped threads let each connection borrow `program` / `static_dir`.
    std::thread::scope(|s| {
        for stream in listener.incoming().flatten() {
            s.spawn(move || {
                let _ = handle_conn(stream, program, static_dir);
            });
        }
    });
}

/// Build a rustls `ServerConfig` from PEM cert-chain + private-key files. Panics
/// with a clear message on any I/O or parse failure — this runs once at startup,
/// before the accept loop, so a bad cert should fail loud and immediately.
fn load_tls(cert: &str, key: &str) -> rustls::ServerConfig {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let cert_file =
        std::fs::File::open(cert).unwrap_or_else(|e| panic!("xeres serve --tls: cannot open TLS_CERT {} ({})", cert, e));
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
        .collect::<Result<_, _>>()
        .expect("xeres serve --tls: cannot parse TLS_CERT PEM");
    let key_file =
        std::fs::File::open(key).unwrap_or_else(|e| panic!("xeres serve --tls: cannot open TLS_KEY {} ({})", key, e));
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
        .expect("xeres serve --tls: cannot read TLS_KEY PEM")
        .expect("xeres serve --tls: no private key found in TLS_KEY");
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("xeres serve --tls: invalid certificate/key pair")
}

fn handle_conn<S: Read + Write>(mut stream: S, program: &XeresProgram, static_dir: &str) -> std::io::Result<()> {
    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf[..n]).to_string();
    let first = req.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    let body = req.splitn(2, "\r\n\r\n").nth(1).unwrap_or("");

    let csrf_cookie = cookie_value(&req, "xeres_csrf");

    // Default S1 CSRF: a state-changing RPC fn call must echo the double-submit
    // token (the `xeres_csrf` cookie value, resent as the X-CSRF-Token header).
    // Sync replication is exempt. SameSite=Strict already blocks the cross-site
    // case; this is defense-in-depth the developer never writes.
    if method == "POST" && path.starts_with("/__xeres/") && !path.starts_with("/__xeres/sync/") {
        let header = header_value(&req, "x-csrf-token");
        let ok = matches!((&csrf_cookie, &header), (Some(c), Some(h)) if !c.is_empty() && c == h);
        if !ok {
            return write_response(
                &mut stream,
                403,
                "application/json",
                "{\"error\":\"csrf token missing or invalid\"}",
                "",
            );
        }
    }

    // Recover the actor from a verified session cookie (None = anonymous).
    let actor = cookie_value(&req, "xeres_session").and_then(|c| crate::interp::session_verify(&c));

    let (code, ctype, payload, set_cookie) =
        dispatch(method, path, body, actor, program, static_dir);

    // Set-Cookie(s): a session mint (if `session.login`/`logout` ran) plus a
    // fresh CSRF token when the client doesn't have one yet (readable by JS so
    // the client can echo it back as a header).
    let mut cookies = String::new();
    if let Some(c) = set_cookie {
        cookies.push_str(&format!("Set-Cookie: {}\r\n", c));
    }
    if csrf_cookie.is_none() {
        cookies.push_str(&format!(
            "Set-Cookie: xeres_csrf={}; Secure; SameSite=Strict; Path=/\r\n",
            rand_token()
        ));
    }

    write_response(&mut stream, code, ctype, &payload, &cookies)
}

/// Default S1/S2: the always-on security headers. Strict CSP forbids inline
/// script (backstops R22); inline style is allowed for the language's `<style>`/
/// `style=""`. HSTS is always set (honored once TLS is terminated in front);
/// `Access-Control-Allow-Origin` is intentionally absent — the app is same-origin.
const SECURITY_HEADERS: &str = "X-Content-Type-Options: nosniff\r\n\
    Referrer-Policy: no-referrer\r\n\
    X-Frame-Options: DENY\r\n\
    Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n\
    Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\n";

/// Write a response with the security headers + any `Set-Cookie` lines.
fn write_response<S: Write>(
    stream: &mut S,
    code: u16,
    ctype: &str,
    payload: &str,
    cookies: &str,
) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n{}{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        reason(code),
        ctype,
        SECURITY_HEADERS,
        cookies,
        payload.as_bytes().len(),
        payload
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

/// Extract a cookie value from the raw request headers (case-insensitive header
/// name, case-sensitive value).
fn cookie_value(req: &str, name: &str) -> Option<String> {
    for line in req.lines() {
        if line.get(..7).map_or(false, |p| p.eq_ignore_ascii_case("cookie:")) {
            for pair in line[7..].split(';') {
                if let Some(v) = pair.trim().strip_prefix(&format!("{}=", name)) {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Extract an arbitrary request header value (case-insensitive name).
fn header_value(req: &str, name: &str) -> Option<String> {
    let key = format!("{}:", name);
    for line in req.lines() {
        if line.get(..key.len()).map_or(false, |p| p.eq_ignore_ascii_case(&key)) {
            return Some(line[key.len()..].trim().to_string());
        }
    }
    None
}

/// A 128-bit random token (CSRF), std-only: `RandomState` is OS-seeded.
fn rand_token() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mk = || std::collections::hash_map::RandomState::new().build_hasher().finish();
    format!("{:016x}{:016x}", mk(), mk())
}

fn dispatch(
    method: &str,
    path: &str,
    body: &str,
    actor: Option<String>,
    program: &XeresProgram,
    static_dir: &str,
) -> (u16, &'static str, String, Option<String>) {
    if method == "POST" && path.starts_with("/__xeres/sync/") {
        let coll = &path["/__xeres/sync/".len()..];
        return (200, "application/json", sync_dispatch(coll, body), None);
    }
    if method == "POST" && path.starts_with("/__xeres/") {
        let fname = &path["/__xeres/".len()..];
        return match rpc(program, fname, body, actor) {
            Ok((json, set_cookie)) => (200, "application/json", json, set_cookie),
            Err(e) => (500, "application/json", format!("{{\"error\":{}}}", json_str(&e)), None),
        };
    }
    let (code, ctype, payload) = serve_static(path, static_dir);
    (code, ctype, payload, None)
}

fn rpc(
    program: &XeresProgram,
    fname: &str,
    body: &str,
    actor: Option<String>,
) -> Result<(String, Option<String>), String> {
    let f = program
        .functions
        .iter()
        .find(|f| f.name == fname && f.env == EnvModifier::Server)
        .ok_or("no such rpc")?;
    let parsed = jparse(body);
    let args: Vec<Value> = f
        .params
        .iter()
        .enumerate()
        .map(|(i, p)| decode_arg(parsed.idx(i), &p.type_name, program))
        .collect();
    let interp = Interp::with_session(program, actor);
    let result = interp.call(&f.name, args)?;
    Ok((interp.wire_json(&result), interp.take_set_cookie()))
}

/// Decode a JSON value into a runtime Value, guided by the declared type.
/// Handles scalars, models, `List<T>`, `Optional<T>`, and any nesting — the
/// interpreter half of full-grammar RPC arguments.
fn decode_arg(j: Option<&J>, ty: &str, program: &XeresProgram) -> Value {
    // `List<T>` — a JSON array, each element decoded as `T` (absent ⇒ empty).
    if let Some(inner) = generic_inner("List", ty) {
        return match j {
            Some(J::Arr(items)) => {
                Value::List(items.iter().map(|e| decode_arg(Some(e), inner, program)).collect())
            }
            _ => Value::List(Vec::new()),
        };
    }
    // `Optional<T>` — JSON null / absent ⇒ Null, otherwise the inner value.
    if let Some(inner) = generic_inner("Optional", ty) {
        return match j {
            None | Some(J::Null) => Value::Null,
            Some(v) => decode_arg(Some(v), inner, program),
        };
    }
    let j = match j {
        Some(j) => j,
        None => return Value::Null,
    };
    match ty {
        // Decimal rides the wire as a string (exact, string-backed).
        "String" | "Decimal" => Value::Str(j.as_string()),
        "Int" | "DateTime" => Value::Int(j.as_i64()),
        "Float" => Value::Float(j.as_f64()),
        "Bool" => Value::Bool(j.as_bool()),
        _ if program.enums.iter().any(|e| e.name == ty) => Value::Str(j.as_string()),
        _ => {
            if let Some(model) = program.models.iter().find(|m| m.name == ty) {
                let fields = model
                    .properties
                    .iter()
                    .map(|p| (p.name.clone(), decode_arg(j.get(&p.name), &p.data_type, program)))
                    .collect();
                Value::Record(ty.to_string(), fields)
            } else {
                Value::Null
            }
        }
    }
}

/// Inner type of a one-level generic, e.g. `("List", "List<User>") -> "User"`.
fn generic_inner<'a>(base: &str, ty: &'a str) -> Option<&'a str> {
    ty.strip_prefix(base)
        .and_then(|r| r.strip_prefix('<'))
        .and_then(|r| r.strip_suffix('>'))
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn serve_static(path: &str, static_dir: &str) -> (u16, &'static str, String) {
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    let full = format!("{}/{}", static_dir, rel);
    let ctype = if full.ends_with(".js") {
        "text/javascript"
    } else if full.ends_with(".css") {
        "text/css"
    } else {
        "text/html; charset=utf-8"
    };
    match std::fs::read_to_string(&full) {
        Ok(c) => (200, ctype, c),
        // SPA fallback (P2 router): an extension-less path is a client route, not
        // a real file — serve index.html so a deep link / reload boots the app and
        // the router resolves the URL. Missing assets (with a `.`) stay a 404.
        Err(_) if !rel.contains('.') => {
            match std::fs::read_to_string(format!("{}/index.html", static_dir)) {
                Ok(c) => (200, "text/html; charset=utf-8", c),
                Err(_) => (404, "text/html", String::from("<h1>404 - not found</h1>")),
            }
        }
        Err(_) => (404, "text/html", String::from("<h1>404 - not found</h1>")),
    }
}

// ---- local-first sync store (generic: id -> row JSON, LWW by lamport) ----

struct CollState {
    rows: HashMap<String, (String, u64)>,
    lamport: u64,
}

fn sync_store() -> &'static Mutex<HashMap<String, CollState>> {
    static S: OnceLock<Mutex<HashMap<String, CollState>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn sync_dispatch(coll: &str, body: &str) -> String {
    let req = jparse(body);
    let mut guard = sync_store().lock().unwrap();
    let cs = guard
        .entry(coll.to_string())
        .or_insert_with(|| CollState { rows: HashMap::new(), lamport: 0 });

    if let Some(J::Arr(ops)) = req.get("ops") {
        for op in ops {
            let kind = op.get("kind").and_then(J::str).unwrap_or("");
            let id = op.get("id").and_then(J::str).unwrap_or("").to_string();
            if id.is_empty() {
                continue;
            }
            let lam = op.get("lamport").map(J::as_f64).unwrap_or(0.0) as u64;
            let seen = cs.rows.get(&id).map(|(_, v)| *v).unwrap_or(0);
            if lam < seen {
                continue;
            }
            if kind == "put" {
                let row = op.get("row").map(|j| j.to_json()).unwrap_or_else(|| "null".into());
                cs.rows.insert(id.clone(), (row, lam));
            } else if kind == "del" {
                cs.rows.insert(id.clone(), ("null".into(), lam));
            }
            if lam > cs.lamport {
                cs.lamport = lam;
            }
        }
    }

    let mut out: Vec<String> = Vec::new();
    for (id, (row, v)) in cs.rows.iter() {
        if row == "null" {
            out.push(format!("{{\"kind\":\"del\",\"id\":{},\"row\":null,\"lamport\":{}}}", json_str(id), v));
        } else {
            out.push(format!("{{\"kind\":\"put\",\"id\":{},\"row\":{},\"lamport\":{}}}", json_str(id), row, v));
        }
    }
    out.sort();
    format!("{{\"lamport\":{},\"ops\":[{}]}}", cs.lamport, out.join(","))
}

// ---- minimal JSON value + parser ----

enum J {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    fn get(&self, k: &str) -> Option<&J> {
        if let J::Obj(v) = self {
            v.iter().find(|(kk, _)| kk == k).map(|(_, vv)| vv)
        } else {
            None
        }
    }
    fn idx(&self, i: usize) -> Option<&J> {
        if let J::Arr(v) = self {
            v.get(i)
        } else {
            None
        }
    }
    fn str(&self) -> Option<&str> {
        if let J::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }
    fn as_string(&self) -> String {
        self.str().unwrap_or("").to_string()
    }
    fn as_f64(&self) -> f64 {
        if let J::Num(n) = self {
            *n
        } else {
            0.0
        }
    }
    fn as_i64(&self) -> i64 {
        self.as_f64() as i64
    }
    fn as_bool(&self) -> bool {
        matches!(self, J::Bool(true))
    }
    fn to_json(&self) -> String {
        match self {
            J::Null => "null".into(),
            J::Bool(b) => b.to_string(),
            J::Num(n) => {
                if n.fract() == 0.0 {
                    (*n as i64).to_string()
                } else {
                    n.to_string()
                }
            }
            J::Str(s) => json_str(s),
            J::Arr(a) => format!("[{}]", a.iter().map(|x| x.to_json()).collect::<Vec<_>>().join(",")),
            J::Obj(o) => format!(
                "{{{}}}",
                o.iter().map(|(k, v)| format!("{}:{}", json_str(k), v.to_json())).collect::<Vec<_>>().join(",")
            ),
        }
    }
}

fn jparse(s: &str) -> J {
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    jval(&b, &mut i)
}

fn jws(b: &[char], i: &mut usize) {
    while *i < b.len() && b[*i].is_whitespace() {
        *i += 1;
    }
}

fn jstr(b: &[char], i: &mut usize) -> String {
    if *i < b.len() && b[*i] == '"' {
        *i += 1;
    }
    let mut s = String::new();
    while *i < b.len() && b[*i] != '"' {
        if b[*i] == '\\' && *i + 1 < b.len() {
            *i += 1;
            match b[*i] {
                'n' => s.push('\n'),
                't' => s.push('\t'),
                'r' => s.push('\r'),
                c => s.push(c),
            }
        } else {
            s.push(b[*i]);
        }
        *i += 1;
    }
    if *i < b.len() {
        *i += 1;
    }
    s
}

fn jval(b: &[char], i: &mut usize) -> J {
    jws(b, i);
    if *i >= b.len() {
        return J::Null;
    }
    match b[*i] {
        '{' => {
            *i += 1;
            let mut o = Vec::new();
            loop {
                jws(b, i);
                if *i >= b.len() || b[*i] == '}' {
                    if *i < b.len() {
                        *i += 1;
                    }
                    break;
                }
                let k = jstr(b, i);
                jws(b, i);
                if *i < b.len() && b[*i] == ':' {
                    *i += 1;
                }
                o.push((k, jval(b, i)));
                jws(b, i);
                if *i < b.len() && b[*i] == ',' {
                    *i += 1;
                }
            }
            J::Obj(o)
        }
        '[' => {
            *i += 1;
            let mut a = Vec::new();
            loop {
                jws(b, i);
                if *i >= b.len() || b[*i] == ']' {
                    if *i < b.len() {
                        *i += 1;
                    }
                    break;
                }
                a.push(jval(b, i));
                jws(b, i);
                if *i < b.len() && b[*i] == ',' {
                    *i += 1;
                }
            }
            J::Arr(a)
        }
        '"' => J::Str(jstr(b, i)),
        't' => {
            *i += 4;
            J::Bool(true)
        }
        'f' => {
            *i += 5;
            J::Bool(false)
        }
        'n' => {
            *i += 4;
            J::Null
        }
        _ => {
            let st = *i;
            while *i < b.len()
                && (b[*i].is_ascii_digit() || b[*i] == '-' || b[*i] == '+' || b[*i] == '.' || b[*i] == 'e' || b[*i] == 'E')
            {
                *i += 1;
            }
            if *i == st {
                *i += 1;
                return J::Null;
            }
            let s: String = b[st..*i].iter().collect();
            J::Num(s.parse().unwrap_or(0.0))
        }
    }
}
