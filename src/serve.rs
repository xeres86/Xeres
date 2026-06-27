// In-process HTTP runtime for `xeres serve`: serves the client bundle, runs
// server fns through the interpreter (secret-stripping the response), and
// handles local-first sync — all with no generated Rust and no cargo.

use crate::interp::{json_str, Interp, Value};
use crate::frontend::parser::{EnvModifier, XeresProgram};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Keep-alive: idle read timeout that reaps a persistent connection holding a
/// thread, and a per-connection request cap that recycles resources.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
const MAX_REQUESTS_PER_CONN: u32 = 1024;

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
                let _ = stream.set_read_timeout(Some(KEEPALIVE_IDLE));
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
            let _ = stream.set_read_timeout(Some(KEEPALIVE_IDLE));
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

/// One connection — **keep-alive**: a request/response loop reusing the socket
/// until the client opts out, an idle read times out (reaping the thread), or the
/// per-connection cap is hit. HTTP/1.1 framing: read the full headers, then exactly
/// `Content-Length` body bytes, leaving any pipelined remainder buffered for the
/// next iteration.
fn handle_conn<S: Read + Write>(mut stream: S, program: &XeresProgram, static_dir: &str) -> std::io::Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 16384];
    let mut served: u32 = 0;

    loop {
        // 1) Read until the header terminator (\r\n\r\n) is buffered.
        let head_end = loop {
            if let Some(pos) = find_subseq(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
            if buf.len() > 1 << 20 {
                return Ok(()); // oversized headers — drop the connection
            }
            match stream.read(&mut tmp) {
                Ok(0) => return Ok(()),                   // peer closed cleanly
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) if is_idle(&e) => return Ok(()),   // idle keep-alive — reap
                Err(e) => return Err(e),
            }
        };
        // 2) Read until the full body (Content-Length bytes) is buffered.
        let need = {
            let head = String::from_utf8_lossy(&buf[..head_end]);
            head_end + content_length(&head)
        };
        while buf.len() < need {
            match stream.read(&mut tmp) {
                Ok(0) => return Ok(()),
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) if is_idle(&e) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        // 3) Take exactly this request; any pipelined bytes stay in `buf`.
        let req_bytes: Vec<u8> = buf.drain(..need).collect();
        let req = String::from_utf8_lossy(&req_bytes);
        let body = String::from_utf8_lossy(&req_bytes[head_end..]);

        let first = req.lines().next().unwrap_or("");
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("/");
        let version = parts.next().unwrap_or("HTTP/1.1");

        // Keep-alive unless the client opts out (HTTP/1.0 defaults to close) or the
        // per-connection request cap is reached.
        served += 1;
        let conn_hdr = header_value(&req, "connection").unwrap_or_default().to_ascii_lowercase();
        let client_keep = if version.eq_ignore_ascii_case("HTTP/1.0") {
            conn_hdr.contains("keep-alive")
        } else {
            !conn_hdr.contains("close")
        };
        let keep = client_keep && served < MAX_REQUESTS_PER_CONN;

        let csrf_cookie = cookie_value(&req, "xeres_csrf");

        // Default S1 CSRF: a state-changing RPC fn call must echo the double-submit
        // token (the `xeres_csrf` cookie value, resent as the X-CSRF-Token header).
        // Sync replication is exempt. SameSite=Strict already blocks the cross-site
        // case; this is defense-in-depth the developer never writes.
        if method == "POST" && path.starts_with("/__xeres/") && !path.starts_with("/__xeres/sync/") {
            let header = header_value(&req, "x-csrf-token");
            let ok = matches!((&csrf_cookie, &header), (Some(c), Some(h)) if !c.is_empty() && c == h);
            if !ok {
                write_response(&mut stream, 403, "application/json", "{\"error\":\"csrf token missing or invalid\"}", "", keep)?;
                if keep { continue; } else { return Ok(()); }
            }
        }

        // Recover the actor from a verified session cookie (None = anonymous).
        let actor = cookie_value(&req, "xeres_session").and_then(|c| crate::interp::session_verify(&c));

        let (code, ctype, payload, set_cookie) =
            dispatch(method, path, &body, actor, program, static_dir);

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

        write_response(&mut stream, code, ctype, &payload, &cookies, keep)?;
        if !keep {
            return Ok(());
        }
    }
}

/// First occurrence of `needle` in `hay` (used to find the \r\n\r\n header end).
fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse `Content-Length` from a request head (0 if absent/invalid).
fn content_length(head: &str) -> usize {
    for line in head.lines() {
        if line.len() > 15 && line[..15].eq_ignore_ascii_case("content-length:") {
            return line[15..].trim().parse().unwrap_or(0);
        }
    }
    0
}

/// A read that timed out (idle keep-alive connection) vs a real I/O error.
fn is_idle(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
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
    keep: bool,
) -> std::io::Result<()> {
    let conn = if keep { "keep-alive" } else { "close" };
    // A 302 carries no body; `payload` is the redirect target (the Location).
    if code == 302 {
        let resp = format!(
            "HTTP/1.1 302 Found\r\nLocation: {}\r\n{}{}Content-Length: 0\r\nConnection: {}\r\n\r\n",
            payload, SECURITY_HEADERS, cookies, conn
        );
        stream.write_all(resp.as_bytes())?;
        return stream.flush();
    }
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n{}{}Content-Length: {}\r\nConnection: {}\r\n\r\n{}",
        code,
        reason(code),
        ctype,
        SECURITY_HEADERS,
        cookies,
        payload.as_bytes().len(),
        conn,
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
            Err(e) => {
                // Surface server-fn failures in the dev terminal — otherwise a 500
                // is opaque (the cause only rode in the response body).
                eprintln!("xeres: rpc `{}` failed: {}", fname, e);
                (500, "application/json", format!("{{\"error\":{}}}", json_str(&e)), None)
            }
        };
    }
    // Inbound API (spec 23): match a declared route before the SPA shell. Mirrors
    // codegen's `api_dispatch` so `xeres serve` ≡ the ejected server.
    if let Some((code, json)) = api_route_dispatch(program, method, path, body, actor.clone()) {
        return (code, "application/json", json, None);
    }
    // R31 auth-route guard: a protected route requires a valid session. `actor` is
    // `Some` iff the request carried a verified session cookie; bounce everyone
    // else to the public root (the client router does the same for in-app nav).
    if method == "GET" && actor.is_none() && is_protected_route(path, program) {
        return (302, "text/html", "/".to_string(), None);
    }
    let (code, ctype, payload) = serve_static(path, static_dir);
    (code, ctype, payload, None)
}

/// Inbound API routing for the interpreter (spec 23). Matches method+path against
/// declared `api` routes, decodes the JSON-object body into the body model, runs
/// the handler through the interpreter, and wire-projects the response (secrets
/// stripped). `Optional<T>` return ⇒ `None` is a 404. An unmatched path under a
/// declared `base` is a JSON 404 (not the SPA shell). Mirrors codegen exactly.
fn api_route_dispatch(
    program: &XeresProgram,
    method: &str,
    path: &str,
    body: &str,
    actor: Option<String>,
) -> Option<(u16, String)> {
    for api in &program.apis {
        for route in &api.routes {
            let full = format!("{}{}", api.base, route.path);
            if route.method.as_str() != method || full != path {
                continue;
            }
            let interp = Interp::with_session(program, actor);
            let body_param = route.body.as_ref().map(|b| {
                let parsed = jparse(body);
                (b.name.clone(), decode_arg(Some(&parsed), &b.type_name, program))
            });
            return Some(
                match interp.call_api_route(&route.body_stmts, body_param, route.return_type.as_deref()) {
                    Ok(v) => {
                        let optional = route
                            .return_type
                            .as_deref()
                            .and_then(|t| generic_inner("Optional", t))
                            .is_some();
                        if optional && matches!(v, Value::Null) {
                            (404, String::new())
                        } else {
                            (200, interp.wire_json(&v))
                        }
                    }
                    Err(e) => {
                        eprintln!("xeres: api {} {} failed: {}", method, full, e);
                        (500, format!("{{\"error\":{}}}", json_str(&e)))
                    }
                },
            );
        }
    }
    // Unmatched path under a declared base ⇒ a genuine API miss (JSON 404), not
    // the SPA shell.
    if program.apis.iter().any(|a| path.starts_with(&a.base)) {
        return Some((404, String::from("{\"error\":\"not found\"}")));
    }
    None
}

/// Does `path` map to an `auth` (protected) route? Mirrors the client router's
/// path map: the first prop-less screen is `/`, the rest `/<name lowercased>`.
/// The default route can't be `auth` (R31), so protected paths are `/<name>`.
fn is_protected_route(path: &str, program: &XeresProgram) -> bool {
    let navigable: Vec<_> =
        program.screens.iter().filter(|s| !s.is_component && s.params.is_empty()).collect();
    let Some(default) = navigable.first() else { return false };
    navigable.iter().filter(|s| s.is_auth).any(|s| {
        let p = if s.name == default.name { "/".to_string() } else { format!("/{}", s.name.to_lowercase()) };
        p == path
    })
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
        302 => "Found",
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

// ---- local-first sync store (generic, field-level LWW) ----
//
// Each row is a map of field -> Cell, where a Cell carries the field's value
// (stored as raw JSON) plus its own Lamport stamp + site id. Concurrent edits to
// *different* fields of the same row therefore both survive — the headline
// correctness fix over the old whole-row LWW. A delete is a row-level tombstone
// with its own stamp; a row stays visible unless its tombstone dominates every
// field stamp, so a late (lower-stamped) write can't resurrect a deleted row.
// Stamps form a total order — higher Lamport wins, ties broken by the (stable,
// random) site id — so every replica converges regardless of arrival order.
// This merge MUST stay identical to the generated server's (`SYNC_SERVER` in
// `src/codegen.rs`).

struct Cell {
    value: String, // the field's value, stored as raw JSON
    lamport: u64,
    site: String,
}

struct Row {
    fields: HashMap<String, Cell>,
    tomb: Option<(u64, String)>, // (lamport, site) of a delete, if any
}

struct CollState {
    rows: HashMap<String, Row>,
    lamport: u64,
}

/// Total order on `(lamport, site)` stamps: higher Lamport wins; equal Lamports
/// break by the lexicographically-greater site id. True iff `a` strictly
/// dominates `b`.
fn stamp_gt(al: u64, asite: &str, bl: u64, bsite: &str) -> bool {
    al > bl || (al == bl && asite > bsite)
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
            let site = op.get("site").and_then(J::str).unwrap_or("").to_string();
            if lam > cs.lamport {
                cs.lamport = lam;
            }
            let row = cs.rows.entry(id).or_insert_with(|| Row { fields: HashMap::new(), tomb: None });
            if kind == "set" {
                let field = op.get("field").and_then(J::str).unwrap_or("").to_string();
                if field.is_empty() {
                    continue;
                }
                let value = op.get("value").map(|j| j.to_json()).unwrap_or_else(|| "null".into());
                let win = match row.fields.get(&field) {
                    None => true,
                    Some(c) => stamp_gt(lam, &site, c.lamport, &c.site),
                };
                if win {
                    row.fields.insert(field, Cell { value, lamport: lam, site });
                }
            } else if kind == "del" {
                let win = match &row.tomb {
                    None => true,
                    Some((l, s)) => stamp_gt(lam, &site, *l, s),
                };
                if win {
                    row.tomb = Some((lam, site));
                }
            }
        }
    }

    let mut out: Vec<String> = Vec::new();
    for (id, row) in cs.rows.iter() {
        // A tombstone hides the row unless some field write strictly dominates it
        // (a genuinely-later re-add revives the whole row; a late write can't).
        let alive = match &row.tomb {
            None => !row.fields.is_empty(),
            Some((tl, ts)) => row.fields.values().any(|c| stamp_gt(c.lamport, &c.site, *tl, ts)),
        };
        if alive {
            for (f, c) in row.fields.iter() {
                out.push(format!(
                    "{{\"kind\":\"set\",\"id\":{},\"field\":{},\"value\":{},\"lamport\":{},\"site\":{}}}",
                    json_str(id),
                    json_str(f),
                    c.value,
                    c.lamport,
                    json_str(&c.site)
                ));
            }
        } else if let Some((tl, ts)) = &row.tomb {
            out.push(format!(
                "{{\"kind\":\"del\",\"id\":{},\"lamport\":{},\"site\":{}}}",
                json_str(id),
                tl,
                json_str(ts)
            ));
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

// ---- field-level sync merge: convergence tests ----
//
// These drive the real `sync_dispatch` (JSON in, JSON out) with crafted
// concurrent payloads — the actual proof that the merge converges. `.xrs`
// fixtures only check compilation, so this is where the runtime semantics are
// pinned. Each test uses a unique collection name so the process-global store
// (keyed by collection) keeps them isolated even running in parallel.
#[cfg(test)]
mod sync_tests {
    use super::{jparse, sync_dispatch, J};

    /// Push a batch of ops and return the merged store as a parsed response.
    fn push(coll: &str, ops: &[String]) -> J {
        jparse(&sync_dispatch(coll, &format!("{{\"ops\":[{}]}}", ops.join(","))))
    }
    fn set_op(id: &str, field: &str, value: &str, lamport: u64, site: &str) -> String {
        format!(
            "{{\"kind\":\"set\",\"id\":\"{}\",\"field\":\"{}\",\"value\":{},\"lamport\":{},\"site\":\"{}\"}}",
            id, field, value, lamport, site
        )
    }
    fn del_op(id: &str, lamport: u64, site: &str) -> String {
        format!("{{\"kind\":\"del\",\"id\":\"{}\",\"lamport\":{},\"site\":\"{}\"}}", id, lamport, site)
    }
    /// The merged value of `id.field` in a response, as raw JSON (e.g. `"\"hi\""`).
    fn field_val(resp: &J, id: &str, field: &str) -> Option<String> {
        if let Some(J::Arr(ops)) = resp.get("ops") {
            for op in ops {
                if op.get("kind").and_then(J::str) == Some("set")
                    && op.get("id").and_then(J::str) == Some(id)
                    && op.get("field").and_then(J::str) == Some(field)
                {
                    return op.get("value").map(|v| v.to_json());
                }
            }
        }
        None
    }
    fn is_deleted(resp: &J, id: &str) -> bool {
        matches!(resp.get("ops"), Some(J::Arr(ops)) if ops.iter().any(|op| {
            op.get("kind").and_then(J::str) == Some("del") && op.get("id").and_then(J::str) == Some(id)
        }))
    }

    #[test]
    fn concurrent_edits_to_different_fields_both_survive() {
        // The headline case: two sites edit different fields of the same row at
        // the same logical time. Old row-level LWW lost one; field-level keeps both.
        let c = "test_concurrent_fields";
        push(c, &[set_op("r1", "title", "\"hello\"", 1, "a")]);
        let resp = push(c, &[set_op("r1", "done", "true", 1, "b")]);
        assert_eq!(field_val(&resp, "r1", "title").as_deref(), Some("\"hello\""));
        assert_eq!(field_val(&resp, "r1", "done").as_deref(), Some("true"));
    }

    #[test]
    fn same_field_is_lww_by_lamport_regardless_of_arrival_order() {
        // The higher-Lamport write wins even when the lower one arrives last.
        let c = "test_same_field_lww";
        push(c, &[set_op("r1", "title", "\"new\"", 2, "a")]);
        let resp = push(c, &[set_op("r1", "title", "\"old\"", 1, "b")]);
        assert_eq!(field_val(&resp, "r1", "title").as_deref(), Some("\"new\""));
    }

    #[test]
    fn equal_lamport_is_broken_deterministically_by_site() {
        // Same field, same Lamport, different sites — the greater site id wins,
        // so both replicas converge on the same value.
        let c = "test_tie_break_site";
        push(c, &[set_op("r1", "title", "\"aaa\"", 5, "aaa")]);
        let resp = push(c, &[set_op("r1", "title", "\"bbb\"", 5, "bbb")]);
        assert_eq!(field_val(&resp, "r1", "title").as_deref(), Some("\"bbb\""));
    }

    #[test]
    fn a_tombstone_resists_a_late_lower_stamped_write() {
        // A delete, then a concurrent but lower-stamped field write arriving after
        // it — the row must stay deleted (no resurrection).
        let c = "test_tombstone_wins";
        push(c, &[set_op("r1", "title", "\"x\"", 1, "a")]);
        push(c, &[del_op("r1", 3, "a")]);
        let resp = push(c, &[set_op("r1", "title", "\"y\"", 2, "b")]);
        assert!(is_deleted(&resp, "r1"), "a late write must not resurrect a deleted row");
    }

    #[test]
    fn a_genuinely_later_write_revives_a_deleted_row() {
        // A field write stamped strictly above the tombstone is a real re-add and
        // brings the row back (the symmetric case to the test above).
        let c = "test_revive_after_delete";
        push(c, &[set_op("r1", "title", "\"x\"", 1, "a")]);
        push(c, &[del_op("r1", 2, "a")]);
        let resp = push(c, &[set_op("r1", "title", "\"z\"", 3, "a")]);
        assert!(!is_deleted(&resp, "r1"));
        assert_eq!(field_val(&resp, "r1", "title").as_deref(), Some("\"z\""));
    }
}
