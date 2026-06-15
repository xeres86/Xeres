// src/codegen.rs
//
// Tier-splitting code generator. Runs AFTER the checker has proven the program
// boundary-safe, so codegen can assume every rule (R1..R6) already holds.
//
//   server.rs  — the server tier. Full model structs (secrets included),
//                real bodies for `server` fns. UI code does not exist here.
//
//   client.ts  — the browser tier. Model interfaces with `secret` fields
//                STRIPPED (they can never cross the wire), `ui` fns/screens as
//                real code, and every `server` fn replaced by a typed async RPC
//                stub — the dev never hand-writes a fetch.

use crate::parser::{
    BinOp, EnvModifier, Expr, FunctionNode, Handler, MatchPat, Stmt, UnOp, ViewNode, XeresProgram,
};
use std::collections::{HashMap, HashSet};

pub fn generate(
    program: &XeresProgram,
    _returns_secret: &HashMap<String, bool>,
) -> (String, String, String, String) {
    (
        gen_server(program),
        gen_client(program),
        gen_index(program),
        gen_cargo(program),
    )
}

/// The generated app's Cargo.toml. A dependency is added only when the app
/// actually uses the capability — `postgres` for `db`, `argon2` for
/// `hash`/`verify`. A plain app stays a zero-dependency std crate.
fn gen_cargo(program: &XeresProgram) -> String {
    let mut deps = String::new();
    if uses_db(program) {
        deps.push_str("postgres = \"0.19\"\npostgres-native-tls = \"0.5\"\nnative-tls = \"0.2\"\n");
    }
    if uses_auth(program) {
        deps.push_str("argon2 = { version = \"0.5\", features = [\"std\"] }\n");
    }
    let dep_section = if deps.is_empty() {
        "\n".to_string()
    } else {
        format!("\n[dependencies]\n{}", deps)
    };
    format!(
        "[package]\nname = \"xeres-app\"\nversion = \"0.0.1\"\nedition = \"2021\"\n\n\
         [[bin]]\nname = \"xeres-app\"\npath = \"src/main.rs\"\n{}",
        dep_section
    )
}

/// Does any function body call the `hash`/`verify` auth builtins?
fn uses_auth(program: &XeresProgram) -> bool {
    program.functions.iter().any(|f| f.body.iter().any(stmt_uses_auth))
}
fn stmt_uses_auth(s: &Stmt) -> bool {
    match s {
        Stmt::Let { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::Return(value)
        | Stmt::Expr(value) => expr_uses_auth(value),
        Stmt::Try { body, handler } => {
            body.iter().any(stmt_uses_auth) || handler.iter().any(stmt_uses_auth)
        }
        Stmt::If { cond, then_body, else_body } => {
            expr_uses_auth(cond) || then_body.iter().any(stmt_uses_auth) || else_body.iter().any(stmt_uses_auth)
        }
        Stmt::For { iter, body, .. } => expr_uses_auth(iter) || body.iter().any(stmt_uses_auth),
        Stmt::While { cond, body } => expr_uses_auth(cond) || body.iter().any(stmt_uses_auth),
        Stmt::Match { scrutinee, arms } => {
            expr_uses_auth(scrutinee) || arms.iter().any(|a| a.body.iter().any(stmt_uses_auth))
        }
        Stmt::Break | Stmt::Continue => false,
    }
}
fn expr_uses_auth(e: &Expr) -> bool {
    match e {
        Expr::Call { callee, args } => {
            callee == "hash" || callee == "verify" || args.iter().any(expr_uses_auth)
        }
        Expr::MethodCall { receiver, args, .. } => {
            expr_uses_auth(receiver) || args.iter().any(expr_uses_auth)
        }
        Expr::Field { base, .. } => expr_uses_auth(base),
        Expr::Unary { expr, .. } => expr_uses_auth(expr),
        Expr::Binary { left, right, .. } => expr_uses_auth(left) || expr_uses_auth(right),
        Expr::Declassify(i) | Expr::Await(i) => expr_uses_auth(i),
        Expr::Record { fields, .. } => fields.iter().any(|(_, v)| expr_uses_auth(v)),
        Expr::ListLit(items) => items.iter().any(expr_uses_auth),
        Expr::Ternary { cond, then, otherwise } => {
            expr_uses_auth(cond) || expr_uses_auth(then) || expr_uses_auth(otherwise)
        }
        Expr::Range { start, end } => expr_uses_auth(start) || expr_uses_auth(end),
        _ => false,
    }
}

/// Does any function body reference the `db` capability?
fn uses_db(program: &XeresProgram) -> bool {
    program.functions.iter().any(|f| f.body.iter().any(stmt_uses_db))
}
fn stmt_uses_db(s: &Stmt) -> bool {
    match s {
        Stmt::Let { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::Return(value)
        | Stmt::Expr(value) => expr_uses_db(value),
        Stmt::Try { body, handler } => {
            body.iter().any(stmt_uses_db) || handler.iter().any(stmt_uses_db)
        }
        Stmt::If { cond, then_body, else_body } => {
            expr_uses_db(cond) || then_body.iter().any(stmt_uses_db) || else_body.iter().any(stmt_uses_db)
        }
        Stmt::For { iter, body, .. } => expr_uses_db(iter) || body.iter().any(stmt_uses_db),
        Stmt::While { cond, body } => expr_uses_db(cond) || body.iter().any(stmt_uses_db),
        Stmt::Match { scrutinee, arms } => {
            expr_uses_db(scrutinee) || arms.iter().any(|a| a.body.iter().any(stmt_uses_db))
        }
        Stmt::Break | Stmt::Continue => false,
    }
}
fn expr_uses_db(e: &Expr) -> bool {
    match e {
        Expr::MethodCall { receiver, args, .. } => {
            matches!(receiver.as_ref(), Expr::Ident(n) if n == "db")
                || expr_uses_db(receiver)
                || args.iter().any(expr_uses_db)
        }
        Expr::Field { base, .. } => expr_uses_db(base),
        Expr::Call { args, .. } => args.iter().any(expr_uses_db),
        Expr::Unary { expr, .. } => expr_uses_db(expr),
        Expr::Binary { left, right, .. } => expr_uses_db(left) || expr_uses_db(right),
        Expr::Declassify(i) | Expr::Await(i) => expr_uses_db(i),
        Expr::Record { fields, .. } => fields.iter().any(|(_, v)| expr_uses_db(v)),
        Expr::ListLit(items) => items.iter().any(expr_uses_db),
        Expr::Ternary { cond, then, otherwise } => {
            expr_uses_db(cond) || expr_uses_db(then) || expr_uses_db(otherwise)
        }
        Expr::Range { start, end } => expr_uses_db(start) || expr_uses_db(end),
        _ => false,
    }
}

// ------------------------------------------------------------------ server.rs

fn gen_server(program: &XeresProgram) -> String {
    let models: HashSet<&str> = program.models.iter().map(|m| m.name.as_str()).collect();

    let mut out = String::new();
    out.push_str("// GENERATED by xeres — server tier (std-only HTTP). Do not edit.\n");
    out.push_str("#![allow(dead_code, unused_variables, unused_parens, unused_mut)]\n\n");
    out.push_str(SERVER_HEAD);
    out.push('\n');
    if uses_db(program) {
        out.push_str(DB_PRELUDE);
        out.push('\n');
    }
    if uses_auth(program) {
        out.push_str(CRYPTO_PRELUDE);
        out.push('\n');
    }

    // Enums are string-backed: the variant validity is proven by the checker
    // (R20), so the server tier carries them as `String` (wire = the variant).
    for e in &program.enums {
        let variants = e.variants.iter().map(|v| format!("// {}", v)).collect::<Vec<_>>().join(" ");
        out.push_str(&format!("pub type {} = String;  {}\n", e.name, variants));
    }
    if !program.enums.is_empty() {
        out.push('\n');
    }

    // Models: full fidelity (secrets stay server-side) + a wire projection that
    // OMITS secret fields. The wire codec is the runtime half of R3/R5.
    for m in &program.models {
        out.push_str(&format!("#[derive(Debug, Clone, Default)]\npub struct {} {{\n", m.name));
        for p in &m.properties {
            let note = if p.is_secret { "  // secret — never leaves the server" } else { "" };
            out.push_str(&format!(
                "    pub {}: {},{}\n",
                p.name,
                map_rust_type(&p.data_type),
                note
            ));
        }
        out.push_str("}\n\n");

        // to_wire_json: build JSON from non-secret fields only.
        out.push_str(&format!("impl {} {{\n", m.name));
        out.push_str("    /// Serialize for the wire. `secret` fields are omitted by construction.\n");
        out.push_str("    pub fn to_wire_json(&self) -> String {\n");
        out.push_str("        let mut s = String::from(\"{\");\n");
        let mut first = true;
        for p in &m.properties {
            if p.is_secret {
                out.push_str(&format!("        // {} is secret — not serialized\n", p.name));
                continue;
            }
            if !first {
                out.push_str("        s.push(',');\n");
            }
            first = false;
            out.push_str(&format!("        s.push_str(\"\\\"{}\\\":\");\n", p.name));
            let path = format!("self.{}", p.name);
            out.push_str(&format!("        s.push_str(&{});\n", wire_serialize(&path, &p.data_type, &models)));
        }
        out.push_str("        s.push('}');\n");
        out.push_str("        s\n");
        out.push_str("    }\n}\n\n");
    }

    // Functions: only server (and unscoped) bodies live here.
    for f in &program.functions {
        if f.env == EnvModifier::Ui {
            out.push_str(&format!("// `{}` runs in the browser — see client.ts\n\n", f.name));
            continue;
        }
        let params = f
            .params
            .iter()
            .map(|p| format!("{}: {}", p.name, map_rust_type(&p.type_name)))
            .collect::<Vec<_>>()
            .join(", ");
        let ret = match &f.return_type {
            Some(t) => format!(" -> {}", map_rust_type(t)),
            None => String::new(),
        };
        out.push_str(&format!("pub fn {}({}){} {{\n", f.name, params, ret));
        for s in &f.body {
            out.push_str(&format!("    {}\n", emit_server_stmt(s, f, program)));
        }
        out.push_str("}\n\n");

        // RPC entry: runs the fn, then serializes the result through the wire
        // codec so secret fields are physically absent from the response.
        let arg_names = f.params.iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", ");
        out.push_str(&format!(
            "/// RPC entry for `{name}` — response goes through the wire projection.\n\
             pub fn {name}_rpc({params}) -> String {{\n\
             \x20   let __r = {name}({args});\n",
            name = f.name,
            params = params,
            args = arg_names
        ));
        let body = match &f.return_type {
            Some(t) => wire_serialize("__r", t, &models),
            None => "String::from(\"null\")".to_string(),
        };
        out.push_str(&format!("    {}\n}}\n\n", body));
    }

    // Sync endpoint. The store is generic (id -> raw row JSON, LWW by lamport),
    // so it needs no per-model code. Client rows are already secret-free
    // (the client interface omits secret fields).
    if program.states.is_empty() {
        out.push_str(
            "fn sync_dispatch(_coll: &str, _body: &str) -> String { String::from(\"{\\\"lamport\\\":0,\\\"ops\\\":[]}\") }\n\n",
        );
    } else {
        out.push_str(SYNC_SERVER);
        out.push('\n');
    }

    // Generated router: maps each server fn endpoint to its _rpc wrapper.
    // Args (scalars AND model objects) are decoded from the JSON body array.
    out.push_str("fn route(path: &str, body: &str) -> Option<(u16, String)> {\n");
    out.push_str("    let __a = jparse(body);\n");
    out.push_str("    match path {\n");
    for f in &program.functions {
        if f.env != EnvModifier::Server {
            continue;
        }
        let args = f
            .params
            .iter()
            .enumerate()
            .map(|(i, p)| arg_extractor(i, &p.type_name, program))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "        \"/__xeres/{name}\" => Some((200, {name}_rpc({args}))),\n",
            name = f.name,
            args = args
        ));
    }
    out.push_str("        _ => None,\n    }\n}\n\n");

    out.push_str(SERVER_MAIN);
    out
}

/// Rust expression decoding RPC argument `i` of type `ty` from the parsed JSON
/// array `__a`. Delegates to the recursive decoder, so an argument may be any
/// type in the grammar — scalar, model, `List<T>`, `Optional<T>`, or any nesting
/// (e.g. `List<Model>`, `Optional<Model>`, a model with a `List` field).
fn arg_extractor(i: usize, ty: &str, program: &XeresProgram) -> String {
    decode_json_rust(&format!("__a.idx({})", i), ty, program, 0)
}

/// Recursive JSON→Rust decoder. `src` is a Rust expression of type `Option<&J>`
/// (the value to decode; absent ⇒ the type's default). `depth` keeps generated
/// binding names unique across nesting. The runtime half of model-typed RPC
/// args — secret fields simply never appear in the client payload, so a missing
/// field defaults, exactly as before.
fn decode_json_rust(src: &str, ty: &str, program: &XeresProgram, depth: usize) -> String {
    if let Some(inner) = generic_inner("List", ty) {
        let ev = format!("__e{}", depth);
        let elem = decode_json_rust(&format!("Some({})", ev), inner, program, depth + 1);
        return format!(
            "(match {src} {{ Some(J::Arr(__v)) => __v.iter().map(|{ev}| {elem}).collect::<Vec<_>>(), _ => Vec::new() }})",
            src = src, ev = ev, elem = elem
        );
    }
    if let Some(inner) = generic_inner("Optional", ty) {
        let inner_dec = decode_json_rust("__s", inner, program, depth + 1);
        return format!(
            "(match {src} {{ None | Some(J::Null) => None, __s => Some({inner_dec}) }})",
            src = src, inner_dec = inner_dec
        );
    }
    if let Some(model) = program.models.iter().find(|m| m.name == ty) {
        let ov = format!("__o{}", depth);
        let fields = model
            .properties
            .iter()
            .map(|p| {
                let fsrc = format!("{}.and_then(|{ov}| {ov}.get(\"{f}\"))", src, ov = ov, f = p.name);
                format!("{}: {}", p.name, decode_json_rust(&fsrc, &p.data_type, program, depth + 1))
            })
            .collect::<Vec<_>>()
            .join(", ");
        return format!("{} {{ {} }}", ty, fields);
    }
    // String and string-backed enums decode from a JSON string.
    if ty == "String" || program.enums.iter().any(|e| e.name == ty) {
        return format!("{}.map(|__v| __v.as_string()).unwrap_or_default()", src);
    }
    // scalar (Int, DateTime as i64; Float; Bool)
    match ty {
        "Float" => format!("{}.and_then(|__v| __v.as_f64()).unwrap_or(0.0)", src),
        "Bool" => format!("{}.map(|__v| __v.as_bool()).unwrap_or_default()", src),
        _ => format!("{}.map(|__v| __v.as_i64()).unwrap_or_default()", src),
    }
}

/// Rust expression (evaluating to `String`) that serializes `path` of type `ty`
/// for the wire. Models recurse through their own secret-stripping codec;
/// List -> JSON array, Optional -> value or null.
fn wire_serialize(path: &str, ty: &str, models: &HashSet<&str>) -> String {
    if let Some(inner) = generic_inner("List", ty) {
        let item = wire_serialize("__it", inner, models);
        return format!(
            "{{ let __v: Vec<String> = {}.iter().map(|__it| {}).collect(); format!(\"[{{}}]\", __v.join(\",\")) }}",
            path, item
        );
    }
    if let Some(inner) = generic_inner("Optional", ty) {
        let item = wire_serialize("__o", inner, models);
        return format!(
            "match &{} {{ Some(__o) => {}, None => String::from(\"null\") }}",
            path, item
        );
    }
    if models.contains(ty) {
        format!("{}.to_wire_json()", path)
    } else if matches!(ty, "Int" | "Float" | "Bool" | "DateTime") {
        // valid JSON number/bool scalars as-is
        format!("{}.to_string()", path)
    } else {
        // String and (string-backed) enums -> a JSON string
        format!("json_str(&{})", path)
    }
}

const SERVER_HEAD: &str = r#"use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// Minimal JSON string escaping (spike-grade).
fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The `uid()` builtin, server side (std-only). Matches the client and
/// interpreter: a hex of the wall-clock nanos. Used e.g. to mint a row id on a
/// `db.exec` insert.
fn uid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("{:x}", n)
}

/// The `now()` builtin, server side: epoch milliseconds (matches `Date.now()`).
fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// A JSON value + a recursive-descent parser (std-only). Shared by the RPC
/// router (to decode args, including model objects) and the sync endpoint.
enum J { Null, Bool(bool), Num(f64), Str(String), Arr(Vec<J>), Obj(Vec<(String, J)>) }
impl J {
    fn get(&self, k: &str) -> Option<&J> {
        if let J::Obj(v) = self { v.iter().find(|(kk, _)| kk == k).map(|(_, vv)| vv) } else { None }
    }
    fn idx(&self, i: usize) -> Option<&J> {
        if let J::Arr(v) = self { v.get(i) } else { None }
    }
    fn as_str(&self) -> Option<&str> { if let J::Str(s) = self { Some(s) } else { None } }
    fn as_f64(&self) -> Option<f64> { if let J::Num(n) = self { Some(*n) } else { None } }
    fn as_string(&self) -> String { self.as_str().unwrap_or("").to_string() }
    fn as_i64(&self) -> i64 { self.as_f64().unwrap_or(0.0) as i64 }
    fn as_bool(&self) -> bool { if let J::Bool(b) = self { *b } else { false } }
    fn to_json(&self) -> String {
        match self {
            J::Null => String::from("null"),
            J::Bool(b) => b.to_string(),
            J::Num(n) => if n.fract() == 0.0 { (*n as i64).to_string() } else { n.to_string() },
            J::Str(s) => json_str(s),
            J::Arr(a) => format!("[{}]", a.iter().map(|x| x.to_json()).collect::<Vec<_>>().join(",")),
            J::Obj(o) => format!("{{{}}}", o.iter().map(|(k, v)| format!("{}:{}", json_str(k), v.to_json())).collect::<Vec<_>>().join(",")),
        }
    }
}

fn jws(b: &[char], i: &mut usize) { while *i < b.len() && b[*i].is_whitespace() { *i += 1; } }
fn jstr(b: &[char], i: &mut usize) -> String {
    if *i < b.len() && b[*i] == '"' { *i += 1; }
    let mut s = String::new();
    while *i < b.len() && b[*i] != '"' {
        if b[*i] == '\\' && *i + 1 < b.len() {
            *i += 1;
            match b[*i] { 'n' => s.push('\n'), 't' => s.push('\t'), 'r' => s.push('\r'), c => s.push(c) }
        } else { s.push(b[*i]); }
        *i += 1;
    }
    if *i < b.len() { *i += 1; }
    s
}
fn jval(b: &[char], i: &mut usize) -> J {
    jws(b, i);
    if *i >= b.len() { return J::Null; }
    match b[*i] {
        '{' => {
            *i += 1;
            let mut o = Vec::new();
            loop {
                jws(b, i);
                if *i >= b.len() || b[*i] == '}' { if *i < b.len() { *i += 1; } break; }
                let k = jstr(b, i);
                jws(b, i);
                if *i < b.len() && b[*i] == ':' { *i += 1; }
                o.push((k, jval(b, i)));
                jws(b, i);
                if *i < b.len() && b[*i] == ',' { *i += 1; }
            }
            J::Obj(o)
        }
        '[' => {
            *i += 1;
            let mut a = Vec::new();
            loop {
                jws(b, i);
                if *i >= b.len() || b[*i] == ']' { if *i < b.len() { *i += 1; } break; }
                a.push(jval(b, i));
                jws(b, i);
                if *i < b.len() && b[*i] == ',' { *i += 1; }
            }
            J::Arr(a)
        }
        '"' => J::Str(jstr(b, i)),
        't' => { *i += 4; J::Bool(true) }
        'f' => { *i += 5; J::Bool(false) }
        'n' => { *i += 4; J::Null }
        _ => {
            let st = *i;
            while *i < b.len() && (b[*i].is_ascii_digit() || b[*i] == '-' || b[*i] == '+' || b[*i] == '.' || b[*i] == 'e' || b[*i] == 'E') { *i += 1; }
            if *i == st { *i += 1; return J::Null; }
            let s: String = b[st..*i].iter().collect();
            J::Num(s.parse().unwrap_or(0.0))
        }
    }
}
fn jparse(s: &str) -> J { let b: Vec<char> = s.chars().collect(); let mut i = 0; jval(&b, &mut i) }
"#;

const SERVER_MAIN: &str = r#"fn reason(code: u16) -> &'static str {
    match code { 200 => "OK", 404 => "Not Found", 501 => "Not Implemented", _ => "OK" }
}

fn serve_static(path: &str) -> (u16, &'static str, String) {
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    let full = format!("static/{}", rel);
    let ctype = if full.ends_with(".js") { "text/javascript" }
        else if full.ends_with(".css") { "text/css" }
        else { "text/html; charset=utf-8" };
    match std::fs::read_to_string(&full) {
        Ok(c) => (200, ctype, c),
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
    serve_static(path)
}

fn handle_conn(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf)?;
    if n == 0 { return Ok(()); }
    let req = String::from_utf8_lossy(&buf[..n]).to_string();
    let first = req.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    let body = req.splitn(2, "\r\n\r\n").nth(1).unwrap_or("");
    let (code, ctype, payload) = dispatch(method, path, body);
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code, reason(code), ctype, payload.as_bytes().len(), payload
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

fn main() {
    let addr = "127.0.0.1:8080";
    let listener = TcpListener::bind(addr).expect("xeres: cannot bind 127.0.0.1:8080");
    println!("xeres app serving http://{}", addr);
    for stream in listener.incoming() {
        if let Ok(mut s) = stream {
            // One thread per connection: an idle/slow socket (e.g. a browser's
            // speculative connection) must not block the accept loop.
            std::thread::spawn(move || { let _ = handle_conn(&mut s); });
        }
    }
}
"#;

// Sync endpoint: a generic id->row-JSON store, merged last-write-wins by a
// Lamport counter. No per-model code — client rows are already secret-free.
const SYNC_SERVER: &str = r#"use std::sync::{Mutex, OnceLock};

struct CollState { rows: std::collections::HashMap<String, (String, u64)>, lamport: u64 }
fn sync_store() -> &'static Mutex<std::collections::HashMap<String, CollState>> {
    static S: OnceLock<Mutex<std::collections::HashMap<String, CollState>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn sync_dispatch(coll: &str, body: &str) -> String {
    let req = jparse(body);
    let mut guard = sync_store().lock().unwrap();
    let cs = guard.entry(coll.to_string()).or_insert_with(|| CollState { rows: std::collections::HashMap::new(), lamport: 0 });
    if let Some(J::Arr(ops)) = req.get("ops") {
        for op in ops {
            let kind = op.get("kind").and_then(|j| j.as_str()).unwrap_or("");
            let id = op.get("id").and_then(|j| j.as_str()).unwrap_or("").to_string();
            if id.is_empty() { continue; }
            let lam = op.get("lamport").and_then(|j| j.as_f64()).unwrap_or(0.0) as u64;
            let seen = cs.rows.get(&id).map(|(_, v)| *v).unwrap_or(0);
            if lam < seen { continue; }
            if kind == "put" {
                let row = op.get("row").map(|j| j.to_json()).unwrap_or_else(|| String::from("null"));
                cs.rows.insert(id.clone(), (row, lam));
            } else if kind == "del" {
                cs.rows.insert(id.clone(), (String::from("null"), lam));
            }
            if lam > cs.lamport { cs.lamport = lam; }
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
"#;

// ------------------------------------------------------------------ client.ts

fn gen_client(program: &XeresProgram) -> String {
    let mut out = String::new();
    out.push_str("// GENERATED by xeres — browser tier. Do not edit.\n\n");
    out.push_str(RPC_RUNTIME);
    out.push('\n');
    out.push_str(UID_FN);
    out.push('\n');

    // Enums — a string union (the variant names). String-backed end to end.
    for e in &program.enums {
        let union = e.variants.iter().map(|v| format!("\"{}\"", v)).collect::<Vec<_>>().join(" | ");
        let union = if union.is_empty() { "never".to_string() } else { union };
        out.push_str(&format!("export type {} = {};\n", e.name, union));
    }
    if !program.enums.is_empty() {
        out.push('\n');
    }

    // Model interfaces — secret fields are STRIPPED. They never reach the client.
    for m in &program.models {
        out.push_str(&format!("export interface {} {{\n", m.name));
        for p in &m.properties {
            if p.is_secret {
                out.push_str(&format!("  // {}: <stripped> — secret never crosses the wire\n", p.name));
                continue;
            }
            out.push_str(&format!("  {}: {};\n", p.name, map_ts_type(&p.data_type)));
        }
        out.push_str("}\n\n");
    }

    // Functions.
    for f in &program.functions {
        match f.env {
            EnvModifier::Server => {
                // Server fn → typed async RPC stub. The compiler writes the fetch.
                let params = f
                    .params
                    .iter()
                    .map(|p| format!("{}: {}", p.name, map_ts_type(&p.type_name)))
                    .collect::<Vec<_>>()
                    .join(", ");
                let ret = f
                    .return_type
                    .as_deref()
                    .map(map_ts_type)
                    .unwrap_or_else(|| "void".to_string());
                let arg_names = f
                    .params
                    .iter()
                    .map(|p| p.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push_str(&format!(
                    "// server fn — runs server-side; this is the auto-generated call site.\n\
                     export async function {name}({params}): Promise<{ret}> {{\n\
                     \x20 return __rpc(\"{name}\", [{args}]);\n\
                     }}\n\n",
                    name = f.name,
                    params = params,
                    ret = ret,
                    args = arg_names
                ));
            }
            EnvModifier::Ui | EnvModifier::None => {
                let params = f
                    .params
                    .iter()
                    .map(|p| format!("{}: {}", p.name, map_ts_type(&p.type_name)))
                    .collect::<Vec<_>>()
                    .join(", ");
                let ret = f
                    .return_type
                    .as_deref()
                    .map(map_ts_type)
                    .unwrap_or_else(|| "void".to_string());
                // A fn that awaits a server RPC is async (returns a Promise).
                let (kw, ret_ty) = if stmts_have_await(&f.body) {
                    ("export async function", format!("Promise<{}>", ret))
                } else {
                    ("export function", ret)
                };
                out.push_str(&format!("{} {}({}): {} {{\n", kw, f.name, params, ret_ty));
                for s in &f.body {
                    out.push_str(&format!("  {}\n", emit_stmt(s, "let", true)));
                }
                out.push_str("}\n\n");
            }
        }
    }

    // DOM runtime FIRST so on()/mount() exist before screens register handlers.
    if !program.screens.is_empty() {
        out.push_str(MOUNT_RUNTIME);
        out.push('\n');
    }

    // Screens + components: state cells, inline handlers, render functions.
    // (A component compiles to the same render-fn shape as a screen; it's just
    // invoked by name instead of auto-mounted.)
    let synced: HashSet<String> = program.states.iter().map(|s| s.name.clone()).collect();
    let components: HashMap<String, Vec<String>> = program
        .screens
        .iter()
        .filter(|s| s.is_component)
        .map(|s| (s.name.clone(), s.params.iter().map(|p| p.name.clone()).collect()))
        .collect();
    for sc in &program.screens {
        out.push_str(&gen_screen(sc, &synced, &components));
    }

    // Local-first sync: the runtime + one reactive collection per `synced state`.
    if !program.states.is_empty() {
        out.push_str(SYNC_RUNTIME);
        out.push('\n');
        for st in &program.states {
            out.push_str(&format!(
                "export const {name} = new SyncedCollection<{ty}>(\"{name}\");\n",
                name = st.name,
                ty = st.collection_type
            ));
        }
        out.push('\n');
    }

    // Register zero-arg ui/none fns as named handlers, then auto-start.
    if !program.screens.is_empty() {
        for f in &program.functions {
            if f.env != EnvModifier::Server && f.params.is_empty() {
                out.push_str(&format!("on(\"{name}\", {name});\n", name = f.name));
            }
        }
        // Redraw the view whenever a synced collection changes (local or pulled).
        for st in &program.states {
            out.push_str(&format!(
                "{name}.subscribe(() => {{ if (__draw) __draw(); }});\n",
                name = st.name
            ));
        }
        if let Some(sc) = program.screens.iter().find(|s| !s.is_component && s.params.is_empty()) {
            out.push_str(&format!(
                "\nexport function __start(rootId: string): void {{\n\
                 \x20 const el = document.getElementById(rootId);\n\
                 \x20 if (el) mount(el, () => {screen}());\n\
                 }}\n",
                screen = sc.name
            ));
        }
    }

    out
}

/// Emit one screen: its `state` object, inline click-handler functions, and a
/// reactive render function (re-reads state each draw).
fn gen_screen(
    sc: &crate::parser::ScreenNode,
    synced: &HashSet<String>,
    components: &HashMap<String, Vec<String>>,
) -> String {
    let mut out = String::new();
    let state_vars: HashSet<String> = sc.states.iter().map(|s| s.name.clone()).collect();

    if !sc.states.is_empty() {
        let inits = sc
            .states
            .iter()
            .map(|s| format!("{}: {}", s.name, emit_expr(&s.init, true)))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("const {}_state = {{ {} }};\n", sc.name, inits));
    }

    let mut em = ScreenEmit {
        screen: sc.name.clone(),
        state_vars,
        synced: synced.clone(),
        components: components.clone(),
        handlers: String::new(),
        hcount: 0,
        loop_ctx: None,
    };
    let render_expr = em.nodes(&sc.body);
    out.push_str(&em.handlers);

    let props = sc
        .params
        .iter()
        .map(|p| format!("{}: {}", p.name, map_ts_type(&p.type_name)))
        .collect::<Vec<_>>()
        .join(", ");
    let destr = if sc.states.is_empty() {
        String::new()
    } else {
        let names = sc
            .states
            .iter()
            .map(|s| s.name.clone())
            .collect::<Vec<_>>()
            .join(", ");
        format!("  const {{ {} }} = {}_state;\n", names, sc.name)
    };
    out.push_str(&format!(
        "export function {}({}): string {{\n{}  return {};\n}}\n\n",
        sc.name, props, destr, render_expr
    ));
    out
}

/// Where a `for` loop's items live, so per-item handlers can re-look-up the
/// bound item from its key at click time (event delegation).
#[derive(Clone)]
struct LoopCtx {
    var: String,
    /// JS expression (in module/handler scope) that yields the backing store:
    /// a `SyncedCollection` (keyed by `id`) or an array (keyed by index).
    source: String,
    synced: bool,
    /// For an array loop, the index binding name (`for x in arr` -> arr.map((x,
    /// idx)=>…)); items are re-bound by index, which works for any element type.
    index: Option<String>,
}

/// Walks a screen's view, allocating named handlers for inline `-> { ... }`
/// blocks and rewriting `state` reads/writes to the screen's state object.
struct ScreenEmit {
    screen: String,
    state_vars: HashSet<String>,
    /// Names of program-level `synced state` collections (iterate via `.all()`).
    synced: HashSet<String>,
    /// Component name -> its param names in declaration order (named args at a
    /// call site are reordered to this positional order).
    components: HashMap<String, Vec<String>>,
    handlers: String,
    hcount: usize,
    /// When inside `for var in <iterable>`, how to re-bind items in handlers.
    loop_ctx: Option<LoopCtx>,
}

impl ScreenEmit {
    fn nodes(&mut self, nodes: &[ViewNode]) -> String {
        match nodes.len() {
            0 => "\"\"".to_string(),
            1 => self.node(&nodes[0]),
            _ => {
                let mut s = String::from("`");
                for n in nodes {
                    s.push_str("${");
                    s.push_str(&self.node(n));
                    s.push('}');
                }
                s.push('`');
                s
            }
        }
    }

    fn node(&mut self, v: &ViewNode) -> String {
        match v {
            ViewNode::Element { tag, arg, style, bind, event, children } => {
                let html = map_tag(tag);
                let void = is_void(html);
                let mut s = String::from("`<");
                s.push_str(html);
                // Layout + styling. `row`/`column` are flex containers; an
                // explicit `style "..."` takes over the element's look (and
                // drops the default class so global rules don't fight it).
                let base_layout = match tag.as_str() {
                    "row" => Some("display:flex;flex-direction:row;"),
                    "column" => Some("display:flex;flex-direction:column;"),
                    "grid" => Some("display:grid;"),
                    _ => None,
                };
                match style {
                    Some(style_expr) => {
                        s.push_str(" style=\"");
                        if let Some(base) = base_layout {
                            s.push_str(base);
                        }
                        match style_expr {
                            // a literal CSS string is inlined (whitespace tidied)
                            Expr::Str(css) => s.push_str(&inline_css(css)),
                            // a dynamic style expression is interpolated
                            e => {
                                s.push_str("${");
                                s.push_str(&emit_expr(e, true));
                                s.push('}');
                            }
                        }
                        s.push('"');
                    }
                    None => match tag.as_str() {
                        "row" => s.push_str(" class=\"x-row\""),
                        "column" => s.push_str(" class=\"x-col\""),
                        _ => {}
                    },
                }
                match event {
                    Some(Handler::Call(e)) => {
                        s.push_str(" data-onclick=\"");
                        s.push_str(&emit_expr(e, true));
                        s.push('"');
                    }
                    Some(Handler::Block(stmts)) => {
                        let hname = format!("{}_h{}", self.screen, self.hcount);
                        self.hcount += 1;
                        let body: String = stmts
                            .iter()
                            .map(|st| emit_h_stmt(st, &self.screen, &self.state_vars))
                            .collect::<Vec<_>>()
                            .join(" ");
                        let kw = if stmts_have_await(stmts) { "async function" } else { "function" };
                        if let Some(ctx) = self.loop_ctx.clone() {
                            // Inside a `for`: re-bind the item from its key at
                            // click time (event delegation). Synced collections
                            // key by `id` (`.get`); arrays key by index (`[i]`),
                            // which works for any element type incl. primitives.
                            let (lookup, key) = if ctx.synced {
                                (format!("{}.get(__key)", ctx.source), format!("{}.id", ctx.var))
                            } else {
                                let idx = ctx.index.clone().unwrap_or_else(|| "0".to_string());
                                (format!("{}[__key]", ctx.source), idx)
                            };
                            self.handlers.push_str(&format!(
                                "{kw} {h}(__key) {{ const {v} = {lookup}; {b} }}\non(\"{h}\", {h});\n",
                                kw = kw, h = hname, v = ctx.var, lookup = lookup, b = body
                            ));
                            s.push_str(" data-onclick=\"");
                            s.push_str(&hname);
                            s.push_str("\" data-key=\"${");
                            s.push_str(&key);
                            s.push_str("}\"");
                        } else {
                            self.handlers.push_str(&format!(
                                "{kw} {h}() {{ {b} }}\non(\"{h}\", {h});\n",
                                kw = kw, h = hname, b = body
                            ));
                            s.push_str(" data-onclick=\"");
                            s.push_str(&hname);
                            s.push('"');
                        }
                    }
                    None => {}
                }
                // input placeholder from a string arg; `password` masks input
                if void {
                    if tag == "password" {
                        s.push_str(" type=\"password\"");
                    }
                    if let Some(Expr::Str(ph)) = arg {
                        s.push_str(" placeholder=\"");
                        s.push_str(ph);
                        s.push('"');
                    }
                }
                // two-way bind: value reflects state; oninput updates state.
                if let Some(var) = bind {
                    let bname = format!("{}:{}", self.screen, var);
                    self.handlers.push_str(&format!(
                        "onBind(\"{bn}\", (v) => {{ {sc}_state.{v} = v; }});\n",
                        bn = bname,
                        sc = self.screen,
                        v = var
                    ));
                    s.push_str(" value=\"${");
                    s.push_str(var);
                    s.push_str("}\" data-bind=\"");
                    s.push_str(&bname);
                    s.push('"');
                }
                if void {
                    s.push_str(" />`");
                    return s;
                }
                s.push('>');
                match arg {
                    Some(Expr::Str(t)) => s.push_str(t),
                    Some(e) => {
                        s.push_str("${");
                        s.push_str(&emit_expr(e, true));
                        s.push('}');
                    }
                    None => {}
                }
                for c in children {
                    s.push_str("${");
                    s.push_str(&self.node(c));
                    s.push('}');
                }
                s.push_str("</");
                s.push_str(html);
                s.push_str(">`");
                s
            }
            ViewNode::For { var, iter, body } => {
                // Is this a `synced` collection (iterate via `.all()`) or a
                // plain `List<T>` cell / prop (a JS array, iterate directly)?
                let synced = matches!(iter, Expr::Ident(c) if self.synced.contains(c));
                // Where handlers in the body re-look-up an item by its key:
                // synced -> the module-level collection; a screen `state` array
                // -> `<Screen>_state.<name>`; a prop array -> the prop name.
                let source = match iter {
                    Expr::Ident(c) if synced => Some(c.clone()),
                    Expr::Ident(c) if self.state_vars.contains(c) => {
                        Some(format!("{}_state.{}", self.screen, c))
                    }
                    Expr::Ident(c) => Some(c.clone()),
                    _ => None,
                };
                let index = if synced { None } else { Some(format!("__i_{}", var)) };
                let prev = self.loop_ctx.take();
                self.loop_ctx = source.map(|src| LoopCtx {
                    var: var.clone(),
                    source: src,
                    synced,
                    index: index.clone(),
                });
                let body_js = self.nodes(body);
                self.loop_ctx = prev;
                if synced {
                    format!("{}.all().map(({}) => {}).join(\"\")", emit_expr(iter, true), var, body_js)
                } else {
                    // Array: bind the index too, so handlers can re-key items.
                    format!(
                        "{}.map(({}, {}) => {}).join(\"\")",
                        emit_expr(iter, true),
                        var,
                        index.unwrap_or_else(|| "__i".to_string()),
                        body_js
                    )
                }
            }
            ViewNode::If { cond, then_body, else_body } => {
                let then_js = self.nodes(then_body);
                let else_js = self.nodes(else_body);
                format!("({} ? {} : {})", emit_expr(cond, true), then_js, else_js)
            }
            ViewNode::Component { name, args, .. } => {
                // Invoke the component's render fn with named args reordered to
                // the component's declared param order.
                let order = self.components.get(name);
                let positional: Vec<String> = match order {
                    Some(params) => params
                        .iter()
                        .map(|pname| {
                            args.iter()
                                .find(|(f, _)| f == pname)
                                .map(|(_, v)| emit_expr(v, true))
                                .unwrap_or_else(|| "undefined".to_string())
                        })
                        .collect(),
                    // Unknown component (checker already errored): emit args as-is.
                    None => args.iter().map(|(_, v)| emit_expr(v, true)).collect(),
                };
                format!("{}({})", name, positional.join(", "))
            }
        }
    }
}

/// Handler-statement emitter: rewrites `state` cells to `<Screen>_state.x`.
fn emit_h_stmt(s: &Stmt, screen: &str, sv: &HashSet<String>) -> String {
    match s {
        Stmt::Assign { name, value } => {
            let target = if sv.contains(name) {
                format!("{}_state.{}", screen, name)
            } else {
                name.clone()
            };
            format!("{} = {};", target, emit_h_expr(value, screen, sv))
        }
        Stmt::Let { name, value, .. } => format!("let {} = {};", name, emit_h_expr(value, screen, sv)),
        Stmt::Return(e) => format!("return {};", emit_h_expr(e, screen, sv)),
        Stmt::Expr(e) => format!("{};", emit_h_expr(e, screen, sv)),
        Stmt::Try { body, handler } => {
            let b = body.iter().map(|x| emit_h_stmt(x, screen, sv)).collect::<Vec<_>>().join(" ");
            let h = handler.iter().map(|x| emit_h_stmt(x, screen, sv)).collect::<Vec<_>>().join(" ");
            format!("try {{ {} }} catch (_e) {{ {} }}", b, h)
        }
        Stmt::If { cond, then_body, else_body } => {
            let then = then_body.iter().map(|x| emit_h_stmt(x, screen, sv)).collect::<Vec<_>>().join(" ");
            if else_body.is_empty() {
                format!("if ({}) {{ {} }}", emit_h_expr(cond, screen, sv), then)
            } else {
                let els = else_body.iter().map(|x| emit_h_stmt(x, screen, sv)).collect::<Vec<_>>().join(" ");
                format!("if ({}) {{ {} }} else {{ {} }}", emit_h_expr(cond, screen, sv), then, els)
            }
        }
        Stmt::For { var, iter, body } => {
            let b = body.iter().map(|x| emit_h_stmt(x, screen, sv)).collect::<Vec<_>>().join(" ");
            if let Expr::Range { start, end } = iter {
                format!(
                    "for (let {v} = {s}; {v} < {e}; {v}++) {{ {b} }}",
                    v = var, s = emit_h_expr(start, screen, sv), e = emit_h_expr(end, screen, sv), b = b
                )
            } else {
                format!("for (const {v} of {it}) {{ {b} }}", v = var, it = emit_h_expr(iter, screen, sv), b = b)
            }
        }
        Stmt::While { cond, body } => {
            let b = body.iter().map(|x| emit_h_stmt(x, screen, sv)).collect::<Vec<_>>().join(" ");
            format!("while ({}) {{ {} }}", emit_h_expr(cond, screen, sv), b)
        }
        Stmt::Break => "break;".to_string(),
        Stmt::Continue => "continue;".to_string(),
        Stmt::Match { scrutinee, arms } => {
            let mut out = format!("switch ({}) {{ ", emit_h_expr(scrutinee, screen, sv));
            for arm in arms {
                match &arm.pattern {
                    MatchPat::Wildcard => out.push_str("default: { "),
                    MatchPat::Variant(v) => out.push_str(&format!("case {:?}: {{ ", v)),
                }
                let b = arm.body.iter().map(|x| emit_h_stmt(x, screen, sv)).collect::<Vec<_>>().join(" ");
                out.push_str(&b);
                out.push_str(" break; } ");
            }
            out.push('}');
            out
        }
    }
}

fn emit_h_expr(e: &Expr, screen: &str, sv: &HashSet<String>) -> String {
    match e {
        Expr::Ident(v) => {
            if sv.contains(v) {
                format!("{}_state.{}", screen, v)
            } else {
                v.clone()
            }
        }
        Expr::Int(n) => n.to_string(),
        Expr::Float(f) => format!("{:?}", f),
        Expr::Str(s) => format!("{:?}", s),
        Expr::Bool(b) => b.to_string(),
        Expr::Field { base, field } => {
            if let Expr::Ident(name) = base.as_ref() {
                if name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                    return format!("{:?}", field); // `Enum.Variant` -> variant string
                }
            }
            format!("{}.{}", emit_h_expr(base, screen, sv), field)
        }
        Expr::Call { callee, args } => {
            if callee == "now" && args.is_empty() {
                return "Date.now()".to_string();
            }
            let a: Vec<String> = args.iter().map(|x| emit_h_expr(x, screen, sv)).collect();
            let arg = |i: usize| a.get(i).cloned().unwrap_or_default();
            match callee.as_str() {
                "abs" => return format!("Math.abs({})", arg(0)),
                "min" => return format!("Math.min({}, {})", arg(0), arg(1)),
                "max" => return format!("Math.max({}, {})", arg(0), arg(1)),
                _ => {}
            }
            format!("{}({})", callee, a.join(", "))
        }
        Expr::Unary { op, expr } => {
            let sym = match op {
                UnOp::Neg => "-",
                UnOp::Not => "!",
            };
            format!("{}{}", sym, emit_h_expr(expr, screen, sv))
        }
        Expr::Binary { op, left, right } => format!(
            "({} {} {})",
            emit_h_expr(left, screen, sv),
            binop_sym(*op),
            emit_h_expr(right, screen, sv)
        ),
        Expr::Declassify(inner) => emit_h_expr(inner, screen, sv),
        Expr::Await(inner) => format!("await {}", emit_h_expr(inner, screen, sv)),
        Expr::MethodCall { receiver, method, args } => {
            if method == "or" && args.len() == 1 {
                return format!(
                    "({} ?? {})",
                    emit_h_expr(receiver, screen, sv),
                    emit_h_expr(&args[0], screen, sv)
                );
            }
            let recv = emit_h_expr(receiver, screen, sv);
            let a: Vec<String> = args.iter().map(|x| emit_h_expr(x, screen, sv)).collect();
            if let Some(s) = emit_string_method(&recv, method, &a, true) {
                return s;
            }
            format!("{}.{}({})", recv, method, a.join(", "))
        }
        Expr::NoneLit => "null".to_string(),
        Expr::ListLit(items) => {
            let body = items.iter().map(|x| emit_h_expr(x, screen, sv)).collect::<Vec<_>>().join(", ");
            format!("[{}]", body)
        }
        Expr::Ternary { cond, then, otherwise } => format!(
            "({} ? {} : {})",
            emit_h_expr(cond, screen, sv),
            emit_h_expr(then, screen, sv),
            emit_h_expr(otherwise, screen, sv)
        ),
        // Record in a handler is a client object literal; rewrite state refs.
        Expr::Record { fields, .. } => {
            let body = fields
                .iter()
                .map(|(f, v)| format!("{}: {}", f, emit_h_expr(v, screen, sv)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{ {} }}", body)
        }
        Expr::Range { start, end } => format!(
            "Array.from({{length: ({e}) - ({s})}}, (_, __i) => __i + ({s}))",
            s = emit_h_expr(start, screen, sv), e = emit_h_expr(end, screen, sv)
        ),
    }
}

/// Does a body / expression contain an `await` (so its fn must be `async`)?
fn stmts_have_await(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s| match s {
        Stmt::Let { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::Return(value)
        | Stmt::Expr(value) => expr_has_await(value),
        Stmt::Try { body, handler } => stmts_have_await(body) || stmts_have_await(handler),
        Stmt::If { cond, then_body, else_body } => {
            expr_has_await(cond) || stmts_have_await(then_body) || stmts_have_await(else_body)
        }
        Stmt::For { iter, body, .. } => expr_has_await(iter) || stmts_have_await(body),
        Stmt::While { cond, body } => expr_has_await(cond) || stmts_have_await(body),
        Stmt::Match { scrutinee, arms } => {
            expr_has_await(scrutinee) || arms.iter().any(|a| stmts_have_await(&a.body))
        }
        Stmt::Break | Stmt::Continue => false,
    })
}

fn expr_has_await(e: &Expr) -> bool {
    match e {
        Expr::Await(_) => true,
        Expr::Field { base, .. } => expr_has_await(base),
        Expr::Call { args, .. } => args.iter().any(expr_has_await),
        Expr::Unary { expr, .. } => expr_has_await(expr),
        Expr::Binary { left, right, .. } => expr_has_await(left) || expr_has_await(right),
        Expr::Declassify(inner) => expr_has_await(inner),
        Expr::MethodCall { receiver, args, .. } => {
            expr_has_await(receiver) || args.iter().any(expr_has_await)
        }
        Expr::Record { fields, .. } => fields.iter().any(|(_, v)| expr_has_await(v)),
        Expr::ListLit(items) => items.iter().any(expr_has_await),
        Expr::Ternary { cond, then, otherwise } => {
            expr_has_await(cond) || expr_has_await(then) || expr_has_await(otherwise)
        }
        Expr::Range { start, end } => expr_has_await(start) || expr_has_await(end),
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) | Expr::Ident(_)
        | Expr::NoneLit => false,
    }
}

const MOUNT_RUNTIME: &str = r#"// ---- xeres dom runtime ----
type XHandler = (key?: string) => void | Promise<void>;
const __handlers = new Map<string, XHandler>();
const __binds = new Map<string, (v: string) => void>();
let __draw: (() => void) | null = null;   // set by mount; called on reactive updates
export function on(name: string, fn: XHandler): void { __handlers.set(name, fn); }
export function onBind(name: string, fn: (v: string) => void): void { __binds.set(name, fn); }

// Render a screen into `el`, then wire events. Clicks re-render afterwards;
// input binds update state WITHOUT re-rendering (so the field keeps focus).
export function mount(el: HTMLElement, render: () => string): void {
  const draw = () => {
    el.innerHTML = render();
    el.querySelectorAll<HTMLElement>("[data-onclick]").forEach((node) => {
      const name = node.getAttribute("data-onclick") || "";
      const key = node.getAttribute("data-key") || undefined;
      node.onclick = async () => { const h = __handlers.get(name); if (h) await h(key); draw(); };
    });
    el.querySelectorAll<HTMLInputElement>("[data-bind]").forEach((node) => {
      const name = node.getAttribute("data-bind") || "";
      node.oninput = () => { const b = __binds.get(name); if (b) b(node.value); };
    });
  };
  __draw = draw;
  draw();
}
"#;

// ------------------------------------------------------------------ index.html

/// Generate the host page. A screen whose root carries an explicit `style`
/// "owns the canvas": it renders full-bleed on a neutral page (no centered
/// card, logo, or purple gradient). Unstyled apps keep the branded shell.
fn gen_index(program: &XeresProgram) -> String {
    let mut out = String::new();
    let first = program.screens.iter().find(|s| !s.is_component && s.params.is_empty());
    let bleed = first.map(screen_is_bleed).unwrap_or(false);

    if bleed {
        // Full-bleed: just the mount point on a neutral page.
        out.push_str(INDEX_HEAD_BLEED);
        out.push_str("<div id=\"app\"></div>");
        out.push_str(
            "<script type=\"module\">import { __start } from \"./client.js\"; __start(\"app\");</script>",
        );
        out.push_str("</body></html>");
        return out;
    }

    out.push_str(INDEX_HEAD);
    if first.is_some() {
        out.push_str("<div id=\"app\"></div>");
    } else {
        out.push_str("<div id=\"app\" class=\"hint\">Add a <code>ui screen Name { … }</code> to app.xrs.</div>");
    }
    out.push_str("<footer>powered by <b>Xeres</b> · tier-safe web · zero framework runtime</footer>");
    out.push_str("</main>");
    if first.is_some() {
        out.push_str(
            "<script type=\"module\">import { __start } from \"./client.js\"; __start(\"app\");</script>",
        );
    }
    out.push_str("</body></html>");
    out
}

/// A screen "owns the canvas" when one of its top-level view nodes is a styled
/// element — the dev has taken explicit control of the page's look.
fn screen_is_bleed(sc: &crate::parser::ScreenNode) -> bool {
    sc.body
        .iter()
        .any(|n| matches!(n, ViewNode::Element { style: Some(_), .. }))
}

const INDEX_HEAD: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Xeres app</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center;
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif; color: #e6e6ef;
  background: radial-gradient(900px 500px at 50% -10%, #241546 0%, #13151a 60%); }
.x-app { display: flex; flex-direction: column; align-items: center; text-align: center; padding: 2rem; gap: .25rem; }
.x-logo { font-size: 5rem; line-height: 1; margin-bottom: 1rem;
  background: linear-gradient(135deg, #a855f7, #6366f1); -webkit-background-clip: text; background-clip: text; color: transparent;
  filter: drop-shadow(0 0 26px rgba(124, 58, 237, .45)); }
#app h1 { font-size: 2.8rem; margin: .2rem 0; letter-spacing: -.02em; color: #c084fc; }
#app .x-col { display: flex; flex-direction: column; align-items: center; gap: .5rem; }
#app .x-row { display: flex; align-items: center; gap: .5rem; }
#app span { color: #a4a4c0; }
#app input { padding: .6rem .85rem; font-size: 1rem; border: 1px solid #3a3d48; border-radius: .5rem;
  background: #1c1f27; color: #e6e6ef; min-width: 18rem; }
#app input:focus { outline: none; border-color: #7c3aed; }
#app input::placeholder { color: #6f6f88; }
#app button { padding: .55rem 1.2rem; font-size: 1rem; border: 1px solid #7c3aed; border-radius: .5rem;
  background: #7c3aed; color: #fff; cursor: pointer; transition: background .15s; }
#app button:hover { background: #6d28d9; }
.hint { color: #7a7a96; }
.hint code { color: #d8b4fe; background: rgba(255,255,255,.06); padding: .1rem .4rem; border-radius: .3rem; }
footer { color: #6f6f88; font-size: .85rem; margin-top: 2rem; }
footer b { color: #a9a9c2; }
</style>
</head>
<body>
<main class="x-app">
<div class="x-logo">&#9670;</div>
"#;

// Full-bleed host page for screens that style their own root. No centered card,
// no logo/footer, no purple gradient — the screen controls the whole viewport.
// Nested unstyled `row`/`column` still get sensible flex defaults; `button` and
// `input` get neutral (theme-agnostic) styling that inline `style` can override.
const INDEX_HEAD_BLEED: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Xeres app</title>
<style>
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body { min-height: 100vh; font-family: Inter, system-ui, -apple-system, "Segoe UI", sans-serif; }
#app { min-height: 100vh; }
#app .x-col { display: flex; flex-direction: column; gap: .5rem; }
#app .x-row { display: flex; gap: .5rem; }
#app button { font: inherit; padding: .5rem 1rem; border: 0; border-radius: .5rem; cursor: pointer; }
#app input { font: inherit; padding: .5rem .75rem; border: 1px solid #cbd5e1; border-radius: .5rem; }
</style>
</head>
<body>
"#;

const UID_FN: &str = r#"function uid(): string {
  return (typeof crypto !== "undefined" && crypto.randomUUID)
    ? crypto.randomUUID()
    : Date.now().toString(36) + Math.random().toString(36).slice(2);
}
"#;

const RPC_RUNTIME: &str = "\
async function __rpc<T>(name: string, args: unknown[]): Promise<T> {
  const res = await fetch(`/__xeres/${name}`, {
    method: \"POST\",
    headers: { \"content-type\": \"application/json\" },
    body: JSON.stringify(args),
  });
  if (!res.ok) throw new Error(`xeres rpc ${name} failed: ${res.status}`);
  return res.json() as Promise<T>;
}
";

// Local-first sync runtime. Shape: on-device store + offline oplog + network
// trawler, with last-write-wins merge by a Lamport counter. Swap MemoryStore
// for a sql.js / cr-sqlite adapter to get real on-device SQLite + CRDT merge.
const SYNC_RUNTIME: &str = r#"// ---- xeres local-first sync runtime (spike) ----
type XOpKind = "put" | "del";
interface XOp<T> { kind: XOpKind; id: string; row: T | null; lamport: number; }

export interface LocalStore<T> {
  load(): { rows: Map<string, T>; versions: Map<string, number>; lamport: number };
  persist(rows: Map<string, T>, versions: Map<string, number>, lamport: number): void;
}

// Default adapter: in-memory mirror, snapshotted to localStorage. Replace with a
// SQLite-backed adapter (sql.js / cr-sqlite) without changing SyncedCollection.
class MemoryStore<T> implements LocalStore<T> {
  constructor(private key: string) {}
  load() {
    try {
      const raw = typeof localStorage !== "undefined" ? localStorage.getItem(this.key) : null;
      if (raw) {
        const o = JSON.parse(raw);
        return {
          rows: new Map(Object.entries(o.rows ?? {})) as Map<string, T>,
          versions: new Map(Object.entries(o.versions ?? {})) as Map<string, number>,
          lamport: o.lamport ?? 0,
        };
      }
    } catch { /* fall through to empty */ }
    return { rows: new Map<string, T>(), versions: new Map<string, number>(), lamport: 0 };
  }
  persist(rows: Map<string, T>, versions: Map<string, number>, lamport: number) {
    if (typeof localStorage === "undefined") return;
    localStorage.setItem(this.key, JSON.stringify({
      rows: Object.fromEntries(rows),
      versions: Object.fromEntries(versions),
      lamport,
    }));
  }
}

export class SyncedCollection<T extends { id: string }> {
  private rows = new Map<string, T>();
  private versions = new Map<string, number>();
  private pending: XOp<T>[] = [];
  private lamport = 0;
  private subs = new Set<(rows: T[]) => void>();

  constructor(private name: string, private store: LocalStore<T> = new MemoryStore<T>("xeres:" + name)) {
    const snap = store.load();
    this.rows = snap.rows; this.versions = snap.versions; this.lamport = snap.lamport;
    if (typeof addEventListener !== "undefined") addEventListener("online", () => { void this.sync(); });
    if (typeof setInterval !== "undefined") setInterval(() => { void this.sync(); }, 2000); // trawler
  }

  all(): T[] { return [...this.rows.values()]; }
  get(id: string): T | undefined { return this.rows.get(id); }

  subscribe(fn: (rows: T[]) => void): () => void {
    this.subs.add(fn); fn(this.all());
    return () => { this.subs.delete(fn); };
  }

  add(row: T): void {
    this.lamport++;
    const op: XOp<T> = { kind: "put", id: row.id, row, lamport: this.lamport };
    this.applyLocal(op); this.pending.push(op); this.commit(); void this.sync();
  }

  remove(id: string): void {
    this.lamport++;
    const op: XOp<T> = { kind: "del", id, row: null, lamport: this.lamport };
    this.applyLocal(op); this.pending.push(op); this.commit(); void this.sync();
  }

  // Last-write-wins by Lamport counter. Returns whether state changed.
  private applyLocal(op: XOp<T>): boolean {
    const seen = this.versions.get(op.id) ?? -1;
    if (op.lamport < seen) return false;
    this.versions.set(op.id, op.lamport);
    if (op.kind === "del") this.rows.delete(op.id);
    else if (op.row) this.rows.set(op.id, op.row);
    return true;
  }

  private commit(): void {
    this.store.persist(this.rows, this.versions, this.lamport);
    const rows = this.all();
    this.subs.forEach((f) => f(rows));
  }

  // Network trawler step: flush the offline oplog, pull authoritative changes,
  // merge. Fully offline-safe — any failure leaves the queue intact for retry.
  async sync(): Promise<void> {
    if (typeof navigator !== "undefined" && navigator.onLine === false) return;
    let res: Response;
    try {
      res = await fetch(`/__xeres/sync/${this.name}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ since: this.lamport, ops: this.pending }),
      });
    } catch { return; }
    if (!res.ok) return;
    const remote = (await res.json()) as { lamport: number; ops: XOp<T>[] };
    let changed = false;
    for (const op of remote.ops ?? []) changed = this.applyLocal(op) || changed;
    this.pending = [];
    this.lamport = Math.max(this.lamport, remote.lamport ?? this.lamport);
    if (changed) this.commit();
  }
}
"#;

// ------------------------------------------------------------------ shared

/// One expression printer for BOTH targets: the operators in this subset
/// (+ - * / == != < > <= >= && || ! and field access / calls) are spelled
/// identically in Rust and TypeScript.
fn emit_expr(e: &Expr, ts: bool) -> String {
    match e {
        Expr::Int(n) => n.to_string(),
        Expr::Float(f) => format!("{:?}", f),
        // Rust strings are owned end-to-end (fields, lists, returns all expect String).
        Expr::Str(s) => if ts { format!("{:?}", s) } else { format!("String::from({:?})", s) },
        Expr::Bool(b) => b.to_string(),
        Expr::Ident(v) => v.clone(),
        Expr::Field { base, field } => {
            // `Enum.Variant` (Capitalized base) -> the variant string; enums are
            // string-backed. A lowercase base is an ordinary field access.
            if let Expr::Ident(name) = base.as_ref() {
                if name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                    return if ts { format!("{:?}", field) } else { format!("String::from({:?})", field) };
                }
            }
            format!("{}.{}", emit_expr(base, ts), field)
        }
        Expr::Call { callee, args } => {
            // now() — epoch millis. Browser: Date.now(); server: the now() helper.
            if callee == "now" && args.is_empty() {
                return if ts { "Date.now()".to_string() } else { "now()".to_string() };
            }
            let a: Vec<String> = args.iter().map(|x| emit_expr(x, ts)).collect();
            let arg = |i: usize| a.get(i).cloned().unwrap_or_default();
            // math stdlib (tier-specific spelling)
            match callee.as_str() {
                "abs" if ts => return format!("Math.abs({})", arg(0)),
                "abs" => return format!("({}).abs()", arg(0)),
                "min" if ts => return format!("Math.min({}, {})", arg(0), arg(1)),
                "min" => return format!("({}).min({})", arg(0), arg(1)),
                "max" if ts => return format!("Math.max({}, {})", arg(0), arg(1)),
                "max" => return format!("({}).max({})", arg(0), arg(1)),
                _ => {}
            }
            format!("{}({})", callee, a.join(", "))
        }
        Expr::Unary { op, expr } => {
            let sym = match op {
                UnOp::Neg => "-",
                UnOp::Not => "!",
            };
            format!("{}{}", sym, emit_expr(expr, ts))
        }
        Expr::Binary { op, left, right } => {
            format!("({} {} {})", emit_expr(left, ts), binop_sym(*op), emit_expr(right, ts))
        }
        // declassify is a server-only, audited identity at the value level.
        Expr::Declassify(inner) => emit_expr(inner, ts),
        Expr::Await(inner) => format!("await {}", emit_expr(inner, ts)),
        Expr::MethodCall { receiver, method, args } => {
            // `db.*` compiles to Postgres helper calls (server tier only).
            if matches!(receiver.as_ref(), Expr::Ident(n) if n == "db") {
                let sql = args.first().map(|a| emit_expr(a, ts)).unwrap_or_else(|| "\"\"".into());
                let params = pg_params(args.get(1..).unwrap_or(&[]));
                return if method == "exec" {
                    format!("db_exec(&({}), {})", sql, params)
                } else {
                    format!("db_query(&({}), {})", sql, params)
                };
            }
            // `optional.or(default)` — TS `??`, Rust `unwrap_or`.
            if method == "or" && args.len() == 1 {
                let r = emit_expr(receiver, ts);
                let d = emit_expr(&args[0], ts);
                return if ts {
                    format!("({} ?? {})", r, d)
                } else {
                    format!("{}.clone().unwrap_or({})", r, d)
                };
            }
            let recv = emit_expr(receiver, ts);
            let a: Vec<String> = args.iter().map(|x| emit_expr(x, ts)).collect();
            // String stdlib methods (tier-specific spelling).
            if let Some(s) = emit_string_method(&recv, method, &a, ts) {
                return s;
            }
            format!("{}.{}({})", recv, method, a.join(", "))
        }
        Expr::NoneLit => if ts { "null".to_string() } else { "None".to_string() },
        Expr::ListLit(items) => {
            let body = items.iter().map(|x| emit_expr(x, ts)).collect::<Vec<_>>().join(", ");
            if ts {
                format!("[{}]", body)
            } else {
                format!("vec![{}]", body)
            }
        }
        // Ternary: TS keeps `?:`; Rust spells it as an if-else expression.
        Expr::Ternary { cond, then, otherwise } => {
            if ts {
                format!("({} ? {} : {})", emit_expr(cond, ts), emit_expr(then, ts), emit_expr(otherwise, ts))
            } else {
                format!("(if {} {{ {} }} else {{ {} }})", emit_expr(cond, ts), emit_expr(then, ts), emit_expr(otherwise, ts))
            }
        }
        // Record literal. TS: a plain object. Rust: fields pass through
        // `.into()` (covers T -> T and the T -> Option<T> coercion) and any
        // omitted Optional/List fields are filled by struct update.
        Expr::Record { name, fields } => {
            if ts {
                let body = fields
                    .iter()
                    .map(|(f, v)| format!("{}: {}", f, emit_expr(v, ts)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{{ {} }}", body)
            } else {
                let body = fields
                    .iter()
                    .map(|(f, v)| format!("{}: ({}).into()", f, emit_expr(v, ts)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{} {{ {}, ..Default::default() }}", name, body)
            }
        }
        // `a..b` as a value: TS array / Rust Vec (the for-loop forms below
        // consume ranges directly without materializing a Vec).
        Expr::Range { start, end } => {
            if ts {
                format!(
                    "Array.from({{length: ({e}) - ({s})}}, (_, __i) => __i + ({s}))",
                    s = emit_expr(start, ts), e = emit_expr(end, ts)
                )
            } else {
                format!("(({}..{}).collect::<Vec<i64>>())", emit_expr(start, ts), emit_expr(end, ts))
            }
        }
    }
}

fn emit_stmt(s: &Stmt, let_kw: &str, ts: bool) -> String {
    let block = |body: &[Stmt]| body.iter().map(|x| emit_stmt(x, let_kw, ts)).collect::<Vec<_>>().join(" ");
    match s {
        Stmt::Let { name, value, .. } => format!("{} {} = {};", let_kw, name, emit_expr(value, ts)),
        Stmt::Assign { name, value } => format!("{} = {};", name, emit_expr(value, ts)),
        Stmt::Return(e) => format!("return {};", emit_expr(e, ts)),
        Stmt::Expr(e) => format!("{};", emit_expr(e, ts)),
        // browser-only (checker R16); the Rust tier never sees a Try.
        Stmt::Try { body, handler } => {
            format!("try {{ {} }} catch (_e) {{ {} }}", block(body), block(handler))
        }
        Stmt::If { cond, then_body, else_body } => {
            let head = if ts {
                format!("if ({})", emit_expr(cond, ts))
            } else {
                format!("if {}", emit_expr(cond, ts))
            };
            if else_body.is_empty() {
                format!("{} {{ {} }}", head, block(then_body))
            } else {
                format!("{} {{ {} }} else {{ {} }}", head, block(then_body), block(else_body))
            }
        }
        Stmt::For { var, iter, body } => {
            if let Expr::Range { start, end } = iter {
                let (s, e) = (emit_expr(start, ts), emit_expr(end, ts));
                if ts {
                    format!("for (let {v} = {s}; {v} < {e}; {v}++) {{ {b} }}", v = var, s = s, e = e, b = block(body))
                } else {
                    format!("for {v} in {s}..{e} {{ {b} }}", v = var, s = s, e = e, b = block(body))
                }
            } else if ts {
                format!("for (const {v} of {it}) {{ {b} }}", v = var, it = emit_expr(iter, ts), b = block(body))
            } else {
                // clone so the source binding stays usable after the loop
                format!("for {v} in {it}.clone() {{ {b} }}", v = var, it = emit_expr(iter, ts), b = block(body))
            }
        }
        Stmt::While { cond, body } => {
            let head = if ts {
                format!("while ({})", emit_expr(cond, ts))
            } else {
                format!("while {}", emit_expr(cond, ts))
            };
            format!("{} {{ {} }}", head, block(body))
        }
        Stmt::Break => "break;".to_string(),
        Stmt::Continue => "continue;".to_string(),
        // enums are string-backed: TS switches on the string, Rust matches the
        // variant strings via `.as_str()` (with a `_` arm for exhaustiveness).
        Stmt::Match { scrutinee, arms } => {
            if ts {
                let mut out = format!("switch ({}) {{ ", emit_expr(scrutinee, ts));
                for arm in arms {
                    match &arm.pattern {
                        MatchPat::Wildcard => out.push_str("default: { "),
                        MatchPat::Variant(v) => out.push_str(&format!("case {:?}: {{ ", v)),
                    }
                    out.push_str(&block(&arm.body));
                    out.push_str(" break; } ");
                }
                out.push('}');
                out
            } else {
                let mut out = format!("match ({}).as_str() {{ ", emit_expr(scrutinee, ts));
                let mut has_wild = false;
                for arm in arms {
                    match &arm.pattern {
                        MatchPat::Wildcard => {
                            out.push_str("_ => { ");
                            has_wild = true;
                        }
                        MatchPat::Variant(v) => out.push_str(&format!("{:?} => {{ ", v)),
                    }
                    out.push_str(&block(&arm.body));
                    out.push_str(" } ");
                }
                if !has_wild {
                    out.push_str("_ => {} ");
                }
                out.push('}');
                out
            }
        }
    }
}

/// Postgres parameter list: `&[&arg as &(dyn ToSql + Sync), ...]`.
fn pg_params(args: &[Expr]) -> String {
    if args.is_empty() {
        return "&[]".to_string();
    }
    let items = args
        .iter()
        .map(|a| format!("&{} as &(dyn ToSql + Sync)", emit_expr(a, false)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{}]", items)
}

/// Server-side statement emitter. Maps `db.query_one(...)` / `db.query(...)`
/// onto the target model in both `return` and typed-`let` position; otherwise
/// falls back to the normal statement emitter.
fn emit_server_stmt(s: &Stmt, f: &FunctionNode, program: &XeresProgram) -> String {
    // `return db.query_*(...)` — mapped onto the function's return type.
    if let Stmt::Return(Expr::MethodCall { receiver, method, args }) = s {
        if matches!(receiver.as_ref(), Expr::Ident(n) if n == "db") {
            if let Some(ret) = &f.return_type {
                if let Some(expr) = db_map_expr(method, args, ret, program) {
                    return format!("return {};", expr);
                }
            }
        }
    }
    // `let u: Model = db.query_*(...)` — mapped onto the annotated type, so a
    // server fn can fetch a row and compute on it (e.g. verify a password hash).
    if let Stmt::Let { name, type_ann: Some(ty), value: Expr::MethodCall { receiver, method, args } } = s {
        if matches!(receiver.as_ref(), Expr::Ident(n) if n == "db") {
            if let Some(expr) = db_map_expr(method, args, ty, program) {
                return format!("let mut {} = {};", name, expr);
            }
        }
    }
    // `let mut` on the server: control flow makes reassignment common
    // (`total = total + i`); Rust needs the binding mutable.
    emit_stmt(s, "let mut", false)
}

/// Rust expression that runs `db.query_one`/`db.query` and maps rows onto `ty`:
/// `query_one` -> `Model` (row required) or `Optional<Model>` (graceful miss);
/// `query` -> `List<Model>`. Shared by `return` and typed-`let` lowering.
fn db_map_expr(method: &str, args: &[Expr], ty: &str, program: &XeresProgram) -> Option<String> {
    let sql = args.first().map(|a| emit_expr(a, false)).unwrap_or_else(|| "\"\"".into());
    let params = pg_params(args.get(1..).unwrap_or(&[]));
    if method == "query_one" {
        if let Some(model_name) = generic_inner("Optional", ty) {
            let model = program.models.iter().find(|m| m.name == model_name)?;
            let fields = row_fields(model);
            return Some(format!(
                "{{ let __rows = db_query(&({sql}), {params}); \
                 match __rows.into_iter().next() {{ Some(__r) => Some({model} {{ {fields} }}), None => None }} }}",
                sql = sql, params = params, model = model_name, fields = fields
            ));
        }
        let model = program.models.iter().find(|m| m.name == ty)?;
        let fields = row_fields(model);
        return Some(format!(
            "{{ let __rows = db_query(&({sql}), {params}); \
             let __r = __rows.into_iter().next().expect(\"xeres: query_one returned no rows\"); \
             {model} {{ {fields} }} }}",
            sql = sql, params = params, model = ty, fields = fields
        ));
    }
    if method == "query" {
        let model_name = generic_inner("List", ty)?;
        let model = program.models.iter().find(|m| m.name == model_name)?;
        let fields = row_fields(model);
        return Some(format!(
            "db_query(&({sql}), {params}).into_iter().map(|__r| {model} {{ {fields} }}).collect()",
            sql = sql, params = params, model = model_name, fields = fields
        ));
    }
    None
}

/// `name: __r.get("name"), ...` — map a postgres Row's columns onto a model.
fn row_fields(model: &crate::parser::ModelNode) -> String {
    model
        .properties
        .iter()
        .map(|p| format!("{n}: __r.get(\"{n}\")", n = p.name))
        .collect::<Vec<_>>()
        .join(", ")
}

// The `hash`/`verify` builtins, server side: Argon2id with a random salt,
// emitting/parsing a standard PHC string. Added only when the app uses them.
const CRYPTO_PRELUDE: &str = r#"use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash, rand_core::OsRng};

/// hash() — derive a salted Argon2id password hash (a self-describing PHC string).
fn hash(s: String) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(s.as_bytes(), &salt)
        .expect("xeres: password hashing failed")
        .to_string()
}
/// verify() — check a password against a stored PHC hash (false on any mismatch).
fn verify(password: String, stored: String) -> bool {
    match PasswordHash::new(&stored) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}
"#;

const DB_PRELUDE: &str = r#"use postgres::types::ToSql;

fn db_client() -> postgres::Client {
    let url = std::env::var("DATABASE_URL").expect("xeres: DATABASE_URL is not set");
    // TLS-capable connector: hosted Postgres (Supabase/Neon/RDS) requires SSL.
    // Honors sslmode in DATABASE_URL (e.g. ?sslmode=require / disable).
    let tls = postgres_native_tls::MakeTlsConnector::new(
        native_tls::TlsConnector::new().expect("xeres: TLS init failed"),
    );
    postgres::Client::connect(&url, tls).expect("xeres: database connection failed")
}
fn db_exec(sql: &str, params: &[&(dyn ToSql + Sync)]) -> i64 {
    db_client().execute(sql, params).map(|n| n as i64).unwrap_or(0)
}
fn db_query(sql: &str, params: &[&(dyn ToSql + Sync)]) -> Vec<postgres::Row> {
    db_client().query(sql, params).expect("xeres: database query failed")
}
"#;

/// String stdlib methods, spelled for each tier (`recv`/`args` are already
/// emitted). Returns None if `method` isn't a String method.
fn emit_string_method(recv: &str, method: &str, args: &[String], ts: bool) -> Option<String> {
    let arg = |i: usize| args.get(i).cloned().unwrap_or_default();
    Some(match (method, ts) {
        ("trim", true) => format!("{}.trim()", recv),
        ("trim", false) => format!("{}.trim().to_string()", recv),
        ("upper", true) => format!("{}.toUpperCase()", recv),
        ("upper", false) => format!("{}.to_uppercase()", recv),
        ("lower", true) => format!("{}.toLowerCase()", recv),
        ("lower", false) => format!("{}.to_lowercase()", recv),
        ("length", true) => format!("{}.length", recv),
        ("length", false) => format!("({}.chars().count() as i64)", recv),
        ("contains", true) => format!("{}.includes({})", recv, arg(0)),
        ("contains", false) => format!("{}.contains({}.as_str())", recv, arg(0)),
        ("split", true) => format!("{}.split({})", recv, arg(0)),
        ("split", false) => {
            format!("{}.split({}.as_str()).map(|__p| __p.to_string()).collect::<Vec<String>>()", recv, arg(0))
        }
        // replace-all on both tiers
        ("replace", true) => format!("{}.split({}).join({})", recv, arg(0), arg(1)),
        ("replace", false) => format!("{}.replace({}.as_str(), {}.as_str())", recv, arg(0), arg(1)),
        _ => return None,
    })
}

fn binop_sym(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        BinOp::Eq => "==",
        BinOp::NotEq => "!=",
        BinOp::Lt => "<",
        BinOp::Gt => ">",
        BinOp::LtEq => "<=",
        BinOp::GtEq => ">=",
        BinOp::And => "&&",
        BinOp::Or => "||",
    }
}

/// Inner type of a one-level generic, e.g. `("List", "List<User>") -> "User"`.
fn generic_inner<'a>(base: &str, ty: &'a str) -> Option<&'a str> {
    ty.strip_prefix(base)
        .and_then(|r| r.strip_prefix('<'))
        .and_then(|r| r.strip_suffix('>'))
}

fn map_rust_type(name: &str) -> String {
    if let Some(inner) = generic_inner("List", name) {
        return format!("Vec<{}>", map_rust_type(inner));
    }
    if let Some(inner) = generic_inner("Optional", name) {
        return format!("Option<{}>", map_rust_type(inner));
    }
    match name {
        "String" => "String".to_string(),
        "Int" => "i64".to_string(),
        "Float" => "f64".to_string(),
        "Bool" => "bool".to_string(),
        // DateTime is epoch milliseconds — an i64 over the wire/db.
        "DateTime" => "i64".to_string(),
        other => other.to_string(),
    }
}

fn map_ts_type(name: &str) -> String {
    if let Some(inner) = generic_inner("List", name) {
        return format!("{}[]", map_ts_type(inner));
    }
    if let Some(inner) = generic_inner("Optional", name) {
        return format!("({} | null)", map_ts_type(inner));
    }
    match name {
        "String" => "string".to_string(),
        "Int" | "Float" | "DateTime" => "number".to_string(),
        "Bool" => "boolean".to_string(),
        other => other.to_string(),
    }
}

/// Tidy a literal `style "..."` string into a single-line CSS attribute value:
/// collapse the (often multi-line, indented) source whitespace to single spaces
/// and escape `"` so it can't terminate the HTML attribute.
fn inline_css(css: &str) -> String {
    css.split_whitespace().collect::<Vec<_>>().join(" ").replace('"', "&quot;")
}

/// HTML void elements have no children/closing tag.
fn is_void(html_tag: &str) -> bool {
    matches!(html_tag, "input" | "br" | "img" | "hr")
}

fn map_tag(tag: &str) -> &str {
    match tag {
        "column" => "div",
        "row" => "div",
        "box" => "div",       // neutral container — no layout opinion
        "grid" => "div",      // CSS grid container (display:grid added by codegen)
        "heading" => "h1",
        "subheading" => "h2",
        "title" => "h3",      // smaller section title
        "text" => "span",
        "paragraph" => "p",
        "button" => "button",
        "password" => "input",
        other => other,
    }
}
