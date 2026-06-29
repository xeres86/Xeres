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

use crate::frontend::parser::{
    BinOp, EnvModifier, Expr, FunctionNode, Handler, MatchPat, Param, ScreenNode, Stmt, UnOp,
    ViewNode, XeresProgram,
};
use std::collections::{HashMap, HashSet};

thread_local! {
    /// Declared `endpoint` names for the program being generated, so `emit_expr`
    /// can recognize `Name.get/post(...)` egress calls without threading the
    /// program through every emitter. Set once at the start of `generate`.
    static ENDPOINTS: std::cell::RefCell<HashSet<String>> = std::cell::RefCell::new(HashSet::new());
}

fn is_endpoint_name(n: &str) -> bool {
    ENDPOINTS.with(|e| e.borrow().contains(n))
}

pub fn generate(
    program: &XeresProgram,
    _returns_secret: &HashMap<String, bool>,
) -> (String, String, String, String) {
    ENDPOINTS.with(|e| {
        *e.borrow_mut() = program.endpoints.iter().map(|x| x.name.clone()).collect();
    });
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
    // Signed `session` cookies (R24) ride an `auth` feature, mirroring the
    // compiler: the HMAC-SHA256 signer's crates are optional so a non-session
    // build stays lean, and `--features auth` turns the real signer on (a plain
    // build gets the inert stubs in SESSION_PRELUDE).
    if uses_session(program) {
        deps.push_str("hmac = { version = \"0.13\", optional = true }\n");
        deps.push_str("sha2 = { version = \"0.11\", optional = true }\n");
    }
    if !program.endpoints.is_empty() {
        deps.push_str("ureq = \"2\"\n");
    }
    // Exact Decimal money math (spec 18): rust_decimal, optional + gated behind a
    // `decimal` cargo feature (made default below) — exact base-10, no f64.
    if uses_decimal(program) {
        deps.push_str("rust_decimal = { version = \"1\", optional = true }\n");
    }
    // App-listener TLS (opt-in via `--features tls`), mirroring the compiler's own
    // `xeres serve --tls`: pure-Rust rustls on the `ring` backend, no system deps.
    // Optional, so a default build of the emitted crate stays HTTP-only and lean.
    deps.push_str("rustls = { version = \"0.23\", default-features = false, features = [\"ring\", \"std\", \"tls12\"], optional = true }\n");
    deps.push_str("rustls-pemfile = { version = \"2\", optional = true }\n");
    let mut tail = String::new();
    if !deps.is_empty() {
        tail.push_str(&format!("\n[dependencies]\n{}", deps));
    }
    // `tls` is always offered; `auth` only when the app uses sessions.
    let mut features = String::from("tls = [\"dep:rustls\", \"dep:rustls-pemfile\"]\n");
    if uses_session(program) {
        features.push_str("auth = [\"dep:hmac\", \"dep:sha2\"]\n");
    }
    // `decimal` carries the rust_decimal helpers; make it a default feature so the
    // ejected crate builds out of the box (drop it with --no-default-features).
    if uses_decimal(program) {
        features.push_str("decimal = [\"dep:rust_decimal\"]\ndefault = [\"decimal\"]\n");
    }
    tail.push_str(&format!("\n[features]\n{}", features));
    format!(
        "[package]\nname = \"xeres-app\"\nversion = \"0.0.1\"\nedition = \"2021\"\n\n\
         [[bin]]\nname = \"xeres-app\"\npath = \"src/main.rs\"\n{}",
        tail
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
        Stmt::Transaction(body) => body.iter().any(stmt_uses_auth),
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
        Expr::Declassify(i) | Expr::Await(i) | Expr::Raw(i) => expr_uses_auth(i),
        Expr::Record { fields, .. } => fields.iter().any(|(_, v)| expr_uses_auth(v)),
        Expr::ListLit(items) => items.iter().any(expr_uses_auth),
        Expr::Ternary { cond, then, otherwise } => {
            expr_uses_auth(cond) || expr_uses_auth(then) || expr_uses_auth(otherwise)
        }
        Expr::Range { start, end } => expr_uses_auth(start) || expr_uses_auth(end),
        Expr::Closure { body, .. } => expr_uses_auth(body),
        Expr::Index { base, index } => expr_uses_auth(base) || expr_uses_auth(index),
        _ => false,
    }
}

/// Does any function reference the `session` capability? The ejected server
/// doesn't support it yet (cookie threading is interpreter-only), so its
/// presence triggers a clean `compile_error!` rather than broken/insecure code.
fn uses_session(program: &XeresProgram) -> bool {
    program.functions.iter().any(|f| f.body.iter().any(stmt_uses_session))
}
fn stmt_uses_session(s: &Stmt) -> bool {
    match s {
        Stmt::Let { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::Return(value)
        | Stmt::Expr(value) => expr_uses_session(value),
        Stmt::Try { body, handler } => {
            body.iter().any(stmt_uses_session) || handler.iter().any(stmt_uses_session)
        }
        Stmt::If { cond, then_body, else_body } => {
            expr_uses_session(cond)
                || then_body.iter().any(stmt_uses_session)
                || else_body.iter().any(stmt_uses_session)
        }
        Stmt::For { iter, body, .. } => expr_uses_session(iter) || body.iter().any(stmt_uses_session),
        Stmt::While { cond, body } => expr_uses_session(cond) || body.iter().any(stmt_uses_session),
        Stmt::Match { scrutinee, arms } => {
            expr_uses_session(scrutinee) || arms.iter().any(|a| a.body.iter().any(stmt_uses_session))
        }
        Stmt::Transaction(body) => body.iter().any(stmt_uses_session),
        Stmt::Break | Stmt::Continue => false,
    }
}
fn expr_uses_session(e: &Expr) -> bool {
    let is_session = |x: &Expr| matches!(x, Expr::Ident(n) if n == "session");
    match e {
        Expr::Field { base, .. } => is_session(base) || expr_uses_session(base),
        Expr::MethodCall { receiver, args, .. } => {
            is_session(receiver) || expr_uses_session(receiver) || args.iter().any(expr_uses_session)
        }
        Expr::Call { args, .. } => args.iter().any(expr_uses_session),
        Expr::Unary { expr, .. } => expr_uses_session(expr),
        Expr::Binary { left, right, .. } => expr_uses_session(left) || expr_uses_session(right),
        Expr::Declassify(i) | Expr::Await(i) | Expr::Raw(i) => expr_uses_session(i),
        Expr::Record { fields, .. } => fields.iter().any(|(_, v)| expr_uses_session(v)),
        Expr::ListLit(items) => items.iter().any(expr_uses_session),
        Expr::Ternary { cond, then, otherwise } => {
            expr_uses_session(cond) || expr_uses_session(then) || expr_uses_session(otherwise)
        }
        Expr::Range { start, end } => expr_uses_session(start) || expr_uses_session(end),
        Expr::Closure { body, .. } => expr_uses_session(body),
        Expr::Index { base, index } => expr_uses_session(base) || expr_uses_session(index),
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
        Stmt::Transaction(body) => body.iter().any(stmt_uses_db),
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
        Expr::Declassify(i) | Expr::Await(i) | Expr::Raw(i) => expr_uses_db(i),
        Expr::Record { fields, .. } => fields.iter().any(|(_, v)| expr_uses_db(v)),
        Expr::ListLit(items) => items.iter().any(expr_uses_db),
        Expr::Ternary { cond, then, otherwise } => {
            expr_uses_db(cond) || expr_uses_db(then) || expr_uses_db(otherwise)
        }
        Expr::Range { start, end } => expr_uses_db(start) || expr_uses_db(end),
        Expr::Closure { body, .. } => expr_uses_db(body),
        Expr::Index { base, index } => expr_uses_db(base) || expr_uses_db(index),
        _ => false,
    }
}

/// Does the program use Decimal arithmetic? After the checker's typed desugaring
/// (spec 18) that surfaces as `__dec_*` builtin calls. Scans functions AND screens
/// (Decimal math runs on either tier) so both the server `rust_decimal` helpers +
/// dep and the client BigInt runtime are gated on a single, never-missing signal.
fn uses_decimal(program: &XeresProgram) -> bool {
    program.functions.iter().any(|f| f.body.iter().any(stmt_uses_decimal))
        || program.screens.iter().any(screen_uses_decimal)
}
fn screen_uses_decimal(s: &ScreenNode) -> bool {
    s.states.iter().any(|st| expr_uses_decimal(&st.init))
        || s.load.iter().any(stmt_uses_decimal)
        || s.body.iter().any(view_uses_decimal)
}
fn view_uses_decimal(v: &ViewNode) -> bool {
    match v {
        ViewNode::Element { arg, style, event, children, .. } => {
            arg.as_ref().is_some_and(expr_uses_decimal)
                || style.as_ref().is_some_and(expr_uses_decimal)
                || match event {
                    Some(Handler::Call(e)) => expr_uses_decimal(e),
                    Some(Handler::Block(stmts)) => stmts.iter().any(stmt_uses_decimal),
                    None => false,
                }
                || children.iter().any(view_uses_decimal)
        }
        ViewNode::For { iter, body, .. } => {
            expr_uses_decimal(iter) || body.iter().any(view_uses_decimal)
        }
        ViewNode::If { cond, then_body, else_body } => {
            expr_uses_decimal(cond)
                || then_body.iter().any(view_uses_decimal)
                || else_body.iter().any(view_uses_decimal)
        }
        ViewNode::Component { args, .. } => args.iter().any(|(_, v)| expr_uses_decimal(v)),
    }
}
fn stmt_uses_decimal(s: &Stmt) -> bool {
    match s {
        Stmt::Let { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::Return(value)
        | Stmt::Expr(value) => expr_uses_decimal(value),
        Stmt::Try { body, handler } => {
            body.iter().any(stmt_uses_decimal) || handler.iter().any(stmt_uses_decimal)
        }
        Stmt::If { cond, then_body, else_body } => {
            expr_uses_decimal(cond)
                || then_body.iter().any(stmt_uses_decimal)
                || else_body.iter().any(stmt_uses_decimal)
        }
        Stmt::For { iter, body, .. } => expr_uses_decimal(iter) || body.iter().any(stmt_uses_decimal),
        Stmt::While { cond, body } => expr_uses_decimal(cond) || body.iter().any(stmt_uses_decimal),
        Stmt::Match { scrutinee, arms } => {
            expr_uses_decimal(scrutinee) || arms.iter().any(|a| a.body.iter().any(stmt_uses_decimal))
        }
        Stmt::Transaction(body) => body.iter().any(stmt_uses_decimal),
        Stmt::Break | Stmt::Continue => false,
    }
}
fn expr_uses_decimal(e: &Expr) -> bool {
    match e {
        Expr::Call { callee, args } => {
            callee.starts_with("__dec_") || args.iter().any(expr_uses_decimal)
        }
        Expr::MethodCall { receiver, args, .. } => {
            expr_uses_decimal(receiver) || args.iter().any(expr_uses_decimal)
        }
        Expr::Field { base, .. } => expr_uses_decimal(base),
        Expr::Unary { expr, .. } => expr_uses_decimal(expr),
        Expr::Binary { left, right, .. } => expr_uses_decimal(left) || expr_uses_decimal(right),
        Expr::Declassify(i) | Expr::Await(i) | Expr::Raw(i) => expr_uses_decimal(i),
        Expr::Record { fields, .. } => fields.iter().any(|(_, v)| expr_uses_decimal(v)),
        Expr::ListLit(items) => items.iter().any(expr_uses_decimal),
        Expr::Ternary { cond, then, otherwise } => {
            expr_uses_decimal(cond) || expr_uses_decimal(then) || expr_uses_decimal(otherwise)
        }
        Expr::Range { start, end } => expr_uses_decimal(start) || expr_uses_decimal(end),
        Expr::Closure { body, .. } => expr_uses_decimal(body),
        Expr::Index { base, index } => expr_uses_decimal(base) || expr_uses_decimal(index),
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
    // Signed `session` cookie (R24): the interpreter's HMAC-SHA256 signer, ported
    // verbatim so a cookie minted by `xeres serve` verifies here and vice-versa.
    if uses_session(program) {
        out.push_str(SESSION_PRELUDE);
        out.push('\n');
    }
    // Exact Decimal money (spec 18): rust_decimal helpers, gated behind `decimal`.
    if uses_decimal(program) {
        out.push_str(DECIMAL_PRELUDE);
        out.push('\n');
    }
    // Egress endpoints (R26): the ureq helpers + a fixed base const and bearer
    // loader per declaration. The host is baked in here, never caller-supplied.
    if !program.endpoints.is_empty() {
        out.push_str(HTTP_PRELUDE);
        out.push('\n');
        for ep in &program.endpoints {
            out.push_str(&format!(
                "const __EP_{}_BASE: &str = \"{}\";\n",
                ep.name.to_uppercase(),
                ep.base
            ));
            let bearer = match ep.secrets.first() {
                Some((f, _)) => format!(
                    "std::env::var(\"{}_{}\").unwrap_or_default()",
                    ep.name.to_uppercase(),
                    f.to_uppercase()
                ),
                None => "String::new()".to_string(),
            };
            out.push_str(&format!(
                "fn __ep_{}_bearer() -> String {{ {} }}\n",
                ep.name.to_lowercase(),
                bearer
            ));
        }
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
        // `PartialEq` powers `List<Model>.contains` (spec 19). Not `Eq` — a model
        // may carry a `Float` field, which isn't `Eq`.
        out.push_str(&format!("#[derive(Debug, Clone, Default, PartialEq)]\npub struct {} {{\n", m.name));
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

    // Inbound API (spec 23): per-route handler fns + the `api_dispatch` router.
    // Emitted only when the app declares an `api` block.
    if !program.apis.is_empty() {
        out.push_str(&gen_api(program, &models));
        out.push('\n');
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

    // Weave session cookie recovery + Set-Cookie into the request loop. The
    // actor is recovered from a verified `xeres_session` cookie into a per-request
    // thread-local (read by `session.actor`); a `session.login`/`logout` records a
    // pending Set-Cookie, taken out after dispatch. Non-session apps get neither.
    let server_main = if uses_session(program) {
        SERVER_MAIN
            .replace("    //__XERES_RECOVER__", SESSION_RECOVER)
            .replace("    //__XERES_SETCOOKIE__", SESSION_SETCOOKIE)
    } else {
        SERVER_MAIN
            .replace("    //__XERES_RECOVER__\n", "")
            .replace("    //__XERES_SETCOOKIE__\n", "")
    };
    // R31 auth-route guard: refuse the SPA shell for a protected route without a
    // verified session (the actor was recovered into the thread-local just above).
    // Mirrors the guard in src/serve.rs. Only an app with an `auth` route needs it.
    let has_auth_route =
        program.screens.iter().any(|s| s.is_auth && !s.is_component && s.params.is_empty());
    let server_main = if has_auth_route {
        out.push_str(&gen_protected_paths(program));
        server_main.replace("    //__XERES_GUARD__", AUTH_GUARD)
    } else {
        server_main.replace("    //__XERES_GUARD__\n", "")
    };
    // Inbound API dispatch (spec 23): match a declared route before the SPA shell
    // fallback. Api responses are always JSON.
    let server_main = if program.apis.is_empty() {
        server_main.replace("    //__XERES_API__\n", "")
    } else {
        server_main.replace(
            "    //__XERES_API__",
            "    if let Some((__c, __j)) = api_dispatch(method, path, body) { return (__c, \"application/json\", __j); }",
        )
    };
    out.push_str(&server_main);
    out
}

/// Inbound API codegen (spec 23). Emits one handler fn per route (typed like a
/// server fn) + an `api_dispatch(method, path, body)` router that decodes the
/// JSON-object body into the body model, runs the handler, and wire-projects the
/// response (so `secret` fields can't appear). `Optional<T>` return ⇒ `None` is
/// a 404. The client tier ignores `api` — this surface is for external callers.
fn gen_api(program: &XeresProgram, models: &HashSet<&str>) -> String {
    let mut out = String::new();
    // Per-route handler fns.
    for (ai, api) in program.apis.iter().enumerate() {
        for (ri, route) in api.routes.iter().enumerate() {
            let hname = format!("__api_{}_{}", ai, ri);
            let params = match &route.body {
                Some(b) => format!("{}: {}", b.name, map_rust_type(&b.type_name)),
                None => String::new(),
            };
            let ret = match &route.return_type {
                Some(t) => format!(" -> {}", map_rust_type(t)),
                None => String::new(),
            };
            let synth = FunctionNode {
                env: EnvModifier::Server,
                is_auth: false,
                name: hname.clone(),
                params: route
                    .body
                    .iter()
                    .map(|b| Param { name: b.name.clone(), type_name: b.type_name.clone() })
                    .collect(),
                return_type: route.return_type.clone(),
                body: route.body_stmts.clone(),
                line: route.line,
                is_pub: false,
                module: api.module.clone(),
            };
            out.push_str(&format!("pub fn {}({}){} {{\n", hname, params, ret));
            for s in &synth.body {
                out.push_str(&format!("    {}\n", emit_server_stmt(s, &synth, program)));
            }
            out.push_str("}\n\n");
        }
    }
    // The router.
    out.push_str("fn api_dispatch(method: &str, path: &str, body: &str) -> Option<(u16, String)> {\n");
    out.push_str("    let _ = body;\n"); // silence unused when no route has a body
    out.push_str("    let __hit = match (method, path) {\n");
    for (ai, api) in program.apis.iter().enumerate() {
        for (ri, route) in api.routes.iter().enumerate() {
            let hname = format!("__api_{}_{}", ai, ri);
            let full = format!("{}{}", api.base, route.path);
            let method = route.method.as_str();
            let (pre, call) = match &route.body {
                Some(b) => {
                    let decode = decode_json_rust("Some(&__b)", &b.type_name, program, 0);
                    (format!("let __b = jparse(body); let __arg = {}; ", decode), format!("{}(__arg)", hname))
                }
                None => (String::new(), format!("{}()", hname)),
            };
            let respond = match &route.return_type {
                Some(t) if generic_inner("Optional", t).is_some() => {
                    let inner = generic_inner("Optional", t).unwrap();
                    let ser = wire_serialize("__v", inner, models);
                    format!("match {call} {{ Some(__v) => Some((200, {ser})), None => Some((404, String::new())) }}")
                }
                Some(t) => {
                    let ser = wire_serialize("__r", t, models);
                    format!("let __r = {call}; Some((200, {ser}))")
                }
                None => format!("{call}; Some((200, String::from(\"null\")))"),
            };
            out.push_str(&format!("        (\"{method}\", \"{full}\") => {{ {pre}{respond} }}\n"));
        }
    }
    out.push_str("        _ => None,\n    };\n");
    out.push_str("    if __hit.is_some() { return __hit; }\n");
    // An unmatched path UNDER a declared base is a genuine API miss — return a
    // JSON 404 rather than falling through to the SPA shell (which would serve
    // HTML for a typo'd endpoint). Truly-unrelated paths return None (→ SPA).
    let mut bases: Vec<&str> = program.apis.iter().map(|a| a.base.as_str()).collect();
    bases.sort();
    bases.dedup();
    let guard = bases
        .iter()
        .map(|b| format!("path.starts_with(\"{}\")", b))
        .collect::<Vec<_>>()
        .join(" || ");
    out.push_str(&format!("    if {guard} {{\n"));
    out.push_str("        return Some((404, String::from(\"{\\\"error\\\":\\\"not found\\\"}\")));\n");
    out.push_str("    }\n    None\n}\n\n");
    out
}

/// R31 — the generated `is_protected_path`: the literal set of `auth` route paths,
/// mirroring the client router's path map (first prop-less screen `/`, rest
/// `/<name>`). The default route can't be `auth`, so these are all `/<name>`.
fn gen_protected_paths(program: &XeresProgram) -> String {
    let navigable: Vec<_> =
        program.screens.iter().filter(|s| !s.is_component && s.params.is_empty()).collect();
    let default = navigable.first().map(|s| s.name.clone()).unwrap_or_default();
    let arms: Vec<String> = navigable
        .iter()
        .filter(|s| s.is_auth)
        .map(|s| {
            let p = if s.name == default { "/".to_string() } else { format!("/{}", s.name.to_lowercase()) };
            format!("{:?}", p)
        })
        .collect();
    format!("fn is_protected_path(p: &str) -> bool {{ matches!(p, {}) }}\n\n", arms.join(" | "))
}

/// Recover the actor from a verified session cookie into the per-request
/// thread-local, before dispatch (session apps only). Mirrors `serve.rs`.
const SESSION_RECOVER: &str = "    let __actor = cookie_value(&req, \"xeres_session\").and_then(|c| session_verify(&c));\n    session_set_actor(__actor);";

/// Emit any Set-Cookie recorded by `session.login`/`logout` during the call,
/// before the CSRF cookie (session apps only). Mirrors `serve.rs`.
const SESSION_SETCOOKIE: &str = "    if let Some(c) = session_take_cookie() {\n        cookies.push_str(&format!(\"Set-Cookie: {}\\r\\n\", c));\n    }";

/// R31 — the generated auth-route guard, spliced into `dispatch` (only for apps
/// with an `auth` route). `session_actor()` was set by SESSION_RECOVER before
/// dispatch, so `None` means no valid session ⇒ bounce to the public root.
const AUTH_GUARD: &str = "    if method == \"GET\" && session_actor().is_none() && is_protected_path(path) {\n        return (302, \"text/html\", String::from(\"/\"));\n    }";

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
    // String, Decimal (string-backed), and string-backed enums decode from JSON.
    if ty == "String" || ty == "Decimal" || program.enums.iter().any(|e| e.name == ty) {
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

const SERVER_HEAD: &str = include_str!("../../runtime/server_head.rs");

const SERVER_MAIN: &str = include_str!("../../runtime/server_main.rs");

// Sync endpoint: a generic, field-level LWW store. Each row is a map of
// field -> Cell (the field's raw-JSON value + its own Lamport stamp + site id),
// so concurrent edits to different fields of a row both survive. A delete is a
// row tombstone with its own stamp; a row stays visible unless its tombstone
// dominates every field stamp, so a late (lower-stamped) write can't resurrect
// it. Stamps form a total order (higher Lamport wins, ties broken by the stable
// site id) ⇒ replicas converge regardless of arrival order. No per-model code —
// client rows are already secret-free. This MUST stay identical to the merge in
// `src/serve.rs` (the two run modes would otherwise diverge).
const SYNC_SERVER: &str = include_str!("../../runtime/sync_server.rs");

// ------------------------------------------------------------------ client.ts

fn gen_client(program: &XeresProgram) -> String {
    let mut out = String::new();
    out.push_str("// GENERATED by xeres — browser tier. Do not edit.\n\n");
    out.push_str(RPC_RUNTIME);
    out.push('\n');
    out.push_str(UID_FN);
    out.push('\n');
    // Exact Decimal money math (spec 18): zero-dep BigInt fixed-point. Emitted
    // only when the app does Decimal arithmetic (keeps a plain bundle lean).
    if uses_decimal(program) {
        out.push_str(DECIMAL_RUNTIME);
        out.push('\n');
    }

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
        out.push_str(&gen_router(program));
    }

    out
}

/// The client router (P2): a route map over the prop-less, non-component
/// screens, `__navigate` (switch screen + push the URL), back/forward via
/// `popstate`, and `__start` (mount + resolve the initial URL). Each navigable
/// screen gets a path — the first/default screen is `/`, the rest `/<name>`.
/// A screen's `on load` runs whenever it's navigated to (generalizing P1's
/// mount hook). Empty when the program has no mountable screen (unchanged: no
/// auto-mount, as before).
fn gen_router(program: &XeresProgram) -> String {
    let navigable: Vec<&crate::frontend::parser::ScreenNode> = program
        .screens
        .iter()
        .filter(|s| !s.is_component && s.params.is_empty())
        .collect();
    let Some(default) = navigable.first() else {
        return String::new();
    };
    let path_of = |sc: &crate::frontend::parser::ScreenNode| -> String {
        if sc.name == default.name {
            "/".to_string()
        } else {
            format!("/{}", sc.name.to_lowercase())
        }
    };

    // Param routes (`route "/post/:id"`) match by pattern, not an exact path, so
    // they join the render/loader maps but not __path/__byPath. R32 keeps a param
    // route's props in sync with its `:name` segments.
    let param_routes: Vec<&crate::frontend::parser::ScreenNode> =
        program.screens.iter().filter(|s| !s.is_component && s.route.is_some()).collect();
    let all_routes: Vec<&crate::frontend::parser::ScreenNode> =
        navigable.iter().copied().chain(param_routes.iter().copied()).collect();

    let render = all_routes
        .iter()
        .map(|s| format!("{:?}: {}", s.name, s.name))
        .collect::<Vec<_>>()
        .join(", ");
    let paths = navigable
        .iter()
        .map(|s| format!("{:?}: {:?}", s.name, path_of(s)))
        .collect::<Vec<_>>()
        .join(", ");
    let by_path = navigable
        .iter()
        .map(|s| format!("{:?}: {:?}", path_of(s), s.name))
        .collect::<Vec<_>>()
        .join(", ");
    let loaders = all_routes
        .iter()
        .filter(|s| !s.load.is_empty())
        .map(|s| format!("{:?}: {}__load", s.name, s.name))
        .collect::<Vec<_>>()
        .join(", ");
    // R31 — protected (`auth`) routes the client router redirects away from when
    // the readable `xeres_auth` flag cookie is absent (server enforces too).
    let protected = navigable
        .iter()
        .filter(|s| s.is_auth)
        .map(|s| format!("{:?}: true", s.name))
        .collect::<Vec<_>>()
        .join(", ");
    // R32 — each param route as { screen, segs }: the URL pattern split on `/`,
    // with `:name` segments captured at match time and substituted on navigate.
    let param_route_entries = param_routes
        .iter()
        .map(|s| {
            let segs = s
                .route
                .as_deref()
                .unwrap_or("")
                .split('/')
                .map(|seg| format!("{:?}", seg))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{ screen: {:?}, segs: [{}] }}", s.name, segs)
        })
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"
// ---- xeres client router ----
const __render: Record<string, () => string> = {{ {render} }};
const __path: Record<string, string> = {{ {paths} }};
const __byPath: Record<string, string> = {{ {by_path} }};
const __loaders: Record<string, () => void | Promise<void>> = {{ {loaders} }};
const __defaultScreen = {default:?};
const __protected: Record<string, boolean> = {{ {protected} }};
let __screen = __defaultScreen;
let __params: Record<string, string> = {{}};
const __paramRoutes: Array<{{ screen: string; segs: string[] }}> = [ {param_routes} ];

// R32 — match a URL against the param-route patterns; on a hit, capture the
// `:name` segments into __params (the matched screen reads them, coerced).
function __matchRoute(path: string): string | null {{
  const parts = path.split("/");
  for (const r of __paramRoutes) {{
    if (r.segs.length !== parts.length) continue;
    const cap: Record<string, string> = {{}};
    let ok = true;
    for (let i = 0; i < r.segs.length; i++) {{
      const seg = r.segs[i];
      if (seg.startsWith(":")) cap[seg.slice(1)] = decodeURIComponent(parts[i]);
      else if (seg !== parts[i]) {{ ok = false; break; }}
    }}
    if (ok) {{ __params = cap; return r.screen; }}
  }}
  return null;
}}

// `navigate(Screen {{ id: x }})` (R32): set the params, build the URL from the
// route pattern, switch screen, run its loader.
export function __navigateTo(screen: string, params: Record<string, string>): void {{
  const r = __paramRoutes.find((x) => x.screen === screen);
  if (!r) return;
  __params = params;
  __screen = screen;
  const path = r.segs.map((s) => s.startsWith(":") ? encodeURIComponent(params[s.slice(1)] ?? "") : s).join("/") || "/";
  if (typeof history !== "undefined") history.pushState({{}}, "", path);
  if (__draw) __draw();
  const l = __loaders[screen]; if (l) l();
}}

// R31 — the readable `xeres_auth` flag (set alongside the HttpOnly session on
// login) lets the router bounce unauthenticated users off `auth` routes. It is
// only a UX hint: forging it reveals an empty shell, since data still needs the
// signed session (R24), and the server applies the same guard on shell requests.
function __authed(): boolean {{
  return typeof document !== "undefined"
    && document.cookie.split(";").some((c) => c.trim().startsWith("xeres_auth="));
}}
function __guard(name: string): string {{
  return (__protected[name] && !__authed()) ? __defaultScreen : name;
}}

export function __navigate(name: string): void {{
  if (!(name in __render)) return;
  name = __guard(name);
  __screen = name;
  if (typeof history !== "undefined") history.pushState({{}}, "", __path[name]);
  if (__draw) __draw();
  const l = __loaders[name]; if (l) l();
}}

function __routeFromUrl(): void {{
  const p = (typeof location !== "undefined") ? location.pathname : "/";
  __screen = __guard(__byPath[p] || __matchRoute(p) || __defaultScreen);
}}

if (typeof window !== "undefined") {{
  window.addEventListener("popstate", () => {{
    __routeFromUrl();
    if (__draw) __draw();
    const l = __loaders[__screen]; if (l) l();
  }});
}}

export function __start(rootId: string): void {{
  const el = document.getElementById(rootId);
  __routeFromUrl();
  if (el) mount(el, () => __render[__screen]());
  const l = __loaders[__screen]; if (l) l();
}}
__start("app");
"#,
        render = render,
        paths = paths,
        by_path = by_path,
        loaders = loaders,
        protected = protected,
        param_routes = param_route_entries,
        default = default.name,
    )
}

/// Emit one screen: its `state` object, inline click-handler functions, and a
/// reactive render function (re-reads state each draw).
fn gen_screen(
    sc: &crate::frontend::parser::ScreenNode,
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

    // A param route (`route "/post/:id"`) reads its props from the router's
    // `__params` (coerced by type), so its render/loader take no arguments; a
    // component takes its props as function args; a plain screen has none.
    let is_param_route = sc.route.is_some() && !sc.is_component;
    let (props, param_reads) = if is_param_route {
        let reads = sc
            .params
            .iter()
            .map(|p| {
                let v = if p.type_name == "Int" {
                    format!("Number(__params[{:?}])", p.name)
                } else {
                    format!("__params[{:?}]", p.name)
                };
                format!("  const {} = {};\n", p.name, v)
            })
            .collect::<String>();
        (String::new(), reads)
    } else {
        let props = sc
            .params
            .iter()
            .map(|p| format!("{}: {}", p.name, map_ts_type(&p.type_name)))
            .collect::<Vec<_>>()
            .join(", ");
        (props, String::new())
    };
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
        "export function {}({}): string {{\n{}{}  return {};\n}}\n\n",
        sc.name, props, param_reads, destr, render_expr
    ));

    // `on load { … }` — an async lifecycle fn run once on mount (P1). It may
    // await server fns; after it settles it triggers a redraw so fetched data
    // shows. State assignments rewrite to `<Screen>_state.x` via emit_h_stmt.
    if !sc.load.is_empty() {
        let body = sc
            .load
            .iter()
            .map(|s| emit_h_stmt(s, &sc.name, &em.state_vars))
            .collect::<Vec<_>>()
            .join("\n  ");
        out.push_str(&format!(
            "export async function {sc}__load(): Promise<void> {{\n{reads}  {body}\n  if (__draw) __draw();\n}}\n\n",
            sc = sc.name,
            reads = param_reads,
            body = body
        ));
    }
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
                // `link "Label" -> Screen` — a client-router anchor. The `->`
                // slot is a navigation target (checker R28), so it's rendered
                // specially (href from the route map + data-link), not via the
                // generic element path.
                if tag == "link" {
                    return link_node(arg, style, event);
                }
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
                            s.push_str("\" data-key=\"${__esc(");
                            s.push_str(&key);
                            s.push_str(")}\"");
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
                // void elements: input type, image src, or input placeholder.
                if void {
                    if tag == "password" {
                        s.push_str(" type=\"password\"");
                    }
                    if tag == "checkbox" {
                        s.push_str(" type=\"checkbox\"");
                    }
                    if tag == "number" {
                        s.push_str(" type=\"number\"");
                    }
                    if tag == "image" {
                        // the (string) arg is the image src — escaped (R22).
                        if let Some(e) = arg {
                            s.push_str(" src=\"${__esc(");
                            s.push_str(&emit_expr(e, true));
                            s.push_str(")}\"");
                        }
                    } else if let Some(Expr::Str(ph)) = arg {
                        s.push_str(" placeholder=\"");
                        s.push_str(ph);
                        s.push('"');
                    }
                }
                // two-way bind. `checkbox` reflects a Bool via `checked` (runtime
                // reads node.checked); `textarea` reflects via element content
                // (added below); everything else reflects via the `value` attr.
                if let Some(var) = bind {
                    let bname = format!("{}:{}", self.screen, var);
                    self.handlers.push_str(&format!(
                        "onBind(\"{bn}\", (v) => {{ {sc}_state.{v} = v; }});\n",
                        bn = bname,
                        sc = self.screen,
                        v = var
                    ));
                    if tag == "checkbox" {
                        s.push_str(" ${");
                        s.push_str(var);
                        s.push_str(" ? \"checked\" : \"\"} data-bind=\"");
                        s.push_str(&bname);
                        s.push('"');
                    } else if tag == "textarea" || tag == "select" {
                        s.push_str(" data-bind=\"");
                        s.push_str(&bname);
                        s.push('"');
                    } else if tag == "radio" {
                        // the data-bind + name go on each generated input (content).
                    } else {
                        s.push_str(" value=\"${__esc(");
                        s.push_str(var);
                        s.push_str(")}\" data-bind=\"");
                        s.push_str(&bname);
                        s.push('"');
                    }
                }
                if void {
                    s.push_str(" />`");
                    return s;
                }
                s.push('>');
                // A bound `textarea` carries its value as element content; a
                // `select` generates `<option>`s from its list arg (the bound
                // value is the selected one); every other tag emits its arg.
                if tag == "textarea" {
                    if let Some(var) = bind {
                        s.push_str("${__esc(");
                        s.push_str(var);
                        s.push_str(")}");
                    }
                } else if tag == "select" {
                    if let (Some(var), Some(opts)) = (bind, arg) {
                        s.push_str("${(");
                        s.push_str(&emit_expr(opts, true));
                        s.push_str(").map((__o) => `<option ${(");
                        s.push_str(var);
                        s.push_str(") === __o ? \"selected\" : \"\"}>${__esc(__o)}</option>`).join(\"\")}");
                    }
                } else if tag == "radio" {
                    if let (Some(var), Some(opts)) = (bind, arg) {
                        let bname = format!("{}:{}", self.screen, var);
                        s.push_str("${(");
                        s.push_str(&emit_expr(opts, true));
                        s.push_str(").map((__o) => `<label><input type=\"radio\" name=\"");
                        s.push_str(&bname);
                        s.push_str("\" value=\"${__esc(__o)}\" ${(");
                        s.push_str(var);
                        s.push_str(") === __o ? \"checked\" : \"\"} data-bind=\"");
                        s.push_str(&bname);
                        s.push_str("\" />${__esc(__o)}</label>`).join(\"\")}");
                    }
                } else {
                    match arg {
                        Some(Expr::Str(t)) => s.push_str(t),
                        // `raw(...)` — the single audited un-escaped HTML sink (R22).
                        Some(Expr::Raw(inner)) => {
                            s.push_str("${");
                            s.push_str(&emit_expr(inner, true));
                            s.push('}');
                        }
                        // Default: every interpolated value is HTML-escaped (R22).
                        Some(e) => {
                            s.push_str("${__esc(");
                            s.push_str(&emit_expr(e, true));
                            s.push_str(")}");
                        }
                        None => {}
                    }
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
        // `transaction` is server-only (R33); a ui handler never contains one.
        Stmt::Transaction(_) => String::new(),
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
            // decimal("19.99") — string-backed money; forward the inner string.
            if callee == "decimal" {
                return args
                    .first()
                    .map(|x| emit_h_expr(x, screen, sv))
                    .unwrap_or_else(|| "\"\"".to_string());
            }
            // Lowered Decimal ops (spec 18) → the zero-dep `__dec.*` BigInt runtime.
            if let Some(op) = callee.strip_prefix("__dec_") {
                let a = args.first().map(|x| emit_h_expr(x, screen, sv)).unwrap_or_default();
                let b = args.get(1).map(|x| emit_h_expr(x, screen, sv)).unwrap_or_default();
                return format!("__dec.{}({}, {})", op, a, b);
            }
            // `__list_contains(list, x)` — lowered `List.contains` (spec 19); a
            // structural (JSON) match so it agrees with the server/interp.
            if callee == "__list_contains" {
                let list = args.first().map(|x| emit_h_expr(x, screen, sv)).unwrap_or_default();
                let needle = args.get(1).map(|x| emit_h_expr(x, screen, sv)).unwrap_or_default();
                return format!("{}.some((__e) => JSON.stringify(__e) === JSON.stringify({}))", list, needle);
            }
            // Lowered `String + <scalar>` (spec 24) → JS `+` seeded with `""`.
            if callee == "__str_concat" {
                let a = args.first().map(|x| emit_h_expr(x, screen, sv)).unwrap_or_default();
                let b = args.get(1).map(|x| emit_h_expr(x, screen, sv)).unwrap_or_default();
                return format!("(\"\" + ({}) + ({}))", a, b);
            }
            // `navigate(Screen)` — the argument is a screen *name* (R28), lowered
            // to the router's `__navigate("Screen")` (switch screen + URL). A
            // `navigate(Screen { id: x })` is a typed-route-param nav (R32) →
            // `__navigateTo`, which builds the URL from the route pattern.
            if callee == "navigate" {
                if let Some(Expr::Record { name, fields }) = args.first() {
                    let ps = fields
                        .iter()
                        .map(|(f, v)| format!("{:?}: String({})", f, emit_h_expr(v, screen, sv)))
                        .collect::<Vec<_>>()
                        .join(", ");
                    return format!("__navigateTo({:?}, {{ {} }})", name, ps);
                }
                return format!("__navigate({})", nav_target_js(args));
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
        Expr::Declassify(inner) | Expr::Raw(inner) => emit_h_expr(inner, screen, sv),
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
            // Higher-order list ops (spec 19) — Array.map/filter/reduce; reduce's
            // args are `(callback, init)`, so reverse our `(init, closure)`.
            match method.as_str() {
                "map" if args.len() == 1 => {
                    return format!("{}.map({})", recv, emit_h_expr(&args[0], screen, sv))
                }
                "filter" if args.len() == 1 => {
                    return format!("{}.filter({})", recv, emit_h_expr(&args[0], screen, sv))
                }
                "reduce" if args.len() == 2 => {
                    return format!(
                        "{}.reduce({}, {})",
                        recv,
                        emit_h_expr(&args[1], screen, sv),
                        emit_h_expr(&args[0], screen, sv)
                    )
                }
                _ => {}
            }
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
        // Closure (spec 19): an arrow fn in the view tier.
        Expr::Closure { params, body } => {
            format!("({}) => {}", params.join(", "), emit_h_expr(body, screen, sv))
        }
        // `xs[i]` → `.at(i)` → Optional<T> (`?? null`).
        Expr::Index { base, index } => {
            let b = emit_h_expr(base, screen, sv);
            let i = emit_h_expr(index, screen, sv);
            emit_list_method(&b, "at", &[i], true).unwrap_or_default()
        }
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
        Stmt::Transaction(body) => stmts_have_await(body),
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
        Expr::Declassify(inner) | Expr::Raw(inner) => expr_has_await(inner),
        Expr::MethodCall { receiver, args, .. } => {
            expr_has_await(receiver) || args.iter().any(expr_has_await)
        }
        Expr::Record { fields, .. } => fields.iter().any(|(_, v)| expr_has_await(v)),
        Expr::ListLit(items) => items.iter().any(expr_has_await),
        Expr::Ternary { cond, then, otherwise } => {
            expr_has_await(cond) || expr_has_await(then) || expr_has_await(otherwise)
        }
        Expr::Range { start, end } => expr_has_await(start) || expr_has_await(end),
        Expr::Closure { body, .. } => expr_has_await(body),
        Expr::Index { base, index } => expr_has_await(base) || expr_has_await(index),
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) | Expr::Ident(_)
        | Expr::NoneLit => false,
    }
}

const MOUNT_RUNTIME: &str = include_str!("../../runtime/mount_runtime.ts");

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
            // Absolute path so a deep link to a nested route (e.g. `/post/123`)
            // still resolves the bundle (a relative `./client.js` would 404 as
            // `/post/client.js`).
            "<script type=\"module\" src=\"/client.js\"></script>",
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
            // Absolute path so a deep link to a nested route (e.g. `/post/123`)
            // still resolves the bundle (a relative `./client.js` would 404 as
            // `/post/client.js`).
            "<script type=\"module\" src=\"/client.js\"></script>",
        );
    }
    out.push_str("</body></html>");
    out
}

/// A screen "owns the canvas" when one of its top-level view nodes is a styled
/// element — the dev has taken explicit control of the page's look.
fn screen_is_bleed(sc: &crate::frontend::parser::ScreenNode) -> bool {
    sc.body
        .iter()
        .any(|n| matches!(n, ViewNode::Element { style: Some(_), .. }))
}

const INDEX_HEAD: &str = include_str!("../../runtime/index_head.html");

// Full-bleed host page for screens that style their own root. No centered card,
// no logo/footer, no purple gradient — the screen controls the whole viewport.
// Nested unstyled `row`/`column` still get sensible flex defaults; `button` and
// `input` get neutral (theme-agnostic) styling that inline `style` can override.
const INDEX_HEAD_BLEED: &str = include_str!("../../runtime/index_head_bleed.html");

const UID_FN: &str = include_str!("../../runtime/uid_fn.ts");

const RPC_RUNTIME: &str = "\
function __csrf(): string {
  return (document.cookie.match(/(?:^|;\\s*)xeres_csrf=([^;]*)/) || [])[1] || \"\";
}
async function __rpc<T>(name: string, args: unknown[]): Promise<T> {
  const res = await fetch(`/__xeres/${name}`, {
    method: \"POST\",
    headers: { \"content-type\": \"application/json\", \"x-csrf-token\": __csrf() },
    body: JSON.stringify(args),
  });
  if (!res.ok) throw new Error(`xeres rpc ${name} failed: ${res.status}`);
  return res.json() as Promise<T>;
}
";

// Exact Decimal money math (spec 18), browser tier. Zero-dep and exact: a scaled
// BigInt, never the binary `number`. A Decimal is a string end-to-end (parse ->
// compute -> format). The checker's typed desugaring lowers Decimal `+ - * < >
// <= >=` to `__dec.*` calls handled here; `Decimal * Int` accepts a number
// operand. Mirrors the server's rust_decimal helpers and the interpreter's i128
// core to the cent — the dual-backend parity rule.
const DECIMAL_RUNTIME: &str = include_str!("../../runtime/decimal_runtime.ts");

// Local-first sync runtime. Shape: on-device store + offline oplog + network
// trawler, with last-write-wins merge by a Lamport counter. Swap MemoryStore
// for a sql.js / cr-sqlite adapter to get real on-device SQLite + CRDT merge.
const SYNC_RUNTIME: &str = include_str!("../../runtime/sync_runtime.ts");

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
            // `session.actor` — the authenticated actor id (Optional<String>),
            // read from the per-request thread-local. Server-only (R24), so the
            // `ts` branch is unreachable; emit a harmless `null` if ever hit.
            if matches!(base.as_ref(), Expr::Ident(n) if n == "session") && field == "actor" {
                return if ts { "null".to_string() } else { "session_actor()".to_string() };
            }
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
            // decimal("19.99") — string-backed money. The constructor is the
            // identity over its string argument: a `String` literal already
            // emits as a JS string on the TS tier and `String::from("..")` on
            // the server tier, so just forward the inner expression.
            if callee == "decimal" {
                return args
                    .first()
                    .map(|a| emit_expr(a, ts))
                    .unwrap_or_else(|| if ts { "\"\"".to_string() } else { "String::new()".to_string() });
            }
            // Lowered Decimal ops (spec 18): the checker desugars Decimal
            // `+ - * < > <= >=` to these. Browser/shared (ts): the zero-dep
            // `__dec.*` BigInt runtime; server: the `rust_decimal` helpers, whose
            // operands are taken by reference (a Decimal is a `String`, an `Int` an
            // `i64`/`i32`, all `IntoDec`).
            if let Some(op) = callee.strip_prefix("__dec_") {
                let a = args.first().map(|x| emit_expr(x, ts)).unwrap_or_default();
                let b = args.get(1).map(|x| emit_expr(x, ts)).unwrap_or_default();
                return if ts {
                    format!("__dec.{}({}, {})", op, a, b)
                } else {
                    format!("__dec_{}(&({}), &({}))", op, a, b)
                };
            }
            // `__list_contains(list, x)` — lowered `List.contains` (spec 19), kept
            // distinct from `String.contains` (different per-tier spelling). TS uses
            // a structural (JSON) match so it agrees with the server/interp value
            // equality; Rust uses `Vec::contains` (models derive PartialEq).
            if callee == "__list_contains" {
                let list = args.first().map(|x| emit_expr(x, ts)).unwrap_or_default();
                let needle = args.get(1).map(|x| emit_expr(x, ts)).unwrap_or_default();
                return if ts {
                    format!("{}.some((__e) => JSON.stringify(__e) === JSON.stringify({}))", list, needle)
                } else {
                    format!("{}.contains(&({}))", list, needle)
                };
            }
            // Lowered `String + <scalar>` (spec 24): Rust uses `format!` (Display
            // coerces each operand: String/i64/f64/bool); TS uses `+` seeded with
            // `""` so numbers stringify rather than add.
            if callee == "__str_concat" {
                let a = args.first().map(|x| emit_expr(x, ts)).unwrap_or_default();
                let b = args.get(1).map(|x| emit_expr(x, ts)).unwrap_or_default();
                return if ts {
                    format!("(\"\" + ({}) + ({}))", a, b)
                } else {
                    format!("format!(\"{{}}{{}}\", {}, {})", a, b)
                };
            }
            // `navigate(Screen)` — browser-only (R28), so only the TS tier emits
            // it; lower to the router's `__navigate("Screen")`. The param form
            // `navigate(Screen { id: x })` (R32) lowers to `__navigateTo`.
            if callee == "navigate" {
                if let Some(Expr::Record { name, fields }) = args.first() {
                    let ps = fields
                        .iter()
                        .map(|(f, v)| format!("{:?}: String({})", f, emit_expr(v, ts)))
                        .collect::<Vec<_>>()
                        .join(", ");
                    return format!("__navigateTo({:?}, {{ {} }})", name, ps);
                }
                return format!("__navigate({})", nav_target_js(args));
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
        Expr::Declassify(inner) | Expr::Raw(inner) => emit_expr(inner, ts),
        Expr::Await(inner) => format!("await {}", emit_expr(inner, ts)),
        Expr::MethodCall { receiver, method, args } => {
            // `session.login(id)` / `session.logout()` — record a pending
            // Set-Cookie (the server emits it after the call). Mirrors
            // `interp::session_method`. Server-only (R24); the `ts` branch is
            // unreachable, so emit a harmless `undefined` if ever hit.
            if matches!(receiver.as_ref(), Expr::Ident(n) if n == "session") {
                if ts {
                    return "undefined".to_string();
                }
                return match method.as_str() {
                    "login" => {
                        let id = args.first().map(|a| emit_expr(a, ts)).unwrap_or_else(|| "String::new()".into());
                        format!("session_login(&({}))", id)
                    }
                    "logout" => "session_logout()".to_string(),
                    other => format!("session_{}()", other), // checker rejects other methods
                };
            }
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
            // `log.{info,warn,error}(msg)` — structured server-side log line (R27).
            if matches!(receiver.as_ref(), Expr::Ident(n) if n == "log") {
                let arg = args.first().map(|a| emit_expr(a, ts)).unwrap_or_else(|| "\"\"".into());
                return if ts {
                    format!("console.{}({})", method, arg) // server-only by R27; harmless fallback
                } else {
                    format!(
                        "eprintln!(\"{{{{\\\"level\\\":\\\"{}\\\",\\\"msg\\\":{{}}}}}}\", json_str(&({})))",
                        method, arg
                    )
                };
            }
            // endpoint egress: `Name.get(path)` / `Name.post(path, body)` (R26).
            // Host is the declared `base` (a generated const); only the path is
            // appended. Server-only, so the `ts` branch is unreachable.
            if let Expr::Ident(n) = receiver.as_ref() {
                if is_endpoint_name(n) {
                    if ts {
                        return "\"\"".to_string();
                    }
                    let path = args.first().map(|a| emit_expr(a, ts)).unwrap_or_else(|| "String::new()".into());
                    let base = format!("__EP_{}_BASE", n.to_uppercase());
                    let bearer = format!("__ep_{}_bearer()", n.to_lowercase());
                    return if method == "post" {
                        let body = args.get(1).map(|a| emit_expr(a, ts)).unwrap_or_else(|| "String::new()".into());
                        format!("http_post({}, &({}), &({}), &{})", base, path, body, bearer)
                    } else {
                        format!("http_get({}, &({}), &{})", base, path, bearer)
                    };
                }
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
            // Higher-order list ops (spec 19): the closure arg emits as `(x) => e`
            // (TS) / `|x| e` (Rust). TS uses Array.map/filter/reduce directly (but
            // reduce's args are `(callback, init)`); Rust iterates + collects (and
            // `fold` for reduce), cloning the receiver so the source list survives.
            match method.as_str() {
                "map" if args.len() == 1 => {
                    let cl = emit_expr(&args[0], ts);
                    return if ts {
                        format!("{}.map({})", recv, cl)
                    } else {
                        format!("{}.clone().into_iter().map({}).collect::<Vec<_>>()", recv, cl)
                    };
                }
                "filter" if args.len() == 1 => {
                    let cl = emit_expr(&args[0], ts);
                    return if ts {
                        format!("{}.filter({})", recv, cl)
                    } else {
                        format!("{}.clone().into_iter().filter({}).collect::<Vec<_>>()", recv, cl)
                    };
                }
                "reduce" if args.len() == 2 => {
                    let init = emit_expr(&args[0], ts);
                    let cl = emit_expr(&args[1], ts);
                    return if ts {
                        format!("{}.reduce({}, {})", recv, cl, init)
                    } else {
                        format!("{}.clone().into_iter().fold({}, {})", recv, init, cl)
                    };
                }
                _ => {}
            }
            let a: Vec<String> = args.iter().map(|x| emit_expr(x, ts)).collect();
            // String stdlib methods (tier-specific spelling).
            if let Some(s) = emit_string_method(&recv, method, &a, ts) {
                return s;
            }
            // List stdlib methods (spec 08) — safe accessors yield Optional<T>.
            if let Some(s) = emit_list_method(&recv, method, &a, ts) {
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
        // Closure (spec 19): only as a higher-order arg. TS arrow / Rust `|x| e`.
        Expr::Closure { params, body } => {
            let ps = params.join(", ");
            if ts {
                format!("({}) => {}", ps, emit_expr(body, ts))
            } else {
                format!("|{}| {}", ps, emit_expr(body, ts))
            }
        }
        // `xs[i]` index sugar → `.at(i)` → Optional<T>.
        Expr::Index { base, index } => {
            let b = emit_expr(base, ts);
            let i = emit_expr(index, ts);
            emit_list_method(&b, "at", &[i], ts).unwrap_or_default()
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
        // R33 — atomic block: BEGIN on a shared connection, run the body (its
        // `db.*` calls reuse that connection), COMMIT on normal completion or
        // ROLLBACK if any operation failed. Server-only, so `ts` never sees it.
        // Mirrors the interpreter. (A transaction directly in a fn body is emitted
        // by `emit_server_stmt` with full db-return mapping; this handles one
        // nested in control flow, where plain `db.exec` is the norm.)
        Stmt::Transaction(body) => {
            if ts {
                format!("{{ {} }}", block(body))
            } else {
                format!("{{ tx_begin(); {} tx_end(); }}", block(body))
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
    // `return endpoint.get(...)` / `let x: T = endpoint.get(...)` — decode the
    // JSON response into a model shape (spec 24). A `String` return stays raw.
    if let Stmt::Return(Expr::MethodCall { receiver, method, args }) = s {
        if let Expr::Ident(n) = receiver.as_ref() {
            if is_endpoint_name(n) && method == "get" {
                if let Some(expr) = f.return_type.as_deref().and_then(|ret| endpoint_map_expr(n, args, ret, program)) {
                    return format!("return {};", expr);
                }
            }
        }
    }
    if let Stmt::Let { name, type_ann: Some(ty), value: Expr::MethodCall { receiver, method, args } } = s {
        if let Expr::Ident(n) = receiver.as_ref() {
            if is_endpoint_name(n) && method == "get" {
                if let Some(expr) = endpoint_map_expr(n, args, ty, program) {
                    return format!("let mut {} = {};", name, expr);
                }
            }
        }
    }
    // `transaction { … }` — emit the body via `emit_server_stmt` so db.query_*
    // return-mapping still applies inside it, wrapped in BEGIN/COMMIT/ROLLBACK
    // (the body's db calls reuse the transaction's connection via the TX
    // thread-local in DB_PRELUDE).
    if let Stmt::Transaction(body) = s {
        let inner: String =
            body.iter().map(|x| emit_server_stmt(x, f, program)).collect::<Vec<_>>().join(" ");
        return format!("{{ tx_begin(); {} tx_end(); }}", inner);
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

/// Rust expression that runs `endpoint.get(path)` and decodes its JSON response
/// into a model shape `ty` (model / `List<Model>` / `Optional<Model>`), reusing
/// the recursive JSON decoder (spec 24). Returns `None` for a non-model `ty` (a
/// `String` return stays the raw body). Mirrors `db_map_expr`.
fn endpoint_map_expr(n: &str, args: &[Expr], ty: &str, program: &XeresProgram) -> Option<String> {
    let bare = generic_inner("List", ty).or_else(|| generic_inner("Optional", ty)).unwrap_or(ty);
    if !program.models.iter().any(|m| m.name == bare) {
        return None;
    }
    let path = args.first().map(|a| emit_expr(a, false)).unwrap_or_else(|| "String::new()".into());
    let base = format!("__EP_{}_BASE", n.to_uppercase());
    let bearer = format!("__ep_{}_bearer()", n.to_lowercase());
    let decode = decode_json_rust("Some(&__body)", ty, program, 0);
    Some(format!(
        "{{ let __body = jparse(&http_get({base}, &({path}), &{bearer})); {decode} }}"
    ))
}

/// `name: __r.get("name"), ...` — map a postgres Row's columns onto a model.
fn row_fields(model: &crate::frontend::parser::ModelNode) -> String {
    model
        .properties
        .iter()
        .map(|p| format!("{n}: __r.get(\"{n}\")", n = p.name))
        .collect::<Vec<_>>()
        .join(", ")
}

// The `hash`/`verify` builtins, server side: Argon2id with a random salt,
// emitting/parsing a standard PHC string. Added only when the app uses them.
const CRYPTO_PRELUDE: &str = include_str!("../../runtime/crypto_prelude.rs");

// The `session` capability, server side — a verbatim port of the interpreter's
// signed-cookie machinery (src/interp.rs). The cookie value is `<actor-id>.<hmac>`
// signed with HMAC-SHA256 over SESSION_SECRET, set `HttpOnly; Secure;
// SameSite=Strict`. The signing/verification is byte-identical to `xeres serve`,
// so a cookie minted by one run mode verifies under the other (build ≡ serve).
//
// The interpreter keeps the actor + a pending Set-Cookie in the `Interp` (a
// per-call store with interior mutability). The free-function server has no such
// `self`, so a per-request thread-local plays the same role: the request loop is
// one-thread-per-connection (Connection: close), so the actor set before dispatch
// and the cookie taken after never cross requests. The crypto rides the `auth`
// feature (same as hash/verify); a non-`auth` build gets the same inert stubs the
// interpreter uses.
const SESSION_PRELUDE: &str = include_str!("../../runtime/session_prelude.rs");

const HTTP_PRELUDE: &str = include_str!("../../runtime/http_prelude.rs");

const DB_PRELUDE: &str = include_str!("../../runtime/db_prelude.rs");

// Exact Decimal money math (spec 18 / R29), server tier. A Decimal is a `String`
// end-to-end; these helpers parse → compute exactly in base-10 (rust_decimal,
// never f64) → re-stringify. The checker's typed desugaring lowers Decimal
// `+ - * < > <= >=` to `__dec_*` calls handled here. `Decimal * Int` accepts an
// integer operand via `IntoDec`. Gated behind the `decimal` cargo feature (made
// default when the app uses Decimal). Mirrors the interpreter's i128 core and the
// browser's BigInt runtime to the cent — the dual-backend parity rule.
const DECIMAL_PRELUDE: &str = include_str!("../../runtime/decimal_prelude.rs");

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
        // Unified across String + List via the XLen trait (see SERVER_HEAD), so
        // `.length()` needs no receiver-type info at codegen time.
        ("length", true) => format!("{}.length", recv),
        ("length", false) => format!("({}).x_len()", recv),
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

/// List stdlib methods (spec 08). `first`/`last`/`at` are safe accessors that
/// lower to `Optional<T>` (TS `T | null`, Rust `Option<T>`): out-of-bounds (or
/// negative) is `none`, never a panic/`undefined`. `length` is handled by
/// `emit_string_method` via the `XLen` trait (works for String + List alike).
fn emit_list_method(recv: &str, method: &str, args: &[String], ts: bool) -> Option<String> {
    let arg = |i: usize| args.get(i).cloned().unwrap_or_default();
    Some(match (method, ts) {
        ("first", true) => format!("({}.at(0) ?? null)", recv),
        ("first", false) => format!("{}.first().cloned()", recv),
        ("last", true) => format!("({}.at(-1) ?? null)", recv),
        ("last", false) => format!("{}.last().cloned()", recv),
        // JS `Array.at` takes negatives; Rust guards the negative case to `None`.
        ("at", true) => format!("({}.at({}) ?? null)", recv, arg(0)),
        ("at", false) => {
            format!("{{ let __i: i64 = {}; if __i < 0 {{ None }} else {{ {}.get(__i as usize).cloned() }} }}", arg(0), recv)
        }
        ("reverse", true) => format!("[...{}].reverse()", recv),
        ("reverse", false) => format!("{{ let mut __v = {}.clone(); __v.reverse(); __v }}", recv),
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
        // Decimal is a string-backed exact money value — a String end-to-end
        // (wire/db/interp), never f64, so it can't pick up binary-float error.
        "String" | "Decimal" => "String".to_string(),
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
        // Decimal stays a string in the browser tier (zero-dep, exact).
        "String" | "Decimal" => "string".to_string(),
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

/// The JS string literal for a `navigate(Screen)` argument — the screen name
/// (an `Ident`, per R28). Used by both expression emitters.
fn nav_target_js(args: &[Expr]) -> String {
    match args.first() {
        Some(Expr::Ident(name)) => format!("{:?}", name),
        _ => "\"\"".to_string(), // checker R28 already rejected a non-screen arg
    }
}

/// `link "Label" -> Screen` → an `<a>` whose `href` comes from the runtime
/// route map (`__path`, module scope) and whose `data-link` drives the SPA
/// click handler in `mount()` (preventDefault + pushState, no full reload). The
/// label goes through the same R22 escape path as any other element arg.
fn link_node(arg: &Option<Expr>, style: &Option<Expr>, event: &Option<Handler>) -> String {
    let target = match event {
        Some(Handler::Call(Expr::Ident(name))) => name.clone(),
        _ => String::new(), // checker R28 already rejected a target-less link
    };
    let mut s = String::from("`<a");
    s.push_str(&format!(" href=\"${{__path[{:?}]}}\" data-link={:?}", target, target));
    if let Some(style_expr) = style {
        s.push_str(" style=\"");
        match style_expr {
            Expr::Str(css) => s.push_str(&inline_css(css)),
            e => {
                s.push_str("${");
                s.push_str(&emit_expr(e, true));
                s.push('}');
            }
        }
        s.push('"');
    }
    s.push('>');
    match arg {
        Some(Expr::Str(t)) => s.push_str(t),
        Some(Expr::Raw(inner)) => {
            s.push_str("${");
            s.push_str(&emit_expr(inner, true));
            s.push('}');
        }
        Some(e) => {
            s.push_str("${__esc(");
            s.push_str(&emit_expr(e, true));
            s.push_str(")}");
        }
        None => {}
    }
    s.push_str("</a>`");
    s
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
        "checkbox" => "input",  // type="checkbox" added in codegen
        "number" => "input",    // type="number" added in codegen
        "image" => "img",
        "radio" => "div",       // a <div> wrapping the generated radio-input group
        "link" => "a",          // client-router anchor (href + data-link, see node())
        other => other,         // text, input, textarea, select, option …
    }
}
