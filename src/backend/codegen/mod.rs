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
    BinOp, Expr, FunctionNode, Handler, MatchPat, ScreenNode, Stmt, UnOp, ViewNode, XeresProgram,
};
use std::collections::{HashMap, HashSet};

// The three output tiers live in sibling modules; each `use super::*` to reach
// the shared emitters, type maps, capability detection, and CSS helpers that
// stay here in the core. Only these three entry points cross back (spec 31).
mod server;
mod client;
mod index;
use server::gen_server;
use client::gen_client;
use index::gen_index;

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
) -> (String, String, String, String, String) {
    ENDPOINTS.with(|e| {
        *e.borrow_mut() = program.endpoints.iter().map(|x| x.name.clone()).collect();
    });
    // Global CSS (spec 26): tokens + named styles + dark block, one static
    // sheet. Empty when the app declares neither — the "zero framework/DX
    // stays lean by default" case (no `<link>`, no `static/app.css`).
    let css = gen_stylesheet(program);
    (
        gen_server(program),
        gen_client(program),
        gen_index(program, !css.is_empty()),
        gen_cargo(program),
        css,
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

// ------------------------------------------------------------------ app.css (spec 26)

/// The CSS variable name a token expands to: `color` tokens stay bare
/// (`--primary`), every other category is prefixed by its category
/// (`--space-lg`) — see `ThemeToken`'s doc comment for why.
fn token_var_name(category: &str, name: &str) -> String {
    if category == "color" {
        name.to_string()
    } else {
        format!("{}-{}", category, name)
    }
}

/// name -> the css var name it expands to, across every `theme`/`theme dark`
/// block (one merged namespace, mirroring the checker's `table.tokens`).
fn build_token_map(program: &XeresProgram) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for t in &program.themes {
        for tok in &t.tokens {
            map.insert(tok.name.clone(), token_var_name(&tok.category, &tok.name));
        }
    }
    map
}

/// Collapse a CSS source string's whitespace to single spaces (shared by the
/// HTML-attribute path and the stylesheet path; only the former also escapes
/// `"`, since a generated CSS file isn't an HTML attribute value).
fn tidy_css(css: &str) -> String {
    css.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Rewrite every `token(name)` in a literal CSS string to `var(--<varname>)`
/// (spec 26). Purely textual — checker's R37 already proved every reference
/// resolves, so an unresolvable name here (dead code / unreachable in a valid
/// program) is left as-is rather than panicking.
fn resolve_tokens(css: &str, tokens: &HashMap<String, String>) -> String {
    let mut out = String::new();
    let mut rest = css;
    while let Some(pos) = rest.find("token(") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + "token(".len()..];
        match after.find(')') {
            Some(end) => {
                let name = after[..end].trim();
                match tokens.get(name) {
                    Some(var) => out.push_str(&format!("var(--{})", var)),
                    None => out.push_str(&after[..end + 1]), // unresolved: leave literal
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str("token(");
                rest = after;
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Tidy a literal `style "..."` string into a single-line CSS attribute value:
/// collapse the (often multi-line, indented) source whitespace to single spaces
/// and escape `"` so it can't terminate the HTML attribute.
fn inline_css(css: &str) -> String {
    tidy_css(css).replace('"', "&quot;")
}

/// The generated `static/app.css` (spec 26): tokens → `:root` (+ a dark block),
/// named styles → `.x-<name>` classes. Empty when the app declares neither —
/// callers treat an empty string as "no stylesheet" (no file, no `<link>`).
fn gen_stylesheet(program: &XeresProgram) -> String {
    if program.themes.is_empty() && program.styles.is_empty() {
        return String::new();
    }
    let tokens = build_token_map(program);
    let mut out = String::new();

    let light_vars: Vec<String> = program
        .themes
        .iter()
        .filter(|t| !t.is_dark)
        .flat_map(|t| &t.tokens)
        .map(|t| format!("  --{}: {};", token_var_name(&t.category, &t.name), t.value))
        .collect();
    if !light_vars.is_empty() {
        out.push_str(":root {\n");
        out.push_str(&light_vars.join("\n"));
        out.push_str("\n}\n\n");
    }

    let dark_vars: Vec<String> = program
        .themes
        .iter()
        .filter(|t| t.is_dark)
        .flat_map(|t| &t.tokens)
        .map(|t| format!("  --{}: {};", token_var_name(&t.category, &t.name), t.value))
        .collect();
    if !dark_vars.is_empty() {
        // Automatic (OS `prefers-color-scheme`) AND manual (`toggle_theme()`,
        // via `data-theme`) — both apply the same variables (spec 26).
        out.push_str("@media (prefers-color-scheme: dark) {\n  :root {\n");
        for v in &dark_vars {
            out.push_str("  ");
            out.push_str(v);
            out.push('\n');
        }
        out.push_str("  }\n}\n\n");
        out.push_str("[data-theme=\"dark\"] {\n");
        out.push_str(&dark_vars.join("\n"));
        out.push_str("\n}\n\n");
    }

    for s in &program.styles {
        let css = tidy_css(&resolve_tokens(&s.css, &tokens));
        out.push_str(&format!(".x-{} {{ {} }}\n", s.name.to_lowercase(), css));
    }
    out
}

const UID_FN: &str = include_str!("../../../runtime/uid_fn.ts");

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

// Dark-mode toggle (spec 26): persist a manual `toggle_theme()` choice to
// `localStorage` and restore it (via `data-theme`) on the next load, on top of
// the CSS-only `prefers-color-scheme` default.
const THEME_RUNTIME: &str = include_str!("../../../runtime/theme_runtime.ts");

// Exact Decimal money math (spec 18), browser tier. Zero-dep and exact: a scaled
// BigInt, never the binary `number`. A Decimal is a string end-to-end (parse ->
// compute -> format). The checker's typed desugaring lowers Decimal `+ - * < >
// <= >=` to `__dec.*` calls handled here; `Decimal * Int` accepts a number
// operand. Mirrors the server's rust_decimal helpers and the interpreter's i128
// core to the cent — the dual-backend parity rule.
const DECIMAL_RUNTIME: &str = include_str!("../../../runtime/decimal_runtime.ts");

// Local-first sync runtime. Shape: on-device store + offline oplog + network
// trawler, with last-write-wins merge by a Lamport counter. Swap MemoryStore
// for a sql.js / cr-sqlite adapter to get real on-device SQLite + CRDT merge.
const SYNC_RUNTIME: &str = include_str!("../../../runtime/sync_runtime.ts");

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
            // `toggle_theme()` (spec 26) — browser-only builtin (like `navigate`).
            if callee == "toggle_theme" {
                return "__toggleTheme()".to_string();
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
    let decode = server::decode_json_rust("Some(&__body)", ty, program, 0);
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
const CRYPTO_PRELUDE: &str = include_str!("../../../runtime/crypto_prelude.rs");

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
const SESSION_PRELUDE: &str = include_str!("../../../runtime/session_prelude.rs");

const HTTP_PRELUDE: &str = include_str!("../../../runtime/http_prelude.rs");

const DB_PRELUDE: &str = include_str!("../../../runtime/db_prelude.rs");

// Exact Decimal money math (spec 18 / R29), server tier. A Decimal is a `String`
// end-to-end; these helpers parse → compute exactly in base-10 (rust_decimal,
// never f64) → re-stringify. The checker's typed desugaring lowers Decimal
// `+ - * < > <= >=` to `__dec_*` calls handled here. `Decimal * Int` accepts an
// integer operand via `IntoDec`. Gated behind the `decimal` cargo feature (made
// default when the app uses Decimal). Mirrors the interpreter's i128 core and the
// browser's BigInt runtime to the cent — the dual-backend parity rule.
const DECIMAL_PRELUDE: &str = include_str!("../../../runtime/decimal_prelude.rs");

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
fn link_node(
    arg: &Option<Expr>,
    style: &Option<Expr>,
    event: &Option<Handler>,
    tokens: &HashMap<String, String>,
    named_styles: &HashSet<String>,
) -> String {
    let target = match event {
        Some(Handler::Call(Expr::Ident(name))) => name.clone(),
        _ => String::new(), // checker R28 already rejected a target-less link
    };
    let mut s = String::from("`<a");
    s.push_str(&format!(" href=\"${{__path[{:?}]}}\" data-link={:?}", target, target));
    match style {
        // `style Name` (spec 26) — same class-not-inline treatment as `node()`.
        Some(Expr::Ident(name)) if named_styles.contains(name) => {
            s.push_str(&format!(" class=\"x-{}\"", name.to_lowercase()));
        }
        Some(style_expr) => {
            s.push_str(" style=\"");
            match style_expr {
                Expr::Str(css) => s.push_str(&inline_css(&resolve_tokens(css, tokens))),
                e => {
                    s.push_str("${");
                    s.push_str(&emit_expr(e, true));
                    s.push('}');
                }
            }
            s.push('"');
        }
        None => {}
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

#[cfg(test)]
mod protocol_tests {
    use crate::frontend::parser::Parser;
    use crate::frontend::lexer::Lexer;
    use std::collections::HashMap;

    // F1 anti-drift guard (spec 32): the emitted server and the live interpreter
    // host must serve the SAME security-header policy. Both now derive it from
    // `crate::protocol::SECURITY_HEADERS`, so this can't drift by construction —
    // the test locks that in (and fails if someone re-hardcodes a divergent copy
    // into the emitted server template).
    #[test]
    fn emitted_server_embeds_the_shared_security_headers() {
        let src = "ui screen Home { view { column { heading \"hi\" } } }";
        let mut lexer = Lexer::new(src);
        let mut parser = Parser::new(&mut lexer);
        let program = parser.parse_program();
        let (server, ..) = super::generate(&program, &HashMap::new());

        // The generated server must contain exactly the shared CSP/HSTS block —
        // the same bytes `serve.rs` sends — and no leftover placeholder.
        let expected = format!("const SECURITY_HEADERS: &str = {:?};", crate::protocol::SECURITY_HEADERS);
        assert!(
            server.contains(&expected),
            "emitted server does not embed the shared protocol::SECURITY_HEADERS constant"
        );
        assert!(
            !server.contains("//__XERES_SECURITY_HEADERS__"),
            "the security-headers placeholder was left unfilled in the emitted server"
        );
        // The full CSP directive string must survive verbatim (the security bit).
        assert!(
            crate::protocol::SECURITY_HEADERS.contains("frame-ancestors 'none'")
                && server.contains("frame-ancestors 'none'"),
            "the CSP frame-ancestors directive drifted between the constant and the emitted server"
        );
    }
}
