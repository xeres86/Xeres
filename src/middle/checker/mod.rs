// The semantic analysis phase. This core module owns the symbol table, type
// resolution, and the `analyze` orchestrator; the R-numbered rule checks live in
// `rules`, and the post-check typed lowering in `lower` (both `use super::*` to
// reach this core). Only `analyze` + `lower` are the crate-facing API (spec 31).
use crate::frontend::parser::{
    BinOp, EndpointNode, EnumNode, EnvModifier, Expr, ModelNode, ScreenNode, SyncedStateNode,
    XeresProgram,
};
use crate::middle::diagnostics::Diagnostic;
use std::collections::{HashMap, HashSet};

mod rules;
mod lower;
use rules::*;
pub use lower::lower;

const BUILTINS: &[&str] = &["String", "Int", "Float", "Bool", "DateTime", "Decimal"];

/// Stdlib methods on a `String` receiver.
const STRING_METHODS: &[&str] = &["trim", "upper", "lower", "length", "contains", "split", "replace"];

pub struct Analysis {
    pub errors: Vec<Diagnostic>,
    pub returns_secret: HashMap<String, bool>,
}

struct FnSig {
    env: EnvModifier,
    ret: Option<String>,
}

struct SymbolTable<'a> {
    models: HashMap<String, &'a ModelNode>,
    enums: HashMap<String, &'a EnumNode>,
    fns: HashMap<String, FnSig>,
    states: HashMap<String, &'a SyncedStateNode>,
    /// Reusable `ui component`s, keyed by name (for invocation checking).
    components: HashMap<String, &'a ScreenNode>,
    /// `ui screen`s (not components), keyed by name — the navigation targets
    /// for `navigate(...)` / `link` (R28). Prop-less ones are mountable routes.
    screens: HashMap<String, &'a ScreenNode>,
    /// Declared egress `endpoint`s, keyed by name (R26).
    endpoints: HashMap<String, &'a EndpointNode>,
    /// Declared `theme` token names (spec 26), light + dark merged into one
    /// namespace — `token(x)` resolves by name regardless of which theme block
    /// declared it (R37).
    tokens: HashSet<String>,
    /// Declared top-level `style Name` names (spec 26), for the element
    /// `style Name` reference (R37).
    styles: HashSet<String>,
}

/// Inner type of a one-level generic, e.g. `("List", "List<User>") -> "User"`.
fn generic_inner<'a>(base: &str, ty: &'a str) -> Option<&'a str> {
    ty.strip_prefix(base)
        .and_then(|r| r.strip_prefix('<'))
        .and_then(|r| r.strip_suffix('>'))
}

/// A component name (and thus its invocation tag) must begin with an uppercase
/// letter, the same convention that distinguishes types from value identifiers.
fn starts_uppercase(name: &str) -> bool {
    name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
}

/// Does `ty` (after stripping one `List<...>`/`Optional<...>` wrapper) name a
/// model? (spec 29) A model-shaped return is protected by wire-projection's
/// automatic field-level `secret` stripping (`wire_json` in interp.rs / the
/// stripped client `interface` in codegen.rs); a bare scalar isn't — pulling a
/// `secret` field's value into a `String`/`Int`/… loses the type-level marker,
/// so nothing is left to strip at serialization. Used by R5's server-side
/// scalar-leak check.
fn is_model_shaped(ty: &str, table: &SymbolTable) -> bool {
    let inner = generic_inner("List", ty).or_else(|| generic_inner("Optional", ty)).unwrap_or(ty);
    table.models.contains_key(inner)
}

fn is_known_type(name: &str, table: &SymbolTable) -> bool {
    if let Some(inner) = generic_inner("List", name).or_else(|| generic_inner("Optional", name)) {
        return is_known_type(inner, table);
    }
    BUILTINS.contains(&name) || table.models.contains_key(name) || table.enums.contains_key(name)
}

fn is_bool_op(op: BinOp) -> bool {
    matches!(op, BinOp::Eq | BinOp::NotEq | BinOp::Lt | BinOp::Gt | BinOp::LtEq | BinOp::GtEq | BinOp::And | BinOp::Or)
}

fn resolve_type(
    expr: &Expr,
    locals: &HashMap<String, (Option<String>, bool)>,
    table: &SymbolTable,
) -> Option<String> {
    match expr {
        Expr::Int(_) => Some("Int".into()),
        Expr::Float(_) => Some("Float".into()),
        Expr::Str(_) => Some("String".into()),
        Expr::Bool(_) => Some("Bool".into()),
        Expr::Ident(v) => locals.get(v).and_then(|(t, _)| t.clone()),
        Expr::Field { base, field } => {
            // `session.actor` — the authenticated actor id, or none.
            if matches!(base.as_ref(), Expr::Ident(n) if n == "session") && field == "actor" {
                return Some("Optional<String>".into());
            }
            // enum variant access: `Status.Active` is a value of type `Status`.
            if let Expr::Ident(name) = base.as_ref() {
                if table.enums.contains_key(name) {
                    return Some(name.clone());
                }
            }
            let base_ty = resolve_type(base, locals, table)?;
            let model = table.models.get(&base_ty)?;
            model.field(field).map(|p| p.data_type.clone())
        }
        Expr::Call { callee, args } => match callee.as_str() {
            // builtins: uid() unique id, hash() password hash, verify() check,
            // now() current timestamp.
            "uid" | "hash" => Some("String".into()),
            "verify" => Some("Bool".into()),
            "now" => Some("DateTime".into()),
            // decimal("19.99") — a string-backed exact money value, kept
            // distinct from Float so the two can't silently mix (R29).
            "decimal" => Some("Decimal".into()),
            // Lowered Decimal ops (spec 18). The typed-desugaring pass below
            // rewrites Decimal `+ - * < > <= >=` into these calls; typing them
            // here lets nested arithmetic like `(a + b) * c` compose after the
            // inner rewrite, and keeps `resolve_type` correct post-lowering.
            "__dec_add" | "__dec_sub" | "__dec_mul" => Some("Decimal".into()),
            "__dec_lt" | "__dec_gt" | "__dec_le" | "__dec_ge" => Some("Bool".into()),
            // Lowered string concatenation (spec 24): `String + <scalar>` desugars
            // to this. Always a String (the result of display-concatenation).
            "__str_concat" => Some("String".into()),
            // math: result type follows the (numeric) argument
            "abs" | "min" | "max" => args
                .first()
                .and_then(|a| resolve_type(a, locals, table))
                .or_else(|| Some("Int".into())),
            _ => table.fns.get(callee).and_then(|s| s.ret.clone()),
        },
        Expr::Unary { op, expr } => match op {
            crate::frontend::parser::UnOp::Not => Some("Bool".into()),
            crate::frontend::parser::UnOp::Neg => resolve_type(expr, locals, table),
        },
        Expr::Binary { op, left, right } => {
            if is_bool_op(*op) {
                return Some("Bool".into());
            }
            let lt = resolve_type(left, locals, table);
            let rt = resolve_type(right, locals, table);
            // String display-concatenation (spec 24): `String + <anything>` (or
            // `<anything> + String`) yields a String — checked before the numeric
            // arms so `"lat=" + 51.5` is a String, not a Float. Lowered to
            // `__str_concat` in `lower`.
            if matches!(*op, BinOp::Add)
                && (lt.as_deref() == Some("String") || rt.as_deref() == Some("String"))
            {
                return Some("String".into());
            }
            match (lt.as_deref(), rt.as_deref()) {
                (Some("Int"), Some("Int")) => Some("Int".into()),
                // Exact money (R29 / spec 18): Decimal arithmetic stays Decimal,
                // and `Decimal * Int` / `Int * Decimal` scales exactly. Mixing
                // with Float, `Decimal {+,-} Int`, and `/` are rejected as R29 in
                // `check_decimal_binary` (so they never reach lowering/codegen).
                (Some("Decimal"), Some("Decimal")) if matches!(*op, BinOp::Add | BinOp::Sub | BinOp::Mul) => {
                    Some("Decimal".into())
                }
                (Some("Decimal"), Some("Int")) | (Some("Int"), Some("Decimal")) if matches!(*op, BinOp::Mul) => {
                    Some("Decimal".into())
                }
                (Some("Float"), _) | (_, Some("Float")) => Some("Float".into()),
                // temporal: `DateTime - DateTime` is the elapsed milliseconds
                // (Int); shifting a `DateTime` by `Int` ms yields a `DateTime`.
                (Some("DateTime"), Some("DateTime")) if matches!(*op, BinOp::Sub) => Some("Int".into()),
                (Some("DateTime"), Some("Int")) if matches!(*op, BinOp::Add | BinOp::Sub) => {
                    Some("DateTime".into())
                }
                (Some("Int"), Some("DateTime")) if matches!(*op, BinOp::Add) => Some("DateTime".into()),
                _ => None,
            }
        }
        Expr::Declassify(inner) => resolve_type(inner, locals, table),
        Expr::Raw(inner) => resolve_type(inner, locals, table),
        Expr::Await(inner) => resolve_type(inner, locals, table),
        Expr::MethodCall { receiver, method, args } => {
            if let Expr::Ident(name) = receiver.as_ref() {
                // `db.exec` returns affected-row count; `db.query_one` is typed
                // by the surrounding fn's return model (resolved in codegen).
                if name == "db" {
                    return if method == "exec" { Some("Int".into()) } else { None };
                }
                // endpoint verbs: `.get` -> String (response body), `.post` -> Int (status).
                if table.endpoints.contains_key(name) {
                    return match method.as_str() {
                        "get" => Some("String".into()),
                        "post" => Some("Int".into()),
                        _ => None,
                    };
                }
                // `collection.get(id)` yields the element type.
                if method == "get" {
                    if let Some(state) = table.states.get(name) {
                        return Some(state.collection_type.clone());
                    }
                }
            }
            // `optional.or(default)` unwraps to the inner type.
            if method == "or" {
                if let Some(rt) = resolve_type(receiver, locals, table) {
                    if let Some(inner) = generic_inner("Optional", &rt) {
                        return Some(inner.to_string());
                    }
                }
            }
            // List stdlib methods (R-free; see spec 08). `at`/`first`/`last` are
            // safe — they yield `Optional<T>` (miss ⇒ `none`).
            if let Some(rt) = resolve_type(receiver, locals, table) {
                if let Some(elem) = generic_inner("List", &rt).map(str::to_string) {
                    match method.as_str() {
                        "length" => return Some("Int".into()),
                        "first" | "last" | "at" => return Some(format!("Optional<{}>", elem)),
                        "reverse" => return Some(format!("List<{}>", elem)),
                        // Higher-order ops (spec 19). `map` binds the closure
                        // param to the element type and the result element type is
                        // the body's; `filter` keeps `List<T>`; `reduce` is the
                        // type of its `init`; `contains` is Bool.
                        "filter" => return Some(format!("List<{}>", elem)),
                        "contains" => return Some("Bool".into()),
                        "map" => {
                            if let Some(Expr::Closure { params, body }) = args.first() {
                                if params.len() == 1 {
                                    let mut inner = locals.clone();
                                    inner.insert(params[0].clone(), (Some(elem.clone()), false));
                                    if let Some(u) = resolve_type(body, &inner, table) {
                                        return Some(format!("List<{}>", u));
                                    }
                                }
                            }
                            return None;
                        }
                        "reduce" => {
                            return args.first().and_then(|init| resolve_type(init, locals, table));
                        }
                        _ => {}
                    }
                }
            }
            // String stdlib methods.
            if STRING_METHODS.contains(&method.as_str()) {
                return match method.as_str() {
                    "length" => Some("Int".into()),
                    "contains" => Some("Bool".into()),
                    "split" => Some("List<String>".into()),
                    _ => Some("String".into()), // trim, upper, lower, replace
                };
            }
            None
        }
        Expr::Record { name, .. } => Some(name.clone()),
        Expr::NoneLit => Some("None".into()),
        Expr::ListLit(items) => {
            let elem = items.first().and_then(|e| resolve_type(e, locals, table))?;
            Some(format!("List<{}>", elem))
        }
        // A ternary's type is its then-branch (both branches should agree).
        Expr::Ternary { then, otherwise, .. } => {
            resolve_type(then, locals, table).or_else(|| resolve_type(otherwise, locals, table))
        }
        // `a..b` yields a sequence of Int (so `for i in 0..n` binds `i: Int`).
        Expr::Range { .. } => Some("List<Int>".into()),
        // A closure has no first-class type in Cut 1 (argument-only); its body's
        // type is resolved in context by the higher-order op above.
        Expr::Closure { .. } => None,
        // `xs[i]` is `.at(i)` sugar → `Optional<T>` (miss ⇒ `none`).
        Expr::Index { base, .. } => {
            let bt = resolve_type(base, locals, table)?;
            generic_inner("List", &bt).map(|elem| format!("Optional<{}>", elem))
        }
    }
}

fn env_label(e: EnvModifier) -> &'static str {
    match e {
        EnvModifier::Server => "server-side",
        EnvModifier::Ui => "in the browser",
        EnvModifier::None => "in an unspecified environment (may run client-side)",
    }
}

pub fn analyze(program: &XeresProgram) -> Analysis {
    let mut errors = Vec::new();
    let mut table = SymbolTable {
        models: HashMap::new(),
        enums: HashMap::new(),
        fns: HashMap::new(),
        states: HashMap::new(),
        components: HashMap::new(),
        screens: HashMap::new(),
        endpoints: HashMap::new(),
        tokens: HashSet::new(),
        styles: HashSet::new(),
    };

    // Theme tokens (spec 26): light + dark share one name namespace for
    // `token(x)` resolution, but duplicates are checked PER theme (a name
    // legitimately repeats across light/dark — that's how a dark variant
    // overrides a token's value, not a duplicate declaration).
    let mut light_token_names: HashSet<&str> = HashSet::new();
    let mut dark_token_names: HashSet<&str> = HashSet::new();
    for t in &program.themes {
        let seen = if t.is_dark { &mut dark_token_names } else { &mut light_token_names };
        for tok in &t.tokens {
            if !seen.insert(tok.name.as_str()) {
                errors.push(Diagnostic {
                    file: String::new(),
                    rule: "R2 duplicate-decl",
                    message: format!(
                        "theme token `{}` is declared more than once in the {} theme.",
                        tok.name,
                        if t.is_dark { "dark" } else { "default" }
                    ),
                    line: tok.line,
                });
            }
            table.tokens.insert(tok.name.clone());
        }
    }
    // Named styles (spec 26): register + reject a duplicate name (R2), same
    // convention as every other top-level decl.
    let mut style_names: HashSet<&str> = HashSet::new();
    for s in &program.styles {
        if !style_names.insert(s.name.as_str()) {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R2 duplicate-decl",
                message: format!("style `{}` is declared more than once.", s.name),
                line: s.line,
            });
        }
        table.styles.insert(s.name.clone());
    }
    // R37 unknown-token — a named style's own CSS body may reference `token(x)`.
    for s in &program.styles {
        check_token_refs(&s.css, s.line, &table, &mut errors);
    }

    for ep in &program.endpoints {
        if table.endpoints.insert(ep.name.clone(), ep).is_some() {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R2 duplicate-decl",
                message: format!("endpoint `{}` is declared more than once.", ep.name),
                line: ep.line,
            });
        }
    }

    // Enums: register, and reject duplicate enum names / duplicate variants (R2).
    for e in &program.enums {
        if table.enums.insert(e.name.clone(), e).is_some() || table.models.contains_key(&e.name) {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R2 duplicate-decl",
                message: format!("type `{}` is declared more than once.", e.name),
                line: e.line,
            });
        }
        let mut seen = HashSet::new();
        for v in &e.variants {
            if !seen.insert(v) {
                errors.push(Diagnostic {
                    file: String::new(),
                    rule: "R2 duplicate-decl",
                    message: format!("variant `{}` is declared twice in enum `{}`.", v, e.name),
                    line: e.line,
                });
            }
        }
    }

    // Screens and components compile to render functions in one namespace and
    // are mounted/invoked by name — so names must be unique (R2), and a
    // component must be Capitalized so a view can tell `StatCard { … }`
    // (invocation) from a lowercase built-in element (R17).
    let mut screen_names: HashSet<&str> = HashSet::new();
    for s in &program.screens {
        if !screen_names.insert(s.name.as_str()) {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R2 duplicate-decl",
                message: format!(
                    "{} `{}` is declared more than once.",
                    if s.is_component { "component" } else { "screen" },
                    s.name
                ),
                line: s.line,
            });
        }
        if s.is_component {
            if !starts_uppercase(&s.name) {
                errors.push(Diagnostic {
                    file: String::new(),
                    rule: "R17 component",
                    message: format!(
                        "component `{}` must start with an uppercase letter — components are invoked as a Capitalized tag in views (e.g. `{}` vs a lowercase built-in element).",
                        s.name, s.name
                    ),
                    line: s.line,
                });
            }
            table.components.insert(s.name.clone(), s);
        } else {
            // A `ui screen` is a navigation target (R28); prop-less ones are
            // mountable routes (see `navigate(...)` / `link` checks).
            table.screens.insert(s.name.clone(), s);
        }
    }

    for m in &program.models {
        if table.models.insert(m.name.clone(), m).is_some() {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R2 duplicate-decl",
                message: format!("model `{}` is declared more than once.", m.name),
                line: m.line,
            });
        }
        let mut seen = HashSet::new();
        for p in &m.properties {
            if !seen.insert(&p.name) {
                errors.push(Diagnostic {
                    file: String::new(),
                    rule: "R2 duplicate-decl",
                    message: format!("field `{}` is declared twice in model `{}`.", p.name, m.name),
                    line: p.line,
                });
            }
        }
    }
    for f in &program.functions {
        if table.fns.insert(f.name.clone(), FnSig { env: f.env, ret: f.return_type.clone() }).is_some() {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R2 duplicate-decl",
                message: format!("function `{}` is declared more than once.", f.name),
                line: f.line,
            });
        }
    }

    for m in &program.models {
        for p in &m.properties {
            if !is_known_type(&p.data_type, &table) {
                errors.push(Diagnostic {
                    file: String::new(),
                    rule: "R1 unknown-type",
                    message: format!("field `{}.{}` has unknown type `{}`.", m.name, p.name, p.data_type),
                    line: p.line,
                });
            }
        }
    }
    for s in &program.states {
        table.states.insert(s.name.clone(), s);
        if !is_known_type(&s.collection_type, &table) {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R1 unknown-type",
                message: format!("synced state `{}` references unknown type `{}`.", s.name, s.collection_type),
                line: s.line,
            });
        } else if let Some(model) = table.models.get(s.collection_type.as_str()) {
            // R10 — a synced collection needs a stable string key to merge on.
            let has_id = model.field("id").map(|p| p.data_type == "String").unwrap_or(false);
            if !has_id {
                errors.push(Diagnostic {
                    file: String::new(),
                    rule: "R10 sync-key",
                    message: format!(
                        "synced collection `{}` requires model `{}` to have an `id: String` field (the merge key).",
                        s.name, s.collection_type
                    ),
                    line: s.line,
                });
            }
        }
    }
    for f in &program.functions {
        for p in &f.params {
            if !is_known_type(&p.type_name, &table) {
                errors.push(Diagnostic {
                    file: String::new(),
                    rule: "R1 unknown-type",
                    message: format!("parameter `{}: {}` of `{}` has unknown type.", p.name, p.type_name, f.name),
                    line: f.line,
                });
            }
        }
        if let Some(ret) = &f.return_type {
            if !is_known_type(ret, &table) {
                errors.push(Diagnostic {
                    file: String::new(),
                    rule: "R1 unknown-type",
                    message: format!("return type `{}` of `{}` is unknown.", ret, f.name),
                    line: f.line,
                });
            }
        }
    }

    // R24 — an `auth` fn must be server-side and must consult `session`.
    for f in &program.functions {
        if !f.is_auth {
            continue;
        }
        if f.env != EnvModifier::Server {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R24 authn-required",
                message: format!("`auth` is a server-only modifier, but `{}` runs {}.", f.name, env_label(f.env)),
                line: f.line,
            });
        }
        if !stmts_use_session(&f.body) {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R24 authn-required",
                message: format!(
                    "`auth fn {}` never consults `session`. Read `session.actor` to authenticate the caller — an `auth` fn that ignores the session is the 'forgot the auth check' bug.",
                    f.name
                ),
                line: f.line,
            });
        }
        // R25 — a parameterized `db` query in this protected fn must bind the
        // actor (anti-IDOR).
        check_actor_scope(&f.body, &f.name, f.line, &mut errors);
    }

    for f in &program.functions {
        check_flow(f, &table, &mut errors);
    }

    // Inbound API routes (spec 23): R36 structural discipline + check each route
    // body as a server-tier function (so R5/R15/R23/R30/... all fire).
    check_apis(program, &table, &mut errors);

    for s in &program.screens {
        check_screen(s, &table, &mut errors);
    }

    // R31 — auth-gated routes. A protected (`auth`) screen needs: to be a route
    // (prop-less, not a component), a session to gate against (some fn must
    // establish one), and a *public* default route to bounce unauthenticated
    // users to. The enforcement is two-tier (client redirect + server shell
    // guard); this rule keeps the surface coherent.
    let navigable_root = program
        .screens
        .iter()
        .find(|s| !s.is_component && s.params.is_empty())
        .map(|s| s.name.clone());
    let app_uses_session = program.functions.iter().any(|f| stmts_use_session(&f.body));
    for s in &program.screens {
        if !s.is_auth {
            continue;
        }
        if s.is_component {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R31 auth-route",
                message: format!("`auth` marks a protected route; it can't be used on component `{}`.", s.name),
                line: s.line,
            });
            continue;
        }
        if !s.params.is_empty() {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R31 auth-route",
                message: format!("an `auth` screen must be a prop-less route; `{}` takes props.", s.name),
                line: s.line,
            });
        }
        if !app_uses_session {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R31 auth-route",
                message: format!(
                    "`auth ui screen {}` needs a session, but no function establishes one (call `session.login(...)` in an `auth server fn`).",
                    s.name
                ),
                line: s.line,
            });
        }
        if navigable_root.as_deref() == Some(s.name.as_str()) {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R31 auth-route",
                message: format!(
                    "the default route `{}` must be public so unauthenticated users have a landing/login page — mark a different screen `auth`.",
                    s.name
                ),
                line: s.line,
            });
        }
    }

    // R32 — typed route params. A `route "/post/:id"` pattern binds the screen's
    // props from the URL: every `:name` must name a prop and every prop must be
    // bound, the param props must be `String`/`Int` (parseable from a segment),
    // the pattern needs at least one `:param`, and `route` is for screens (a
    // component is invoked, not navigated to). A valid param route is then
    // navigable via `navigate(Screen { … })` (R28's "routes are prop-less" is
    // relaxed for it — see check_nav_target).
    for s in &program.screens {
        let Some(pattern) = &s.route else { continue };
        if s.is_component {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R32 route-param",
                message: format!("`route` is for screens, not component `{}`.", s.name),
                line: s.line,
            });
            continue;
        }
        let pat: Vec<String> = route_params(pattern);
        if pat.is_empty() {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R32 route-param",
                message: format!("route `{}` on `{}` has no `:param` segment — use a plain screen for a static path.", pattern, s.name),
                line: s.line,
            });
        }
        for pp in &pat {
            if !s.params.iter().any(|p| &p.name == pp) {
                errors.push(Diagnostic {
                    file: String::new(),
                    rule: "R32 route-param",
                    message: format!("route param `:{}` on `{}` has no matching prop — add `{}: String` (or `Int`).", pp, s.name, pp),
                    line: s.line,
                });
            }
        }
        for p in &s.params {
            if !pat.contains(&p.name) {
                errors.push(Diagnostic {
                    file: String::new(),
                    rule: "R32 route-param",
                    message: format!("prop `{}` on route `{}` isn't bound by the pattern `{}` (add `:{}`).", p.name, s.name, pattern, p.name),
                    line: s.line,
                });
            }
            if p.type_name != "String" && p.type_name != "Int" {
                errors.push(Diagnostic {
                    file: String::new(),
                    rule: "R32 route-param",
                    message: format!("route param `{}` on `{}` must be `String` or `Int`, got `{}` (it's parsed from a URL segment).", p.name, s.name, p.type_name),
                    line: s.line,
                });
            }
        }
    }

    let mut returns_secret: HashMap<String, bool> =
        program.functions.iter().map(|f| (f.name.clone(), false)).collect();
    loop {
        let mut changed = false;
        for f in &program.functions {
            let now = function_returns_secret(f, &table, &returns_secret);
            if now && !returns_secret[&f.name] {
                returns_secret.insert(f.name.clone(), true);
                changed = true;
            }
        }
        if !changed { break; }
    }

    for f in &program.functions {
        if !returns_secret[&f.name] {
            continue;
        }
        if f.env != EnvModifier::Server {
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R5 secret-leak-via-return",
                message: format!(
                    "`{}` returns secret-derived data but runs {}. Only `server` functions may return secret data; use `declassify(...)` server-side if release is intended.",
                    f.name, env_label(f.env)
                ),
                line: f.line,
            });
        } else if !f.return_type.as_deref().is_some_and(|t| is_model_shaped(t, &table)) {
            // R5, server side (spec 29 sweep finding): a `server fn` was
            // exempted above on the assumption that wire-projection strips
            // `secret` fields automatically — true for a Model return, but a
            // bare scalar (String/Int/…) built from a secret field carries no
            // such marker once extracted, so it crosses to ANY RPC caller as
            // plain text (proven live: a `server fn` returning `user.
            // password_hash` as a bare `String` compiled clean and the raw
            // value appeared in the `/__xeres/<fn>` JSON response). Require
            // the same `declassify(...)` this rule's own message always
            // recommended, now actually enforced server-side too.
            errors.push(Diagnostic {
                file: String::new(),
                rule: "R5 secret-leak-via-return",
                message: format!(
                    "server fn `{}` returns a bare `{}` built from a secret field, with no `declassify(...)`. A Model return gets its `secret` fields stripped automatically on the wire; a scalar return doesn't, so this value would reach any RPC caller as plain text. Wrap it in `declassify(...)` to confirm the release is deliberate.",
                    f.name,
                    f.return_type.as_deref().unwrap_or("value")
                ),
                line: f.line,
            });
        }
    }

    // stable, readable ordering: by line
    errors.sort_by_key(|e| e.line);

    Analysis { errors, returns_secret }
}
