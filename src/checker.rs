// src/checker.rs
use crate::parser::{
    BinOp, EndpointNode, EnumNode, EnvModifier, Expr, FunctionNode, Handler, MatchArm, MatchPat,
    ModelNode, ScreenNode, Stmt, SyncedStateNode, ViewNode, XeresProgram,
};
use std::collections::{HashMap, HashSet};

const BUILTINS: &[&str] = &["String", "Int", "Float", "Bool", "DateTime", "Decimal"];

/// Stdlib methods on a `String` receiver.
const STRING_METHODS: &[&str] = &["trim", "upper", "lower", "length", "contains", "split", "replace"];

pub struct SemanticError {
    pub rule: &'static str,
    pub message: String,
    pub line: usize,
}

pub struct Analysis {
    pub errors: Vec<SemanticError>,
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

/// R20 — a `match` scrutinee must be an enum; every arm names a real variant;
/// and the arms are exhaustive (cover all variants, or include `_`).
fn check_match_patterns(
    scrutinee: &Expr,
    arms: &[MatchArm],
    locals: &HashMap<String, (Option<String>, bool)>,
    table: &SymbolTable,
    line: usize,
    errors: &mut Vec<SemanticError>,
) {
    let enum_name = match resolve_type(scrutinee, locals, table) {
        Some(t) if table.enums.contains_key(&t) => t,
        Some(t) => {
            errors.push(SemanticError {
                rule: "R20 match",
                message: format!("`match` expects an enum, got `{}`.", t),
                line,
            });
            return;
        }
        None => return, // unresolvable — leave to R1
    };
    let en = table.enums[&enum_name];
    let mut covered: HashSet<&str> = HashSet::new();
    let mut has_wildcard = false;
    for arm in arms {
        match &arm.pattern {
            MatchPat::Wildcard => has_wildcard = true,
            MatchPat::Variant(v) => {
                if !en.variants.iter().any(|x| x == v) {
                    errors.push(SemanticError {
                        rule: "R20 match",
                        message: format!("enum `{}` has no variant `{}`.", enum_name, v),
                        line,
                    });
                }
                covered.insert(v.as_str());
            }
        }
    }
    if !has_wildcard {
        let missing: Vec<&str> = en
            .variants
            .iter()
            .map(String::as_str)
            .filter(|v| !covered.contains(v))
            .collect();
        if !missing.is_empty() {
            errors.push(SemanticError {
                rule: "R20 match",
                message: format!(
                    "`match` on `{}` is not exhaustive — missing {} (add it, or `_`).",
                    enum_name,
                    missing.join(", ")
                ),
                line,
            });
        }
    }
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
            // math: result type follows the (numeric) argument
            "abs" | "min" | "max" => args
                .first()
                .and_then(|a| resolve_type(a, locals, table))
                .or_else(|| Some("Int".into())),
            _ => table.fns.get(callee).and_then(|s| s.ret.clone()),
        },
        Expr::Unary { op, expr } => match op {
            crate::parser::UnOp::Not => Some("Bool".into()),
            crate::parser::UnOp::Neg => resolve_type(expr, locals, table),
        },
        Expr::Binary { op, left, right } => {
            if is_bool_op(*op) {
                return Some("Bool".into());
            }
            let lt = resolve_type(left, locals, table);
            let rt = resolve_type(right, locals, table);
            match (lt.as_deref(), rt.as_deref()) {
                (Some("Int"), Some("Int")) => Some("Int".into()),
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
        Expr::MethodCall { receiver, method, args: _ } => {
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
    }
}

fn is_tainted(
    expr: &Expr,
    locals: &HashMap<String, (Option<String>, bool)>,
    table: &SymbolTable,
    returns_secret: &HashMap<String, bool>,
) -> bool {
    match expr {
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) => false,
        Expr::Ident(v) => locals.get(v).map(|(_, t)| *t).unwrap_or(false),
        Expr::Field { base, field } => {
            if is_tainted(base, locals, table, returns_secret) {
                return true;
            }
            if let Some(model_name) = resolve_type(base, locals, table) {
                if let Some(model) = table.models.get(&model_name) {
                    if let Some(p) = model.field(field) {
                        return p.is_secret;
                    }
                }
            }
            false
        }
        Expr::Call { callee, .. } => *returns_secret.get(callee).unwrap_or(&false),
        Expr::Unary { expr, .. } => is_tainted(expr, locals, table, returns_secret),
        Expr::Binary { left, right, .. } => {
            is_tainted(left, locals, table, returns_secret)
                || is_tainted(right, locals, table, returns_secret)
        }
        Expr::Declassify(_) => false,
        // `raw()` is an HTML-trust marker, orthogonal to secret taint: it does
        // NOT launder a secret, so propagate the inner expression's taint.
        Expr::Raw(inner) => is_tainted(inner, locals, table, returns_secret),
        // An awaited value crossed the wire (secrets stripped) — it is clean.
        Expr::Await(_) => false,
        Expr::MethodCall { .. } => false,
        Expr::NoneLit => false,
        Expr::ListLit(items) => items
            .iter()
            .any(|e| is_tainted(e, locals, table, returns_secret)),
        // A constructed record is tainted if any field value is tainted —
        // secret-derived data does not become clean by being wrapped.
        Expr::Record { fields, .. } => fields
            .iter()
            .any(|(_, v)| is_tainted(v, locals, table, returns_secret)),
        // A ternary is tainted if its condition or either branch is.
        Expr::Ternary { cond, then, otherwise } => {
            is_tainted(cond, locals, table, returns_secret)
                || is_tainted(then, locals, table, returns_secret)
                || is_tainted(otherwise, locals, table, returns_secret)
        }
        Expr::Range { start, end } => {
            is_tainted(start, locals, table, returns_secret)
                || is_tainted(end, locals, table, returns_secret)
        }
    }
}

fn function_returns_secret(
    f: &FunctionNode,
    table: &SymbolTable,
    returns_secret: &HashMap<String, bool>,
) -> bool {
    let mut locals: HashMap<String, (Option<String>, bool)> = HashMap::new();
    for p in &f.params {
        locals.insert(p.name.clone(), (Some(p.type_name.clone()), false));
    }
    taint_scan(&f.body, &mut locals, table, returns_secret)
}

/// Walk statements (recursing into `try`/`catch` blocks) looking for a return
/// of secret-derived data.
fn taint_scan(
    stmts: &[Stmt],
    locals: &mut HashMap<String, (Option<String>, bool)>,
    table: &SymbolTable,
    returns_secret: &HashMap<String, bool>,
) -> bool {
    let mut tainted_return = false;
    for stmt in stmts {
        match stmt {
            Stmt::Let { name, type_ann, value } => {
                let t = is_tainted(value, locals, table, returns_secret);
                let ty = type_ann.clone().or_else(|| resolve_type(value, locals, table));
                locals.insert(name.clone(), (ty, t));
            }
            Stmt::Return(e) => {
                if is_tainted(e, locals, table, returns_secret) {
                    tainted_return = true;
                }
            }
            Stmt::Try { body, handler } => {
                let mut b = locals.clone();
                let mut h = locals.clone();
                tainted_return |= taint_scan(body, &mut b, table, returns_secret);
                tainted_return |= taint_scan(handler, &mut h, table, returns_secret);
            }
            Stmt::If { cond: _, then_body, else_body } => {
                let mut t = locals.clone();
                let mut e = locals.clone();
                tainted_return |= taint_scan(then_body, &mut t, table, returns_secret);
                tainted_return |= taint_scan(else_body, &mut e, table, returns_secret);
            }
            Stmt::For { var, iter, body } => {
                let mut inner = locals.clone();
                let elem = resolve_type(iter, locals, table)
                    .as_deref()
                    .and_then(|t| generic_inner("List", t))
                    .map(str::to_string);
                inner.insert(var.clone(), (elem, false));
                tainted_return |= taint_scan(body, &mut inner, table, returns_secret);
            }
            Stmt::While { cond: _, body } => {
                let mut inner = locals.clone();
                tainted_return |= taint_scan(body, &mut inner, table, returns_secret);
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    let mut inner = locals.clone();
                    tainted_return |= taint_scan(&arm.body, &mut inner, table, returns_secret);
                }
            }
            Stmt::Assign { .. } | Stmt::Expr(_) | Stmt::Break | Stmt::Continue => {}
        }
    }
    tainted_return
}

fn check_flow(f: &FunctionNode, table: &SymbolTable, errors: &mut Vec<SemanticError>) {
    let mut locals: HashMap<String, (Option<String>, bool)> = HashMap::new();
    for p in &f.params {
        locals.insert(p.name.clone(), (Some(p.type_name.clone()), false));
    }
    check_flow_stmts(&f.body, &mut locals, f, table, errors);
}

fn check_flow_stmts(
    stmts: &[Stmt],
    locals: &mut HashMap<String, (Option<String>, bool)>,
    f: &FunctionNode,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    let in_browser = f.env != EnvModifier::Server;
    for stmt in stmts {
        match stmt {
            Stmt::Let { name, type_ann, value } => {
                check_expr(value, locals, f.env, &f.name, f.line, table, errors);
                check_await(value, false, in_browser, &f.name, f.line, table, errors);
                // an explicit `: Type` wins (it's what lets `db.query_one`
                // bind onto a model); otherwise infer from the initializer.
                let ty = type_ann.clone().or_else(|| resolve_type(value, locals, table));
                locals.insert(name.clone(), (ty, false));
            }
            Stmt::Return(e) => {
                check_expr(e, locals, f.env, &f.name, f.line, table, errors);
                check_await(e, false, in_browser, &f.name, f.line, table, errors);
                check_return_type(f, e, locals, table, errors);
            }
            Stmt::Expr(e) => {
                check_expr(e, locals, f.env, &f.name, f.line, table, errors);
                check_await(e, false, in_browser, &f.name, f.line, table, errors);
            }
            Stmt::Assign { value, .. } => {
                check_expr(value, locals, f.env, &f.name, f.line, table, errors);
                check_await(value, false, in_browser, &f.name, f.line, table, errors);
            }
            Stmt::Try { body, handler } => {
                // R16 — try is browser-only: server/shared tiers compile to
                // Rust (no exceptions); server failures surface to the client
                // as a failed RPC, which the client's `try` catches.
                if f.env != EnvModifier::Ui {
                    errors.push(SemanticError {
                        rule: "R16 try-context",
                        message: format!(
                            "`try` in `{}` is only valid in ui code; a server failure surfaces to the caller as a failed `await`.",
                            f.name
                        ),
                        line: f.line,
                    });
                }
                let mut b = locals.clone();
                check_flow_stmts(body, &mut b, f, table, errors);
                let mut h = locals.clone();
                check_flow_stmts(handler, &mut h, f, table, errors);
            }
            Stmt::If { cond, then_body, else_body } => {
                check_expr(cond, locals, f.env, &f.name, f.line, table, errors);
                check_await(cond, false, in_browser, &f.name, f.line, table, errors);
                // R14 — the condition must be Bool (when resolvable).
                if let Some(t) = resolve_type(cond, locals, table) {
                    if t != "Bool" {
                        errors.push(SemanticError {
                            rule: "R14 if-condition",
                            message: format!("`if` condition in `{}` must be Bool, got `{}`.", f.name, t),
                            line: f.line,
                        });
                    }
                }
                let mut t = locals.clone();
                check_flow_stmts(then_body, &mut t, f, table, errors);
                let mut e = locals.clone();
                check_flow_stmts(else_body, &mut e, f, table, errors);
            }
            Stmt::For { var, iter, body } => {
                check_expr(iter, locals, f.env, &f.name, f.line, table, errors);
                check_await(iter, false, in_browser, &f.name, f.line, table, errors);
                let elem = element_type_of(iter, locals, table);
                let mut inner = locals.clone();
                inner.insert(var.clone(), (elem, false));
                check_flow_stmts(body, &mut inner, f, table, errors);
            }
            Stmt::While { cond, body } => {
                check_expr(cond, locals, f.env, &f.name, f.line, table, errors);
                check_await(cond, false, in_browser, &f.name, f.line, table, errors);
                if let Some(t) = resolve_type(cond, locals, table) {
                    if t != "Bool" {
                        errors.push(SemanticError {
                            rule: "R14 if-condition",
                            message: format!("`while` condition in `{}` must be Bool, got `{}`.", f.name, t),
                            line: f.line,
                        });
                    }
                }
                let mut inner = locals.clone();
                check_flow_stmts(body, &mut inner, f, table, errors);
            }
            Stmt::Match { scrutinee, arms } => {
                check_expr(scrutinee, locals, f.env, &f.name, f.line, table, errors);
                check_await(scrutinee, false, in_browser, &f.name, f.line, table, errors);
                check_match_patterns(scrutinee, arms, locals, table, f.line, errors);
                for arm in arms {
                    let mut inner = locals.clone();
                    check_flow_stmts(&arm.body, &mut inner, f, table, errors);
                }
            }
            Stmt::Break | Stmt::Continue => {}
        }
    }
}

/// R7 — a `return` must yield the declared return type.
/// We only flag when the expression's type is *resolvable*; an unknown type is
/// left to R1 rather than producing a misleading mismatch.
fn check_return_type(
    f: &FunctionNode,
    e: &Expr,
    locals: &HashMap<String, (Option<String>, bool)>,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    let actual = match resolve_type(e, locals, table) {
        Some(t) => t,
        None => return, // unresolvable — not our error to report
    };
    match &f.return_type {
        Some(declared) => {
            if !type_compatible(&actual, declared) {
                errors.push(SemanticError {
                    rule: "R7 return-type",
                    message: format!(
                        "`{}` is declared to return `{}`, but this `return` yields `{}`.",
                        f.name, declared, actual
                    ),
                    line: f.line,
                });
            }
        }
        None => {
            errors.push(SemanticError {
                rule: "R7 return-type",
                message: format!(
                    "`{}` returns a value of type `{}` but declares no return type; add `-> {}`.",
                    f.name, actual, actual
                ),
                line: f.line,
            });
        }
    }
}

/// Type assignability. Exact match, the numeric widening Int -> Float, and
/// Optional coercion: `none` and a bare `T` both fit an `Optional<T>`.
fn type_compatible(actual: &str, declared: &str) -> bool {
    if actual == declared || (actual == "Int" && declared == "Float") {
        return true;
    }
    if let Some(inner) = generic_inner("Optional", declared) {
        return actual == "None" || type_compatible(actual, inner);
    }
    false
}

// ---------------------------------------------------------------- screens
//
// Screens run in the browser. They get their data from typed props, so the
// boundary rules (R3 secret-containment, R4 env-call-discipline) apply to view
// expressions exactly as they do to a `ui fn`, plus a scope rule (R8): every
// identifier must be a declared prop, a `for` binding, or a known function.

fn check_screen(s: &ScreenNode, table: &SymbolTable, errors: &mut Vec<SemanticError>) {
    for p in &s.params {
        if !is_known_type(&p.type_name, table) {
            errors.push(SemanticError {
                rule: "R1 unknown-type",
                message: format!(
                    "prop `{}: {}` of screen `{}` has unknown type.",
                    p.name, p.type_name, s.name
                ),
                line: s.line,
            });
        }
    }

    let mut locals: HashMap<String, (Option<String>, bool)> = HashMap::new();
    for p in &s.params {
        locals.insert(p.name.clone(), (Some(p.type_name.clone()), false));
    }

    // `state name: Type = init` — client-side reactive cells, in scope below.
    for st in &s.states {
        if !is_known_type(&st.type_name, table) {
            errors.push(SemanticError {
                rule: "R1 unknown-type",
                message: format!("state `{}: {}` in screen `{}` has unknown type.", st.name, st.type_name, s.name),
                line: st.line,
            });
        } else if let Some(actual) = resolve_type(&st.init, &locals, table) {
            if !type_compatible(&actual, &st.type_name) {
                errors.push(SemanticError {
                    rule: "R11 state-init",
                    message: format!(
                        "state `{}` is `{}` but its initializer is `{}`.",
                        st.name, st.type_name, actual
                    ),
                    line: st.line,
                });
            }
        }
        locals.insert(st.name.clone(), (Some(st.type_name.clone()), false));
    }

    let state_names: HashSet<String> = s.states.iter().map(|st| st.name.clone()).collect();
    for v in &s.body {
        check_view(v, &locals, &state_names, &s.name, s.line, table, errors);
    }

    // `on load { … }` runs in the browser on mount: check it as a ui handler so
    // the await discipline (R4) and `try` rule (R16) apply. A synthetic ui fn
    // carries the env/name; locals already hold the props + state cells.
    if !s.load.is_empty() {
        let synthetic = FunctionNode {
            env: EnvModifier::Ui,
            is_auth: false,
            name: format!("{} on load", s.name),
            params: vec![],
            return_type: None,
            body: vec![],
            line: s.line,
        };
        check_flow_stmts(&s.load, &mut locals, &synthetic, table, errors);
    }

    // R30 — the inbound-taint rule: `raw(...)` (the audited un-escaped HTML sink)
    // may not wrap untrusted *inbound* data (a prop or an input-bound `state`).
    check_raw_taint(s, errors);
}

/// R30 (raw-taint) — generalizes the secret-*out* flow (R5) into untrusted-*in*
/// flow for the one place it isn't already covered. Everything in a view is
/// HTML-escaped by default (R22); `raw(...)` is the single opt-out. This rule
/// makes that opt-out impossible to feed with request-derived data, closing the
/// last reflected-XSS hole.
///
/// The untrusted sources of a view are kept small and explicit (over-tainting
/// erodes trust): a screen/component's **props** (they arrive from the caller /
/// over the wire) and any **`state` cell bound to an input** (`bind cell` — the
/// user types into it). Taint propagates structurally (field access, operators,
/// records, ternaries, `for`-bindings over a tainted source). Values that are
/// *not* request-derived stay clean — notably a `state` cell populated from a
/// server `await` (server-vetted HTML is the intended escape hatch:
/// `state safe = ""` filled in `on load` from `await render(...)`, then
/// `raw(safe)`), and string literals. The check is purely local to each
/// screen/component (props of a component are themselves untrusted), so no
/// interprocedural flow is needed, and conservative by design — like R7/R18 it
/// only fires on provable taint.
fn check_raw_taint(s: &ScreenNode, errors: &mut Vec<SemanticError>) {
    // Untrusted-in sources: this view's props + any state cell bound to an input.
    let mut tainted: HashSet<String> = s.params.iter().map(|p| p.name.clone()).collect();
    for v in &s.body {
        collect_bound_states(v, &mut tainted);
    }
    for v in &s.body {
        raw_walk_view(v, &tainted, s, errors);
    }
}

/// Collect every `state` cell that is two-way bound to an input control
/// (`... bind cell`) anywhere in the view — those carry user-typed, untrusted data.
fn collect_bound_states(v: &ViewNode, out: &mut HashSet<String>) {
    match v {
        ViewNode::Element { bind, children, .. } => {
            if let Some(var) = bind {
                out.insert(var.clone());
            }
            for c in children {
                collect_bound_states(c, out);
            }
        }
        ViewNode::For { body, .. } => {
            for c in body {
                collect_bound_states(c, out);
            }
        }
        ViewNode::If { then_body, else_body, .. } => {
            for c in then_body {
                collect_bound_states(c, out);
            }
            for c in else_body {
                collect_bound_states(c, out);
            }
        }
        ViewNode::Component { .. } => {}
    }
}

/// Walk a view node's expression slots looking for `raw(...)` sinks, carrying the
/// set of untrusted idents (extended by a `for` that iterates a tainted source).
fn raw_walk_view(v: &ViewNode, tainted: &HashSet<String>, s: &ScreenNode, errors: &mut Vec<SemanticError>) {
    match v {
        ViewNode::Element { arg, style, event, children, .. } => {
            if let Some(a) = arg {
                raw_walk_expr(a, tainted, s, errors);
            }
            if let Some(st) = style {
                raw_walk_expr(st, tainted, s, errors);
            }
            if let Some(Handler::Call(e)) = event {
                raw_walk_expr(e, tainted, s, errors);
            }
            for c in children {
                raw_walk_view(c, tainted, s, errors);
            }
        }
        ViewNode::For { var, iter, body } => {
            raw_walk_expr(iter, tainted, s, errors);
            let mut inner = tainted.clone();
            if expr_untrusted(iter, tainted) {
                inner.insert(var.clone());
            }
            for c in body {
                raw_walk_view(c, &inner, s, errors);
            }
        }
        ViewNode::If { cond, then_body, else_body } => {
            raw_walk_expr(cond, tainted, s, errors);
            for c in then_body {
                raw_walk_view(c, tainted, s, errors);
            }
            for c in else_body {
                raw_walk_view(c, tainted, s, errors);
            }
        }
        ViewNode::Component { args, .. } => {
            for (_, e) in args {
                raw_walk_expr(e, tainted, s, errors);
            }
        }
    }
}

/// Descend an expression looking for `raw(inner)` sinks. A `raw` wrapping an
/// untrusted value is the violation. Descent does not enter `declassify(...)`
/// (the audited server-side downgrade laund­ers its subtree by construction).
fn raw_walk_expr(e: &Expr, tainted: &HashSet<String>, s: &ScreenNode, errors: &mut Vec<SemanticError>) {
    match e {
        Expr::Raw(inner) => {
            if expr_untrusted(inner, tainted) {
                errors.push(SemanticError {
                    rule: "R30 raw-taint",
                    message: format!(
                        "`raw(...)` in {} `{}` wraps untrusted inbound data (a prop or input-bound `state`), which would inject unescaped HTML from the request surface. Render it with default escaping (drop `raw`), or build the trusted HTML in a `server fn` and `await` it into a non-bound `state` first.",
                        if s.is_component { "component" } else { "screen" },
                        s.name
                    ),
                    line: s.line,
                });
            }
            raw_walk_expr(inner, tainted, s, errors);
        }
        Expr::Declassify(_) => {}
        Expr::Field { base, .. } => raw_walk_expr(base, tainted, s, errors),
        Expr::Unary { expr, .. } => raw_walk_expr(expr, tainted, s, errors),
        Expr::Binary { left, right, .. } => {
            raw_walk_expr(left, tainted, s, errors);
            raw_walk_expr(right, tainted, s, errors);
        }
        Expr::Await(inner) => raw_walk_expr(inner, tainted, s, errors),
        Expr::MethodCall { receiver, args, .. } => {
            raw_walk_expr(receiver, tainted, s, errors);
            for a in args {
                raw_walk_expr(a, tainted, s, errors);
            }
        }
        Expr::Call { args, .. } => {
            for a in args {
                raw_walk_expr(a, tainted, s, errors);
            }
        }
        Expr::Record { fields, .. } => {
            for (_, v) in fields {
                raw_walk_expr(v, tainted, s, errors);
            }
        }
        Expr::ListLit(items) => {
            for it in items {
                raw_walk_expr(it, tainted, s, errors);
            }
        }
        Expr::Ternary { cond, then, otherwise } => {
            raw_walk_expr(cond, tainted, s, errors);
            raw_walk_expr(then, tainted, s, errors);
            raw_walk_expr(otherwise, tainted, s, errors);
        }
        Expr::Range { start, end } => {
            raw_walk_expr(start, tainted, s, errors);
            raw_walk_expr(end, tainted, s, errors);
        }
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) | Expr::Ident(_) | Expr::NoneLit => {}
    }
}

/// Is `e` derived from untrusted inbound data? Mirrors `is_tainted` but on the
/// separate untrusted-in dimension: the sources are the idents in `tainted`
/// (props + input-bound state, plus `for`-bindings over a tainted source).
/// `declassify(...)` and `await` (server-derived; secrets already stripped) are
/// laundered; literals are clean.
fn expr_untrusted(e: &Expr, tainted: &HashSet<String>) -> bool {
    match e {
        Expr::Ident(v) => tainted.contains(v),
        Expr::Field { base, .. } => expr_untrusted(base, tainted),
        Expr::Unary { expr, .. } => expr_untrusted(expr, tainted),
        Expr::Binary { left, right, .. } => expr_untrusted(left, tainted) || expr_untrusted(right, tainted),
        // `raw` is an HTML-trust marker, not a launder — propagate the inner taint.
        Expr::Raw(inner) => expr_untrusted(inner, tainted),
        // A method on untrusted data (e.g. `.upper()`) does not clean it.
        Expr::MethodCall { receiver, args, .. } => {
            expr_untrusted(receiver, tainted) || args.iter().any(|a| expr_untrusted(a, tainted))
        }
        Expr::Record { fields, .. } => fields.iter().any(|(_, v)| expr_untrusted(v, tainted)),
        Expr::ListLit(items) => items.iter().any(|it| expr_untrusted(it, tainted)),
        Expr::Ternary { cond, then, otherwise } => {
            expr_untrusted(cond, tainted) || expr_untrusted(then, tainted) || expr_untrusted(otherwise, tainted)
        }
        Expr::Range { start, end } => expr_untrusted(start, tainted) || expr_untrusted(end, tainted),
        // Laundered / clean: the audited downgrade, server-derived awaits, fn
        // results (not tracked as untrusted in this cut), and literals.
        Expr::Declassify(_) | Expr::Await(_) | Expr::Call { .. } => false,
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) | Expr::NoneLit => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn check_view(
    v: &ViewNode,
    locals: &HashMap<String, (Option<String>, bool)>,
    states: &HashSet<String>,
    sname: &str,
    sline: usize,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    match v {
        ViewNode::Element { tag, arg, bind, event, children, .. } => {
            if let Some(a) = arg {
                check_screen_expr(a, locals, sname, sline, table, errors);
            }
            // R13 — `bind x` requires a matching `state` cell. `checkbox` binds a
            // `Bool`; `number` binds an `Int` or `Float` (the input yields a JS
            // number — deliberately *not* `Decimal`, whose whole point is to stay
            // off binary float); every other control (input/password/textarea/
            // select/radio) binds a `String`.
            if let Some(var) = bind {
                let want: &[&str] = match tag.as_str() {
                    "checkbox" => &["Bool"],
                    "number" => &["Int", "Float"],
                    _ => &["String"],
                };
                let ok = states.contains(var)
                    && matches!(locals.get(var), Some((Some(t), _)) if want.contains(&t.as_str()));
                if !ok {
                    errors.push(SemanticError {
                        rule: "R13 input-binding",
                        message: format!(
                            "`bind {}` on `{}` in screen `{}` requires a `state {}: {}` cell.",
                            var, tag, sname, var, want.join(" or ")
                        ),
                        line: sline,
                    });
                }
            }
            if tag == "link" {
                // `link "Label" -> Screen` — the `->` slot is a navigation
                // target (R28), not a click handler / value binding.
                match event {
                    Some(Handler::Call(target)) => {
                        check_nav_target(target, "`link`", sname, sline, locals, table, errors)
                    }
                    _ => errors.push(SemanticError {
                        rule: "R28 navigation",
                        message: format!(
                            "`link` in screen `{}` needs a target screen: `link \"Label\" -> Screen`.",
                            sname
                        ),
                        line: sline,
                    }),
                }
            } else {
                match event {
                    Some(Handler::Call(e)) => check_screen_expr(e, locals, sname, sline, table, errors),
                    Some(Handler::Block(stmts)) => {
                        check_handler_block(stmts, locals, sname, sline, table, errors)
                    }
                    None => {}
                }
            }
            for c in children {
                check_view(c, locals, states, sname, sline, table, errors);
            }
        }
        ViewNode::For { var, iter, body } => {
            check_screen_expr(iter, locals, sname, sline, table, errors);
            // bind the loop variable to the collection's element type when known.
            let elem = element_type_of(iter, locals, table);
            let mut inner = locals.clone();
            inner.insert(var.clone(), (elem, false));
            for c in body {
                check_view(c, &inner, states, sname, sline, table, errors);
            }
        }
        ViewNode::If { cond, then_body, else_body } => {
            check_screen_expr(cond, locals, sname, sline, table, errors);
            // R14 — an `if` condition must be Bool (when its type is resolvable).
            if let Some(t) = resolve_type(cond, locals, table) {
                if t != "Bool" {
                    errors.push(SemanticError {
                        rule: "R14 if-condition",
                        message: format!("`if` condition in screen `{}` must be Bool, got `{}`.", sname, t),
                        line: sline,
                    });
                }
            }
            for c in then_body {
                check_view(c, locals, states, sname, sline, table, errors);
            }
            for c in else_body {
                check_view(c, locals, states, sname, sline, table, errors);
            }
        }
        ViewNode::Component { name, args, line } => {
            check_component(name, args, *line, locals, sname, table, errors);
        }
    }
}

/// R17 — validate a component invocation `Name { field: expr … }`: the component
/// must exist, each arg is boundary/scope-checked in the caller's (Ui) context,
/// and the args must match the component's params (each once, type-compatible,
/// required ones present). Because args are checked here as ordinary Ui
/// expressions, secret-containment (R3) and scope (R8) apply — a component
/// cannot be a back door around the tier boundary.
fn check_component(
    name: &str,
    args: &[(String, Expr)],
    line: usize,
    locals: &HashMap<String, (Option<String>, bool)>,
    sname: &str,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    // Arg expressions are checked in the caller's (Ui) context.
    for (_, v) in args {
        check_screen_expr(v, locals, sname, line, table, errors);
    }

    let comp = match table.components.get(name) {
        Some(c) => c,
        None => {
            errors.push(SemanticError {
                rule: "R17 component",
                message: format!(
                    "`{}` is not a known component. Declare it with `ui component {}(...) {{ view {{ … }} }}`.",
                    name, name
                ),
                line,
            });
            return;
        }
    };

    let mut provided: HashSet<&str> = HashSet::new();
    for (field, value) in args {
        match comp.params.iter().find(|p| &p.name == field) {
            None => errors.push(SemanticError {
                rule: "R17 component",
                message: format!("component `{}` has no param `{}`.", name, field),
                line,
            }),
            Some(param) => {
                if !provided.insert(field.as_str()) {
                    errors.push(SemanticError {
                        rule: "R17 component",
                        message: format!("param `{}` is set more than once for `{}`.", field, name),
                        line,
                    });
                }
                if let Some(actual) = resolve_type(value, locals, table) {
                    if !type_compatible(&actual, &param.type_name) {
                        errors.push(SemanticError {
                            rule: "R17 component",
                            message: format!(
                                "param `{}.{}` expects `{}`, but got `{}`.",
                                name, field, param.type_name, actual
                            ),
                            line,
                        });
                    }
                }
            }
        }
    }

    for p in &comp.params {
        let omittable = generic_inner("Optional", &p.type_name).is_some()
            || generic_inner("List", &p.type_name).is_some();
        if !provided.contains(p.name.as_str()) && !omittable {
            errors.push(SemanticError {
                rule: "R17 component",
                message: format!("missing param `{}` when invoking `{}`.", p.name, name),
                line,
            });
        }
    }
}

/// Extract the `:name` route params from a pattern, e.g. `/post/:id` -> `["id"]`.
fn route_params(pattern: &str) -> Vec<String> {
    pattern.split('/').filter_map(|seg| seg.strip_prefix(':').map(str::to_string)).collect()
}

/// R28 / R32 — a navigation target. A bare `Screen` (`navigate(Home)` / `link …
/// -> Home`) must be a navigable route: a `ui screen` (not a component) that is
/// prop-less, so the router mounts it with no arguments. A `Screen { … }` target
/// is a typed-route-param navigation (R32): the screen must declare a `route`
/// pattern, and the supplied params must match its props (each once,
/// type-compatible, all present). The target bypasses R8 as a screen name, but a
/// param record's *values* are ordinary in-scope expressions, so they're checked.
fn check_nav_target(
    target: &Expr,
    site: &str,
    sname: &str,
    line: usize,
    locals: &HashMap<String, (Option<String>, bool)>,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    match target {
        Expr::Ident(name) => match table.screens.get(name.as_str()) {
            None => errors.push(SemanticError {
                rule: "R28 navigation",
                message: format!(
                    "{} targets `{}`, which is not a navigable screen. Declare a prop-less `ui screen {} {{ … }}`.",
                    site, name, name
                ),
                line,
            }),
            Some(sc) if sc.route.is_some() => errors.push(SemanticError {
                rule: "R32 route-param",
                message: format!("{} targets the route `{}`, which takes params — supply them: `navigate({} {{ … }})`.", site, name, name),
                line,
            }),
            Some(sc) if !sc.params.is_empty() => errors.push(SemanticError {
                rule: "R28 navigation",
                message: format!(
                    "{} targets `{}`, which takes props — only prop-less screens are navigable. Have `{}` fetch its data in `on load` instead.",
                    site, name, name
                ),
                line,
            }),
            Some(_) => {}
        },
        Expr::Record { name, fields } => {
            let Some(sc) = table.screens.get(name.as_str()) else {
                errors.push(SemanticError {
                    rule: "R32 route-param",
                    message: format!("{} targets `{}`, which is not a known screen.", site, name),
                    line,
                });
                return;
            };
            if sc.route.is_none() || sc.is_component {
                errors.push(SemanticError {
                    rule: "R32 route-param",
                    message: format!("{} supplies params to `{}`, but it has no `route` pattern — only a route with params takes `{{ … }}`.", site, name),
                    line,
                });
                return;
            }
            let mut seen: Vec<&str> = Vec::new();
            for (f, v) in fields {
                check_bindings(v, locals, sname, line, table, errors); // value must be in scope (R8)
                if seen.contains(&f.as_str()) {
                    errors.push(SemanticError {
                        rule: "R32 route-param",
                        message: format!("param `{}` supplied twice to `{}`.", f, name),
                        line,
                    });
                }
                seen.push(f.as_str());
                match sc.params.iter().find(|p| &p.name == f) {
                    None => errors.push(SemanticError {
                        rule: "R32 route-param",
                        message: format!("`{}` is not a param of route `{}`.", f, name),
                        line,
                    }),
                    Some(p) => {
                        if let Some(actual) = resolve_type(v, locals, table) {
                            if !type_compatible(&actual, &p.type_name) {
                                errors.push(SemanticError {
                                    rule: "R32 route-param",
                                    message: format!("param `{}` of `{}` is `{}`, got `{}`.", f, name, p.type_name, actual),
                                    line,
                                });
                            }
                        }
                    }
                }
            }
            for p in &sc.params {
                if !seen.contains(&p.name.as_str()) {
                    errors.push(SemanticError {
                        rule: "R32 route-param",
                        message: format!("{} to `{}` is missing param `{}`.", site, name, p.name),
                        line,
                    });
                }
            }
        }
        _ => errors.push(SemanticError {
            rule: "R28 navigation",
            message: format!(
                "{} in `{}` must name a screen, e.g. `navigate(Home)` — not an arbitrary expression.",
                site, sname
            ),
            line,
        }),
    }
}

/// Check an inline click-handler block (runs in the browser). Assignments must
/// target an in-scope cell (a `state` or a `let`) with a compatible value type.
fn check_handler_block(
    stmts: &[Stmt],
    locals: &HashMap<String, (Option<String>, bool)>,
    sname: &str,
    sline: usize,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    let mut local = locals.clone();
    for s in stmts {
        match s {
            Stmt::Let { name, type_ann, value } => {
                check_screen_expr(value, &local, sname, sline, table, errors);
                let ty = type_ann.clone().or_else(|| resolve_type(value, &local, table));
                local.insert(name.clone(), (ty, false));
            }
            Stmt::Assign { name, value } => {
                check_screen_expr(value, &local, sname, sline, table, errors);
                match local.get(name) {
                    None => errors.push(SemanticError {
                        rule: "R8 unknown-binding",
                        message: format!(
                            "cannot assign to `{}` in screen `{}` — it is not a declared `state` cell.",
                            name, sname
                        ),
                        line: sline,
                    }),
                    Some((Some(target_ty), _)) => {
                        if let Some(actual) = resolve_type(value, &local, table) {
                            if !type_compatible(&actual, target_ty) {
                                errors.push(SemanticError {
                                    rule: "R11 state-init",
                                    message: format!(
                                        "`{}` is `{}` but is assigned `{}`.",
                                        name, target_ty, actual
                                    ),
                                    line: sline,
                                });
                            }
                        }
                    }
                    Some((None, _)) => {}
                }
            }
            Stmt::Return(e) | Stmt::Expr(e) => {
                check_screen_expr(e, &local, sname, sline, table, errors)
            }
            Stmt::Try { body, handler } => {
                // handlers run in the browser, so try is always valid here
                check_handler_block(body, &local, sname, sline, table, errors);
                check_handler_block(handler, &local, sname, sline, table, errors);
            }
            Stmt::If { cond, then_body, else_body } => {
                check_screen_expr(cond, &local, sname, sline, table, errors);
                if let Some(t) = resolve_type(cond, &local, table) {
                    if t != "Bool" {
                        errors.push(SemanticError {
                            rule: "R14 if-condition",
                            message: format!("`if` condition in screen `{}` must be Bool, got `{}`.", sname, t),
                            line: sline,
                        });
                    }
                }
                check_handler_block(then_body, &local, sname, sline, table, errors);
                check_handler_block(else_body, &local, sname, sline, table, errors);
            }
            Stmt::For { var, iter, body } => {
                check_screen_expr(iter, &local, sname, sline, table, errors);
                let elem = element_type_of(iter, &local, table);
                let mut inner = local.clone();
                inner.insert(var.clone(), (elem, false));
                check_handler_block(body, &inner, sname, sline, table, errors);
            }
            Stmt::While { cond, body } => {
                check_screen_expr(cond, &local, sname, sline, table, errors);
                check_handler_block(body, &local, sname, sline, table, errors);
            }
            Stmt::Match { scrutinee, arms } => {
                check_screen_expr(scrutinee, &local, sname, sline, table, errors);
                check_match_patterns(scrutinee, arms, &local, table, sline, errors);
                for arm in arms {
                    check_handler_block(&arm.body, &local, sname, sline, table, errors);
                }
            }
            Stmt::Break | Stmt::Continue => {}
        }
    }
}

/// A screen expression is checked twice: the boundary rules via `check_expr`
/// (as a Ui context), and scope via `check_bindings`.
fn check_screen_expr(
    e: &Expr,
    locals: &HashMap<String, (Option<String>, bool)>,
    sname: &str,
    sline: usize,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    check_expr(e, locals, EnvModifier::Ui, sname, sline, table, errors);
    check_bindings(e, locals, sname, sline, table, errors);
    check_await(e, false, true, sname, sline, table, errors);
}

/// R8 — every identifier must resolve to a prop, a `for` binding, or a function.
fn check_bindings(
    e: &Expr,
    locals: &HashMap<String, (Option<String>, bool)>,
    sname: &str,
    sline: usize,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    match e {
        Expr::Ident(v) => {
            let in_scope = locals.contains_key(v)
                || table.fns.contains_key(v)
                || table.states.contains_key(v);
            if !in_scope {
                errors.push(SemanticError {
                    rule: "R8 unknown-binding",
                    message: format!(
                        "`{}` is not in scope in screen `{}`. Pass it as a prop, e.g. `ui screen {}({}: Type)`.",
                        v, sname, sname, v
                    ),
                    line: sline,
                });
            }
        }
        Expr::Field { base, .. } => {
            // `Enum.Variant` — the base is a type name, not a value binding.
            if let Expr::Ident(name) = base.as_ref() {
                if table.enums.contains_key(name) {
                    return;
                }
            }
            check_bindings(base, locals, sname, sline, table, errors)
        }
        Expr::Call { callee, args } => {
            // `navigate(Screen)`'s argument is a screen name (validated by R28),
            // not a value binding — don't subject it to R8.
            if callee == "navigate" {
                return;
            }
            for a in args {
                check_bindings(a, locals, sname, sline, table, errors);
            }
        }
        Expr::Unary { expr, .. } => check_bindings(expr, locals, sname, sline, table, errors),
        Expr::Binary { left, right, .. } => {
            check_bindings(left, locals, sname, sline, table, errors);
            check_bindings(right, locals, sname, sline, table, errors);
        }
        Expr::Declassify(inner) => check_bindings(inner, locals, sname, sline, table, errors),
        Expr::Raw(inner) => check_bindings(inner, locals, sname, sline, table, errors),
        Expr::Await(inner) => check_bindings(inner, locals, sname, sline, table, errors),
        Expr::MethodCall { receiver, args, .. } => {
            check_bindings(receiver, locals, sname, sline, table, errors);
            for a in args {
                check_bindings(a, locals, sname, sline, table, errors);
            }
        }
        Expr::Record { fields, .. } => {
            for (_, v) in fields {
                check_bindings(v, locals, sname, sline, table, errors);
            }
        }
        Expr::ListLit(items) => {
            for it in items {
                check_bindings(it, locals, sname, sline, table, errors);
            }
        }
        Expr::Ternary { cond, then, otherwise } => {
            check_bindings(cond, locals, sname, sline, table, errors);
            check_bindings(then, locals, sname, sline, table, errors);
            check_bindings(otherwise, locals, sname, sline, table, errors);
        }
        Expr::Range { start, end } => {
            check_bindings(start, locals, sname, sline, table, errors);
            check_bindings(end, locals, sname, sline, table, errors);
        }
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) | Expr::NoneLit => {}
    }
}

/// Element type of an iterable. Resolves `for x in <synced collection>` and
/// `for x in <List<T> state/prop>` to the element type `T`.
fn element_type_of(
    iter: &Expr,
    locals: &HashMap<String, (Option<String>, bool)>,
    table: &SymbolTable,
) -> Option<String> {
    if let Expr::Ident(name) = iter {
        if let Some(state) = table.states.get(name) {
            return Some(state.collection_type.clone());
        }
    }
    // A plain `List<T>` cell (screen state or prop) iterates its element type.
    resolve_type(iter, locals, table)
        .as_deref()
        .and_then(|t| generic_inner("List", t))
        .map(str::to_string)
}

#[allow(clippy::too_many_arguments)]
fn check_expr(
    expr: &Expr,
    locals: &HashMap<String, (Option<String>, bool)>,
    fn_env: EnvModifier,
    fn_name: &str,
    fn_line: usize,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    match expr {
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) | Expr::Ident(_) => {}
        Expr::Field { base, field } => {
            // `session` capability: a server-only Located read of `.actor` (R24).
            if matches!(base.as_ref(), Expr::Ident(n) if n == "session") {
                check_session_member(field, 0, fn_env, fn_name, fn_line, errors);
                return;
            }
            // enum variant access: validate the variant exists (R20).
            if let Expr::Ident(name) = base.as_ref() {
                if let Some(en) = table.enums.get(name) {
                    if !en.variants.iter().any(|v| v == field) {
                        errors.push(SemanticError {
                            rule: "R20 match",
                            message: format!("enum `{}` has no variant `{}`.", name, field),
                            line: fn_line,
                        });
                    }
                    return;
                }
            }
            check_expr(base, locals, fn_env, fn_name, fn_line, table, errors);
            if let Some(model_name) = resolve_type(base, locals, table) {
                if let Some(model) = table.models.get(&model_name) {
                    if let Some(prop) = model.field(field) {
                        if prop.is_secret && fn_env != EnvModifier::Server {
                            errors.push(SemanticError {
                                rule: "R3 secret-containment",
                                message: format!(
                                    "secret field `{}.{}` is read inside `{}`, which runs {}. Secret data may only be touched server-side.",
                                    model_name, field, fn_name, env_label(fn_env)
                                ),
                                line: fn_line,
                            });
                        }
                    }
                }
            }
        }
        Expr::Call { callee, args } => {
            // R28 — `navigate(Screen)` switches the mounted screen + URL. It's a
            // browser-only builtin; its single argument is a screen *name*, not a
            // value (so it bypasses R8 in `check_bindings`).
            if callee == "navigate" {
                if fn_env != EnvModifier::Ui {
                    errors.push(SemanticError {
                        rule: "R28 navigation",
                        message: format!(
                            "`navigate(...)` in `{}` runs {}; navigation is browser-only — call it from a `ui` screen handler or `on load`.",
                            fn_name, env_label(fn_env)
                        ),
                        line: fn_line,
                    });
                }
                if args.len() != 1 {
                    errors.push(SemanticError {
                        rule: "R28 navigation",
                        message: "`navigate` takes exactly one screen, e.g. `navigate(Home)`.".into(),
                        line: fn_line,
                    });
                } else {
                    check_nav_target(&args[0], "`navigate(...)`", fn_name, fn_line, locals, table, errors);
                }
                return; // the screen-name arg is not an ordinary value expression
            }
            // R29 — `decimal("19.99")` builds a string-backed exact money value.
            // It takes exactly one `String` (write the amount as a string so it
            // never passes through binary floating point); a `Float`/`Int`
            // argument is the very mixing this primitive exists to prevent.
            if callee == "decimal" {
                if args.len() != 1 {
                    errors.push(SemanticError {
                        rule: "R29 decimal",
                        message: "`decimal(...)` takes exactly one string, e.g. `decimal(\"19.99\")`.".into(),
                        line: fn_line,
                    });
                } else if let Some(t) = resolve_type(&args[0], locals, table) {
                    if t != "String" {
                        errors.push(SemanticError {
                            rule: "R29 decimal",
                            message: format!(
                                "`decimal(...)` takes a `String`, got `{}`. Write the amount as a string literal: `decimal(\"19.99\")`.",
                                t
                            ),
                            line: fn_line,
                        });
                    }
                }
                check_expr(&args[0], locals, fn_env, fn_name, fn_line, table, errors);
                return;
            }
            // R19 — hash()/verify() are server-only crypto builtins: a password
            // hash must be computed (and a secret hash compared) on the server,
            // never in the browser. (Reading the stored `secret` hash is already
            // R3-blocked client-side; this also stops a pointless client hash.)
            if (callee == "hash" || callee == "verify") && fn_env != EnvModifier::Server {
                errors.push(SemanticError {
                    rule: "R19 auth-builtin",
                    message: format!(
                        "`{}(...)` is a server-only builtin; `{}` runs {}. Do password hashing/verification in a `server fn`.",
                        callee, fn_name, env_label(fn_env)
                    ),
                    line: fn_line,
                });
            }
            let want = match callee.as_str() {
                "hash" => Some(1),
                "verify" => Some(2),
                _ => None,
            };
            if let Some(n) = want {
                if args.len() != n {
                    errors.push(SemanticError {
                        rule: "R19 auth-builtin",
                        message: format!("`{}` takes exactly {} argument(s).", callee, n),
                        line: fn_line,
                    });
                }
            }
            // UI->server calls are allowed now; the `await` requirement is
            // enforced separately by check_await (R4).
            for a in args {
                check_expr(a, locals, fn_env, fn_name, fn_line, table, errors);
            }
        }
        Expr::Unary { expr, .. } => check_expr(expr, locals, fn_env, fn_name, fn_line, table, errors),
        Expr::Binary { left, right, .. } => {
            check_expr(left, locals, fn_env, fn_name, fn_line, table, errors);
            check_expr(right, locals, fn_env, fn_name, fn_line, table, errors);
        }
        Expr::Declassify(inner) => {
            if fn_env != EnvModifier::Server {
                errors.push(SemanticError {
                    rule: "R6 declassify-context",
                    message: format!(
                        "`declassify(...)` used inside `{}`, which runs {}. Secret data may only be declassified server-side.",
                        fn_name, env_label(fn_env)
                    ),
                    line: fn_line,
                });
            }
            check_expr(inner, locals, fn_env, fn_name, fn_line, table, errors);
        }
        Expr::Await(inner) => check_expr(inner, locals, fn_env, fn_name, fn_line, table, errors),
        // `raw(...)` has no tier rule (it's a view-escaping sink, not a secret
        // downgrade) — just check the inner expression.
        Expr::Raw(inner) => check_expr(inner, locals, fn_env, fn_name, fn_line, table, errors),
        Expr::MethodCall { receiver, method, args } => {
            // `db.*` / `session.*` are server-only capabilities; everything else
            // is a synced-collection method. (Don't recurse into the capability
            // ident as a value.)
            let is_db = matches!(receiver.as_ref(), Expr::Ident(n) if n == "db");
            let is_session = matches!(receiver.as_ref(), Expr::Ident(n) if n == "session");
            let is_log = matches!(receiver.as_ref(), Expr::Ident(n) if n == "log");
            let is_endpoint =
                matches!(receiver.as_ref(), Expr::Ident(n) if table.endpoints.contains_key(n));
            if !is_db && !is_session && !is_log && !is_endpoint {
                check_expr(receiver, locals, fn_env, fn_name, fn_line, table, errors);
            }
            for a in args {
                check_expr(a, locals, fn_env, fn_name, fn_line, table, errors);
            }
            if is_endpoint {
                check_endpoint_method(method, args, fn_env, fn_name, fn_line, errors);
            } else if is_log {
                check_log_method(method, args, fn_env, fn_name, fn_line, locals, table, errors);
            } else if is_session {
                check_session_member(method, args.len(), fn_env, fn_name, fn_line, errors);
            } else if is_db {
                check_db_method(method, args, fn_env, fn_name, fn_line, errors);
            } else if method == "or"
                && resolve_type(receiver, locals, table)
                    .as_deref()
                    .and_then(|t| generic_inner("Optional", t))
                    .is_some()
            {
                // optional.or(default) — default must fit the inner type
                let inner = resolve_type(receiver, locals, table)
                    .as_deref()
                    .and_then(|t| generic_inner("Optional", t).map(str::to_string))
                    .unwrap_or_default();
                if args.len() != 1 {
                    errors.push(SemanticError {
                        rule: "R9 record-construction",
                        message: "`or` takes exactly one default value.".into(),
                        line: fn_line,
                    });
                } else if let Some(actual) = resolve_type(&args[0], locals, table) {
                    if !type_compatible(&actual, &inner) {
                        errors.push(SemanticError {
                            rule: "R9 record-construction",
                            message: format!("`or` default must be `{}`, got `{}`.", inner, actual),
                            line: fn_line,
                        });
                    }
                }
            } else if is_list_method_call(receiver, method, locals, table) {
                // List stdlib (spec 08) — must precede the String/collection
                // branches because `length` overlaps a String method name.
                check_list_method(method, args, locals, fn_name, fn_line, table, errors);
            } else if STRING_METHODS.contains(&method.as_str()) {
                check_string_method(receiver, method, args, locals, fn_name, fn_line, table, errors);
            } else {
                check_collection_method(receiver, method, args, locals, fn_env, fn_name, fn_line, table, errors);
            }
        }
        Expr::NoneLit => {}
        Expr::ListLit(items) => {
            for it in items {
                check_expr(it, locals, fn_env, fn_name, fn_line, table, errors);
            }
        }
        Expr::Ternary { cond, then, otherwise } => {
            check_expr(cond, locals, fn_env, fn_name, fn_line, table, errors);
            // R14 — the condition must be Bool (when resolvable).
            if let Some(t) = resolve_type(cond, locals, table) {
                if t != "Bool" {
                    errors.push(SemanticError {
                        rule: "R14 if-condition",
                        message: format!("ternary condition in `{}` must be Bool, got `{}`.", fn_name, t),
                        line: fn_line,
                    });
                }
            }
            check_expr(then, locals, fn_env, fn_name, fn_line, table, errors);
            check_expr(otherwise, locals, fn_env, fn_name, fn_line, table, errors);
            // R18 — both branches must yield one type, so `cond ? a : b` has a
            // single static type (no silent String/Int mixing). Only flagged
            // when both branches resolve, matching R7's "resolvable" policy.
            if let (Some(a), Some(b)) = (
                resolve_type(then, locals, table),
                resolve_type(otherwise, locals, table),
            ) {
                if !type_compatible(&a, &b) && !type_compatible(&b, &a) {
                    errors.push(SemanticError {
                        rule: "R18 conditional-branch",
                        message: format!(
                            "the branches of `?:` in `{}` have incompatible types `{}` and `{}`.",
                            fn_name, a, b
                        ),
                        line: fn_line,
                    });
                }
            }
        }
        Expr::Record { name, fields } => {
            // boundary rules still apply to each field value
            for (_, v) in fields {
                check_expr(v, locals, fn_env, fn_name, fn_line, table, errors);
            }
            check_record(name, fields, locals, fn_line, table, errors);
        }
        Expr::Range { start, end } => {
            check_expr(start, locals, fn_env, fn_name, fn_line, table, errors);
            check_expr(end, locals, fn_env, fn_name, fn_line, table, errors);
        }
    }
}

/// R15 — `db` is a server-only `Located` capability (the connection + creds
/// can never reach the browser). Its methods: query_one, query, exec.
/// R23 — the query argument must be a string literal; user values may flow
/// only through the trailing `$1`, `$2`, … parameters, so SQL injection is not
/// expressible (concatenation/interpolation/a variable in query position is a
/// compile error).
fn check_db_method(
    method: &str,
    args: &[Expr],
    fn_env: EnvModifier,
    fn_name: &str,
    line: usize,
    errors: &mut Vec<SemanticError>,
) {
    if fn_env != EnvModifier::Server {
        errors.push(SemanticError {
            rule: "R15 db-capability",
            message: format!(
                "`db` is a server-only capability; `{}` runs {}. The DB connection cannot reach the browser.",
                fn_name, env_label(fn_env)
            ),
            line,
        });
    }
    if !matches!(method, "query_one" | "query" | "exec") {
        errors.push(SemanticError {
            rule: "R15 db-capability",
            message: format!("`db` has no method `{}` (use query_one, query, exec).", method),
            line,
        });
        return;
    }
    // R23: the SQL must be a literal — never built from user input.
    if !matches!(args.first(), Some(Expr::Str(_))) {
        errors.push(SemanticError {
            rule: "R23 sql-literal",
            message: format!(
                "`db.{}(...)` requires a string-literal query. Pass user values as $1, $2, … parameters — never build SQL from a variable, concatenation, or interpolation.",
                method
            ),
            line,
        });
    }
}

/// R26 — `endpoint` egress (anti-SSRF). An endpoint verb call is server-only
/// (Located: the host + its secret never reach the browser), the verb is `get`
/// or `post`, and the path is a **string literal** — so the host is fixed and
/// the program's egress surface stays statically auditable.
fn check_endpoint_method(
    method: &str,
    args: &[Expr],
    fn_env: EnvModifier,
    fn_name: &str,
    line: usize,
    errors: &mut Vec<SemanticError>,
) {
    if fn_env != EnvModifier::Server {
        errors.push(SemanticError {
            rule: "R26 egress-allowlist",
            message: format!(
                "an `endpoint` call runs in `{}`, which is {}. Outbound HTTP is server-only — the host and its secret cannot reach the browser.",
                fn_name, env_label(fn_env)
            ),
            line,
        });
    }
    if !matches!(method, "get" | "post") {
        errors.push(SemanticError {
            rule: "R26 egress-allowlist",
            message: format!("an `endpoint` has no verb `{}` (use get, post).", method),
            line,
        });
        return;
    }
    if !matches!(args.first(), Some(Expr::Str(_))) {
        errors.push(SemanticError {
            rule: "R26 egress-allowlist",
            message: "an `endpoint` path must be a string literal — the host is fixed by `base`, and only a literal path may be appended.".into(),
            line,
        });
    }
    let want = if method == "post" { 2 } else { 1 };
    if args.len() != want {
        errors.push(SemanticError {
            rule: "R26 egress-allowlist",
            message: format!("`endpoint.{}(...)` takes {} argument(s) (path{}).", method, want, if method == "post" { ", body" } else { "" }),
            line,
        });
    }
}

/// R27 — `log` is a server-only structured logger (`log.info`/`warn`/`error`),
/// the web-appropriate output primitive. Its message cannot be a secret/Located
/// value: logging a credential is a compile error (use `declassify(...)` to
/// release something deliberately).
#[allow(clippy::too_many_arguments)]
fn check_log_method(
    method: &str,
    args: &[Expr],
    fn_env: EnvModifier,
    fn_name: &str,
    line: usize,
    locals: &HashMap<String, (Option<String>, bool)>,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    if fn_env != EnvModifier::Server {
        errors.push(SemanticError {
            rule: "R27 log",
            message: format!("`log` is a server-only capability; `{}` runs {}.", fn_name, env_label(fn_env)),
            line,
        });
    }
    if !matches!(method, "info" | "warn" | "error") {
        errors.push(SemanticError {
            rule: "R27 log",
            message: format!("`log` has no method `{}` (use info, warn, error).", method),
            line,
        });
        return;
    }
    if args.len() != 1 {
        errors.push(SemanticError {
            rule: "R27 log",
            message: format!("`log.{}(...)` takes one message argument.", method),
            line,
        });
        return;
    }
    // log-no-secret: the message cannot derive from a secret/Located value.
    let no_taint: HashMap<String, bool> = HashMap::new();
    if is_tainted(&args[0], locals, table, &no_taint) {
        errors.push(SemanticError {
            rule: "R27 log",
            message: format!(
                "a secret value is passed to `log.{}` in `{}`. Logging a credential is forbidden — use `declassify(...)` to release a value deliberately.",
                method, fn_name
            ),
            line,
        });
    }
}

/// R24 — `session` is a server-only `Located` capability (like `db`): the actor
/// and the HMAC signing key never reach the browser. Members are `.actor` (read
/// the authenticated actor id, an `Optional<String>`), `.login(id)` and
/// `.logout()` (mint / clear the signed `HttpOnly; Secure; SameSite=Strict`
/// session cookie).
fn check_session_member(
    member: &str,
    argc: usize,
    fn_env: EnvModifier,
    fn_name: &str,
    line: usize,
    errors: &mut Vec<SemanticError>,
) {
    if fn_env != EnvModifier::Server {
        errors.push(SemanticError {
            rule: "R24 authn-required",
            message: format!(
                "`session` is a server-only capability; `{}` runs {}. The actor and signing key cannot reach the browser.",
                fn_name, env_label(fn_env)
            ),
            line,
        });
    }
    let want = match member {
        "actor" => return, // a field read, no args
        "login" => 1,
        "logout" => 0,
        _ => {
            errors.push(SemanticError {
                rule: "R24 authn-required",
                message: format!("`session` has no member `{}` (use actor, login, logout).", member),
                line,
            });
            return;
        }
    };
    if argc != want {
        errors.push(SemanticError {
            rule: "R24 authn-required",
            message: format!("`session.{}(...)` takes {} argument(s).", member, want),
            line,
        });
    }
}

/// Does any statement in this body consult `session` (R24)? An `auth` fn that
/// never reads `session.actor` is the "I forgot the auth check" bug — so it must
/// not compile.
/// R25 — actor-scope (anti-IDOR). In an `auth` fn, a `db.query/query_one/exec`
/// that binds any parameter must include `session.actor` among those params, so
/// a protected resource can't be fetched or mutated by a caller-supplied id
/// alone (the common IDOR omission stops compiling).
fn check_actor_scope(stmts: &[Stmt], fn_name: &str, line: usize, errors: &mut Vec<SemanticError>) {
    for s in stmts {
        stmt_actor_scope(s, fn_name, line, errors);
    }
}

fn stmt_actor_scope(s: &Stmt, fn_name: &str, line: usize, errors: &mut Vec<SemanticError>) {
    match s {
        Stmt::Let { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::Return(value)
        | Stmt::Expr(value) => expr_actor_scope(value, fn_name, line, errors),
        Stmt::Try { body, handler } => {
            check_actor_scope(body, fn_name, line, errors);
            check_actor_scope(handler, fn_name, line, errors);
        }
        Stmt::If { cond, then_body, else_body } => {
            expr_actor_scope(cond, fn_name, line, errors);
            check_actor_scope(then_body, fn_name, line, errors);
            check_actor_scope(else_body, fn_name, line, errors);
        }
        Stmt::For { iter, body, .. } => {
            expr_actor_scope(iter, fn_name, line, errors);
            check_actor_scope(body, fn_name, line, errors);
        }
        Stmt::While { cond, body } => {
            expr_actor_scope(cond, fn_name, line, errors);
            check_actor_scope(body, fn_name, line, errors);
        }
        Stmt::Match { scrutinee, arms } => {
            expr_actor_scope(scrutinee, fn_name, line, errors);
            for a in arms {
                check_actor_scope(&a.body, fn_name, line, errors);
            }
        }
        Stmt::Break | Stmt::Continue => {}
    }
}

fn expr_actor_scope(e: &Expr, fn_name: &str, line: usize, errors: &mut Vec<SemanticError>) {
    if let Expr::MethodCall { receiver, method, args } = e {
        let is_db = matches!(receiver.as_ref(), Expr::Ident(n) if n == "db");
        if is_db && matches!(method.as_str(), "query" | "query_one" | "exec") {
            // args[0] is the SQL literal; args[1..] are the bound parameters.
            let params = args.get(1..).unwrap_or(&[]);
            if !params.is_empty() && !params.iter().any(expr_uses_session) {
                errors.push(SemanticError {
                    rule: "R25 actor-scope",
                    message: format!(
                        "`db.{}` in `auth fn {}` binds a caller-supplied value but not `session.actor`. Add an ownership predicate bound to the actor (e.g. `… where id = $1 and owner = $2`, …, session.actor) — a protected query scoped only by a caller id is an IDOR.",
                        method, fn_name
                    ),
                    line,
                });
            }
        }
    }
    match e {
        Expr::Field { base, .. } => expr_actor_scope(base, fn_name, line, errors),
        Expr::Call { args, .. } => args.iter().for_each(|a| expr_actor_scope(a, fn_name, line, errors)),
        Expr::MethodCall { receiver, args, .. } => {
            expr_actor_scope(receiver, fn_name, line, errors);
            args.iter().for_each(|a| expr_actor_scope(a, fn_name, line, errors));
        }
        Expr::Unary { expr, .. } => expr_actor_scope(expr, fn_name, line, errors),
        Expr::Binary { left, right, .. } => {
            expr_actor_scope(left, fn_name, line, errors);
            expr_actor_scope(right, fn_name, line, errors);
        }
        Expr::Declassify(i) | Expr::Await(i) | Expr::Raw(i) => expr_actor_scope(i, fn_name, line, errors),
        Expr::Record { fields, .. } => {
            fields.iter().for_each(|(_, v)| expr_actor_scope(v, fn_name, line, errors))
        }
        Expr::ListLit(items) => items.iter().for_each(|i| expr_actor_scope(i, fn_name, line, errors)),
        Expr::Ternary { cond, then, otherwise } => {
            expr_actor_scope(cond, fn_name, line, errors);
            expr_actor_scope(then, fn_name, line, errors);
            expr_actor_scope(otherwise, fn_name, line, errors);
        }
        Expr::Range { start, end } => {
            expr_actor_scope(start, fn_name, line, errors);
            expr_actor_scope(end, fn_name, line, errors);
        }
        _ => {}
    }
}

fn stmts_use_session(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_uses_session)
}

fn stmt_uses_session(s: &Stmt) -> bool {
    match s {
        Stmt::Let { value, .. } | Stmt::Assign { value, .. } | Stmt::Return(value)
        | Stmt::Expr(value) => expr_uses_session(value),
        Stmt::Try { body, handler } => stmts_use_session(body) || stmts_use_session(handler),
        Stmt::If { cond, then_body, else_body } => {
            expr_uses_session(cond) || stmts_use_session(then_body) || stmts_use_session(else_body)
        }
        Stmt::For { iter, body, .. } => expr_uses_session(iter) || stmts_use_session(body),
        Stmt::While { cond, body } => expr_uses_session(cond) || stmts_use_session(body),
        Stmt::Match { scrutinee, arms } => {
            expr_uses_session(scrutinee) || arms.iter().any(|a| stmts_use_session(&a.body))
        }
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
        _ => false,
    }
}

/// R21 — String stdlib methods: the receiver must be a `String` and the arg
/// count must match (`contains`/`split` take 1, `replace` 2, the rest 0).
#[allow(clippy::too_many_arguments)]
fn check_string_method(
    receiver: &Expr,
    method: &str,
    args: &[Expr],
    locals: &HashMap<String, (Option<String>, bool)>,
    fn_name: &str,
    line: usize,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    if let Some(rt) = resolve_type(receiver, locals, table) {
        if rt != "String" {
            errors.push(SemanticError {
                rule: "R21 stdlib",
                message: format!("`.{}()` is a String method, but the receiver in `{}` is `{}`.", method, fn_name, rt),
                line,
            });
        }
    }
    let want = match method {
        "contains" | "split" => 1,
        "replace" => 2,
        _ => 0,
    };
    if args.len() != want {
        errors.push(SemanticError {
            rule: "R21 stdlib",
            message: format!("`.{}()` takes {} argument(s).", method, want),
            line,
        });
    }
}

/// True when `receiver` is a `List<T>` and `method` is a List stdlib method
/// (spec 08). Gates the dispatch so list `.length()` doesn't fall into the String
/// check (R21) and `.first/.last/.at/.reverse` don't fall into the collection
/// check (R12).
fn is_list_method_call(
    receiver: &Expr,
    method: &str,
    locals: &HashMap<String, (Option<String>, bool)>,
    table: &SymbolTable,
) -> bool {
    matches!(method, "length" | "first" | "last" | "at" | "reverse")
        && resolve_type(receiver, locals, table)
            .as_deref()
            .and_then(|t| generic_inner("List", t))
            .is_some()
}

/// List stdlib argument discipline (spec 08; reuses the R21 "stdlib" rule — no new
/// rule). `at` takes one `Int`; `length`/`first`/`last`/`reverse` take none. The
/// safe accessors return `Optional<T>`, so a miss is `none` (caller unwraps via
/// `.or`) — there's no separate bounds rule.
fn check_list_method(
    method: &str,
    args: &[Expr],
    locals: &HashMap<String, (Option<String>, bool)>,
    fn_name: &str,
    line: usize,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    let want = if method == "at" { 1 } else { 0 };
    if args.len() != want {
        errors.push(SemanticError {
            rule: "R21 stdlib",
            message: format!("`.{}()` on a list takes {} argument(s).", method, want),
            line,
        });
        return;
    }
    if method == "at" {
        if let Some(t) = resolve_type(&args[0], locals, table) {
            if t != "Int" {
                errors.push(SemanticError {
                    rule: "R21 stdlib",
                    message: format!("`.at(i)` index must be `Int`, got `{}` in `{}`.", t, fn_name),
                    line,
                });
            }
        }
    }
}

/// R12 — method calls are only on `synced` collections, and only client-side.
/// `add(row)` takes the element type; `remove(id)` takes a String.
#[allow(clippy::too_many_arguments)]
fn check_collection_method(
    receiver: &Expr,
    method: &str,
    args: &[Expr],
    locals: &HashMap<String, (Option<String>, bool)>,
    fn_env: EnvModifier,
    fn_name: &str,
    line: usize,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    let coll = match receiver {
        Expr::Ident(c) if table.states.contains_key(c) => c,
        _ => {
            errors.push(SemanticError {
                rule: "R12 collection-method",
                message: "methods may only be called on `synced` collections.".into(),
                line,
            });
            return;
        }
    };
    if fn_env == EnvModifier::Server {
        errors.push(SemanticError {
            rule: "R12 collection-method",
            message: format!("`{}` runs server-side; synced collections are client-side only.", fn_name),
            line,
        });
        return;
    }
    let elem = table.states.get(coll).map(|s| s.collection_type.clone()).unwrap_or_default();
    match method {
        "add" => check_method_arg(method, coll, args, &elem, locals, line, table, errors),
        "remove" => check_method_arg(method, coll, args, "String", locals, line, table, errors),
        "get" | "all" => {}
        other => errors.push(SemanticError {
            rule: "R12 collection-method",
            message: format!("collection `{}` has no method `{}` (use add, remove, get, all).", coll, other),
            line,
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn check_method_arg(
    method: &str,
    coll: &str,
    args: &[Expr],
    want: &str,
    locals: &HashMap<String, (Option<String>, bool)>,
    line: usize,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    if args.len() != 1 {
        errors.push(SemanticError {
            rule: "R12 collection-method",
            message: format!("`{}.{}` takes exactly one argument.", coll, method),
            line,
        });
        return;
    }
    if let Some(actual) = resolve_type(&args[0], locals, table) {
        if !type_compatible(&actual, want) {
            errors.push(SemanticError {
                rule: "R12 collection-method",
                message: format!("`{}.{}` expects `{}`, got `{}`.", coll, method, want, actual),
                line,
            });
        }
    }
}

/// R4 — in browser code (`ui`/`none`), a call to a `server` fn is an async RPC
/// and must be the direct operand of `await`. `await` is browser-only.
fn check_await(
    e: &Expr,
    awaited: bool,
    in_browser: bool,
    fn_name: &str,
    line: usize,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    match e {
        Expr::Await(inner) => {
            if !in_browser {
                errors.push(SemanticError {
                    rule: "R4 async-call-discipline",
                    message: format!("`await` in `{}` is only valid in ui/screen code.", fn_name),
                    line,
                });
            }
            check_await(inner, true, in_browser, fn_name, line, table, errors);
        }
        Expr::Call { callee, args } => {
            let is_server = table.fns.get(callee).map(|s| s.env == EnvModifier::Server).unwrap_or(false);
            if in_browser && is_server && !awaited {
                errors.push(SemanticError {
                    rule: "R4 async-call-discipline",
                    message: format!(
                        "`{}` is a server fn; calling it from the browser is an async RPC — use `await {}(...)`.",
                        callee, callee
                    ),
                    line,
                });
            }
            for a in args {
                check_await(a, false, in_browser, fn_name, line, table, errors);
            }
        }
        Expr::Field { base, .. } => check_await(base, false, in_browser, fn_name, line, table, errors),
        Expr::Unary { expr, .. } => check_await(expr, false, in_browser, fn_name, line, table, errors),
        Expr::Binary { left, right, .. } => {
            check_await(left, false, in_browser, fn_name, line, table, errors);
            check_await(right, false, in_browser, fn_name, line, table, errors);
        }
        Expr::Declassify(inner) => check_await(inner, false, in_browser, fn_name, line, table, errors),
        Expr::Raw(inner) => check_await(inner, false, in_browser, fn_name, line, table, errors),
        Expr::MethodCall { receiver, args, .. } => {
            check_await(receiver, false, in_browser, fn_name, line, table, errors);
            for a in args {
                check_await(a, false, in_browser, fn_name, line, table, errors);
            }
        }
        Expr::Record { fields, .. } => {
            for (_, v) in fields {
                check_await(v, false, in_browser, fn_name, line, table, errors);
            }
        }
        Expr::ListLit(items) => {
            for it in items {
                check_await(it, false, in_browser, fn_name, line, table, errors);
            }
        }
        Expr::Ternary { cond, then, otherwise } => {
            check_await(cond, false, in_browser, fn_name, line, table, errors);
            check_await(then, false, in_browser, fn_name, line, table, errors);
            check_await(otherwise, false, in_browser, fn_name, line, table, errors);
        }
        Expr::Range { start, end } => {
            check_await(start, false, in_browser, fn_name, line, table, errors);
            check_await(end, false, in_browser, fn_name, line, table, errors);
        }
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) | Expr::Ident(_)
        | Expr::NoneLit => {}
    }
}

/// R9 — a record literal must name a model and supply each field exactly once
/// with a type-compatible value. All fields are required (no defaults yet).
fn check_record(
    name: &str,
    fields: &[(String, Expr)],
    locals: &HashMap<String, (Option<String>, bool)>,
    line: usize,
    table: &SymbolTable,
    errors: &mut Vec<SemanticError>,
) {
    let model = match table.models.get(name) {
        Some(m) => m,
        None => {
            errors.push(SemanticError {
                rule: "R1 unknown-type",
                message: format!("`{}` is not a known model.", name),
                line,
            });
            return;
        }
    };

    let mut provided: HashSet<&str> = HashSet::new();
    for (fname, value) in fields {
        match model.field(fname) {
            None => errors.push(SemanticError {
                rule: "R9 record-construction",
                message: format!("model `{}` has no field `{}`.", name, fname),
                line,
            }),
            Some(prop) => {
                if !provided.insert(fname.as_str()) {
                    errors.push(SemanticError {
                        rule: "R9 record-construction",
                        message: format!("field `{}` is set more than once in `{}`.", fname, name),
                        line,
                    });
                }
                if let Some(actual) = resolve_type(value, locals, table) {
                    if !type_compatible(&actual, &prop.data_type) {
                        errors.push(SemanticError {
                            rule: "R9 record-construction",
                            message: format!(
                                "field `{}.{}` expects `{}`, but got `{}`.",
                                name, fname, prop.data_type, actual
                            ),
                            line,
                        });
                    }
                }
            }
        }
    }

    for p in &model.properties {
        // Optional<T> and List<T> fields may be omitted (default to none / []).
        let omittable = generic_inner("Optional", &p.data_type).is_some()
            || generic_inner("List", &p.data_type).is_some();
        if !provided.contains(p.name.as_str()) && !omittable {
            errors.push(SemanticError {
                rule: "R9 record-construction",
                message: format!("missing field `{}` when constructing `{}`.", p.name, name),
                line,
            });
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
    };
    for ep in &program.endpoints {
        if table.endpoints.insert(ep.name.clone(), ep).is_some() {
            errors.push(SemanticError {
                rule: "R2 duplicate-decl",
                message: format!("endpoint `{}` is declared more than once.", ep.name),
                line: ep.line,
            });
        }
    }

    // Enums: register, and reject duplicate enum names / duplicate variants (R2).
    for e in &program.enums {
        if table.enums.insert(e.name.clone(), e).is_some() || table.models.contains_key(&e.name) {
            errors.push(SemanticError {
                rule: "R2 duplicate-decl",
                message: format!("type `{}` is declared more than once.", e.name),
                line: e.line,
            });
        }
        let mut seen = HashSet::new();
        for v in &e.variants {
            if !seen.insert(v) {
                errors.push(SemanticError {
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
            errors.push(SemanticError {
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
                errors.push(SemanticError {
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
            errors.push(SemanticError {
                rule: "R2 duplicate-decl",
                message: format!("model `{}` is declared more than once.", m.name),
                line: m.line,
            });
        }
        let mut seen = HashSet::new();
        for p in &m.properties {
            if !seen.insert(&p.name) {
                errors.push(SemanticError {
                    rule: "R2 duplicate-decl",
                    message: format!("field `{}` is declared twice in model `{}`.", p.name, m.name),
                    line: p.line,
                });
            }
        }
    }
    for f in &program.functions {
        if table.fns.insert(f.name.clone(), FnSig { env: f.env, ret: f.return_type.clone() }).is_some() {
            errors.push(SemanticError {
                rule: "R2 duplicate-decl",
                message: format!("function `{}` is declared more than once.", f.name),
                line: f.line,
            });
        }
    }

    for m in &program.models {
        for p in &m.properties {
            if !is_known_type(&p.data_type, &table) {
                errors.push(SemanticError {
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
            errors.push(SemanticError {
                rule: "R1 unknown-type",
                message: format!("synced state `{}` references unknown type `{}`.", s.name, s.collection_type),
                line: s.line,
            });
        } else if let Some(model) = table.models.get(s.collection_type.as_str()) {
            // R10 — a synced collection needs a stable string key to merge on.
            let has_id = model.field("id").map(|p| p.data_type == "String").unwrap_or(false);
            if !has_id {
                errors.push(SemanticError {
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
                errors.push(SemanticError {
                    rule: "R1 unknown-type",
                    message: format!("parameter `{}: {}` of `{}` has unknown type.", p.name, p.type_name, f.name),
                    line: f.line,
                });
            }
        }
        if let Some(ret) = &f.return_type {
            if !is_known_type(ret, &table) {
                errors.push(SemanticError {
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
            errors.push(SemanticError {
                rule: "R24 authn-required",
                message: format!("`auth` is a server-only modifier, but `{}` runs {}.", f.name, env_label(f.env)),
                line: f.line,
            });
        }
        if !stmts_use_session(&f.body) {
            errors.push(SemanticError {
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
            errors.push(SemanticError {
                rule: "R31 auth-route",
                message: format!("`auth` marks a protected route; it can't be used on component `{}`.", s.name),
                line: s.line,
            });
            continue;
        }
        if !s.params.is_empty() {
            errors.push(SemanticError {
                rule: "R31 auth-route",
                message: format!("an `auth` screen must be a prop-less route; `{}` takes props.", s.name),
                line: s.line,
            });
        }
        if !app_uses_session {
            errors.push(SemanticError {
                rule: "R31 auth-route",
                message: format!(
                    "`auth ui screen {}` needs a session, but no function establishes one (call `session.login(...)` in an `auth server fn`).",
                    s.name
                ),
                line: s.line,
            });
        }
        if navigable_root.as_deref() == Some(s.name.as_str()) {
            errors.push(SemanticError {
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
            errors.push(SemanticError {
                rule: "R32 route-param",
                message: format!("`route` is for screens, not component `{}`.", s.name),
                line: s.line,
            });
            continue;
        }
        let pat: Vec<String> = route_params(pattern);
        if pat.is_empty() {
            errors.push(SemanticError {
                rule: "R32 route-param",
                message: format!("route `{}` on `{}` has no `:param` segment — use a plain screen for a static path.", pattern, s.name),
                line: s.line,
            });
        }
        for pp in &pat {
            if !s.params.iter().any(|p| &p.name == pp) {
                errors.push(SemanticError {
                    rule: "R32 route-param",
                    message: format!("route param `:{}` on `{}` has no matching prop — add `{}: String` (or `Int`).", pp, s.name, pp),
                    line: s.line,
                });
            }
        }
        for p in &s.params {
            if !pat.contains(&p.name) {
                errors.push(SemanticError {
                    rule: "R32 route-param",
                    message: format!("prop `{}` on route `{}` isn't bound by the pattern `{}` (add `:{}`).", p.name, s.name, pattern, p.name),
                    line: s.line,
                });
            }
            if p.type_name != "String" && p.type_name != "Int" {
                errors.push(SemanticError {
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
        if returns_secret[&f.name] && f.env != EnvModifier::Server {
            errors.push(SemanticError {
                rule: "R5 secret-leak-via-return",
                message: format!(
                    "`{}` returns secret-derived data but runs {}. Only `server` functions may return secret data; use `declassify(...)` server-side if release is intended.",
                    f.name, env_label(f.env)
                ),
                line: f.line,
            });
        }
    }

    // stable, readable ordering: by line
    errors.sort_by_key(|e| e.line);

    Analysis { errors, returns_secret }
}
