// src/checker.rs
use crate::parser::{
    BinOp, EnvModifier, Expr, FunctionNode, Handler, ModelNode, ScreenNode, Stmt, SyncedStateNode,
    ViewNode, XeresProgram,
};
use std::collections::{HashMap, HashSet};

const BUILTINS: &[&str] = &["String", "Int", "Float", "Bool"];

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
    fns: HashMap<String, FnSig>,
    states: HashMap<String, &'a SyncedStateNode>,
}

/// Inner type of a one-level generic, e.g. `("List", "List<User>") -> "User"`.
fn generic_inner<'a>(base: &str, ty: &'a str) -> Option<&'a str> {
    ty.strip_prefix(base)
        .and_then(|r| r.strip_prefix('<'))
        .and_then(|r| r.strip_suffix('>'))
}

fn is_known_type(name: &str, table: &SymbolTable) -> bool {
    if let Some(inner) = generic_inner("List", name).or_else(|| generic_inner("Optional", name)) {
        return is_known_type(inner, table);
    }
    BUILTINS.contains(&name) || table.models.contains_key(name)
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
            let base_ty = resolve_type(base, locals, table)?;
            let model = table.models.get(&base_ty)?;
            model.field(field).map(|p| p.data_type.clone())
        }
        Expr::Call { callee, .. } => {
            if callee == "uid" {
                Some("String".into()) // builtin: unique id generator
            } else {
                table.fns.get(callee).and_then(|s| s.ret.clone())
            }
        }
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
                _ => None,
            }
        }
        Expr::Declassify(inner) => resolve_type(inner, locals, table),
        Expr::Await(inner) => resolve_type(inner, locals, table),
        Expr::MethodCall { receiver, method, args: _ } => {
            if let Expr::Ident(name) = receiver.as_ref() {
                // `db.exec` returns affected-row count; `db.query_one` is typed
                // by the surrounding fn's return model (resolved in codegen).
                if name == "db" {
                    return if method == "exec" { Some("Int".into()) } else { None };
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
            None
        }
        Expr::Record { name, .. } => Some(name.clone()),
        Expr::NoneLit => Some("None".into()),
        Expr::ListLit(items) => {
            let elem = items.first().and_then(|e| resolve_type(e, locals, table))?;
            Some(format!("List<{}>", elem))
        }
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
            Stmt::Let { name, value } => {
                let t = is_tainted(value, locals, table, returns_secret);
                let ty = resolve_type(value, locals, table);
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
            Stmt::Assign { .. } | Stmt::Expr(_) => {}
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
            Stmt::Let { name, value } => {
                check_expr(value, locals, f.env, &f.name, f.line, table, errors);
                check_await(value, false, in_browser, &f.name, f.line, table, errors);
                let ty = resolve_type(value, locals, table);
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
        ViewNode::Element { arg, bind, event, children, .. } => {
            if let Some(a) = arg {
                check_screen_expr(a, locals, sname, sline, table, errors);
            }
            // R13 — `bind x` requires x to be a String `state` cell.
            if let Some(var) = bind {
                let ok = states.contains(var)
                    && matches!(locals.get(var), Some((Some(t), _)) if t == "String");
                if !ok {
                    errors.push(SemanticError {
                        rule: "R13 input-binding",
                        message: format!(
                            "`bind {}` in screen `{}` requires a `state {}: String` cell.",
                            var, sname, var
                        ),
                        line: sline,
                    });
                }
            }
            match event {
                Some(Handler::Call(e)) => check_screen_expr(e, locals, sname, sline, table, errors),
                Some(Handler::Block(stmts)) => {
                    check_handler_block(stmts, locals, sname, sline, table, errors)
                }
                None => {}
            }
            for c in children {
                check_view(c, locals, states, sname, sline, table, errors);
            }
        }
        ViewNode::For { var, iter, body } => {
            check_screen_expr(iter, locals, sname, sline, table, errors);
            // bind the loop variable to the collection's element type when known.
            let elem = element_type_of(iter, table);
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
            Stmt::Let { name, value } => {
                check_screen_expr(value, &local, sname, sline, table, errors);
                let ty = resolve_type(value, &local, table);
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
        Expr::Field { base, .. } => check_bindings(base, locals, sname, sline, table, errors),
        Expr::Call { args, .. } => {
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
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) | Expr::NoneLit => {}
    }
}

/// Element type of an iterable: today, only `for x in <synced state>` resolves.
fn element_type_of(iter: &Expr, table: &SymbolTable) -> Option<String> {
    if let Expr::Ident(name) = iter {
        if let Some(state) = table.states.get(name) {
            return Some(state.collection_type.clone());
        }
    }
    None
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
        Expr::Call { args, .. } => {
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
        Expr::MethodCall { receiver, method, args } => {
            // `db.*` is the server-only database capability; everything else is
            // a synced-collection method. (Don't recurse into `db` as a value.)
            let is_db = matches!(receiver.as_ref(), Expr::Ident(n) if n == "db");
            if !is_db {
                check_expr(receiver, locals, fn_env, fn_name, fn_line, table, errors);
            }
            for a in args {
                check_expr(a, locals, fn_env, fn_name, fn_line, table, errors);
            }
            if is_db {
                check_db_method(method, fn_env, fn_name, fn_line, errors);
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
        Expr::Record { name, fields } => {
            // boundary rules still apply to each field value
            for (_, v) in fields {
                check_expr(v, locals, fn_env, fn_name, fn_line, table, errors);
            }
            check_record(name, fields, locals, fn_line, table, errors);
        }
    }
}

/// R15 — `db` is a server-only `Located` capability (the connection + creds
/// can never reach the browser). Its methods: query_one, query, exec.
fn check_db_method(
    method: &str,
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
        fns: HashMap::new(),
        states: HashMap::new(),
    };

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

    for f in &program.functions {
        check_flow(f, &table, &mut errors);
    }

    for s in &program.screens {
        check_screen(s, &table, &mut errors);
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
