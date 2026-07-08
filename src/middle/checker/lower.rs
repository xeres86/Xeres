// Typed lowering — desugar Decimal ops + String-concat after checking (spec 18/24).
use super::*;
use crate::frontend::parser::*;
use std::collections::{HashMap, HashSet};

// --------------------------------------------------------- typed lowering
//
// Decimal arithmetic desugaring (spec 18). `interp::binary` and codegen's
// `emit_*` are type-blind — a Decimal is a *string*, so a bare `+`/`<` would
// concatenate / compare lexicographically. After type-checking succeeds, this
// pass rewrites Decimal `+ - * < > <= >=` into `__dec_*` builtin calls that every
// backend emits exactly (the interpreter's `__dec_*` dispatch, the browser's
// `__dec.*` BigInt runtime, the server's `rust_decimal` helpers). No new
// `Value`/`Expr` shape, no `emit_*` refactor; the pattern generalizes to any
// future typed operator. Runs only on a program that already passed `analyze`,
// so it can assume types resolve and the R29 discipline holds.

/// The `__dec_*` builtin a Decimal binary op lowers to, or `None` to leave the op
/// as-is (native concat for `String + Decimal`, `==`/`!=`, plain numerics). Only
/// the legal, R29-passing combinations lower — an `analyze`-rejected program
/// never reaches here, so this never has to lower a `Decimal {+} Int` etc.
fn dec_lowering_callee(op: BinOp, lt: Option<&str>, rt: Option<&str>) -> Option<&'static str> {
    let l = lt == Some("Decimal");
    let r = rt == Some("Decimal");
    match op {
        BinOp::Add if l && r => Some("__dec_add"),
        BinOp::Sub if l && r => Some("__dec_sub"),
        BinOp::Mul if (l && r) || (l && rt == Some("Int")) || (r && lt == Some("Int")) => {
            Some("__dec_mul")
        }
        BinOp::Lt if l && r => Some("__dec_lt"),
        BinOp::Gt if l && r => Some("__dec_gt"),
        BinOp::LtEq if l && r => Some("__dec_le"),
        BinOp::GtEq if l && r => Some("__dec_ge"),
        _ => None,
    }
}

/// Rewrite Decimal binary ops to `__dec_*` calls across the whole program. Called
/// from `main::compile` after `analyze` succeeds, before interp/codegen.
pub fn lower(program: &mut XeresProgram) {
    // A read-only symbol table that borrows only the declarations lowering does
    // NOT mutate (models/enums/states/endpoints). `fns` is owned (`FnSig`) and
    // `resolve_type` never reads `screens`/`components`, so we can still take
    // `&mut` to functions/screens below with no borrow conflict.
    let XeresProgram { models, enums, functions, states, endpoints, screens, apis, .. } = program;
    let table = SymbolTable {
        models: models.iter().map(|m| (m.name.clone(), &*m)).collect(),
        enums: enums.iter().map(|e| (e.name.clone(), &*e)).collect(),
        fns: functions
            .iter()
            .map(|f| (f.name.clone(), FnSig { env: f.env, ret: f.return_type.clone() }))
            .collect(),
        states: states.iter().map(|s| (s.name.clone(), &*s)).collect(),
        components: HashMap::new(),
        screens: HashMap::new(),
        endpoints: endpoints.iter().map(|e| (e.name.clone(), &*e)).collect(),
        tokens: HashSet::new(),
        styles: HashSet::new(),
    };

    for f in functions.iter_mut() {
        let mut locals: HashMap<String, (Option<String>, bool)> = HashMap::new();
        for p in &f.params {
            locals.insert(p.name.clone(), (Some(p.type_name.clone()), false));
        }
        lower_stmts(&mut f.body, &mut locals, &table);
    }

    for s in screens.iter_mut() {
        let mut locals: HashMap<String, (Option<String>, bool)> = HashMap::new();
        for p in &s.params {
            locals.insert(p.name.clone(), (Some(p.type_name.clone()), false));
        }
        for st in &mut s.states {
            lower_expr(&mut st.init, &locals, &table);
            locals.insert(st.name.clone(), (Some(st.type_name.clone()), false));
        }
        for v in &mut s.body {
            lower_view(v, &locals, &table);
        }
        // `on load` runs as a browser handler with props + state cells in scope.
        let mut load_locals = locals.clone();
        lower_stmts(&mut s.load, &mut load_locals, &table);
    }

    // API route bodies (spec 23) — same Decimal desugaring as a server fn body,
    // with the `body` model param in scope.
    for api in apis.iter_mut() {
        for route in api.routes.iter_mut() {
            let mut locals: HashMap<String, (Option<String>, bool)> = HashMap::new();
            if let Some(b) = &route.body {
                locals.insert(b.name.clone(), (Some(b.type_name.clone()), false));
            }
            lower_stmts(&mut route.body_stmts, &mut locals, &table);
        }
    }
}

fn lower_stmts(
    stmts: &mut [Stmt],
    locals: &mut HashMap<String, (Option<String>, bool)>,
    table: &SymbolTable,
) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::Let { name, type_ann, value } => {
                lower_expr(value, locals, table);
                let ty = type_ann.clone().or_else(|| resolve_type(&*value, locals, table));
                locals.insert(name.clone(), (ty, false));
            }
            Stmt::Assign { value, .. } => lower_expr(value, locals, table),
            Stmt::Return(e) | Stmt::Expr(e) => lower_expr(e, locals, table),
            Stmt::Try { body, handler } => {
                let mut b = locals.clone();
                lower_stmts(body, &mut b, table);
                let mut h = locals.clone();
                lower_stmts(handler, &mut h, table);
            }
            Stmt::If { cond, then_body, else_body } => {
                lower_expr(cond, locals, table);
                let mut t = locals.clone();
                lower_stmts(then_body, &mut t, table);
                let mut e = locals.clone();
                lower_stmts(else_body, &mut e, table);
            }
            Stmt::For { var, iter, body } => {
                lower_expr(iter, locals, table);
                let elem = element_type_of(&*iter, locals, table);
                let mut inner = locals.clone();
                inner.insert(var.clone(), (elem, false));
                lower_stmts(body, &mut inner, table);
            }
            Stmt::While { cond, body } => {
                lower_expr(cond, locals, table);
                let mut inner = locals.clone();
                lower_stmts(body, &mut inner, table);
            }
            Stmt::Match { scrutinee, arms } => {
                lower_expr(scrutinee, locals, table);
                for arm in arms.iter_mut() {
                    let mut inner = locals.clone();
                    lower_stmts(&mut arm.body, &mut inner, table);
                }
            }
            Stmt::Transaction(body) => {
                let mut inner = locals.clone();
                lower_stmts(body, &mut inner, table);
            }
            Stmt::Break | Stmt::Continue => {}
        }
    }
}

fn lower_expr(
    expr: &mut Expr,
    locals: &HashMap<String, (Option<String>, bool)>,
    table: &SymbolTable,
) {
    match expr {
        Expr::Binary { op, left, right } => {
            let op = *op;
            // Bottom-up: lower the operands first, so a nested `(a + b) * c`
            // resolves the inner result as Decimal (via the `__dec_*` typing in
            // `resolve_type`) before this level decides.
            lower_expr(left, locals, table);
            lower_expr(right, locals, table);
            let lt = resolve_type(&**left, locals, table);
            let rt = resolve_type(&**right, locals, table);
            if let Some(callee) = dec_lowering_callee(op, lt.as_deref(), rt.as_deref()) {
                let l = std::mem::replace(left.as_mut(), Expr::NoneLit);
                let r = std::mem::replace(right.as_mut(), Expr::NoneLit);
                *expr = Expr::Call { callee: callee.to_string(), args: vec![l, r] };
            } else if matches!(op, BinOp::Add)
                && (lt.as_deref() == Some("String") || rt.as_deref() == Some("String"))
            {
                // String display-concatenation (spec 24): `String + <scalar>` →
                // `__str_concat(a, b)` that every backend emits (Rust `format!`,
                // TS `+`, interp Display-concat). Chains: the result is a String,
                // so `"a" + b + c` folds left-to-right.
                let l = std::mem::replace(left.as_mut(), Expr::NoneLit);
                let r = std::mem::replace(right.as_mut(), Expr::NoneLit);
                *expr = Expr::Call { callee: "__str_concat".to_string(), args: vec![l, r] };
            }
        }
        Expr::Field { base, .. } => lower_expr(base, locals, table),
        Expr::Call { args, .. } => {
            for a in args.iter_mut() {
                lower_expr(a, locals, table);
            }
        }
        Expr::Unary { expr: inner, .. } => lower_expr(inner, locals, table),
        Expr::Declassify(inner) | Expr::Raw(inner) | Expr::Await(inner) => {
            lower_expr(inner, locals, table)
        }
        Expr::MethodCall { receiver, method, args } => {
            lower_expr(receiver, locals, table);
            let recv_elem = resolve_type(&**receiver, locals, table)
                .as_deref()
                .and_then(|t| generic_inner("List", t).map(str::to_string));
            // Higher-order closures (spec 19 × 18): lower the body with the closure
            // param(s) bound to the element/accumulator type, so a Decimal op inside
            // the body still desugars (otherwise its operand types wouldn't resolve).
            if let Some(elem) = &recv_elem {
                match method.as_str() {
                    "map" | "filter" => {
                        if let [Expr::Closure { params, body }] = args.as_mut_slice() {
                            if params.len() == 1 {
                                let mut inner = locals.clone();
                                inner.insert(params[0].clone(), (Some(elem.clone()), false));
                                lower_expr(body, &inner, table);
                                return;
                            }
                        }
                    }
                    "reduce" => {
                        if let [init, Expr::Closure { params, body }] = args.as_mut_slice() {
                            if params.len() == 2 {
                                lower_expr(init, locals, table);
                                let u = resolve_type(&*init, locals, table);
                                let mut inner = locals.clone();
                                inner.insert(params[0].clone(), (u, false));
                                inner.insert(params[1].clone(), (Some(elem.clone()), false));
                                lower_expr(body, &inner, table);
                                return;
                            }
                        }
                    }
                    _ => {}
                }
            }
            for a in args.iter_mut() {
                lower_expr(a, locals, table);
            }
            // `List.contains(x)` → a distinct `__list_contains(list, x)` builtin so
            // the type-blind backends don't confuse it with `String.contains`
            // (which has a different per-tier spelling). Spec 19.
            if recv_elem.is_some() && method == "contains" && args.len() == 1 {
                let recv = std::mem::replace(receiver.as_mut(), Expr::NoneLit);
                let needle = std::mem::replace(&mut args[0], Expr::NoneLit);
                *expr = Expr::Call { callee: "__list_contains".to_string(), args: vec![recv, needle] };
            }
        }
        Expr::Record { fields, .. } => {
            for (_, v) in fields.iter_mut() {
                lower_expr(v, locals, table);
            }
        }
        Expr::ListLit(items) => {
            for it in items.iter_mut() {
                lower_expr(it, locals, table);
            }
        }
        Expr::Ternary { cond, then, otherwise } => {
            lower_expr(cond, locals, table);
            lower_expr(then, locals, table);
            lower_expr(otherwise, locals, table);
        }
        Expr::Range { start, end } => {
            lower_expr(start, locals, table);
            lower_expr(end, locals, table);
        }
        // Closure reached outside a higher-order call (unreachable for a checked
        // program) — lower the body best-effort. `xs[i]` lowers its base + index.
        Expr::Closure { body, .. } => lower_expr(body, locals, table),
        Expr::Index { base, index } => {
            lower_expr(base, locals, table);
            lower_expr(index, locals, table);
        }
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) | Expr::Ident(_)
        | Expr::NoneLit => {}
    }
}

fn lower_view(
    v: &mut ViewNode,
    locals: &HashMap<String, (Option<String>, bool)>,
    table: &SymbolTable,
) {
    match v {
        ViewNode::Element { arg, style, event, children, .. } => {
            if let Some(a) = arg {
                lower_expr(a, locals, table);
            }
            if let Some(st) = style {
                lower_expr(st, locals, table);
            }
            match event {
                Some(Handler::Call(e)) => lower_expr(e, locals, table),
                Some(Handler::Block(stmts)) => {
                    let mut inner = locals.clone();
                    lower_stmts(stmts, &mut inner, table);
                }
                None => {}
            }
            for c in children.iter_mut() {
                lower_view(c, locals, table);
            }
        }
        ViewNode::For { var, iter, body } => {
            lower_expr(iter, locals, table);
            let elem = element_type_of(&*iter, locals, table);
            let mut inner = locals.clone();
            inner.insert(var.clone(), (elem, false));
            for c in body.iter_mut() {
                lower_view(c, &inner, table);
            }
        }
        ViewNode::If { cond, then_body, else_body } => {
            lower_expr(cond, locals, table);
            for c in then_body.iter_mut() {
                lower_view(c, locals, table);
            }
            for c in else_body.iter_mut() {
                lower_view(c, locals, table);
            }
        }
        ViewNode::Component { args, .. } => {
            for (_, v) in args.iter_mut() {
                lower_expr(v, locals, table);
            }
        }
    }
}
