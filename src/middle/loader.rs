// src/loader.rs
//
// The module loader (spec 20, Cut 1). It sits IN FRONT of the checker: from an
// entry `.xrs` file it resolves `import "…"` edges (relative paths only in Cut
// 1), parses each file, detects import cycles, and merges every file into ONE
// `XeresProgram`. The checker then analyzes that single flat program — so the
// tier/secret rules (R3/R5/R6, R15/R24/R26, …) compose ACROSS the module
// boundary for free: a module can't widen the boundary because by the time the
// checker runs there is no boundary left, only one program.
//
// Two security rules are enforced HERE, while module identity is still known:
//
//   R35 module-visibility — only `pub` declarations cross a boundary. A qualified
//     call `mod.fn(...)` must target a `pub fn` of an imported module; an
//     unqualified call may only name a function in the caller's own module
//     (referencing another module's function without importing+qualifying is an
//     error). Mirrors Rust.
//
//   R34 module-capability — an imported (non-entry) module that uses a `Located`
//     capability (`db` / `session` / `endpoint`) must DECLARE it (`requires db`
//     at the module head) AND the importing app must GRANT it (`import "m.xrs"
//     grant db`). A module reaching for a capability it didn't declare, or one
//     the importer didn't grant, does not compile. This makes a dependency's
//     authority explicit and auditable — a left-pad / event-stream / xz-style
//     supply-chain attack is *inexpressible*. The entry app is the root of
//     authority and is never capability-gated (it uses `db` directly, as today).
//
// Cut 1 keeps names GLOBAL — no `module__name` mangling yet. Function names are
// unique across the merged program (a genuine clash is the checker's R2), and a
// qualified `mod.fn(...)` lowers to a plain `fn(...)` once visibility is checked.
// Name mangling (so private helpers can share a name across modules — the thing
// the self-hosted stdlib will want) is a deliberate follow-on cut. The
// single-file fast path (no imports) returns the parsed program UNCHANGED, so
// import-free apps are byte-identical to before this pass existed.

use crate::frontend::lexer::Lexer;
use crate::frontend::parser::{Expr, Handler, Parser, Stmt, ViewNode, XeresProgram};
use crate::middle::diagnostics::Diagnostic;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// The `Located` capabilities a module must `requires`/be granted (R34). These
/// are exactly the server-only authority builtins exposed by the native core.
const CAPABILITIES: &[&str] = &["db", "session", "endpoint"];

/// The self-hosted standard library (spec 20, Cut 1.5). Each entry is a module
/// written in Xeres and **compiled into this binary** via `include_str!`, so
/// `import "std:math"` resolves to embedded source rather than a file on disk.
/// This is Layer 2 of the trust model made real: the stdlib is ordinary Xeres
/// checked under R1–R33, with no ambient authority (none of these modules
/// `requires` a capability). See `std/*.xrs` and ARCHITECTURE.md.
const STDLIB: &[(&str, &str)] = &[
    ("math", include_str!("../../std/math.xrs")),
    ("text", include_str!("../../std/text.xrs")),
];

/// Embedded source for a `std:<module>` import, if it exists.
fn stdlib_source(module: &str) -> Option<&'static str> {
    STDLIB.iter().find(|(n, _)| *n == module).map(|(_, s)| *s)
}

/// The embedded stdlib modules (name, source) — used by tests to verify the
/// shipped library itself parses + analyzes clean.
#[cfg(test)]
pub fn stdlib_modules() -> &'static [(&'static str, &'static str)] {
    STDLIB
}

/// One parsed file in the module graph.
struct LoadedModule {
    /// Module name = the file stem (`money.xrs` ⇒ `money`). The qualifier used in
    /// `money.fn(...)` calls and the namespace decls are tagged with.
    name: String,
    /// Display path (as resolved) for diagnostics.
    file: String,
    program: XeresProgram,
    /// Resolved import edges: (canonical child path, child module name, granted
    /// caps, import-statement line in THIS file).
    edges: Vec<(String, String, HashSet<String>, usize)>,
}

/// Resolve an entry `.xrs` file and everything it imports into one merged
/// program, or a list of diagnostics. The single-file (no-import) case returns
/// the parsed program unchanged.
pub fn load_program(entry: &str) -> Result<XeresProgram, Vec<Diagnostic>> {
    let mut loaded: HashMap<String, LoadedModule> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut errors: Vec<Diagnostic> = Vec::new();

    let entry_key = canon_key(Path::new(entry));
    load_recursive(&entry_key, entry, &mut loaded, &mut order, &mut stack, &mut errors);
    if !errors.is_empty() {
        return Err(errors);
    }

    let entry_module = loaded[&entry_key].name.clone();

    // Single-file fast path: no imports anywhere ⇒ hand back the entry program
    // untouched (byte-identical output to a pre-modules build).
    if order.len() == 1 {
        let only = loaded.remove(&entry_key).unwrap();
        return Ok(only.program);
    }

    // Two distinct files can't share a module name in Cut 1 (qualified calls and
    // the global namespace would be ambiguous). Report and stop.
    let mut by_name: HashMap<&str, &str> = HashMap::new();
    for key in &order {
        let m = &loaded[key];
        if let Some(prev) = by_name.insert(m.name.as_str(), m.file.as_str()) {
            errors.push(Diagnostic {
                file: m.file.clone(),
                line: 1,
                rule: "R35 module-visibility",
                message: format!(
                    "module name `{}` is used by two files (`{}` and `{}`) — module names must be unique.",
                    m.name, prev, m.file
                ),
            });
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    // Validate `requires`/`grant` capability names, and collect per-module data.
    let all_modules: HashSet<String> = order.iter().map(|k| loaded[k].name.clone()).collect();
    let mut module_requires: HashMap<String, HashSet<String>> = HashMap::new();
    let mut module_file: HashMap<String, String> = HashMap::new();
    let mut imports_by_module: HashMap<String, HashSet<String>> = HashMap::new();
    for key in &order {
        let m = &loaded[key];
        module_file.insert(m.name.clone(), m.file.clone());
        for cap in &m.program.requires {
            check_cap_name(cap, &m.file, 1, &mut errors);
        }
        module_requires.insert(m.name.clone(), m.program.requires.clone());
        let imported: HashSet<String> = m.edges.iter().map(|(_, name, _, _)| name.clone()).collect();
        imports_by_module.insert(m.name.clone(), imported);
    }

    // R34 (grant side): each import edge must grant every capability the imported
    // module declares it requires. The grant lives at the importer's `import`
    // line, so attribute the error there.
    for key in &order {
        let m = &loaded[key];
        for (_, child_name, grants, line) in &m.edges {
            for cap in grants {
                check_cap_name(cap, &m.file, *line, &mut errors);
            }
            let required = module_requires.get(child_name).cloned().unwrap_or_default();
            for cap in &required {
                if !grants.contains(cap) {
                    errors.push(Diagnostic {
                        file: m.file.clone(),
                        line: *line,
                        rule: "R34 module-capability",
                        message: format!(
                            "module `{}` requires the `{}` capability, but this import doesn't grant it — add `grant {}` (you are authorizing a dependency to use {}).",
                            child_name, cap, cap, cap_explain(cap)
                        ),
                    });
                }
            }
        }
    }

    // Merge: entry module's decls first (so the app's first screen stays the
    // default route, R31), then the rest in load order. Tag every decl with its
    // source module as we go.
    let mut merged = XeresProgram {
        models: vec![], enums: vec![], functions: vec![], states: vec![],
        screens: vec![], endpoints: vec![], imports: vec![], requires: HashSet::new(),
    };
    let mut merge_order: Vec<String> = vec![entry_key.clone()];
    merge_order.extend(order.iter().filter(|k| **k != entry_key).cloned());
    for key in &merge_order {
        let m = loaded.remove(key).unwrap();
        let module = m.name.clone();
        let mut prog = m.program;
        for d in &mut prog.models { d.module = module.clone(); }
        for d in &mut prog.enums { d.module = module.clone(); }
        for d in &mut prog.functions { d.module = module.clone(); }
        for d in &mut prog.states { d.module = module.clone(); }
        for d in &mut prog.screens { d.module = module.clone(); }
        for d in &mut prog.endpoints { d.module = module.clone(); }
        merged.models.append(&mut prog.models);
        merged.enums.append(&mut prog.enums);
        merged.functions.append(&mut prog.functions);
        merged.states.append(&mut prog.states);
        merged.screens.append(&mut prog.screens);
        merged.endpoints.append(&mut prog.endpoints);
    }

    // R34 (declare side): an imported (non-entry) module that USES a capability
    // must have declared it with `requires`. Detection is body-based (db/session
    // calls) plus endpoint declarations/uses.
    let endpoint_names: HashSet<String> =
        merged.endpoints.iter().map(|e| e.name.clone()).collect();
    let mut module_uses: HashMap<String, HashSet<String>> = HashMap::new();
    let mut module_use_line: HashMap<String, usize> = HashMap::new();
    for f in &merged.functions {
        let used = caps_used_in_stmts(&f.body, &endpoint_names);
        if !used.is_empty() {
            module_use_line.entry(f.module.clone()).or_insert(f.line);
            module_uses.entry(f.module.clone()).or_default().extend(used);
        }
    }
    for ep in &merged.endpoints {
        module_use_line.entry(ep.module.clone()).or_insert(ep.line);
        module_uses.entry(ep.module.clone()).or_default().insert("endpoint".to_string());
    }
    for (module, used) in &module_uses {
        if *module == entry_module {
            continue; // the app is the root of authority
        }
        let declared = module_requires.get(module).cloned().unwrap_or_default();
        for cap in used {
            if !declared.contains(cap) {
                let file = module_file.get(module).cloned().unwrap_or_default();
                let line = module_use_line.get(module).copied().unwrap_or(1);
                errors.push(Diagnostic {
                    file,
                    line,
                    rule: "R34 module-capability",
                    message: format!(
                        "module `{}` uses the `{}` capability but doesn't declare it — add `requires {}` at the top of the module. An imported module's authority must be explicit (and the importing app must `grant {}`).",
                        module, cap, cap, cap
                    ),
                });
            }
        }
    }

    // R35 + qualified-call resolution: rewrite `mod.fn(...)` into `fn(...)` once
    // visibility is proven, and reject cross-module references that skip the
    // import/`pub` discipline.
    let pub_fns: HashMap<String, HashSet<String>> = {
        let mut m: HashMap<String, HashSet<String>> = HashMap::new();
        for f in &merged.functions {
            if f.is_pub {
                m.entry(f.module.clone()).or_default().insert(f.name.clone());
            }
        }
        m
    };
    let fn_module: HashMap<String, String> =
        merged.functions.iter().map(|f| (f.name.clone(), f.module.clone())).collect();
    let ctx = ResolveCtx {
        modules: &all_modules,
        imports_by_module: &imports_by_module,
        pub_fns: &pub_fns,
        fn_module: &fn_module,
    };
    // Rewrite needs &mut decls but the context borrows none of them mutably.
    let mut funcs = std::mem::take(&mut merged.functions);
    for f in &mut funcs {
        let file = module_file.get(&f.module).cloned().unwrap_or_default();
        let caller = Caller { module: &f.module, file: &file, line: f.line };
        rewrite_stmts(&mut f.body, caller, &ctx, &mut errors);
    }
    merged.functions = funcs;
    let mut screens = std::mem::take(&mut merged.screens);
    for s in &mut screens {
        let file = module_file.get(&s.module).cloned().unwrap_or_default();
        let caller = Caller { module: &s.module, file: &file, line: s.line };
        for st in &mut s.states {
            rewrite_expr(&mut st.init, caller, &ctx, &mut errors);
        }
        rewrite_stmts(&mut s.load, caller, &ctx, &mut errors);
        for v in &mut s.body {
            rewrite_view(v, caller, &ctx, &mut errors);
        }
    }
    merged.screens = screens;

    if errors.is_empty() {
        errors.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
        Ok(merged)
    } else {
        errors.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
        Err(errors)
    }
}

/// DFS-load `key` (a canonical path) and its imports, recording load order and
/// detecting cycles (a key currently on the DFS stack).
fn load_recursive(
    key: &str,
    display: &str,
    loaded: &mut HashMap<String, LoadedModule>,
    order: &mut Vec<String>,
    stack: &mut Vec<String>,
    errors: &mut Vec<Diagnostic>,
) {
    if loaded.contains_key(key) {
        return; // diamond import — already loaded
    }
    if stack.iter().any(|k| k == key) {
        errors.push(Diagnostic {
            file: display.to_string(),
            line: 1,
            rule: "R35 module-visibility",
            message: format!("import cycle detected at `{}` — modules may not import each other circularly.", display),
        });
        return;
    }

    // `std:<module>` resolves to embedded source; anything else is a file.
    let source = if let Some(m) = key.strip_prefix("std:") {
        match stdlib_source(m) {
            Some(s) => s.to_string(),
            None => {
                errors.push(Diagnostic {
                    file: display.to_string(),
                    line: 1,
                    rule: "R35 module-visibility",
                    message: format!("unknown stdlib module `{}` — there is no `std:{}`.", display, m),
                });
                return;
            }
        }
    } else {
        match std::fs::read_to_string(key) {
            Ok(s) => s,
            Err(e) => {
                errors.push(Diagnostic {
                    file: display.to_string(),
                    line: 1,
                    rule: "R35 module-visibility",
                    message: format!("cannot read module `{}`: {}", display, e),
                });
                return;
            }
        }
    };
    let mut lexer = Lexer::new(&source);
    let mut parser = Parser::new(&mut lexer);
    let program = parser.parse_program();
    let name = module_name(key);
    // Resolve a child's KEY against the canonical dir (so dedup/cycle detection is
    // exact), but its DISPLAY path against the importing file's display dir (so
    // diagnostics show `tests/money.xrs`, not the `\\?\C:\…` canonical form).
    let canon_dir = Path::new(key).parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
    let display_dir = Path::new(display).parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));

    stack.push(key.to_string());
    let mut edges = Vec::new();
    for im in &program.imports {
        // `std:<module>` is an embedded-stdlib edge (no filesystem); everything
        // else resolves relative to the importing file.
        let (child_key, child_display) = if im.path.starts_with("std:") {
            (im.path.clone(), im.path.clone())
        } else {
            (
                canon_key(&canon_dir.join(&im.path)),
                display_dir.join(&im.path).to_string_lossy().to_string(),
            )
        };
        edges.push((child_key.clone(), module_name(&child_key), im.grants.clone(), im.line));
        load_recursive(&child_key, &child_display, loaded, order, stack, errors);
    }
    stack.pop();

    loaded.insert(key.to_string(), LoadedModule { name, file: display.to_string(), program, edges });
    order.push(key.to_string());
}

/// Read-only resolution context for the qualified-call rewrite (R35).
struct ResolveCtx<'a> {
    modules: &'a HashSet<String>,
    imports_by_module: &'a HashMap<String, HashSet<String>>,
    pub_fns: &'a HashMap<String, HashSet<String>>,
    fn_module: &'a HashMap<String, String>,
}

/// Where the code being rewritten lives. The AST carries no per-statement line
/// numbers, so in-body R35 errors attribute to the owning decl's line — enough
/// to point the developer at the right function/screen.
#[derive(Clone, Copy)]
struct Caller<'a> {
    module: &'a str,
    file: &'a str,
    line: usize,
}

fn rewrite_stmts(stmts: &mut [Stmt], caller: Caller, ctx: &ResolveCtx, errors: &mut Vec<Diagnostic>) {
    for s in stmts.iter_mut() {
        match s {
            Stmt::Let { value, .. } | Stmt::Assign { value, .. } | Stmt::Return(value)
            | Stmt::Expr(value) => rewrite_expr(value, caller, ctx, errors),
            Stmt::Try { body, handler } => {
                rewrite_stmts(body, caller, ctx, errors);
                rewrite_stmts(handler, caller, ctx, errors);
            }
            Stmt::If { cond, then_body, else_body } => {
                rewrite_expr(cond, caller, ctx, errors);
                rewrite_stmts(then_body, caller, ctx, errors);
                rewrite_stmts(else_body, caller, ctx, errors);
            }
            Stmt::For { iter, body, .. } => {
                rewrite_expr(iter, caller, ctx, errors);
                rewrite_stmts(body, caller, ctx, errors);
            }
            Stmt::While { cond, body } => {
                rewrite_expr(cond, caller, ctx, errors);
                rewrite_stmts(body, caller, ctx, errors);
            }
            Stmt::Match { scrutinee, arms } => {
                rewrite_expr(scrutinee, caller, ctx, errors);
                for a in arms.iter_mut() {
                    rewrite_stmts(&mut a.body, caller, ctx, errors);
                }
            }
            Stmt::Transaction(body) => rewrite_stmts(body, caller, ctx, errors),
            Stmt::Break | Stmt::Continue => {}
        }
    }
}

fn rewrite_expr(expr: &mut Expr, caller: Caller, ctx: &ResolveCtx, errors: &mut Vec<Diagnostic>) {
    match expr {
        // `mod.fn(args)` — a module-qualified call. If the receiver names a known
        // module, resolve it through the import/`pub` discipline (R35) and lower
        // to a plain `fn(args)` call (Cut 1: names are global).
        Expr::MethodCall { receiver, method, args } => {
            for a in args.iter_mut() {
                rewrite_expr(a, caller, ctx, errors);
            }
            if let Expr::Ident(recv) = receiver.as_ref() {
                if recv != caller.module && ctx.modules.contains(recv) {
                    let imported = ctx
                        .imports_by_module
                        .get(caller.module)
                        .map(|s| s.contains(recv))
                        .unwrap_or(false);
                    if !imported {
                        errors.push(Diagnostic {
                            file: caller.file.to_string(),
                            line: caller.line,
                            rule: "R35 module-visibility",
                            message: format!(
                                "module `{}` is referenced in `{}` but not imported there — add `import \"{}.xrs\"`.",
                                recv, caller.module, recv
                            ),
                        });
                        return;
                    }
                    let is_pub = ctx
                        .pub_fns
                        .get(recv)
                        .map(|s| s.contains(method))
                        .unwrap_or(false);
                    if !is_pub {
                        errors.push(Diagnostic {
                            file: caller.file.to_string(),
                            line: caller.line,
                            rule: "R35 module-visibility",
                            message: format!(
                                "`{}.{}` is not accessible — `{}` has no exported function `{}` (mark it `pub fn {}` to export it).",
                                recv, method, recv, method, method
                            ),
                        });
                        return;
                    }
                    // Visible: lower `mod.fn(args)` to `fn(args)`.
                    let taken = std::mem::take(args);
                    *expr = Expr::Call { callee: method.clone(), args: taken };
                    return;
                }
            }
            // Not a module qualifier — recurse into the receiver as a value.
            rewrite_expr(receiver, caller, ctx, errors);
        }
        // An unqualified call. If it names a function that lives in ANOTHER
        // module, that's a visibility violation — it must be imported and called
        // as `mod.fn(...)`. Same-module calls and builtins pass through.
        Expr::Call { callee, args } => {
            if let Some(owner) = ctx.fn_module.get(callee) {
                if owner != caller.module {
                    errors.push(Diagnostic {
                        file: caller.file.to_string(),
                        line: caller.line,
                        rule: "R35 module-visibility",
                        message: format!(
                            "function `{}` belongs to module `{}` — import it and call it as `{}.{}(...)`.",
                            callee, owner, owner, callee
                        ),
                    });
                }
            }
            for a in args.iter_mut() {
                rewrite_expr(a, caller, ctx, errors);
            }
        }
        Expr::Field { base, .. } => rewrite_expr(base, caller, ctx, errors),
        Expr::Unary { expr: inner, .. }
        | Expr::Declassify(inner)
        | Expr::Raw(inner)
        | Expr::Await(inner) => rewrite_expr(inner, caller, ctx, errors),
        Expr::Binary { left, right, .. } => {
            rewrite_expr(left, caller, ctx, errors);
            rewrite_expr(right, caller, ctx, errors);
        }
        Expr::Record { fields, .. } => {
            for (_, v) in fields.iter_mut() {
                rewrite_expr(v, caller, ctx, errors);
            }
        }
        Expr::ListLit(items) => {
            for it in items.iter_mut() {
                rewrite_expr(it, caller, ctx, errors);
            }
        }
        Expr::Ternary { cond, then, otherwise } => {
            rewrite_expr(cond, caller, ctx, errors);
            rewrite_expr(then, caller, ctx, errors);
            rewrite_expr(otherwise, caller, ctx, errors);
        }
        Expr::Range { start, end } => {
            rewrite_expr(start, caller, ctx, errors);
            rewrite_expr(end, caller, ctx, errors);
        }
        Expr::Closure { body, .. } => rewrite_expr(body, caller, ctx, errors),
        Expr::Index { base, index } => {
            rewrite_expr(base, caller, ctx, errors);
            rewrite_expr(index, caller, ctx, errors);
        }
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) | Expr::Ident(_)
        | Expr::NoneLit => {}
    }
}

fn rewrite_view(v: &mut ViewNode, caller: Caller, ctx: &ResolveCtx, errors: &mut Vec<Diagnostic>) {
    match v {
        ViewNode::Element { arg, style, event, children, .. } => {
            if let Some(a) = arg {
                rewrite_expr(a, caller, ctx, errors);
            }
            if let Some(st) = style {
                rewrite_expr(st, caller, ctx, errors);
            }
            match event {
                Some(Handler::Call(e)) => rewrite_expr(e, caller, ctx, errors),
                Some(Handler::Block(stmts)) => rewrite_stmts(stmts, caller, ctx, errors),
                None => {}
            }
            for c in children.iter_mut() {
                rewrite_view(c, caller, ctx, errors);
            }
        }
        ViewNode::For { iter, body, .. } => {
            rewrite_expr(iter, caller, ctx, errors);
            for c in body.iter_mut() {
                rewrite_view(c, caller, ctx, errors);
            }
        }
        ViewNode::If { cond, then_body, else_body } => {
            rewrite_expr(cond, caller, ctx, errors);
            for c in then_body.iter_mut() {
                rewrite_view(c, caller, ctx, errors);
            }
            for c in else_body.iter_mut() {
                rewrite_view(c, caller, ctx, errors);
            }
        }
        ViewNode::Component { args, .. } => {
            for (_, e) in args.iter_mut() {
                rewrite_expr(e, caller, ctx, errors);
            }
        }
    }
}

// --- capability detection (R34, declare side) ---

/// The set of Located capabilities (`db`/`session`/`endpoint`) a statement list
/// reaches for. Used to require that an imported module declares what it uses.
fn caps_used_in_stmts(stmts: &[Stmt], endpoints: &HashSet<String>) -> HashSet<String> {
    let mut out = HashSet::new();
    for s in stmts {
        collect_caps_stmt(s, endpoints, &mut out);
    }
    out
}

fn collect_caps_stmt(s: &Stmt, endpoints: &HashSet<String>, out: &mut HashSet<String>) {
    match s {
        Stmt::Let { value, .. } | Stmt::Assign { value, .. } | Stmt::Return(value)
        | Stmt::Expr(value) => collect_caps_expr(value, endpoints, out),
        Stmt::Try { body, handler } => {
            for s in body { collect_caps_stmt(s, endpoints, out); }
            for s in handler { collect_caps_stmt(s, endpoints, out); }
        }
        Stmt::If { cond, then_body, else_body } => {
            collect_caps_expr(cond, endpoints, out);
            for s in then_body { collect_caps_stmt(s, endpoints, out); }
            for s in else_body { collect_caps_stmt(s, endpoints, out); }
        }
        Stmt::For { iter, body, .. } => {
            collect_caps_expr(iter, endpoints, out);
            for s in body { collect_caps_stmt(s, endpoints, out); }
        }
        Stmt::While { cond, body } => {
            collect_caps_expr(cond, endpoints, out);
            for s in body { collect_caps_stmt(s, endpoints, out); }
        }
        Stmt::Match { scrutinee, arms } => {
            collect_caps_expr(scrutinee, endpoints, out);
            for a in arms { for s in &a.body { collect_caps_stmt(s, endpoints, out); } }
        }
        Stmt::Transaction(body) => {
            // `transaction { … }` wraps `db` writes — it is itself db authority.
            out.insert("db".to_string());
            for s in body { collect_caps_stmt(s, endpoints, out); }
        }
        Stmt::Break | Stmt::Continue => {}
    }
}

fn collect_caps_expr(e: &Expr, endpoints: &HashSet<String>, out: &mut HashSet<String>) {
    match e {
        // `session.actor` — a Located read.
        Expr::Field { base, .. } => {
            if matches!(base.as_ref(), Expr::Ident(n) if n == "session") {
                out.insert("session".to_string());
            }
            collect_caps_expr(base, endpoints, out);
        }
        Expr::MethodCall { receiver, args, .. } => {
            if let Expr::Ident(n) = receiver.as_ref() {
                if n == "db" {
                    out.insert("db".to_string());
                } else if n == "session" {
                    out.insert("session".to_string());
                } else if endpoints.contains(n) {
                    out.insert("endpoint".to_string());
                }
            }
            collect_caps_expr(receiver, endpoints, out);
            for a in args { collect_caps_expr(a, endpoints, out); }
        }
        Expr::Call { args, .. } => { for a in args { collect_caps_expr(a, endpoints, out); } }
        Expr::Unary { expr, .. } | Expr::Declassify(expr) | Expr::Raw(expr) | Expr::Await(expr) => {
            collect_caps_expr(expr, endpoints, out)
        }
        Expr::Binary { left, right, .. } => {
            collect_caps_expr(left, endpoints, out);
            collect_caps_expr(right, endpoints, out);
        }
        Expr::Record { fields, .. } => { for (_, v) in fields { collect_caps_expr(v, endpoints, out); } }
        Expr::ListLit(items) => { for it in items { collect_caps_expr(it, endpoints, out); } }
        Expr::Ternary { cond, then, otherwise } => {
            collect_caps_expr(cond, endpoints, out);
            collect_caps_expr(then, endpoints, out);
            collect_caps_expr(otherwise, endpoints, out);
        }
        Expr::Range { start, end } => {
            collect_caps_expr(start, endpoints, out);
            collect_caps_expr(end, endpoints, out);
        }
        Expr::Closure { body, .. } => collect_caps_expr(body, endpoints, out),
        Expr::Index { base, index } => {
            collect_caps_expr(base, endpoints, out);
            collect_caps_expr(index, endpoints, out);
        }
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_) | Expr::Ident(_)
        | Expr::NoneLit => {}
    }
}

// --- small helpers ---

/// The module name for a path: the part after `std:` for an embedded stdlib
/// module (`std:math` ⇒ `math`), otherwise the file stem (`a/money.xrs` ⇒
/// `money`).
fn module_name(path: &str) -> String {
    if let Some(m) = path.strip_prefix("std:") {
        return m.to_string();
    }
    Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

/// A stable key for a file (canonical path if it exists, else the joined path),
/// so the same file reached via different relative paths dedupes / detects cycles.
fn canon_key(path: &Path) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| path.to_string_lossy().to_string())
}

fn check_cap_name(cap: &str, file: &str, line: usize, errors: &mut Vec<Diagnostic>) {
    if !CAPABILITIES.contains(&cap) {
        errors.push(Diagnostic {
            file: file.to_string(),
            line,
            rule: "R34 module-capability",
            message: format!(
                "unknown capability `{}` — the Located capabilities are: {}.",
                cap,
                CAPABILITIES.join(", ")
            ),
        });
    }
}

fn cap_explain(cap: &str) -> &'static str {
    match cap {
        "db" => "the database connection",
        "session" => "the authenticated session",
        "endpoint" => "outbound HTTP",
        _ => "a Located capability",
    }
}
