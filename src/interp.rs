// A tree-walking interpreter for `server` functions. The self-contained
// runtime (`xeres serve`) uses this instead of generating + compiling Rust, so
// running an app needs no cargo. Database access is feature-gated (`db`).

use crate::frontend::parser::{BinOp, Expr, MatchPat, Stmt, UnOp, XeresProgram};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub enum Value {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Record(String, Vec<(String, Value)>),
    List(Vec<Value>),
    Null,
}

/// Statement-execution outcome, so loops/`break`/`continue`/`return` propagate
/// correctly through a tree-walk (distinct from "fell off the end").
enum Flow {
    Next,
    Return(Value),
    Break,
    Continue,
}

pub struct Interp<'a> {
    pub program: &'a XeresProgram,
    /// Authenticated actor id, recovered from a verified session cookie
    /// (`None` = anonymous). Read by `session.actor`.
    session_actor: Option<String>,
    /// A `Set-Cookie` header recorded by `session.login`/`session.logout`, read
    /// out by the server after the call. Interior mutability: `call` is `&self`.
    set_cookie: std::cell::RefCell<Option<String>>,
}

impl<'a> Interp<'a> {
    /// Construct with the actor recovered from a verified session cookie
    /// (`None` = anonymous; the sync path and non-session apps pass `None`).
    pub fn with_session(program: &'a XeresProgram, session_actor: Option<String>) -> Self {
        Interp { program, session_actor, set_cookie: std::cell::RefCell::new(None) }
    }

    /// The `Set-Cookie` header to emit after this call, if `session.login` or
    /// `session.logout` ran during it. Takes (clears) the recorded value.
    pub fn take_set_cookie(&self) -> Option<String> {
        self.set_cookie.borrow_mut().take()
    }

    /// `session.login(id)` mints a signed session cookie; `session.logout()`
    /// clears it. Both record a `Set-Cookie` for the server to emit after the
    /// call returns.
    fn session_method(
        &self,
        method: &str,
        args: &[Expr],
        env: &HashMap<String, Value>,
    ) -> Result<Value, String> {
        match method {
            "login" => {
                let id = match self.eval(args.first().ok_or("session.login(id) needs an id")?, env)? {
                    Value::Str(s) => s,
                    _ => return Err("session.login expects a String id".into()),
                };
                *self.set_cookie.borrow_mut() = Some(session_set_cookie(&id));
                Ok(Value::Null)
            }
            "logout" => {
                *self.set_cookie.borrow_mut() = Some(session_clear_cookie());
                Ok(Value::Null)
            }
            other => Err(format!("session has no method `{}`", other)),
        }
    }

    /// `log.info/warn/error(msg)` — emit one structured (JSON) line to stderr.
    fn log_method(
        &self,
        method: &str,
        args: &[Expr],
        env: &HashMap<String, Value>,
    ) -> Result<Value, String> {
        let v = self.eval(args.first().ok_or("log needs a message")?, env)?;
        let msg = match v {
            Value::Str(s) => Value::Str(s),
            other => Value::Str(format!("{:?}", other)),
        };
        eprintln!("{{\"level\":\"{}\",\"msg\":{}}}", method, self.wire_json(&msg));
        Ok(Value::Null)
    }

    /// `Endpoint.get(path)` / `Endpoint.post(path, body)` — host-fixed outbound
    /// HTTP (R26). The base comes from the declaration; a declared secret is
    /// loaded from `<NAME>_<FIELD>` and sent as a bearer token. The host can
    /// never be changed by the caller — only the path is appended.
    fn is_endpoint(&self, n: &str) -> bool {
        self.program.endpoints.iter().any(|e| e.name == n)
    }

    /// If `ty` is a model shape (a model, `List<Model>`, or `Optional<Model>`),
    /// return it — the signal that an `endpoint.get(...)` response should be JSON-
    /// decoded into it (spec 24). A `String` (or any non-model) return falls
    /// through to the raw body.
    fn endpoint_typed_target<'t>(&self, ty: Option<&'t str>) -> Option<&'t str> {
        let t = ty?;
        let bare = crate::json::generic_inner("List", t)
            .or_else(|| crate::json::generic_inner("Optional", t))
            .unwrap_or(t);
        if self.program.models.iter().any(|m| m.name == bare) {
            Some(t)
        } else {
            None
        }
    }

    /// Call `name.get(path)` and decode its JSON response into `ty` (spec 24).
    fn endpoint_typed_get(
        &self,
        name: &str,
        args: &[Expr],
        ty: &str,
        env: &HashMap<String, Value>,
    ) -> Result<Value, String> {
        let raw = self.endpoint_method(name, "get", args, env)?;
        let body = if let Value::Str(s) = raw { s } else { String::new() };
        let parsed = crate::json::jparse(&body);
        Ok(crate::json::decode(Some(&parsed), ty, self.program))
    }

    fn endpoint_method(
        &self,
        name: &str,
        method: &str,
        args: &[Expr],
        env: &HashMap<String, Value>,
    ) -> Result<Value, String> {
        let ep = self
            .program
            .endpoints
            .iter()
            .find(|e| e.name == name)
            .ok_or("unknown endpoint")?;
        let path = match self.eval(args.first().ok_or("endpoint needs a path")?, env)? {
            Value::Str(s) => s,
            _ => return Err("endpoint path must be a string".into()),
        };
        let url = format!("{}{}", ep.base, path);
        let bearer = match ep.secrets.first() {
            Some((f, _)) => std::env::var(format!("{}_{}", name.to_uppercase(), f.to_uppercase()))
                .unwrap_or_default(),
            None => String::new(),
        };
        match method {
            "get" => endpoint_get(&url, &bearer),
            "post" => {
                let body = match args.get(1).map(|a| self.eval(a, env)).transpose()? {
                    Some(Value::Str(s)) => s,
                    Some(other) => self.wire_json(&other),
                    None => String::new(),
                };
                endpoint_post(&url, &body, &bearer)
            }
            other => Err(format!("endpoint has no verb `{}`", other)),
        }
    }

    /// Call a server (or shared) fn by name with positional args.
    pub fn call(&self, fn_name: &str, args: Vec<Value>) -> Result<Value, String> {
        if fn_name == "uid" {
            return Ok(Value::Str(uid()));
        }
        if fn_name == "hash" {
            return auth_hash(&args);
        }
        if fn_name == "verify" {
            return auth_verify(&args);
        }
        if fn_name == "now" {
            return Ok(Value::Int(now_millis()));
        }
        if fn_name == "decimal" {
            // String-backed exact money value — the constructor is the identity
            // over its (already-string) argument (the checker enforces R29).
            return Ok(args.into_iter().next().unwrap_or(Value::Null));
        }
        if let Some(op) = fn_name.strip_prefix("__dec_") {
            // Lowered Decimal arithmetic / ordered comparison: the checker's typed
            // desugaring rewrites Decimal `+ - * < > <= >=` into these. Operands
            // arrive as decimal strings (or an `Int` for `Decimal * Int`).
            let a = dec_str(args.first())?;
            let b = dec_str(args.get(1))?;
            use std::cmp::Ordering;
            return match op {
                "add" => Ok(Value::Str(dec_add(&a, &b)?)),
                "sub" => Ok(Value::Str(dec_sub(&a, &b)?)),
                "mul" => Ok(Value::Str(dec_mul(&a, &b)?)),
                "lt" => Ok(Value::Bool(dec_cmp(&a, &b)? == Ordering::Less)),
                "gt" => Ok(Value::Bool(dec_cmp(&a, &b)? == Ordering::Greater)),
                "le" => Ok(Value::Bool(dec_cmp(&a, &b)? != Ordering::Greater)),
                "ge" => Ok(Value::Bool(dec_cmp(&a, &b)? != Ordering::Less)),
                _ => Err(format!("unknown decimal op `{}`", op)),
            };
        }
        if fn_name == "__list_contains" {
            // Lowered `List.contains(x)` (spec 19): structural element equality
            // (so it agrees with the browser's JSON match and the server's
            // `Vec::contains`). `String.contains` stays the String method.
            let needle = args.get(1).cloned().unwrap_or(Value::Null);
            return match args.first() {
                Some(Value::List(items)) => {
                    Ok(Value::Bool(items.iter().any(|e| values_eq(e, &needle))))
                }
                _ => Err("`contains` needs a list".into()),
            };
        }
        if matches!(fn_name, "abs" | "min" | "max") {
            return math_fn(fn_name, &args);
        }
        let f = self
            .program
            .functions
            .iter()
            .find(|f| f.name == fn_name)
            .ok_or_else(|| format!("no such function `{}`", fn_name))?;
        let mut env: HashMap<String, Value> = HashMap::new();
        for (p, a) in f.params.iter().zip(args) {
            env.insert(p.name.clone(), a);
        }
        match self.exec_block(&f.body, &mut env, f.return_type.as_deref())? {
            Flow::Return(v) => Ok(v),
            _ => Ok(Value::Null),
        }
    }

    /// Run an `api` route body (spec 23): bind the decoded JSON request body (if
    /// the route declares one) and execute the handler, returning the response
    /// Value. The caller wire-projects it (`wire_json`) so secrets are stripped,
    /// exactly like an RPC response.
    pub fn call_api_route(
        &self,
        body_stmts: &[Stmt],
        body_param: Option<(String, Value)>,
        return_type: Option<&str>,
    ) -> Result<Value, String> {
        let mut env: HashMap<String, Value> = HashMap::new();
        if let Some((name, val)) = body_param {
            env.insert(name, val);
        }
        match self.exec_block(body_stmts, &mut env, return_type)? {
            Flow::Return(v) => Ok(v),
            _ => Ok(Value::Null),
        }
    }

    fn exec_block(
        &self,
        stmts: &[Stmt],
        env: &mut HashMap<String, Value>,
        ret_model: Option<&str>,
    ) -> Result<Flow, String> {
        for s in stmts {
            match s {
                Stmt::Let { name, type_ann, value } => {
                    // `let u: Model = db.query_one(...)` maps the row onto Model,
                    // exactly like a `return db.query_one(...)` does.
                    let v = match value {
                        Expr::MethodCall { receiver, method, args }
                            if is_db(receiver) && (method == "query_one" || method == "query") =>
                        {
                            self.db_query(method, args, env, type_ann.as_deref())?
                        }
                        // `let f: Forecast = weather.get("/...")` — decode the JSON
                        // response into the annotated model (spec 24).
                        Expr::MethodCall { receiver, method, args }
                            if method == "get"
                                && matches!(receiver.as_ref(), Expr::Ident(n) if self.is_endpoint(n))
                                && self.endpoint_typed_target(type_ann.as_deref()).is_some() =>
                        {
                            let name = match receiver.as_ref() {
                                Expr::Ident(n) => n.clone(),
                                _ => unreachable!(),
                            };
                            self.endpoint_typed_get(&name, args, type_ann.as_deref().unwrap(), env)?
                        }
                        _ => self.eval(value, env)?,
                    };
                    env.insert(name.clone(), v);
                }
                Stmt::Assign { name, value } => {
                    let v = self.eval(value, env)?;
                    env.insert(name.clone(), v);
                }
                Stmt::Expr(e) => {
                    self.eval(e, env)?;
                }
                Stmt::Return(e) => {
                    // `return db.query_one|query(...)` maps rows onto ret_model;
                    // `db.exec` falls through to eval (which runs db_exec).
                    if let Expr::MethodCall { receiver, method, args } = e {
                        if is_db(receiver) && (method == "query_one" || method == "query") {
                            return Ok(Flow::Return(self.db_query(method, args, env, ret_model)?));
                        }
                        // `return weather.get("/...")` mapped onto the fn's return
                        // model — decode the JSON response (spec 24).
                        if method == "get" {
                            if let Expr::Ident(n) = receiver.as_ref() {
                                if self.is_endpoint(n) {
                                    if let Some(t) = self.endpoint_typed_target(ret_model) {
                                        return Ok(Flow::Return(self.endpoint_typed_get(n, args, t, env)?));
                                    }
                                }
                            }
                        }
                    }
                    return Ok(Flow::Return(self.eval(e, env)?));
                }
                // try/catch is browser-only (checker R16); run the body if present.
                Stmt::Try { body, .. } => match self.exec_block(body, env, ret_model)? {
                    Flow::Next => {}
                    other => return Ok(other),
                },
                Stmt::If { cond, then_body, else_body } => {
                    let branch = if self.truthy(cond, env)? { then_body } else { else_body };
                    match self.exec_block(branch, env, ret_model)? {
                        Flow::Next => {}
                        other => return Ok(other),
                    }
                }
                Stmt::For { var, iter, body } => {
                    let items = match self.eval(iter, env)? {
                        Value::List(vs) => vs,
                        _ => return Err("`for` expects a list or range".into()),
                    };
                    for item in items {
                        env.insert(var.clone(), item);
                        match self.exec_block(body, env, ret_model)? {
                            Flow::Next | Flow::Continue => {}
                            Flow::Break => break,
                            ret @ Flow::Return(_) => return Ok(ret),
                        }
                    }
                }
                Stmt::While { cond, body } => {
                    while self.truthy(cond, env)? {
                        match self.exec_block(body, env, ret_model)? {
                            Flow::Next | Flow::Continue => {}
                            Flow::Break => break,
                            ret @ Flow::Return(_) => return Ok(ret),
                        }
                    }
                }
                Stmt::Break => return Ok(Flow::Break),
                Stmt::Continue => return Ok(Flow::Continue),
                Stmt::Match { scrutinee, arms } => {
                    let v = match self.eval(scrutinee, env)? {
                        Value::Str(s) => s,
                        _ => return Err("`match` scrutinee must be an enum".into()),
                    };
                    let chosen = arms
                        .iter()
                        .find(|a| matches!(&a.pattern, MatchPat::Variant(n) if n == &v))
                        .or_else(|| arms.iter().find(|a| matches!(a.pattern, MatchPat::Wildcard)));
                    if let Some(arm) = chosen {
                        match self.exec_block(&arm.body, env, ret_model)? {
                            Flow::Next => {}
                            other => return Ok(other),
                        }
                    }
                }
                Stmt::Transaction(body) => {
                    // R33 — run the body atomically: commit on normal completion,
                    // roll back if any operation errors, then propagate the error.
                    self.tx_begin()?;
                    match self.exec_block(body, env, ret_model) {
                        Ok(flow) => {
                            self.tx_end(true);
                            if !matches!(flow, Flow::Next) {
                                return Ok(flow);
                            }
                        }
                        Err(e) => {
                            self.tx_end(false);
                            return Err(e);
                        }
                    }
                }
            }
        }
        Ok(Flow::Next)
    }

    /// Evaluate a condition expression to a bool (error if it isn't one).
    fn truthy(&self, e: &Expr, env: &HashMap<String, Value>) -> Result<bool, String> {
        match self.eval(e, env)? {
            Value::Bool(b) => Ok(b),
            _ => Err("condition must be a boolean".into()),
        }
    }

    /// Evaluate a closure body (spec 19) with its params bound to `vals` in a
    /// child of the enclosing env. Drives map/filter/reduce.
    fn eval_closure(
        &self,
        params: &[String],
        body: &Expr,
        vals: &[Value],
        env: &HashMap<String, Value>,
    ) -> Result<Value, String> {
        let mut child = env.clone();
        for (p, v) in params.iter().zip(vals) {
            child.insert(p.clone(), v.clone());
        }
        self.eval(body, &child)
    }

    fn eval(&self, e: &Expr, env: &HashMap<String, Value>) -> Result<Value, String> {
        match e {
            Expr::Int(n) => Ok(Value::Int(*n)),
            Expr::Float(f) => Ok(Value::Float(*f)),
            Expr::Str(s) => Ok(Value::Str(s.clone())),
            Expr::Bool(b) => Ok(Value::Bool(*b)),
            Expr::NoneLit => Ok(Value::Null),
            Expr::Ident(v) => env
                .get(v)
                .cloned()
                .ok_or_else(|| format!("unknown variable `{}`", v)),
            Expr::Field { base, field } => {
                // `session.actor` — the authenticated actor id, or null.
                if matches!(base.as_ref(), Expr::Ident(n) if n == "session") && field == "actor" {
                    return Ok(match &self.session_actor {
                        Some(id) => Value::Str(id.clone()),
                        None => Value::Null,
                    });
                }
                // `Enum.Variant` (Capitalized base) -> the variant string.
                if let Expr::Ident(name) = base.as_ref() {
                    if name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                        return Ok(Value::Str(field.clone()));
                    }
                }
                match self.eval(base, env)? {
                    Value::Record(_, fs) => fs
                        .iter()
                        .find(|(k, _)| k == field)
                        .map(|(_, v)| v.clone())
                        .ok_or_else(|| format!("no field `{}`", field)),
                    _ => Err(format!("`.{}` on a non-record value", field)),
                }
            }
            Expr::Unary { op, expr } => {
                let v = self.eval(expr, env)?;
                match (op, v) {
                    (UnOp::Neg, Value::Int(n)) => Ok(Value::Int(-n)),
                    (UnOp::Neg, Value::Float(f)) => Ok(Value::Float(-f)),
                    (UnOp::Not, Value::Bool(b)) => Ok(Value::Bool(!b)),
                    _ => Err("invalid unary operand".into()),
                }
            }
            Expr::Binary { op, left, right } => {
                let l = self.eval(left, env)?;
                let r = self.eval(right, env)?;
                binary(*op, l, r)
            }
            Expr::Call { callee, args } => {
                let argv = args
                    .iter()
                    .map(|a| self.eval(a, env))
                    .collect::<Result<Vec<_>, _>>()?;
                self.call(callee, argv)
            }
            Expr::Declassify(inner) => self.eval(inner, env),
            Expr::Raw(inner) => self.eval(inner, env),
            Expr::Await(inner) => self.eval(inner, env),
            Expr::Record { name, fields } => {
                let mut fs = Vec::new();
                for (k, v) in fields {
                    fs.push((k.clone(), self.eval(v, env)?));
                }
                Ok(Value::Record(name.clone(), fs))
            }
            Expr::ListLit(items) => {
                let mut vs = Vec::new();
                for it in items {
                    vs.push(self.eval(it, env)?);
                }
                Ok(Value::List(vs))
            }
            Expr::Ternary { cond, then, otherwise } => {
                match self.eval(cond, env)? {
                    Value::Bool(true) => self.eval(then, env),
                    Value::Bool(false) => self.eval(otherwise, env),
                    _ => Err("ternary condition must be a boolean".into()),
                }
            }
            Expr::Range { start, end } => {
                let s = match self.eval(start, env)? {
                    Value::Int(n) => n,
                    _ => return Err("range bounds must be Int".into()),
                };
                let e = match self.eval(end, env)? {
                    Value::Int(n) => n,
                    _ => return Err("range bounds must be Int".into()),
                };
                Ok(Value::List((s..e).map(Value::Int).collect()))
            }
            // `xs[i]` (spec 19): `.at` semantics — out-of-bounds / negative ⇒ none.
            Expr::Index { base, index } => {
                let b = self.eval(base, env)?;
                let i = self.eval(index, env)?;
                match (b, i) {
                    (Value::List(items), Value::Int(n)) if n >= 0 => {
                        Ok(items.get(n as usize).cloned().unwrap_or(Value::Null))
                    }
                    (Value::List(_), Value::Int(_)) => Ok(Value::Null),
                    _ => Err("index `[i]` needs a list and an Int".into()),
                }
            }
            // A closure is only valid as a higher-order argument (handled in the
            // MethodCall arm); reaching here is a checker-prevented misuse.
            Expr::Closure { .. } => {
                Err("a closure may only be passed to map/filter/reduce".into())
            }
            Expr::MethodCall { receiver, method, args } => {
                // `session.login(id)` / `session.logout()` — receiver is the
                // capability, not a value, so handle before evaluating it.
                if matches!(receiver.as_ref(), Expr::Ident(n) if n == "session") {
                    return self.session_method(method, args, env);
                }
                if matches!(receiver.as_ref(), Expr::Ident(n) if n == "log") {
                    return self.log_method(method, args, env);
                }
                if let Expr::Ident(n) = receiver.as_ref() {
                    if self.program.endpoints.iter().any(|e| &e.name == n) {
                        return self.endpoint_method(n, method, args, env);
                    }
                }
                if is_db(receiver) && method == "exec" {
                    return self.db_exec(args, env);
                }
                let recv = self.eval(receiver, env)?;
                // `optional.or(default)` — the receiver is an `Optional<T>`: a
                // present value (of ANY type) returns itself, `none`/Null falls
                // back to the default. This MUST precede the String/List dispatch:
                // a present `Optional<String>` is a `Value::Str`, so checking `.or`
                // after the String branch would mis-route it to `string_method`
                // ("unknown String method `or`"). (`session.actor.or("")` hit this.)
                if method == "or" {
                    return match recv {
                        Value::Null => self.eval(args.first().ok_or("`or` needs a default")?, env),
                        other => Ok(other),
                    };
                }
                // String stdlib methods.
                if let Value::Str(s) = &recv {
                    let argv = args
                        .iter()
                        .map(|a| self.eval(a, env))
                        .collect::<Result<Vec<_>, _>>()?;
                    return string_method(s, method, &argv);
                }
                // List stdlib methods (spec 08) — safe accessors return Null on a miss.
                if let Value::List(items) = &recv {
                    // Higher-order ops (spec 19): the closure body is evaluated per
                    // element in a child env. (`contains` was lowered to a builtin.)
                    match method.as_str() {
                        "map" => {
                            let (params, body) = closure_arg(args, 0)?;
                            let mut out = Vec::with_capacity(items.len());
                            for it in items {
                                out.push(self.eval_closure(params, body, &[it.clone()], env)?);
                            }
                            return Ok(Value::List(out));
                        }
                        "filter" => {
                            let (params, body) = closure_arg(args, 0)?;
                            let mut out = Vec::new();
                            for it in items {
                                if as_bool(&self.eval_closure(params, body, &[it.clone()], env)?)? {
                                    out.push(it.clone());
                                }
                            }
                            return Ok(Value::List(out));
                        }
                        "reduce" => {
                            let init = self.eval(args.first().ok_or("`reduce` needs an init value")?, env)?;
                            let (params, body) = closure_arg(args, 1)?;
                            let mut acc = init;
                            for it in items {
                                acc = self.eval_closure(params, body, &[acc.clone(), it.clone()], env)?;
                            }
                            return Ok(acc);
                        }
                        _ => {}
                    }
                    let argv = args
                        .iter()
                        .map(|a| self.eval(a, env))
                        .collect::<Result<Vec<_>, _>>()?;
                    return list_method(items, method, &argv);
                }
                Err("unsupported method call in server runtime".into())
            }
        }
    }

    /// Serialize a value for the wire: secret model fields are omitted.
    pub fn wire_json(&self, v: &Value) -> String {
        match v {
            Value::Null => "null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Int(n) => n.to_string(),
            Value::Float(f) => {
                if f.fract() == 0.0 {
                    (*f as i64).to_string()
                } else {
                    f.to_string()
                }
            }
            Value::Str(s) => json_str(s),
            Value::List(items) => format!(
                "[{}]",
                items.iter().map(|x| self.wire_json(x)).collect::<Vec<_>>().join(",")
            ),
            Value::Record(name, fields) => {
                let model = self.program.models.iter().find(|m| &m.name == name);
                let parts: Vec<String> = fields
                    .iter()
                    .filter(|(k, _)| {
                        model
                            .and_then(|m| m.field(k))
                            .map(|p| !p.is_secret)
                            .unwrap_or(true)
                    })
                    .map(|(k, v)| format!("{}:{}", json_str(k), self.wire_json(v)))
                    .collect();
                format!("{{{}}}", parts.join(","))
            }
        }
    }

    // ---- database (feature-gated) ----

    // R33 — `transaction { … }` opens one connection, runs BEGIN, and parks it in
    // INTERP_TX so the body's db calls reuse it; tx_end commits, or rolls back when
    // the body errored (the error then propagates to the caller as a failed RPC).
    #[cfg(feature = "db")]
    fn tx_begin(&self) -> Result<(), String> {
        let mut c = db_client()?;
        c.batch_execute("BEGIN").map_err(|e| format!("transaction begin failed: {}", e))?;
        INTERP_TX.with(|t| *t.borrow_mut() = Some(c));
        Ok(())
    }
    #[cfg(feature = "db")]
    fn tx_end(&self, commit: bool) {
        INTERP_TX.with(|t| {
            if let Some(mut c) = t.borrow_mut().take() {
                let _ = c.batch_execute(if commit { "COMMIT" } else { "ROLLBACK" });
            }
        });
    }
    #[cfg(not(feature = "db"))]
    fn tx_begin(&self) -> Result<(), String> {
        Err("this xeres build has no database support (released binaries do)".into())
    }
    #[cfg(not(feature = "db"))]
    fn tx_end(&self, _commit: bool) {}

    #[cfg(feature = "db")]
    fn db_exec(&self, args: &[Expr], env: &HashMap<String, Value>) -> Result<Value, String> {
        let (sql, params) = self.sql_and_params(args, env)?;
        let refs: Vec<&(dyn postgres::types::ToSql + Sync)> = params.iter().map(|p| p.as_ref()).collect();
        // Inside a `transaction { … }` the body runs on the shared tx connection
        // (so the writes are atomic); otherwise each call opens its own.
        let n = INTERP_TX.with(|t| -> Result<u64, String> {
            let mut b = t.borrow_mut();
            if let Some(c) = b.as_mut() {
                c.execute(sql.as_str(), &refs).map_err(|e| format!("db exec failed: {}", e))
            } else {
                drop(b);
                db_client()?.execute(sql.as_str(), &refs).map_err(|e| format!("db exec failed: {}", e))
            }
        })?;
        Ok(Value::Int(n as i64))
    }

    #[cfg(feature = "db")]
    fn db_query(
        &self,
        method: &str,
        args: &[Expr],
        env: &HashMap<String, Value>,
        ret_model: Option<&str>,
    ) -> Result<Value, String> {
        let (sql, params) = self.sql_and_params(args, env)?;
        let refs: Vec<&(dyn postgres::types::ToSql + Sync)> = params.iter().map(|p| p.as_ref()).collect();
        let rows = INTERP_TX.with(|t| -> Result<Vec<postgres::Row>, String> {
            let mut b = t.borrow_mut();
            if let Some(c) = b.as_mut() {
                c.query(sql.as_str(), &refs).map_err(|e| format!("db query failed: {}", e))
            } else {
                drop(b);
                db_client()?.query(sql.as_str(), &refs).map_err(|e| format!("db query failed: {}", e))
            }
        })?;
        // `query` -> List<Model>; `query_one` -> Model or Optional<Model>.
        // An `Optional<Model>` return makes a no-row result `Null` rather than
        // an error (the graceful "miss" form).
        let optional = method == "query_one"
            && ret_model.map(|t| generic_inner("Optional", t).is_some()).unwrap_or(false);
        let model_name = match method {
            "query" => ret_model.and_then(|t| generic_inner("List", t)),
            _ => ret_model.and_then(|t| generic_inner("Optional", t)).or(ret_model),
        };
        let model = model_name
            .and_then(|n| self.program.models.iter().find(|m| m.name == n))
            .ok_or("db query: unknown return model")?;
        let mut out = Vec::new();
        for row in &rows {
            let mut fields = Vec::new();
            for p in &model.properties {
                fields.push((p.name.clone(), pg_get(row, &p.name, &p.data_type)));
            }
            out.push(Value::Record(model.name.clone(), fields));
            if method == "query_one" {
                break;
            }
        }
        if method == "query_one" {
            match out.into_iter().next() {
                Some(v) => Ok(v),
                None if optional => Ok(Value::Null),
                None => Err("query_one: no rows".into()),
            }
        } else {
            Ok(Value::List(out))
        }
    }

    #[cfg(feature = "db")]
    fn sql_and_params(
        &self,
        args: &[Expr],
        env: &HashMap<String, Value>,
    ) -> Result<(String, Vec<Box<dyn postgres::types::ToSql + Sync>>), String> {
        let sql = match self.eval(args.first().ok_or("db call needs SQL")?, env)? {
            Value::Str(s) => s,
            _ => return Err("db call: SQL must be a string".into()),
        };
        let mut params: Vec<Box<dyn postgres::types::ToSql + Sync>> = Vec::new();
        for a in &args[1..] {
            match self.eval(a, env)? {
                Value::Str(s) => params.push(Box::new(s)),
                Value::Int(n) => params.push(Box::new(n)),
                Value::Float(f) => params.push(Box::new(f)),
                Value::Bool(b) => params.push(Box::new(b)),
                _ => return Err("db param must be a scalar".into()),
            }
        }
        Ok((sql, params))
    }

    #[cfg(not(feature = "db"))]
    fn db_exec(&self, _args: &[Expr], _env: &HashMap<String, Value>) -> Result<Value, String> {
        Err("this xeres build has no database support (released binaries do)".into())
    }

    #[cfg(not(feature = "db"))]
    fn db_query(
        &self,
        _method: &str,
        _args: &[Expr],
        _env: &HashMap<String, Value>,
        _ret_model: Option<&str>,
    ) -> Result<Value, String> {
        Err("this xeres build has no database support (released binaries do)".into())
    }
}

fn is_db(e: &Expr) -> bool {
    matches!(e, Expr::Ident(n) if n == "db")
}

/// Inner type of a one-level generic, e.g. `("List", "List<User>") -> "User"`.
#[allow(dead_code)]
fn generic_inner<'b>(base: &str, ty: &'b str) -> Option<&'b str> {
    ty.strip_prefix(base)
        .and_then(|r| r.strip_prefix('<'))
        .and_then(|r| r.strip_suffix('>'))
}

fn binary(op: BinOp, l: Value, r: Value) -> Result<Value, String> {
    use Value::*;
    let num = |v: &Value| -> Option<f64> {
        match v {
            Int(n) => Some(*n as f64),
            Float(f) => Some(*f),
            _ => None,
        }
    };
    match op {
        BinOp::Add => match (&l, &r) {
            (Int(a), Int(b)) => Ok(Int(a + b)),
            (Str(a), b) => Ok(Str(format!("{}{}", a, display(b)))),
            (a, Str(b)) => Ok(Str(format!("{}{}", display(a), b))),
            _ => num2(&l, &r, |a, b| a + b),
        },
        BinOp::Sub => num2(&l, &r, |a, b| a - b),
        BinOp::Mul => num2(&l, &r, |a, b| a * b),
        BinOp::Div => num2(&l, &r, |a, b| a / b),
        BinOp::Eq => Ok(Bool(values_eq(&l, &r))),
        BinOp::NotEq => Ok(Bool(!values_eq(&l, &r))),
        BinOp::Lt | BinOp::Gt | BinOp::LtEq | BinOp::GtEq => {
            let (a, b) = (num(&l).ok_or("comparison needs numbers")?, num(&r).ok_or("comparison needs numbers")?);
            Ok(Bool(match op {
                BinOp::Lt => a < b,
                BinOp::Gt => a > b,
                BinOp::LtEq => a <= b,
                _ => a >= b,
            }))
        }
        BinOp::And => match (l, r) {
            (Bool(a), Bool(b)) => Ok(Bool(a && b)),
            _ => Err("&& needs booleans".into()),
        },
        BinOp::Or => match (l, r) {
            (Bool(a), Bool(b)) => Ok(Bool(a || b)),
            _ => Err("|| needs booleans".into()),
        },
    }
}

fn num2(l: &Value, r: &Value, f: fn(f64, f64) -> f64) -> Result<Value, String> {
    match (l, r) {
        (Value::Int(a), Value::Int(b)) => Ok(Value::Int(f(*a as f64, *b as f64) as i64)),
        (a, b) => {
            let av = as_num(a).ok_or("arithmetic needs numbers")?;
            let bv = as_num(b).ok_or("arithmetic needs numbers")?;
            Ok(Value::Float(f(av, bv)))
        }
    }
}

fn as_num(v: &Value) -> Option<f64> {
    match v {
        Value::Int(n) => Some(*n as f64),
        Value::Float(f) => Some(*f),
        _ => None,
    }
}

// ---- exact decimal arithmetic (R29 / spec 18) -----------------------------
// Decimal stays a string end-to-end; the checker's typed desugaring rewrites
// `+ - * < > <= >=` on Decimals into `__dec_*` builtin calls handled here. Math
// is exact (scaled i128), never f64 — that is the whole point of Decimal.

/// Parse "12.34" / "-5" into a signed integer scaled by its own fractional
/// length, plus that scale: "12.34" -> (1234, 2), "-5" -> (-5, 0).
fn dec_parse(s: &str) -> Option<(i128, u32)> {
    let s = s.trim();
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let (int_part, frac_part) = s.split_once('.').unwrap_or((s, ""));
    let digits = format!("{}{}", int_part, frac_part);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mag: i128 = digits.parse().ok()?;
    Some((if neg { -mag } else { mag }, frac_part.len() as u32))
}

/// Rescale a value from `from` fractional digits up to `to` (>= from).
fn dec_rescale(v: i128, from: u32, to: u32) -> i128 {
    v * 10i128.pow(to - from)
}

/// Format a signed scaled value back to a decimal string.
fn dec_format(value: i128, scale: u32) -> String {
    let neg = value < 0;
    let s = value.unsigned_abs().to_string();
    let body = if scale == 0 {
        s
    } else {
        let scale = scale as usize;
        let s = if s.len() <= scale { format!("{:0>w$}", s, w = scale + 1) } else { s };
        let dot = s.len() - scale;
        format!("{}.{}", &s[..dot], &s[dot..])
    };
    if neg { format!("-{}", body) } else { body }
}

fn dec_add(a: &str, b: &str) -> Result<String, String> {
    let (av, asc) = dec_parse(a).ok_or("invalid Decimal")?;
    let (bv, bsc) = dec_parse(b).ok_or("invalid Decimal")?;
    let sc = asc.max(bsc);
    Ok(dec_format(dec_rescale(av, asc, sc) + dec_rescale(bv, bsc, sc), sc))
}

fn dec_sub(a: &str, b: &str) -> Result<String, String> {
    let (av, asc) = dec_parse(a).ok_or("invalid Decimal")?;
    let (bv, bsc) = dec_parse(b).ok_or("invalid Decimal")?;
    let sc = asc.max(bsc);
    Ok(dec_format(dec_rescale(av, asc, sc) - dec_rescale(bv, bsc, sc), sc))
}

fn dec_mul(a: &str, b: &str) -> Result<String, String> {
    let (av, asc) = dec_parse(a).ok_or("invalid Decimal")?;
    let (bv, bsc) = dec_parse(b).ok_or("invalid Decimal")?;
    Ok(dec_format(av * bv, asc + bsc))
}

fn dec_cmp(a: &str, b: &str) -> Result<std::cmp::Ordering, String> {
    let (av, asc) = dec_parse(a).ok_or("invalid Decimal")?;
    let (bv, bsc) = dec_parse(b).ok_or("invalid Decimal")?;
    let sc = asc.max(bsc);
    Ok(dec_rescale(av, asc, sc).cmp(&dec_rescale(bv, bsc, sc)))
}

/// Coerce a builtin arg to a decimal string (`Decimal` is `Value::Str`; an `Int`
/// operand of `Decimal * Int` arrives as `Value::Int`).
fn dec_str(v: Option<&Value>) -> Result<String, String> {
    match v {
        Some(Value::Str(s)) => Ok(s.clone()),
        Some(Value::Int(n)) => Ok(n.to_string()),
        other => Err(format!("decimal op needs a Decimal/Int, got {:?}", other)),
    }
}

/// Extract the closure at argument position `i` (spec 19): `(params, body)`.
fn closure_arg(args: &[Expr], i: usize) -> Result<(&[String], &Expr), String> {
    match args.get(i) {
        Some(Expr::Closure { params, body }) => Ok((params.as_slice(), &**body)),
        _ => Err("expected a closure argument (`x -> …`)".into()),
    }
}

/// A `filter` predicate result must be a Bool.
fn as_bool(v: &Value) -> Result<bool, String> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err("`filter` predicate must return a Bool".into()),
    }
}

fn values_eq(l: &Value, r: &Value) -> bool {
    match (l, r) {
        (Value::Int(a), Value::Int(b)) => a == b,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Str(a), Value::Str(b)) => a == b,
        (Value::Null, Value::Null) => true,
        // Deep equality for `.contains` on List<Model>/nested lists (spec 19).
        (Value::Record(an, af), Value::Record(bn, bf)) => {
            an == bn
                && af.len() == bf.len()
                && af.iter().zip(bf).all(|((ak, av), (bk, bv))| ak == bk && values_eq(av, bv))
        }
        (Value::List(a), Value::List(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| values_eq(x, y))
        }
        _ => as_num(l).zip(as_num(r)).map(|(a, b)| a == b).unwrap_or(false),
    }
}

fn display(v: &Value) -> String {
    match v {
        Value::Int(n) => n.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Str(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

pub fn json_str(s: &str) -> String {
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

pub fn uid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("{:x}", nanos)
}

/// The `now()` builtin: epoch milliseconds (matches the server + `Date.now()`).
fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// String stdlib methods (the interpreter half of the codegen spellings).
fn string_method(s: &str, method: &str, args: &[Value]) -> Result<Value, String> {
    let sarg = |i: usize| match args.get(i) {
        Some(Value::Str(x)) => Ok(x.clone()),
        _ => Err(format!("`.{}()` argument must be a String", method)),
    };
    Ok(match method {
        "trim" => Value::Str(s.trim().to_string()),
        "upper" => Value::Str(s.to_uppercase()),
        "lower" => Value::Str(s.to_lowercase()),
        "length" => Value::Int(s.chars().count() as i64),
        "contains" => Value::Bool(s.contains(sarg(0)?.as_str())),
        "split" => Value::List(s.split(sarg(0)?.as_str()).map(|p| Value::Str(p.to_string())).collect()),
        "replace" => Value::Str(s.replace(sarg(0)?.as_str(), sarg(1)?.as_str())),
        other => return Err(format!("unknown String method `{}`", other)),
    })
}

/// List stdlib methods (spec 08). `first`/`last`/`at` return `Null` on a miss
/// (the runtime form of `Optional<T>`), so they never panic on an empty or
/// out-of-bounds access. Mirrors `emit_list_method` in codegen.
fn list_method(items: &[Value], method: &str, args: &[Value]) -> Result<Value, String> {
    Ok(match method {
        "length" => Value::Int(items.len() as i64),
        "first" => items.first().cloned().unwrap_or(Value::Null),
        "last" => items.last().cloned().unwrap_or(Value::Null),
        "at" => match args.first() {
            Some(Value::Int(i)) if *i >= 0 => items.get(*i as usize).cloned().unwrap_or(Value::Null),
            Some(Value::Int(_)) => Value::Null, // negative index ⇒ none
            _ => return Err("`.at()` argument must be an Int".into()),
        },
        "reverse" => {
            let mut v = items.to_vec();
            v.reverse();
            Value::List(v)
        }
        other => return Err(format!("unknown List method `{}`", other)),
    })
}

/// Math builtins abs/min/max. Stays Int when all args are Int, else Float.
fn math_fn(name: &str, args: &[Value]) -> Result<Value, String> {
    let num = |v: &Value| match v {
        Value::Int(n) => Some(*n as f64),
        Value::Float(f) => Some(*f),
        _ => None,
    };
    let all_int = args.iter().all(|v| matches!(v, Value::Int(_)));
    let wrap = |x: f64| if all_int { Value::Int(x as i64) } else { Value::Float(x) };
    let a = num(args.first().ok_or("math fn needs an argument")?).ok_or("math fn needs a number")?;
    match name {
        "abs" => Ok(wrap(a.abs())),
        "min" | "max" => {
            let b = num(args.get(1).ok_or("min/max need two arguments")?).ok_or("min/max need numbers")?;
            Ok(wrap(if name == "min" { a.min(b) } else { a.max(b) }))
        }
        _ => Err(format!("unknown math fn `{}`", name)),
    }
}

// ---- auth builtins (feature-gated) ----
// hash()/verify() use Argon2id; like `db`, they're behind the `auth` feature so
// the default std-only build stays dependency-free. Released binaries enable it.

#[cfg(feature = "auth")]
fn auth_hash(args: &[Value]) -> Result<Value, String> {
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    use argon2::{Argon2, PasswordHasher};
    let s = match args.first() {
        Some(Value::Str(s)) => s.clone(),
        _ => return Err("hash() expects a string".into()),
    };
    let salt = SaltString::generate(&mut OsRng);
    let h = Argon2::default()
        .hash_password(s.as_bytes(), &salt)
        .map_err(|e| format!("hash failed: {}", e))?
        .to_string();
    Ok(Value::Str(h))
}

#[cfg(feature = "auth")]
fn auth_verify(args: &[Value]) -> Result<Value, String> {
    use argon2::password_hash::PasswordHash;
    use argon2::{Argon2, PasswordVerifier};
    let (password, stored) = match (args.first(), args.get(1)) {
        (Some(Value::Str(p)), Some(Value::Str(h))) => (p.clone(), h.clone()),
        _ => return Err("verify() expects (password, hash)".into()),
    };
    let ok = match PasswordHash::new(&stored) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    };
    Ok(Value::Bool(ok))
}

#[cfg(not(feature = "auth"))]
fn auth_hash(_args: &[Value]) -> Result<Value, String> {
    Err("this xeres build has no auth support (hash/verify); released binaries do".into())
}

#[cfg(not(feature = "auth"))]
fn auth_verify(_args: &[Value]) -> Result<Value, String> {
    Err("this xeres build has no auth support (hash/verify); released binaries do".into())
}

// ---- session cookie (feature-gated, like auth) ----
// The cookie value is `<actor-id>.<hmac>` signed with HMAC-SHA256 over a server
// secret (SESSION_SECRET). It is set HttpOnly; Secure; SameSite=Strict so it
// cannot be read by JS, forged, or sent cross-site.

/// Verify an incoming `xeres_session` cookie value, returning the actor id if
/// the signature checks out.
#[cfg(feature = "auth")]
pub fn session_verify(raw: &str) -> Option<String> {
    let (id, sig) = raw.rsplit_once('.')?;
    let expected = session_sign(id);
    let expected_sig = expected.rsplit_once('.')?.1.to_string();
    if constant_eq(expected_sig.as_bytes(), sig.as_bytes()) {
        Some(id.to_string())
    } else {
        None
    }
}

#[cfg(feature = "auth")]
fn session_sign(id: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::digest::KeyInit;
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&session_secret())
        .expect("HMAC accepts a key of any length");
    mac.update(id.as_bytes());
    format!("{}.{}", id, hex(&mac.finalize().into_bytes()))
}

#[cfg(feature = "auth")]
fn session_secret() -> Vec<u8> {
    std::env::var("SESSION_SECRET").map(String::into_bytes).unwrap_or_else(|_| {
        eprintln!("xeres: SESSION_SECRET not set — using an insecure dev key. Set it in .env for production.");
        b"xeres-insecure-dev-session-key".to_vec()
    })
}

#[cfg(feature = "auth")]
fn session_set_cookie(id: &str) -> String {
    // Two cookies in one Set-Cookie slot (joined so the writer emits both lines):
    // the signed HttpOnly session, plus a *readable* `xeres_auth` flag the client
    // router reads to bounce unauthenticated users off `auth` routes (R31). The
    // flag holds no secret — forging it only reveals an empty shell, since
    // protected *data* still requires the signed session (R24).
    format!(
        "xeres_session={}; HttpOnly; Secure; SameSite=Strict; Path=/\r\nSet-Cookie: xeres_auth=1; Secure; SameSite=Strict; Path=/",
        session_sign(id)
    )
}

#[cfg(feature = "auth")]
fn session_clear_cookie() -> String {
    "xeres_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0\r\nSet-Cookie: xeres_auth=; Secure; SameSite=Strict; Path=/; Max-Age=0".to_string()
}

#[cfg(feature = "auth")]
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(feature = "auth")]
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

// Non-auth builds: no HMAC, so no real session (released binaries enable it).
#[cfg(not(feature = "auth"))]
pub fn session_verify(_raw: &str) -> Option<String> {
    None
}
#[cfg(not(feature = "auth"))]
fn session_set_cookie(_id: &str) -> String {
    String::new()
}
#[cfg(not(feature = "auth"))]
fn session_clear_cookie() -> String {
    String::new()
}

// ---- endpoint egress (feature-gated `http`) ----
// Outbound HTTP via ureq, only to a declared endpoint's fixed host (R26).

#[cfg(feature = "http")]
fn endpoint_get(url: &str, bearer: &str) -> Result<Value, String> {
    let mut req = ureq::get(url);
    if !bearer.is_empty() {
        req = req.set("Authorization", &format!("Bearer {}", bearer));
    }
    match req.call() {
        Ok(resp) => Ok(Value::Str(resp.into_string().unwrap_or_default())),
        Err(e) => Err(format!("endpoint GET failed: {}", e)),
    }
}

#[cfg(feature = "http")]
fn endpoint_post(url: &str, body: &str, bearer: &str) -> Result<Value, String> {
    let mut req = ureq::post(url);
    if !bearer.is_empty() {
        req = req.set("Authorization", &format!("Bearer {}", bearer));
    }
    match req.send_string(body) {
        Ok(resp) => Ok(Value::Int(resp.status() as i64)),
        Err(ureq::Error::Status(code, _)) => Ok(Value::Int(code as i64)),
        Err(e) => Err(format!("endpoint POST failed: {}", e)),
    }
}

#[cfg(not(feature = "http"))]
fn endpoint_get(_url: &str, _bearer: &str) -> Result<Value, String> {
    Err("this xeres build has no http support (endpoint); released binaries do".into())
}
#[cfg(not(feature = "http"))]
fn endpoint_post(_url: &str, _body: &str, _bearer: &str) -> Result<Value, String> {
    Err("this xeres build has no http support (endpoint); released binaries do".into())
}

// ---- postgres glue (feature-gated) ----

// The active `transaction { … }` connection for this request thread, if any (R33).
// Set by `tx_begin`, read by db_exec/db_query, cleared by `tx_end`. One thread per
// request (Connection: close) means it never leaks across requests.
#[cfg(feature = "db")]
thread_local! { static INTERP_TX: std::cell::RefCell<Option<postgres::Client>> = std::cell::RefCell::new(None); }

#[cfg(feature = "db")]
fn db_client() -> Result<postgres::Client, String> {
    let url = std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is not set")?;
    let tls = postgres_native_tls::MakeTlsConnector::new(
        native_tls::TlsConnector::new().map_err(|e| e.to_string())?,
    );
    postgres::Client::connect(&url, tls).map_err(|e| format!("db connect failed: {}", e))
}

#[cfg(feature = "db")]
fn pg_get(row: &postgres::Row, col: &str, ty: &str) -> Value {
    match ty {
        "Int" | "DateTime" => row.try_get::<_, i64>(col).map(Value::Int).unwrap_or(Value::Null),
        "Float" => row.try_get::<_, f64>(col).map(Value::Float).unwrap_or(Value::Null),
        "Bool" => row.try_get::<_, bool>(col).map(Value::Bool).unwrap_or(Value::Null),
        _ => row.try_get::<_, String>(col).map(Value::Str).unwrap_or(Value::Null),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_program() -> XeresProgram {
        XeresProgram {
            models: vec![],
            enums: vec![],
            functions: vec![],
            states: vec![],
            screens: vec![],
            endpoints: vec![],
            apis: vec![],
            imports: vec![],
            requires: Default::default(),
        }
    }

    // Exact decimal arithmetic — never f64 (spec 18 / R29).
    #[test]
    fn decimal_arithmetic_is_exact() {
        assert_eq!(dec_add("1.50", "2.50").unwrap(), "4.00");
        assert_eq!(dec_add("0.1", "0.2").unwrap(), "0.3"); // no binary-float drift
        assert_eq!(dec_sub("5.00", "1.25").unwrap(), "3.75");
        assert_eq!(dec_mul("19.99", "2").unwrap(), "39.98"); // Decimal * Int
        assert_eq!(dec_mul("1.5", "3").unwrap(), "4.5");
        assert_eq!(dec_add("-1.5", "0.5").unwrap(), "-1.0");
    }

    // Ordered comparison is numeric, not the lexicographic compare a raw string
    // would give ("10.00" must be > "9.99", though '1' < '9' as text).
    #[test]
    fn decimal_compare_is_numeric() {
        use std::cmp::Ordering;
        assert_eq!(dec_cmp("10.00", "9.99").unwrap(), Ordering::Greater);
        assert_eq!(dec_cmp("1.5", "1.50").unwrap(), Ordering::Equal);
        assert_eq!(dec_cmp("0.30", "0.3").unwrap(), Ordering::Equal);
    }

    // End-to-end (spec 18): real source → analyze → lower → interp `call`. Proves
    // the checker's typed desugaring of Decimal `+ - * >` and the interpreter's
    // `__dec_*` dispatch agree with the exact-math core — the same cases the
    // rust_decimal (server) and BigInt (browser) backends are verified against.
    #[test]
    fn decimal_arithmetic_runs_end_to_end() {
        let src = "\
server fn line_total(price: Decimal, qty: Int) -> Decimal { return price * qty }\n\
server fn running(subtotal: Decimal, line: Decimal) -> Decimal { return subtotal + line }\n\
server fn change(paid: Decimal, due: Decimal) -> Decimal { return paid - due }\n\
server fn over(total: Decimal, limit: Decimal) -> Bool { return total > limit }\n";
        let mut lexer = crate::frontend::lexer::Lexer::new(src);
        let mut parser = crate::frontend::parser::Parser::new(&mut lexer);
        let mut program = parser.parse_program();
        let analysis = crate::middle::checker::analyze(&program);
        assert!(
            analysis.errors.is_empty(),
            "unexpected errors: {:?}",
            analysis.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
        );
        crate::middle::checker::lower(&mut program);
        let interp = Interp::with_session(&program, None);

        // Decimal * Int — exact integer scaling, Int arg coerced via dec_str.
        let r = interp.call("line_total", vec![Value::Str("19.99".into()), Value::Int(2)]).unwrap();
        assert!(matches!(&r, Value::Str(s) if s == "39.98"), "line_total => {:?}", r);
        // Decimal + Decimal — no binary-float drift.
        let r = interp.call("running", vec![Value::Str("0.1".into()), Value::Str("0.2".into())]).unwrap();
        assert!(matches!(&r, Value::Str(s) if s == "0.3"), "running => {:?}", r);
        // Decimal - Decimal.
        let r = interp.call("change", vec![Value::Str("5.00".into()), Value::Str("1.25".into())]).unwrap();
        assert!(matches!(&r, Value::Str(s) if s == "3.75"), "change => {:?}", r);
        // Ordered compare → Bool, numeric not lexicographic.
        let r = interp.call("over", vec![Value::Str("10.00".into()), Value::Str("9.99".into())]).unwrap();
        assert!(matches!(r, Value::Bool(true)), "over => {:?}", r);
    }

    // End-to-end (spec 19): source → analyze → lower → interp `call`. Proves the
    // closure binding + map/filter/reduce dispatch, `xs[i]` sugar, and the lowered
    // `__list_contains` all run (the same cases the codegen tiers are checked on).
    #[test]
    fn higher_order_list_ops_run_end_to_end() {
        let src = "\
server fn doubled(xs: List<Int>) -> List<Int> { return xs.map(x -> x * 2) }\n\
server fn big(xs: List<Int>) -> List<Int> { return xs.filter(x -> x >= 2) }\n\
server fn total(xs: List<Int>) -> Int { return xs.reduce(0, (acc, x) -> acc + x) }\n\
server fn nth(xs: List<Int>) -> Int { return xs[1].or(0) }\n\
server fn oob(xs: List<Int>) -> Int { return xs[9].or(-1) }\n\
server fn has(tags: List<String>) -> Bool { return tags.contains(\"b\") }\n";
        let mut lexer = crate::frontend::lexer::Lexer::new(src);
        let mut parser = crate::frontend::parser::Parser::new(&mut lexer);
        let mut program = parser.parse_program();
        let analysis = crate::middle::checker::analyze(&program);
        assert!(
            analysis.errors.is_empty(),
            "unexpected errors: {:?}",
            analysis.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
        );
        crate::middle::checker::lower(&mut program);
        let interp = Interp::with_session(&program, None);
        let ints = |v: &[i64]| Value::List(v.iter().map(|n| Value::Int(*n)).collect());
        let as_ints = |v: Value| -> Vec<i64> {
            match v {
                Value::List(xs) => xs.iter().map(|x| if let Value::Int(n) = x { *n } else { -999 }).collect(),
                other => panic!("expected a list, got {:?}", other),
            }
        };

        assert_eq!(as_ints(interp.call("doubled", vec![ints(&[1, 2, 3])]).unwrap()), vec![2, 4, 6]);
        assert_eq!(as_ints(interp.call("big", vec![ints(&[1, 2, 3])]).unwrap()), vec![2, 3]);
        assert!(matches!(interp.call("total", vec![ints(&[1, 2, 3])]).unwrap(), Value::Int(6)));
        assert!(matches!(interp.call("nth", vec![ints(&[10, 20, 30])]).unwrap(), Value::Int(20)));
        // `xs[9]` is out of bounds ⇒ none ⇒ the `.or(-1)` fallback (never a panic).
        assert!(matches!(interp.call("oob", vec![ints(&[1])]).unwrap(), Value::Int(-1)));
        let tags = Value::List(vec![Value::Str("a".into()), Value::Str("b".into())]);
        assert!(matches!(interp.call("has", vec![tags]).unwrap(), Value::Bool(true)));
        let tags2 = Value::List(vec![Value::Str("a".into())]);
        assert!(matches!(interp.call("has", vec![tags2]).unwrap(), Value::Bool(false)));
    }

    // End-to-end (spec 20): two real files → loader (resolve imports + merge) →
    // analyze → lower → interp `call`. Proves a cross-module qualified call
    // (`money.add` / `money.to_cents`) resolves, a module-private helper
    // (`scale`) runs, and the merged program executes identically to a single
    // file — the same program the ejected Rust crate and esbuild bundle run.
    #[test]
    fn modules_run_end_to_end() {
        let dir = std::env::temp_dir().join(format!("xeres_spec20_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("money.xrs"),
            "fn scale(n: Int) -> Int { return n * 100 }\n\
             pub fn to_cents(dollars: Int) -> Int { return scale(dollars) }\n\
             pub fn add(a: Int, b: Int) -> Int { return a + b }\n",
        )
        .unwrap();
        let app = dir.join("app.xrs");
        std::fs::write(
            &app,
            "import \"money.xrs\"\n\
             server fn checkout(dollars: Int, tax: Int) -> Int { return money.add(money.to_cents(dollars), tax) }\n",
        )
        .unwrap();

        let mut program = crate::middle::loader::load_program(app.to_str().unwrap()).unwrap_or_else(|errs| {
            panic!(
                "load failed: {:?}",
                errs.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
            )
        });
        let analysis = crate::middle::checker::analyze(&program);
        assert!(
            analysis.errors.is_empty(),
            "unexpected errors: {:?}",
            analysis.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
        );
        crate::middle::checker::lower(&mut program);
        let interp = Interp::with_session(&program, None);
        // checkout(2, 5) = to_cents(2) + 5 = 200 + 5 = 205.
        let r = interp.call("checkout", vec![Value::Int(2), Value::Int(5)]).unwrap();
        assert!(matches!(r, Value::Int(205)), "checkout => {:?}", r);
        // The exported helpers are also directly callable in the merged program.
        let r = interp.call("add", vec![Value::Int(40), Value::Int(2)]).unwrap();
        assert!(matches!(r, Value::Int(42)), "add => {:?}", r);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // End-to-end (spec 20, Cut 1.5): the self-hosted stdlib. An app imports the
    // EMBEDDED `std:math` / `std:text` modules (compiled into the binary), and
    // the merged program runs through the interpreter. Proves Layer 2 — the
    // stdlib is Xeres checked under R1–R33 — and exercises `if`/`while`/`reduce`/
    // `split`, intra-module calls (`average`→`sum`, `word_count`→`is_blank`), and
    // integer division, all written in Xeres.
    #[test]
    fn stdlib_runs_end_to_end() {
        let dir = std::env::temp_dir().join(format!("xeres_stdlib_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let app = dir.join("app.xrs");
        std::fs::write(
            &app,
            "import \"std:math\"\n\
             import \"std:text\"\n\
             server fn band(x: Int) -> Int { return math.clamp(x, 0, 10) }\n\
             server fn p(b: Int, e: Int) -> Int { return math.pow(b, e) }\n\
             server fn avg(xs: List<Int>) -> Int { return math.average(xs) }\n\
             server fn slug(s: String) -> String { return text.slugify(s) }\n\
             server fn wc(s: String) -> Int { return text.word_count(s) }\n",
        )
        .unwrap();

        let mut program = crate::middle::loader::load_program(app.to_str().unwrap()).unwrap_or_else(|errs| {
            panic!(
                "load failed: {:?}",
                errs.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
            )
        });
        let analysis = crate::middle::checker::analyze(&program);
        assert!(
            analysis.errors.is_empty(),
            "stdlib errors: {:?}",
            analysis.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
        );
        crate::middle::checker::lower(&mut program);
        let interp = Interp::with_session(&program, None);
        let ints = |v: &[i64]| Value::List(v.iter().map(|n| Value::Int(*n)).collect());

        // clamp (if), pow (while loop + reassignment), average (intra-module call
        // `sum` + integer division), slugify + word_count (String methods, and
        // `word_count` calls `is_blank` — another intra-module call).
        assert!(matches!(interp.call("band", vec![Value::Int(50)]).unwrap(), Value::Int(10)));
        assert!(matches!(interp.call("band", vec![Value::Int(0 - 5)]).unwrap(), Value::Int(0)));
        assert!(matches!(interp.call("band", vec![Value::Int(7)]).unwrap(), Value::Int(7)));
        assert!(matches!(interp.call("p", vec![Value::Int(2), Value::Int(10)]).unwrap(), Value::Int(1024)));
        assert!(matches!(interp.call("avg", vec![ints(&[2, 4, 6])]).unwrap(), Value::Int(4)));
        let r = interp.call("slug", vec![Value::Str("  Hello World  ".into())]).unwrap();
        assert!(matches!(&r, Value::Str(s) if s == "hello-world"), "slug => {:?}", r);
        assert!(matches!(interp.call("wc", vec![Value::Str("a b c".into())]).unwrap(), Value::Int(3)));
        assert!(matches!(interp.call("wc", vec![Value::Str("   ".into())]).unwrap(), Value::Int(0)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // Every embedded stdlib module must itself parse + analyze clean — the shipped
    // library is Xeres compiled under the same R1–R33 rules as user code.
    #[test]
    fn stdlib_modules_are_valid_xeres() {
        for (name, source) in crate::middle::loader::stdlib_modules() {
            let mut lexer = crate::frontend::lexer::Lexer::new(source);
            let mut parser = crate::frontend::parser::Parser::new(&mut lexer);
            let program = parser.parse_program();
            let analysis = crate::middle::checker::analyze(&program);
            assert!(
                analysis.errors.is_empty(),
                "std:{} has errors: {:?}",
                name,
                analysis.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
            );
        }
    }

    // End-to-end (spec 23): an inbound `api` runs through the interpreter — a GET
    // route returns a model whose `secret` field is stripped from the wire JSON,
    // and a POST route reads its decoded body and echoes a field back. Proves the
    // same path `xeres serve` uses (api_route_dispatch -> call_api_route ->
    // wire_json) agrees with the boundary guarantees.
    #[test]
    fn api_runs_end_to_end() {
        let dir = std::env::temp_dir().join(format!("xeres_api_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let app = dir.join("app.xrs");
        std::fs::write(
            &app,
            "model User { id: String name: String secret token: String }\n\
             model Signup { email: String }\n\
             model Conf { ok: Bool echo: String }\n\
             api Public {\n\
               base \"/api\"\n\
               GET \"/me\" -> User { return User { id: \"1\", name: \"Ada\", token: \"SECRET\" } }\n\
               POST \"/signup\" body s: Signup -> Conf { return Conf { ok: true, echo: s.email } }\n\
             }\n\
             ui screen Home { view { column { heading \"x\" } } }\n",
        )
        .unwrap();

        let mut program = crate::middle::loader::load_program(app.to_str().unwrap())
            .unwrap_or_else(|errs| {
                panic!("load failed: {:?}", errs.iter().map(|e| e.message.clone()).collect::<Vec<_>>())
            });
        let analysis = crate::middle::checker::analyze(&program);
        assert!(
            analysis.errors.is_empty(),
            "api errors: {:?}",
            analysis.errors.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
        );
        crate::middle::checker::lower(&mut program);
        let interp = Interp::with_session(&program, None);
        let routes = &program.apis[0].routes;

        // GET /me — the secret `token` must be absent from the wire JSON (R5).
        let me = &routes[0];
        let v = interp.call_api_route(&me.body_stmts, None, me.return_type.as_deref()).unwrap();
        let json = interp.wire_json(&v);
        assert!(json.contains("Ada"), "me => {}", json);
        assert!(!json.contains("SECRET"), "secret leaked on the public api: {}", json);

        // POST /signup — the decoded body is in scope and echoed back.
        let signup = &routes[1];
        let body = signup.body.as_ref().map(|b| {
            (
                b.name.clone(),
                Value::Record("Signup".into(), vec![("email".into(), Value::Str("a@b.com".into()))]),
            )
        });
        let v = interp.call_api_route(&signup.body_stmts, body, signup.return_type.as_deref()).unwrap();
        let json = interp.wire_json(&v);
        assert!(json.contains("a@b.com"), "signup => {}", json);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // Spec 24: a typed `endpoint.get(...)` response — the shared JSON decoder maps
    // a real Open-Meteo payload onto a nested model (the runtime half of
    // `let f: Forecast = weather.get(...)`; the codegen half is `decode_json_rust`).
    #[test]
    fn endpoint_typed_response_decodes() {
        let src = "model Current { temperature_2m: Float relative_humidity_2m: Int wind_speed_10m: Float }\n\
                   model Forecast { current: Current }\n";
        let mut lexer = crate::frontend::lexer::Lexer::new(src);
        let mut parser = crate::frontend::parser::Parser::new(&mut lexer);
        let program = parser.parse_program();

        let json = "{\"current\":{\"temperature_2m\":12.3,\"relative_humidity_2m\":80,\"wind_speed_10m\":5.2},\"x\":1}";
        let parsed = crate::json::jparse(json);
        let v = crate::json::decode(Some(&parsed), "Forecast", &program);

        fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
            match v {
                Value::Record(_, fs) => fs.iter().find(|(n, _)| n == k).map(|(_, vv)| vv).unwrap(),
                _ => panic!("expected record, got {:?}", v),
            }
        }
        let cur = field(&v, "current");
        assert!(matches!(field(cur, "temperature_2m"), Value::Float(f) if (*f - 12.3).abs() < 1e-9));
        assert!(matches!(field(cur, "relative_humidity_2m"), Value::Int(80)));
        assert!(matches!(field(cur, "wind_speed_10m"), Value::Float(f) if (*f - 5.2).abs() < 1e-9));
    }

    // `session.actor.or("")` — `.or` on a present Optional<String>.
    fn actor_or(default: &str) -> Expr {
        Expr::MethodCall {
            receiver: Box::new(Expr::Field {
                base: Box::new(Expr::Ident("session".to_string())),
                field: "actor".to_string(),
            }),
            method: "or".to_string(),
            args: vec![Expr::Str(default.to_string())],
        }
    }

    // Regression: a present `Optional<String>` is a `Value::Str`, so `.or` must be
    // resolved BEFORE the String-method dispatch. It used to mis-route to
    // `string_method` → "unknown String method `or`" (broke `session.actor.or(..)`).
    #[test]
    fn optional_or_on_present_string_returns_the_value() {
        let program = empty_program();
        let interp = Interp::with_session(&program, Some("alice".to_string()));
        let got = interp.eval(&actor_or(""), &HashMap::new());
        assert!(matches!(&got, Ok(Value::Str(s)) if s == "alice"), "got {:?}", got);
    }

    // The `none` path still falls back to the default.
    #[test]
    fn optional_or_on_none_returns_the_default() {
        let program = empty_program();
        let interp = Interp::with_session(&program, None);
        let got = interp.eval(&actor_or("anon"), &HashMap::new());
        assert!(matches!(&got, Ok(Value::Str(s)) if s == "anon"), "got {:?}", got);
    }
}
