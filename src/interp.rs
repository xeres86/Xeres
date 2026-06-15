// A tree-walking interpreter for `server` functions. The self-contained
// runtime (`xeres serve`) uses this instead of generating + compiling Rust, so
// running an app needs no cargo. Database access is feature-gated (`db`).

use crate::parser::{BinOp, Expr, MatchPat, Stmt, UnOp, XeresProgram};
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
            Expr::MethodCall { receiver, method, args } => {
                // `session.login(id)` / `session.logout()` — receiver is the
                // capability, not a value, so handle before evaluating it.
                if matches!(receiver.as_ref(), Expr::Ident(n) if n == "session") {
                    return self.session_method(method, args, env);
                }
                if is_db(receiver) && method == "exec" {
                    return self.db_exec(args, env);
                }
                let recv = self.eval(receiver, env)?;
                // String stdlib methods.
                if let Value::Str(s) = &recv {
                    let argv = args
                        .iter()
                        .map(|a| self.eval(a, env))
                        .collect::<Result<Vec<_>, _>>()?;
                    return string_method(s, method, &argv);
                }
                // `optional.or(default)` — null falls back to the default.
                if method == "or" {
                    return match recv {
                        Value::Null => self.eval(args.first().ok_or("`or` needs a default")?, env),
                        other => Ok(other),
                    };
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

    #[cfg(feature = "db")]
    fn db_exec(&self, args: &[Expr], env: &HashMap<String, Value>) -> Result<Value, String> {
        let (sql, params) = self.sql_and_params(args, env)?;
        let refs: Vec<&(dyn postgres::types::ToSql + Sync)> = params.iter().map(|p| p.as_ref()).collect();
        let mut client = db_client()?;
        let n = client
            .execute(sql.as_str(), &refs)
            .map_err(|e| format!("db exec failed: {}", e))?;
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
        let mut client = db_client()?;
        let rows = client
            .query(sql.as_str(), &refs)
            .map_err(|e| format!("db query failed: {}", e))?;
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

fn values_eq(l: &Value, r: &Value) -> bool {
    match (l, r) {
        (Value::Int(a), Value::Int(b)) => a == b,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Str(a), Value::Str(b)) => a == b,
        (Value::Null, Value::Null) => true,
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
    format!("xeres_session={}; HttpOnly; Secure; SameSite=Strict; Path=/", session_sign(id))
}

#[cfg(feature = "auth")]
fn session_clear_cookie() -> String {
    "xeres_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0".to_string()
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

// ---- postgres glue (feature-gated) ----

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
