// A tree-walking interpreter for `server` functions. The self-contained
// runtime (`xeres serve`) uses this instead of generating + compiling Rust, so
// running an app needs no cargo. Database access is feature-gated (`db`).

use crate::parser::{BinOp, Expr, Stmt, UnOp, XeresProgram};
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

pub struct Interp<'a> {
    pub program: &'a XeresProgram,
}

impl<'a> Interp<'a> {
    pub fn new(program: &'a XeresProgram) -> Self {
        Interp { program }
    }

    /// Call a server (or shared) fn by name with positional args.
    pub fn call(&self, fn_name: &str, args: Vec<Value>) -> Result<Value, String> {
        if fn_name == "uid" {
            return Ok(Value::Str(uid()));
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
        self.exec_block(&f.body, &mut env, f.return_type.as_deref())
    }

    fn exec_block(
        &self,
        stmts: &[Stmt],
        env: &mut HashMap<String, Value>,
        ret_model: Option<&str>,
    ) -> Result<Value, String> {
        for s in stmts {
            match s {
                Stmt::Let { name, value } => {
                    let v = self.eval(value, env)?;
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
                    // `return db.query_one|query(...)` maps rows onto ret_model
                    if let Expr::MethodCall { receiver, method, args } = e {
                        if is_db(receiver) {
                            return self.db_query(method, args, env, ret_model);
                        }
                    }
                    return self.eval(e, env);
                }
                // try/catch is browser-only (checker R16); harmless if present.
                Stmt::Try { body, .. } => {
                    return self.exec_block(body, env, ret_model);
                }
            }
        }
        Ok(Value::Null)
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
            Expr::Field { base, field } => match self.eval(base, env)? {
                Value::Record(_, fs) => fs
                    .iter()
                    .find(|(k, _)| k == field)
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| format!("no field `{}`", field)),
                _ => Err(format!("`.{}` on a non-record value", field)),
            },
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
            Expr::MethodCall { receiver, method, args } => {
                if is_db(receiver) && method == "exec" {
                    return self.db_exec(args, env);
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
        let model_name = match method {
            "query" => ret_model.and_then(|t| generic_inner("List", t)),
            _ => ret_model,
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
            out.into_iter().next().ok_or_else(|| "query_one: no rows".into())
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
        "Int" => row.try_get::<_, i64>(col).map(Value::Int).unwrap_or(Value::Null),
        "Float" => row.try_get::<_, f64>(col).map(Value::Float).unwrap_or(Value::Null),
        "Bool" => row.try_get::<_, bool>(col).map(Value::Bool).unwrap_or(Value::Null),
        _ => row.try_get::<_, String>(col).map(Value::Str).unwrap_or(Value::Null),
    }
}
