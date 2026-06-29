// src/json.rs
//
// A tiny, dependency-free JSON value + parser, plus a type-guided decoder into
// the interpreter's `Value`. Shared by the in-process server (`serve.rs`, for
// RPC args / inbound `api` bodies / sync) and the interpreter (`interp.rs`, for
// typed `endpoint` responses — spec 24). Previously this lived privately in
// serve.rs; sharing it lets `xeres serve` decode an `endpoint.get(...) -> Model`
// response the same way the ejected server does (the codegen half is
// `decode_json_rust`).

use crate::frontend::parser::XeresProgram;
use crate::interp::{json_str, Value};

/// Inner type of a one-level generic, e.g. `("List", "List<User>") -> "User"`.
pub fn generic_inner<'a>(base: &str, ty: &'a str) -> Option<&'a str> {
    ty.strip_prefix(base)
        .and_then(|r| r.strip_prefix('<'))
        .and_then(|r| r.strip_suffix('>'))
}

// ---- minimal JSON value + parser ----

pub enum J {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn get(&self, k: &str) -> Option<&J> {
        if let J::Obj(v) = self {
            v.iter().find(|(kk, _)| kk == k).map(|(_, vv)| vv)
        } else {
            None
        }
    }
    pub fn idx(&self, i: usize) -> Option<&J> {
        if let J::Arr(v) = self {
            v.get(i)
        } else {
            None
        }
    }
    pub fn str(&self) -> Option<&str> {
        if let J::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_string(&self) -> String {
        self.str().unwrap_or("").to_string()
    }
    pub fn as_f64(&self) -> f64 {
        if let J::Num(n) = self {
            *n
        } else {
            0.0
        }
    }
    pub fn as_i64(&self) -> i64 {
        self.as_f64() as i64
    }
    pub fn as_bool(&self) -> bool {
        matches!(self, J::Bool(true))
    }
    pub fn to_json(&self) -> String {
        match self {
            J::Null => "null".into(),
            J::Bool(b) => b.to_string(),
            J::Num(n) => {
                if n.fract() == 0.0 {
                    (*n as i64).to_string()
                } else {
                    n.to_string()
                }
            }
            J::Str(s) => json_str(s),
            J::Arr(a) => format!("[{}]", a.iter().map(|x| x.to_json()).collect::<Vec<_>>().join(",")),
            J::Obj(o) => format!(
                "{{{}}}",
                o.iter().map(|(k, v)| format!("{}:{}", json_str(k), v.to_json())).collect::<Vec<_>>().join(",")
            ),
        }
    }
}

pub fn jparse(s: &str) -> J {
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    jval(&b, &mut i)
}

fn jws(b: &[char], i: &mut usize) {
    while *i < b.len() && b[*i].is_whitespace() {
        *i += 1;
    }
}

fn jstr(b: &[char], i: &mut usize) -> String {
    if *i < b.len() && b[*i] == '"' {
        *i += 1;
    }
    let mut s = String::new();
    while *i < b.len() && b[*i] != '"' {
        if b[*i] == '\\' && *i + 1 < b.len() {
            *i += 1;
            match b[*i] {
                'n' => s.push('\n'),
                't' => s.push('\t'),
                'r' => s.push('\r'),
                c => s.push(c),
            }
        } else {
            s.push(b[*i]);
        }
        *i += 1;
    }
    if *i < b.len() {
        *i += 1;
    }
    s
}

fn jval(b: &[char], i: &mut usize) -> J {
    jws(b, i);
    if *i >= b.len() {
        return J::Null;
    }
    match b[*i] {
        '{' => {
            *i += 1;
            let mut o = Vec::new();
            loop {
                jws(b, i);
                if *i >= b.len() || b[*i] == '}' {
                    if *i < b.len() {
                        *i += 1;
                    }
                    break;
                }
                let k = jstr(b, i);
                jws(b, i);
                if *i < b.len() && b[*i] == ':' {
                    *i += 1;
                }
                o.push((k, jval(b, i)));
                jws(b, i);
                if *i < b.len() && b[*i] == ',' {
                    *i += 1;
                }
            }
            J::Obj(o)
        }
        '[' => {
            *i += 1;
            let mut a = Vec::new();
            loop {
                jws(b, i);
                if *i >= b.len() || b[*i] == ']' {
                    if *i < b.len() {
                        *i += 1;
                    }
                    break;
                }
                a.push(jval(b, i));
                jws(b, i);
                if *i < b.len() && b[*i] == ',' {
                    *i += 1;
                }
            }
            J::Arr(a)
        }
        '"' => J::Str(jstr(b, i)),
        't' => {
            *i += 4;
            J::Bool(true)
        }
        'f' => {
            *i += 5;
            J::Bool(false)
        }
        'n' => {
            *i += 4;
            J::Null
        }
        _ => {
            let st = *i;
            while *i < b.len()
                && (b[*i].is_ascii_digit() || b[*i] == '-' || b[*i] == '+' || b[*i] == '.' || b[*i] == 'e' || b[*i] == 'E')
            {
                *i += 1;
            }
            if *i == st {
                *i += 1;
                return J::Null;
            }
            let s: String = b[st..*i].iter().collect();
            J::Num(s.parse().unwrap_or(0.0))
        }
    }
}

/// Decode a parsed JSON value into a runtime `Value`, guided by the declared
/// type. Handles scalars, models, `List<T>`, `Optional<T>`, and any nesting —
/// the interpreter half of full-grammar RPC args, inbound `api` bodies, and
/// typed `endpoint` responses. A `secret` model field simply never appears in
/// the source JSON, so a missing field defaults.
pub fn decode(j: Option<&J>, ty: &str, program: &XeresProgram) -> Value {
    if let Some(inner) = generic_inner("List", ty) {
        return match j {
            Some(J::Arr(items)) => {
                Value::List(items.iter().map(|e| decode(Some(e), inner, program)).collect())
            }
            _ => Value::List(Vec::new()),
        };
    }
    if let Some(inner) = generic_inner("Optional", ty) {
        return match j {
            None | Some(J::Null) => Value::Null,
            Some(v) => decode(Some(v), inner, program),
        };
    }
    let j = match j {
        Some(j) => j,
        None => return Value::Null,
    };
    match ty {
        "String" | "Decimal" => Value::Str(j.as_string()),
        "Int" | "DateTime" => Value::Int(j.as_i64()),
        "Float" => Value::Float(j.as_f64()),
        "Bool" => Value::Bool(j.as_bool()),
        _ if program.enums.iter().any(|e| e.name == ty) => Value::Str(j.as_string()),
        _ => {
            if let Some(model) = program.models.iter().find(|m| m.name == ty) {
                let fields = model
                    .properties
                    .iter()
                    .map(|p| (p.name.clone(), decode(j.get(&p.name), &p.data_type, program)))
                    .collect();
                Value::Record(ty.to_string(), fields)
            } else {
                Value::Null
            }
        }
    }
}
