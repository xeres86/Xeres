use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::time::Duration;

// Keep-alive: idle read timeout that reaps a persistent connection holding a
// thread, plus a per-connection request cap that recycles resources.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
const MAX_REQUESTS_PER_CONN: u32 = 1024;

/// `.length()` on a String or List lowers to `.x_len()` so codegen needs no type
/// info at the call site: both `str` (char count) and `[T]` (element count)
/// implement it, and String/Vec reach them by auto-deref.
trait XLen { fn x_len(&self) -> i64; }
impl XLen for str { fn x_len(&self) -> i64 { self.chars().count() as i64 } }
impl<T> XLen for [T] { fn x_len(&self) -> i64 { self.len() as i64 } }

/// Minimal JSON string escaping (spike-grade).
fn json_str(s: &str) -> String {
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

/// The `uid()` builtin, server side (std-only). Matches the client and
/// interpreter: a hex of the wall-clock nanos. Used e.g. to mint a row id on a
/// `db.exec` insert.
fn uid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("{:x}", n)
}

/// The `now()` builtin, server side: epoch milliseconds (matches `Date.now()`).
fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// A JSON value + a recursive-descent parser (std-only). Shared by the RPC
/// router (to decode args, including model objects) and the sync endpoint.
enum J { Null, Bool(bool), Num(f64), Str(String), Arr(Vec<J>), Obj(Vec<(String, J)>) }
impl J {
    fn get(&self, k: &str) -> Option<&J> {
        if let J::Obj(v) = self { v.iter().find(|(kk, _)| kk == k).map(|(_, vv)| vv) } else { None }
    }
    fn idx(&self, i: usize) -> Option<&J> {
        if let J::Arr(v) = self { v.get(i) } else { None }
    }
    fn as_str(&self) -> Option<&str> { if let J::Str(s) = self { Some(s) } else { None } }
    fn as_f64(&self) -> Option<f64> { if let J::Num(n) = self { Some(*n) } else { None } }
    fn as_string(&self) -> String { self.as_str().unwrap_or("").to_string() }
    fn as_i64(&self) -> i64 { self.as_f64().unwrap_or(0.0) as i64 }
    fn as_bool(&self) -> bool { if let J::Bool(b) = self { *b } else { false } }
    fn to_json(&self) -> String {
        match self {
            J::Null => String::from("null"),
            J::Bool(b) => b.to_string(),
            J::Num(n) => if n.fract() == 0.0 { (*n as i64).to_string() } else { n.to_string() },
            J::Str(s) => json_str(s),
            J::Arr(a) => format!("[{}]", a.iter().map(|x| x.to_json()).collect::<Vec<_>>().join(",")),
            J::Obj(o) => format!("{{{}}}", o.iter().map(|(k, v)| format!("{}:{}", json_str(k), v.to_json())).collect::<Vec<_>>().join(",")),
        }
    }
}

fn jws(b: &[char], i: &mut usize) { while *i < b.len() && b[*i].is_whitespace() { *i += 1; } }
fn jstr(b: &[char], i: &mut usize) -> String {
    if *i < b.len() && b[*i] == '"' { *i += 1; }
    let mut s = String::new();
    while *i < b.len() && b[*i] != '"' {
        if b[*i] == '\\' && *i + 1 < b.len() {
            *i += 1;
            match b[*i] { 'n' => s.push('\n'), 't' => s.push('\t'), 'r' => s.push('\r'), c => s.push(c) }
        } else { s.push(b[*i]); }
        *i += 1;
    }
    if *i < b.len() { *i += 1; }
    s
}
fn jval(b: &[char], i: &mut usize) -> J {
    jws(b, i);
    if *i >= b.len() { return J::Null; }
    match b[*i] {
        '{' => {
            *i += 1;
            let mut o = Vec::new();
            loop {
                jws(b, i);
                if *i >= b.len() || b[*i] == '}' { if *i < b.len() { *i += 1; } break; }
                let k = jstr(b, i);
                jws(b, i);
                if *i < b.len() && b[*i] == ':' { *i += 1; }
                o.push((k, jval(b, i)));
                jws(b, i);
                if *i < b.len() && b[*i] == ',' { *i += 1; }
            }
            J::Obj(o)
        }
        '[' => {
            *i += 1;
            let mut a = Vec::new();
            loop {
                jws(b, i);
                if *i >= b.len() || b[*i] == ']' { if *i < b.len() { *i += 1; } break; }
                a.push(jval(b, i));
                jws(b, i);
                if *i < b.len() && b[*i] == ',' { *i += 1; }
            }
            J::Arr(a)
        }
        '"' => J::Str(jstr(b, i)),
        't' => { *i += 4; J::Bool(true) }
        'f' => { *i += 5; J::Bool(false) }
        'n' => { *i += 4; J::Null }
        _ => {
            let st = *i;
            while *i < b.len() && (b[*i].is_ascii_digit() || b[*i] == '-' || b[*i] == '+' || b[*i] == '.' || b[*i] == 'e' || b[*i] == 'E') { *i += 1; }
            if *i == st { *i += 1; return J::Null; }
            let s: String = b[st..*i].iter().collect();
            J::Num(s.parse().unwrap_or(0.0))
        }
    }
}
fn jparse(s: &str) -> J { let b: Vec<char> = s.chars().collect(); let mut i = 0; jval(&b, &mut i) }
