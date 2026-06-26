use std::sync::{Mutex, OnceLock};

struct Cell { value: String, lamport: u64, site: String }
struct Row { fields: std::collections::HashMap<String, Cell>, tomb: Option<(u64, String)> }
struct CollState { rows: std::collections::HashMap<String, Row>, lamport: u64 }

fn stamp_gt(al: u64, asite: &str, bl: u64, bsite: &str) -> bool {
    al > bl || (al == bl && asite > bsite)
}

fn sync_store() -> &'static Mutex<std::collections::HashMap<String, CollState>> {
    static S: OnceLock<Mutex<std::collections::HashMap<String, CollState>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn sync_dispatch(coll: &str, body: &str) -> String {
    let req = jparse(body);
    let mut guard = sync_store().lock().unwrap();
    let cs = guard.entry(coll.to_string()).or_insert_with(|| CollState { rows: std::collections::HashMap::new(), lamport: 0 });
    if let Some(J::Arr(ops)) = req.get("ops") {
        for op in ops {
            let kind = op.get("kind").and_then(|j| j.as_str()).unwrap_or("");
            let id = op.get("id").and_then(|j| j.as_str()).unwrap_or("").to_string();
            if id.is_empty() { continue; }
            let lam = op.get("lamport").and_then(|j| j.as_f64()).unwrap_or(0.0) as u64;
            let site = op.get("site").and_then(|j| j.as_str()).unwrap_or("").to_string();
            if lam > cs.lamport { cs.lamport = lam; }
            let row = cs.rows.entry(id).or_insert_with(|| Row { fields: std::collections::HashMap::new(), tomb: None });
            if kind == "set" {
                let field = op.get("field").and_then(|j| j.as_str()).unwrap_or("").to_string();
                if field.is_empty() { continue; }
                let value = op.get("value").map(|j| j.to_json()).unwrap_or_else(|| String::from("null"));
                let win = match row.fields.get(&field) { None => true, Some(c) => stamp_gt(lam, &site, c.lamport, &c.site) };
                if win { row.fields.insert(field, Cell { value, lamport: lam, site }); }
            } else if kind == "del" {
                let win = match &row.tomb { None => true, Some((l, s)) => stamp_gt(lam, &site, *l, s) };
                if win { row.tomb = Some((lam, site)); }
            }
        }
    }
    let mut out: Vec<String> = Vec::new();
    for (id, row) in cs.rows.iter() {
        let alive = match &row.tomb {
            None => !row.fields.is_empty(),
            Some((tl, ts)) => row.fields.values().any(|c| stamp_gt(c.lamport, &c.site, *tl, ts)),
        };
        if alive {
            for (f, c) in row.fields.iter() {
                out.push(format!("{{\"kind\":\"set\",\"id\":{},\"field\":{},\"value\":{},\"lamport\":{},\"site\":{}}}", json_str(id), json_str(f), c.value, c.lamport, json_str(&c.site)));
            }
        } else if let Some((tl, ts)) = &row.tomb {
            out.push(format!("{{\"kind\":\"del\",\"id\":{},\"lamport\":{},\"site\":{}}}", json_str(id), tl, json_str(ts)));
        }
    }
    out.sort();
    format!("{{\"lamport\":{},\"ops\":[{}]}}", cs.lamport, out.join(","))
}
