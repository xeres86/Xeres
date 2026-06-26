// Egress (R26): outbound HTTP only to a declared endpoint's fixed host.
fn http_get(base: &str, path: &str, bearer: &str) -> String {
    let url = format!("{}{}", base, path);
    let mut req = ureq::get(&url);
    if !bearer.is_empty() { req = req.set("Authorization", &format!("Bearer {}", bearer)); }
    req.call().ok().and_then(|r| r.into_string().ok()).unwrap_or_default()
}
fn http_post(base: &str, path: &str, body: &str, bearer: &str) -> i64 {
    let url = format!("{}{}", base, path);
    let mut req = ureq::post(&url);
    if !bearer.is_empty() { req = req.set("Authorization", &format!("Bearer {}", bearer)); }
    match req.send_string(body) {
        Ok(r) => r.status() as i64,
        Err(ureq::Error::Status(code, _)) => code as i64,
        Err(_) => 0,
    }
}
