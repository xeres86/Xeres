thread_local! {
    static SESSION_ACTOR: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
    static SESSION_SET_COOKIE: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}
/// Set the actor recovered from a verified cookie for this request (or None).
fn session_set_actor(a: Option<String>) { SESSION_ACTOR.with(|s| *s.borrow_mut() = a); }
/// `session.actor` — the authenticated actor id for this request, or None.
fn session_actor() -> Option<String> { SESSION_ACTOR.with(|s| s.borrow().clone()) }
/// Take the Set-Cookie recorded by `session.login`/`logout` during this call.
fn session_take_cookie() -> Option<String> { SESSION_SET_COOKIE.with(|c| c.borrow_mut().take()) }
/// `session.login(id)` — mint a signed cookie; the server emits it after the call.
fn session_login(id: &str) { let c = session_set_cookie(id); SESSION_SET_COOKIE.with(|s| *s.borrow_mut() = Some(c)); }
/// `session.logout()` — clear the cookie (Max-Age=0).
fn session_logout() { let c = session_clear_cookie(); SESSION_SET_COOKIE.with(|s| *s.borrow_mut() = Some(c)); }

#[cfg(feature = "auth")]
fn session_verify(raw: &str) -> Option<String> {
    let (id, sig) = raw.rsplit_once('.')?;
    let expected = session_sign(id);
    let expected_sig = expected.rsplit_once('.')?.1.to_string();
    if session_constant_eq(expected_sig.as_bytes(), sig.as_bytes()) { Some(id.to_string()) } else { None }
}
#[cfg(feature = "auth")]
fn session_sign(id: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::digest::KeyInit;
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&session_secret())
        .expect("HMAC accepts a key of any length");
    mac.update(id.as_bytes());
    format!("{}.{}", id, session_hex(&mac.finalize().into_bytes()))
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
    // Signed HttpOnly session + a readable `xeres_auth` flag the client router uses
    // to redirect unauthenticated users off `auth` routes (R31). The flag is not a
    // secret: forging it reveals only an empty shell — data needs the real session.
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
fn session_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push_str(&format!("{:02x}", b)); }
    s
}
#[cfg(feature = "auth")]
fn session_constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) { diff |= x ^ y; }
    diff == 0
}

// Non-auth builds: no HMAC, so no real session (released binaries enable it).
#[cfg(not(feature = "auth"))]
fn session_verify(_raw: &str) -> Option<String> { None }
#[cfg(not(feature = "auth"))]
fn session_set_cookie(_id: &str) -> String { String::new() }
#[cfg(not(feature = "auth"))]
fn session_clear_cookie() -> String { String::new() }
