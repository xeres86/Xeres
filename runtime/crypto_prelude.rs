use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash, rand_core::OsRng};

/// hash() — derive a salted Argon2id password hash (a self-describing PHC string).
fn hash(s: String) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(s.as_bytes(), &salt)
        .expect("xeres: password hashing failed")
        .to_string()
}
/// verify() — check a password against a stored PHC hash (false on any mismatch).
fn verify(password: String, stored: String) -> bool {
    match PasswordHash::new(&stored) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}
