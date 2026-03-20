use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use base64::Engine;

pub fn generate_api_key() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hash_api_key(key: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(key.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

pub fn verify_api_key(key: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(key.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key_length() {
        let key = generate_api_key();
        assert!(key.len() >= 43);
    }

    #[test]
    fn test_hash_and_verify() {
        let key = generate_api_key();
        let hash = hash_api_key(&key).unwrap();
        assert!(verify_api_key(&key, &hash).unwrap());
    }

    #[test]
    fn test_verify_wrong_key() {
        let key = generate_api_key();
        let hash = hash_api_key(&key).unwrap();
        let wrong = generate_api_key();
        assert!(!verify_api_key(&wrong, &hash).unwrap());
    }
}
