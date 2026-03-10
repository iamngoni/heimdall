//
//  heimdall
//  src/auth/mod.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::models::HeimdallResult;

/// Hash a plaintext password using Argon2id.
pub fn hash_password(password: &str) -> HeimdallResult<String> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored Argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> HeimdallResult<bool> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| anyhow::anyhow!("Invalid password hash format: {e}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Generate a random session token as a 64-character hex string.
///
/// Uses two UUID v7 values (which contain cryptographic randomness) to produce
/// 32 bytes of token material, encoded as hex.
pub fn generate_session_token() -> String {
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    format!("{}{}", hex::encode(a.as_bytes()), hex::encode(b.as_bytes()))
}

/// Hash a session token with SHA-256 for safe database storage.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_hash_password_different_salts() {
        let password = "same_password";
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();
        assert_ne!(hash1, hash2); // Different salts produce different hashes
        assert!(verify_password(password, &hash1).unwrap());
        assert!(verify_password(password, &hash2).unwrap());
    }

    #[test]
    fn test_generate_session_token() {
        let token1 = generate_session_token();
        let token2 = generate_session_token();
        assert_eq!(token1.len(), 64); // 2 UUID v7 hex-encoded = 32 bytes = 64 hex chars
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_hash_token_deterministic() {
        let token = "abc123";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);
        assert_eq!(hash1, hash2);
        assert_ne!(hash_token("different"), hash1);
    }

    #[test]
    fn test_hash_token_length() {
        let hash = hash_token("any_token");
        // SHA-256 produces 32 bytes = 64 hex chars
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_empty_password_hashes() {
        // Even empty strings should hash successfully
        let hash = hash_password("").unwrap();
        assert!(verify_password("", &hash).unwrap());
        assert!(!verify_password("notempty", &hash).unwrap());
    }

    #[test]
    fn test_verify_password_invalid_hash_format() {
        let result = verify_password("password", "not-a-valid-argon2-hash");
        assert!(result.is_err());
    }
}
