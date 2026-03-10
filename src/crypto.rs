//
//  heimdall
//  src/crypto.rs
//
//  Created by Ngonidzashe Mangudya on 2026/03/09.
//  Copyright (c) 2026 Codecraft Solutions ZA. All rights reserved.
//  SPDX-License-Identifier: LicenseRef-Heimdall-FSL
//

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

/// Encrypt plaintext with AES-256-GCM.
/// Returns base64-encoded `nonce(12 bytes) || ciphertext || tag(16 bytes)`.
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<String> {
    use aes_gcm::AeadCore;
    use aes_gcm::aead::OsRng;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("Invalid key: {e}"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(&combined))
}

/// Decrypt a base64-encoded ciphertext produced by `encrypt()`.
pub fn decrypt(encoded: &str, key: &[u8; 32]) -> Result<Vec<u8>> {
    let combined = BASE64.decode(encoded).context("Invalid base64")?;
    if combined.len() < 12 {
        bail!("Ciphertext too short");
    }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("Invalid key: {e}"))?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))
}

/// Decode a stored secret value.
///
/// Values are stored in one of three forms:
/// - AES-256-GCM encrypted base64 when `ENCRYPTION_KEY` is configured
/// - hex-encoded plaintext as a compatibility fallback
/// - raw plaintext in older/local development setups
pub fn decode_stored_secret(encoded: &str, key: Option<&[u8; 32]>) -> Result<String> {
    if let Some(key) = key {
        if let Ok(bytes) = decrypt(encoded, key) {
            return String::from_utf8(bytes).context("Stored secret was not valid UTF-8");
        }
    }

    if let Ok(bytes) = hex::decode(encoded) {
        return String::from_utf8(bytes).context("Hex-decoded secret was not valid UTF-8");
    }

    if key.is_none() {
        return Ok(encoded.to_string());
    }

    bail!("Stored secret could not be decrypted or decoded")
}

/// Parse a 64-char hex string into a 32-byte key.
pub fn parse_hex_key(hex_key: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_key).context("Invalid hex key")?;
    if bytes.len() != 32 {
        bail!(
            "Encryption key must be exactly 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        );
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let key = [0xABu8; 32];
        let plaintext = b"sk-ant-api03-secret-key-here";
        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn parse_hex_key_valid() {
        let hex_str = "aa".repeat(32);
        let key = parse_hex_key(&hex_str).unwrap();
        assert_eq!(key, [0xAAu8; 32]);
    }

    #[test]
    fn parse_hex_key_wrong_length() {
        let hex_str = "aa".repeat(16);
        assert!(parse_hex_key(&hex_str).is_err());
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = [0xABu8; 32];
        let key2 = [0xCDu8; 32];
        let encrypted = encrypt(b"secret", &key1).unwrap();
        assert!(decrypt(&encrypted, &key2).is_err());
    }

    #[test]
    fn different_ciphertexts_for_same_plaintext() {
        let key = [0xABu8; 32];
        let plaintext = b"same text";
        let enc1 = encrypt(plaintext, &key).unwrap();
        let enc2 = encrypt(plaintext, &key).unwrap();
        assert_ne!(enc1, enc2); // Different nonces produce different ciphertexts
    }

    #[test]
    fn parse_hex_key_all_zeros() {
        let hex = "00".repeat(32);
        let key = parse_hex_key(&hex).unwrap();
        assert_eq!(key, [0u8; 32]);
    }

    #[test]
    fn parse_hex_key_invalid_hex_chars() {
        assert!(parse_hex_key("zz".repeat(32).as_str()).is_err());
    }

    #[test]
    fn decrypt_invalid_base64() {
        let key = [0xABu8; 32];
        assert!(decrypt("not-valid-base64!!!", &key).is_err());
    }

    #[test]
    fn decrypt_ciphertext_too_short() {
        let key = [0xABu8; 32];
        // Base64 of less than 12 bytes
        let short = BASE64.encode(&[0u8; 5]);
        assert!(decrypt(&short, &key).is_err());
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        let key = [0xABu8; 32];
        let encrypted = encrypt(b"", &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn roundtrip_large_plaintext() {
        let key = [0xABu8; 32];
        let plaintext = vec![0x42u8; 10_000];
        let encrypted = encrypt(&plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decode_stored_secret_supports_hex_fallback() {
        let encoded = hex::encode("secret-token");
        assert_eq!(
            decode_stored_secret(&encoded, None).unwrap(),
            "secret-token"
        );
    }

    #[test]
    fn decode_stored_secret_supports_plaintext_without_key() {
        assert_eq!(
            decode_stored_secret("raw-dev-token", None).unwrap(),
            "raw-dev-token"
        );
    }

    #[test]
    fn decode_stored_secret_supports_encrypted_values() {
        let key = [0xABu8; 32];
        let encrypted = encrypt(b"secret-token", &key).unwrap();
        assert_eq!(
            decode_stored_secret(&encrypted, Some(&key)).unwrap(),
            "secret-token"
        );
    }
}
