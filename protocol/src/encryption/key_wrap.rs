//! Key wrapping using HKDF-derived keys and XChaCha20-Poly1305.

use crate::{Result, error::KeyError};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF salt for deriving wrapping keys from X3DH material
const FILE_HKDF_SALT: &[u8] = b"sbc-crypto-core:x3dh:file";

/// HKDF info parameter for key wrapping derivation
const KEY_WRAP_INFO: &[u8] = b"sbc-wrap-key";

/// Additional authenticated data for key wrapping
const KEY_WRAP_AAD: &[u8] = b"sbc-key-wrap-v1";

/// Wrapped key format: nonce (24) + encrypted_key (32) + auth_tag (16)
pub(super) const WRAPPED_KEY_SIZE: usize = 72;

/// Derives a wrapping key from X3DH shared material and wraps the file key.
///
/// # Process
/// 1. Derive wrapping key: HKDF-SHA256(X3DH_material, salt, info)
/// 2. Generate random 24-byte nonce
/// 3. Encrypt file key with XChaCha20-Poly1305
///
/// # Returns
/// nonce (24 bytes) || wrapped_key (32 bytes plaintext + 16 bytes auth tag) = 72 bytes total
pub(super) fn wrap_file_key<R: CryptoRng + RngCore>(
    x3dh_material: &[u8],
    file_key: &[u8; 32],
    rng: &mut R,
) -> Result<Vec<u8>> {
    // Derive wrapping key from X3DH material using HKDF
    let hkdf = Hkdf::<Sha256>::new(Some(FILE_HKDF_SALT), x3dh_material);
    let mut wrapping_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(KEY_WRAP_INFO, wrapping_key.as_mut())
        .map_err(|_| KeyError::HkdfError)?;

    // Generate random nonce
    let mut nonce = Zeroizing::new([0u8; 24]);
    rng.fill_bytes(nonce.as_mut());

    // Encrypt file key with wrapping key
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*wrapping_key));
    let mut ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&*nonce),
            Payload {
                msg: file_key,
                aad: KEY_WRAP_AAD,
            },
        )
        .map_err(|_| "key wrapping failed")?;

    // Return nonce || ciphertext+tag
    let mut result = nonce.to_vec();
    result.append(&mut ciphertext);
    Ok(result) // WRAPPED_KEY_SIZE bytes
}

/// Unwraps file encryption key using X3DH shared material.
///
/// # Process
/// 1. Validate input is exactly 72 bytes
/// 2. Split nonce (24 bytes) and ciphertext (48 bytes)
/// 3. Derive same wrapping key via HKDF-SHA256
/// 4. Decrypt and authenticate with XChaCha20-Poly1305
///
/// # Input Format
/// nonce (24 bytes) || wrapped_key (48 bytes with tag)
///
/// # Errors
/// - `KeyError::InvalidFormat` if input length != 72 bytes
/// - `KeyError::InvalidSignature` if authentication fails (wrong key or tampered data)
pub(super) fn unwrap_file_key(
    x3dh_material: &[u8],
    wrapped_data: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    if wrapped_data.len() != WRAPPED_KEY_SIZE {
        return Err(KeyError::InvalidFormat);
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = wrapped_data.split_at(24);
    let mut nonce = Zeroizing::new([0u8; 24]);
    nonce.copy_from_slice(nonce_bytes);

    // Derive wrapping key from X3DH material
    let hkdf = Hkdf::<Sha256>::new(Some(FILE_HKDF_SALT), x3dh_material);
    let mut wrapping_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(KEY_WRAP_INFO, wrapping_key.as_mut())
        .map_err(|_| KeyError::HkdfError)?;

    // Decrypt file key
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*wrapping_key));
    let file_key_bytes = cipher
        .decrypt(
            XNonce::from_slice(&*nonce),
            Payload {
                msg: ciphertext,
                aad: KEY_WRAP_AAD,
            },
        )
        .map_err(|_| KeyError::InvalidSignature)?;

    let mut file_key = Zeroizing::new([0u8; 32]);
    file_key.copy_from_slice(&file_key_bytes);
    Ok(file_key)
}
