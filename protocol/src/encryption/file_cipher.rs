//! File encryption using XChaCha20-Poly1305 AEAD cipher.

use crate::Result;
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};

/// Additional authenticated data for file encryption
const FILE_AAD: &[u8] = b"sbc-file-v1";

/// File cipher suite advertised in envelope metadata.
pub const FILE_CIPHER_SUITE: &str = "xchacha20poly1305-v1";

/// Encrypts plaintext with XChaCha20-Poly1305.
///
/// Uses the recommended attachment cipher with 192-bit nonces (XChaCha20)
/// and Poly1305 authentication tags.
///
/// # Arguments
/// - `key`: 32-byte encryption key
/// - `nonce`: 24-byte nonce (must be unique per encryption)
/// - `plaintext`: Data to encrypt
///
/// # Returns
/// Ciphertext with appended 16-byte authentication tag
pub(super) fn encrypt_payload(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    // We locally reuse the XChaCha20-Poly1305 construction used for attachments so
    // callers can seal bytes without additional dependencies.
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: FILE_AAD,
            },
        )
        .map_err(|_| "file encryption failed".into())
}
