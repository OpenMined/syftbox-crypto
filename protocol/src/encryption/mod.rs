//! Multi-recipient file encryption using X3DH key agreement and XChaCha20-Poly1305.
//!
//! This module provides end-to-end encrypted file sharing with:
//! - **X3DH key agreement**: X25519-based key agreement with fresh ephemerals
//! - **Multi-recipient support**: Encrypt once, wrap the key N times for N recipients
//! - **XChaCha20-Poly1305 AEAD**: recommended attachment cipher
//! - **Forward secrecy**: Fresh ephemeral keys for each encryption

mod constant_time;
mod file_cipher;
mod key_wrap;
mod x3dh;

use crate::envelope::{
    EnvelopePayload, ParsedEnvelope, build_envelope_with_wrappings, verify_signature,
};
use crate::keys::{SyftPrivateKeys, SyftPublicKeyBundle};
use crate::{Result, error::KeyError};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

// Re-export public constants
pub use file_cipher::FILE_CIPHER_SUITE;

// Import private functions from submodules
use constant_time::ct_identity_match;
use file_cipher::encrypt_payload;
use key_wrap::{WRAPPED_KEY_SIZE, unwrap_file_key, wrap_file_key};
use x3dh::{derive_recipient_shared_material, derive_sender_shared_material};

/// Additional authenticated data for file decryption
const FILE_AAD: &[u8] = b"sbc-file-v1";

/// Recipient metadata required to encrypt a payload.
pub struct EncryptionRecipient<'a> {
    pub identity: &'a str,
    pub bundle: &'a SyftPublicKeyBundle,
}

/// Encrypt plaintext bytes for the provided recipients, returning a fully formed SBC envelope.
///
/// Supports multiple recipients - the file is encrypted once with a random key, then that key
/// is wrapped separately for each recipient using X3DH-derived material.
pub fn encrypt_message<R: CryptoRng + RngCore>(
    sender_identity: &str,
    sender_keys: &SyftPrivateKeys,
    recipients: &[EncryptionRecipient<'_>],
    plaintext: &[u8],
    filename_hint: Option<&str>,
    rng: &mut R,
) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err("at least one recipient is required".into());
    }

    let sender_public_bundle = sender_keys.to_public_bundle(rng)?;

    // Generate a random file encryption key
    let file_key = Zeroizing::new({
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        key
    });

    // Encrypt the file / the payload once with the generated random key
    let mut file_nonce = Zeroizing::new([0u8; 24]);
    rng.fill_bytes(file_nonce.as_mut());
    let nonce_b64 = URL_SAFE_NO_PAD.encode(file_nonce.as_ref());
    let ciphertext = encrypt_payload(&file_key, &file_nonce, plaintext)?;

    // Wrap file key for each recipient (Key Encapsulation Mechanism)
    let mut recipient_vec = Vec::with_capacity(recipients.len());
    let mut wrappings = Vec::with_capacity(recipients.len());

    for recipient in recipients {
        let (x3dh_material, mut wrapping_info) =
            derive_sender_shared_material(sender_keys, recipient.identity, recipient.bundle, rng)?;

        // Wrap the file key using X3DH material
        let wrapped_key = wrap_file_key(x3dh_material.as_ref(), &file_key, rng)?;

        // Store wrapped key bytes as the wrapping ciphertext
        wrapping_info.wrap_ciphertext = URL_SAFE_NO_PAD.encode(&wrapped_key);

        recipient_vec.push((recipient.identity.to_string(), recipient.bundle.clone()));
        wrappings.push(wrapping_info);
    }

    let payload = EnvelopePayload {
        ciphertext: &ciphertext,
        filename_hint,
        cipher_suite: FILE_CIPHER_SUITE,
        cipher_nonce_b64: &nonce_b64,
    };

    build_envelope_with_wrappings(
        sender_identity,
        sender_keys.identity(),
        &sender_public_bundle,
        &recipient_vec,
        &wrappings,
        &payload,
        rng,
    )
}

/// Decrypt an envelope for the active recipient.
pub fn decrypt_message(
    recipient_identity: &str,
    recipient_keys: &SyftPrivateKeys,
    sender_bundle: &SyftPublicKeyBundle,
    parsed: &ParsedEnvelope,
) -> Result<Vec<u8>> {
    let signature_valid = sender_bundle.verify_signatures();
    let envelope_signature_valid =
        verify_signature(parsed, &sender_bundle.identity_signing_public_key).is_ok();
    let expected_fp = sender_bundle.identity_fingerprint();
    let fingerprint_match = expected_fp
        .as_bytes()
        .ct_eq(parsed.prelude.sender.ik_fingerprint.as_bytes())
        .unwrap_u8();
    let combined = Choice::from(signature_valid as u8)
        & Choice::from(envelope_signature_valid as u8)
        & Choice::from(fingerprint_match);
    if combined.ct_eq(&Choice::from(1)).unwrap_u8() != 1 {
        return Err(KeyError::InvalidSignature);
    }

    if parsed.prelude.cipher.suite != FILE_CIPHER_SUITE {
        return Err(KeyError::InvalidFormat);
    }

    let mut recipient_index = 0usize;
    let mut match_choice = Choice::from(0);
    for (idx, info) in parsed.prelude.recipients.iter().enumerate() {
        let eq = ct_identity_match(info.identity.as_deref(), recipient_identity);
        let eq_mask = usize::from(eq.unwrap_u8());
        recipient_index = eq_mask * idx + (1 - eq_mask) * recipient_index;
        match_choice |= eq;
    }
    if match_choice.unwrap_u8() == 0 {
        return Err(KeyError::RecipientNotFound);
    }

    let wrapping = parsed
        .prelude
        .wrappings
        .get(recipient_index)
        .ok_or(KeyError::InvalidSignature)?;

    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(&parsed.prelude.cipher.nonce)
        .map_err(|_| KeyError::InvalidFormat)?;
    if nonce_bytes.len() != 24 {
        return Err(KeyError::InvalidFormat);
    }
    let mut nonce = Zeroizing::new([0u8; 24]);
    nonce.copy_from_slice(&nonce_bytes);

    // Decode wrapping ciphertext: wrapped_key (72 bytes)
    let wrapped_file_key = URL_SAFE_NO_PAD
        .decode(&wrapping.wrap_ciphertext)
        .map_err(|_| KeyError::InvalidFormat)?;

    if wrapped_file_key.len() != WRAPPED_KEY_SIZE {
        return Err(KeyError::InvalidFormat);
    }

    // Derive X3DH shared material
    let x3dh_material = derive_recipient_shared_material(recipient_keys, sender_bundle, wrapping)?;

    // Unwrap file key using X3DH material
    let file_key = unwrap_file_key(x3dh_material.as_ref(), &wrapped_file_key)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*file_key));
    cipher
        .decrypt(
            XNonce::from_slice(&*nonce),
            Payload {
                msg: &parsed.ciphertext,
                aad: FILE_AAD,
            },
        )
        .map_err(|_| KeyError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
