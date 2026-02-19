//! Key structures for SyftBox X3DH protocol.
//!
//! This module defines the key types used in the SyftBox protocol:
//! - SyftRecoveryKey: 32-byte master secret for deterministic key derivation
//! - SyftPrivateKeys: Container for all private key material
//! - SyftPublicKeyBundle: Container for all public keys and signatures
//!
//! The Syft keys use:
//! - Ed25519 for identity signing
//! - X25519 for identity DH and signed prekeys

use crate::error::{RecoveryError, RecoveryResult};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Compute SHA-256 fingerprint of any public key bytes.
pub fn compute_key_fingerprint(key_bytes: &[u8]) -> String {
    let hash = Sha256::digest(key_bytes);
    hex::encode(hash)
}

/// Compute SHA-256 fingerprint of an identity public key.
///
/// Convenience wrapper around `compute_key_fingerprint` for identity keys specifically.
///
/// # Arguments
/// * `identity_key` - The identity public key
///
/// # Returns
/// A 64-character hex string representing the SHA-256 hash of the public key bytes
///
/// # Example
/// ```
/// use syftbox_crypto_protocol::{SyftRecoveryKey, compute_identity_fingerprint};
///
/// let recovery_key = SyftRecoveryKey::generate();
/// let private_keys = recovery_key.derive_keys().unwrap();
/// let fingerprint = compute_identity_fingerprint(&private_keys.identity().verifying_key());
/// assert_eq!(fingerprint.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
/// ```
pub fn compute_identity_fingerprint(identity_key: &VerifyingKey) -> String {
    compute_key_fingerprint(identity_key.as_bytes())
}

/// 32-byte recovery key that deterministically derives all private keys.
///
/// This is the MASTER secret that can regenerate all private keys.
/// Users must write down the 64-character hex representation for backup.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SyftRecoveryKey([u8; 32]);

impl std::fmt::Debug for SyftRecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyftRecoveryKey")
            .field(
                "first_4_bytes",
                &format!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    self.0[0], self.0[1], self.0[2], self.0[3]
                ),
            )
            .field("remaining", &"<redacted 28 bytes>")
            .finish()
    }
}

impl SyftRecoveryKey {
    /// Generate a new random recovery key with 256 bits of entropy.
    pub fn generate() -> Self {
        loop {
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key);
            if Self::has_min_entropy(&key) {
                return Self(key);
            }
        }
    }

    /// Format: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`
    /// (16 groups of 4 chars)
    pub fn to_hex_string(&self) -> String {
        let hex = hex::encode(self.0);
        hex.as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).expect("hex encoding is ASCII"))
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Parse from hex string (with or without dashes).
    ///
    /// Accepts 64 hex characters in any format (dashes and spaces are ignored).
    pub fn from_hex_string(s: &str) -> RecoveryResult<Self> {
        // Remove readability separators while rejecting unexpected characters.
        let mut cleaned = String::with_capacity(64);
        for ch in s.chars() {
            if ch.is_ascii_hexdigit() {
                cleaned.push(ch);
            } else if matches!(ch, '-' | ' ' | '\n' | '\r' | '\t') {
                continue;
            } else {
                return Err(RecoveryError::InvalidHex(format!(
                    "unexpected character '{ch}' in recovery key"
                )));
            }
        }

        if cleaned.len() != 64 {
            return Err(RecoveryError::InvalidLength {
                expected: 64,
                actual: cleaned.len(),
            });
        }

        let bytes = hex::decode(&cleaned).map_err(|e| RecoveryError::InvalidHex(e.to_string()))?;

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);

        if !Self::has_min_entropy(&key) {
            return Err(RecoveryError::InsufficientEntropy);
        }

        Ok(Self(key))
    }

    /// Convert recovery key to a BIP39 mnemonic phrase (24 words).
    pub fn to_mnemonic(&self) -> String {
        use bip39::{Language, Mnemonic};

        // BIP39 with 32 bytes = 24 words (256 bits entropy)
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &self.0)
            .expect("32 bytes should always create valid mnemonic");

        mnemonic.to_string()
    }

    /// Parse a BIP39 mnemonic phrase back into a recovery key.
    pub fn from_mnemonic(phrase: &str) -> RecoveryResult<Self> {
        use bip39::{Language, Mnemonic};

        // Normalize to lowercase and clean whitespace for BIP39 library
        let normalized = phrase
            .split_whitespace()
            .map(|word| word.to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");

        // Parse mnemonic
        let mnemonic = Mnemonic::parse_in(Language::English, &normalized)
            .map_err(|e| RecoveryError::MnemonicError(e.to_string()))?;

        // Get the entropy (should be 32 bytes for 24-word mnemonic)
        let entropy = mnemonic.to_entropy();

        if entropy.len() != 32 {
            return Err(RecoveryError::InvalidLength {
                expected: 32,
                actual: entropy.len(),
            });
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&entropy);

        // Verify minimum entropy
        if !Self::has_min_entropy(&key) {
            return Err(RecoveryError::InsufficientEntropy);
        }

        Ok(Self(key))
    }

    fn has_min_entropy(bytes: &[u8; 32]) -> bool {
        if bytes.iter().all(|&b| b == 0) {
            return false;
        }

        if bytes.windows(2).all(|w| w[0] == w[1]) {
            return false;
        }

        let mut seen = [false; 256];
        for &byte in bytes {
            seen[byte as usize] = true;
        }
        seen.iter().filter(|&&present| present).count() >= 16
    }

    /// Get raw bytes (for internal use only)
    ///
    /// # Security
    /// This should only be used internally for key derivation.
    /// Never expose these bytes to external APIs.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive all private keys from this recovery key using HKDF-SHA256.
    ///
    /// This is deterministic - the same recovery key will always produce the same keys.
    ///
    /// # Example
    /// ```
    /// use syftbox_crypto_protocol::SyftRecoveryKey;
    /// let recovery_key = SyftRecoveryKey::generate();
    /// let private_keys = recovery_key.derive_keys().expect("derivation should succeed");
    /// ```
    pub fn derive_keys(&self) -> RecoveryResult<SyftPrivateKeys> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let recovery_key_bytes = self.as_bytes();

        // HKDF instance for all key derivations
        let hk = Hkdf::<Sha256>::new(None, recovery_key_bytes);

        // 1. Derive identity signing key (Ed25519)
        let mut identity_sign_seed = Zeroizing::new([0u8; 32]);
        hk.expand(
            b"SyftBox_Identity_Signing_Key_v1",
            identity_sign_seed.as_mut(),
        )
        .map_err(|_| RecoveryError::DerivationFailed)?;
        let identity_signing_key = SigningKey::from_bytes(&identity_sign_seed);

        // 2. Derive identity DH key (X25519)
        let mut identity_dh_seed = Zeroizing::new([0u8; 32]);
        hk.expand(b"SyftBox_Identity_DH_Key_v1", identity_dh_seed.as_mut())
            .map_err(|_| RecoveryError::DerivationFailed)?;
        let identity_dh_key = StaticSecret::from(*identity_dh_seed);

        // 3. Derive signed prekey (X25519)
        let mut spk_seed = Zeroizing::new([0u8; 32]);
        hk.expand(b"SyftBox_Signed_Prekey_v1", spk_seed.as_mut())
            .map_err(|_| RecoveryError::DerivationFailed)?;
        let signed_pre_key = StaticSecret::from(*spk_seed);

        Ok(SyftPrivateKeys {
            identity_signing_key: Sensitive::new(identity_signing_key),
            identity_dh_key: Sensitive::new(identity_dh_key),
            signed_pre_key: Sensitive::new(signed_pre_key),
        })
    }
}

/// Container for all private key material needed for X3DH key agreement.
///
/// Bundles identity signing key (Ed25519), identity DH key (X25519), and signed prekey (X25519).
pub struct SyftPrivateKeys {
    /// Ed25519 identity signing key.
    identity_signing_key: Sensitive<SigningKey>,
    /// X25519 identity DH key.
    identity_dh_key: Sensitive<StaticSecret>,
    /// X25519 signed prekey.
    signed_pre_key: Sensitive<StaticSecret>,
}

impl SyftPrivateKeys {
    /// Create a new container for private key material.
    pub fn new(
        identity_signing_key: SigningKey,
        identity_dh_key: StaticSecret,
        signed_pre_key: StaticSecret,
    ) -> Self {
        Self {
            identity_signing_key: Sensitive::new(identity_signing_key),
            identity_dh_key: Sensitive::new(identity_dh_key),
            signed_pre_key: Sensitive::new(signed_pre_key),
        }
    }

    /// Borrow the identity signing key.
    pub fn identity(&self) -> &SigningKey {
        &self.identity_signing_key
    }

    /// Borrow the identity DH key.
    pub fn identity_dh(&self) -> &StaticSecret {
        &self.identity_dh_key
    }

    /// Borrow the signed prekey.
    pub fn signed_pre_key(&self) -> &StaticSecret {
        &self.signed_pre_key
    }

    /// Create public key bundle with all public keys and signatures.
    pub fn to_public_bundle<R: rand::CryptoRng + rand::Rng>(
        &self,
        _rng: &mut R,
    ) -> Result<SyftPublicKeyBundle, crate::error::KeyError> {
        SyftPublicKeyBundle::new(self.identity(), self.identity_dh(), self.signed_pre_key())
    }
}

/// Wrapper that zeroizes contained data immediately after it has been dropped.
///
/// This avoids relying on `Zeroize` implementations for external key types.
struct Sensitive<T>(ManuallyDrop<T>);

impl<T> Sensitive<T> {
    fn new(value: T) -> Self {
        Self(ManuallyDrop::new(value))
    }
}

impl<T> Deref for Sensitive<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Sensitive<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Drop for Sensitive<T> {
    fn drop(&mut self) {
        struct ZeroizeGuard {
            ptr: *mut u8,
            size: usize,
        }

        impl Drop for ZeroizeGuard {
            fn drop(&mut self) {
                unsafe {
                    for i in 0..self.size {
                        std::ptr::write_volatile(self.ptr.add(i), 0);
                    }
                    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                }
            }
        }

        let guard = ZeroizeGuard {
            ptr: (&mut self.0 as *mut ManuallyDrop<T>).cast::<u8>(),
            size: std::mem::size_of::<T>(),
        };

        unsafe { ManuallyDrop::drop(&mut self.0) };

        drop(guard);
    }
}

/// Bundle of public keys and signatures for publishing in DID documents.
#[derive(Clone)]
pub struct SyftPublicKeyBundle {
    pub identity_signing_public_key: VerifyingKey,
    pub identity_dh_public_key: X25519PublicKey,
    pub identity_dh_signature: Box<[u8]>,
    pub signed_prekey_public_key: X25519PublicKey,
    pub signed_prekey_signature: Box<[u8]>,
}

impl SyftPublicKeyBundle {
    /// Create a new public key bundle from an identity key pair and prekey pairs.
    ///
    /// This will sign both the identity DH key and the signed prekey with the identity signing key.
    pub fn new(
        identity_signing_key: &SigningKey,
        identity_dh_key: &StaticSecret,
        signed_pre_key: &StaticSecret,
    ) -> Result<Self, crate::error::KeyError> {
        let identity_public_key = identity_signing_key.verifying_key();
        let identity_dh_public_key = X25519PublicKey::from(identity_dh_key);
        let signed_pre_key_public = X25519PublicKey::from(signed_pre_key);

        let identity_dh_signature = identity_signing_key
            .sign(identity_dh_public_key.as_bytes())
            .to_bytes()
            .to_vec()
            .into_boxed_slice();

        let signed_pre_key_signature = identity_signing_key
            .sign(signed_pre_key_public.as_bytes())
            .to_bytes()
            .to_vec()
            .into_boxed_slice();

        Ok(Self {
            identity_signing_public_key: identity_public_key,
            identity_dh_public_key,
            identity_dh_signature,
            signed_prekey_public_key: signed_pre_key_public,
            signed_prekey_signature: signed_pre_key_signature,
        })
    }

    /// Verify all signatures in the bundle.
    pub fn verify_signatures(&self) -> bool {
        let identity_dh_sig = Signature::from_slice(&self.identity_dh_signature).ok();
        let signed_pre_key_sig = Signature::from_slice(&self.signed_prekey_signature).ok();

        let identity_dh_valid = identity_dh_sig.is_some_and(|sig| {
            self.identity_signing_public_key
                .verify_strict(self.identity_dh_public_key.as_bytes(), &sig)
                .is_ok()
        });

        let signed_pre_key_valid = signed_pre_key_sig.is_some_and(|sig| {
            self.identity_signing_public_key
                .verify_strict(self.signed_prekey_public_key.as_bytes(), &sig)
                .is_ok()
        });

        identity_dh_valid && signed_pre_key_valid
    }

    /// Compute and return the identity public key fingerprint.
    pub fn identity_fingerprint(&self) -> String {
        compute_identity_fingerprint(&self.identity_signing_public_key)
    }

    /// Get the total size of the bundle in bytes.
    pub fn total_size(&self) -> usize {
        self.identity_signing_public_key.as_bytes().len()
            + self.identity_dh_public_key.as_bytes().len()
            + self.identity_dh_signature.len()
            + self.signed_prekey_public_key.as_bytes().len()
            + self.signed_prekey_signature.len()
    }
}
