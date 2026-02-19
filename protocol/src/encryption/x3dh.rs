//! X3DH key agreement protocol.

use crate::envelope::WrappingInfo;
use crate::keys::{SyftPrivateKeys, SyftPublicKeyBundle};
use crate::{Result, error::KeyError};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{CryptoRng, RngCore};
use rand_core::{CryptoRng as RandCoreCryptoRng, RngCore as RandCoreRngCore};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Serialized X25519 public keys are 32 bytes.
const X25519_PUBLIC_KEY_LEN: usize = 32;

struct RandCoreAdapter<'a, R>(&'a mut R);

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, &b| acc | b) == 0
}

impl<'a, R: RngCore + CryptoRng> RandCoreRngCore for RandCoreAdapter<'a, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<'a, R: RngCore + CryptoRng> RandCoreCryptoRng for RandCoreAdapter<'a, R> {}

/// Performs sender-side X3DH key agreement.
///
/// Establishes shared secret material by combining X25519 DH operations. The sender (Alice)
/// computes:
///
/// - DH1 = DH(IK_A_priv, SPK_B_pub)
/// - DH2 = DH(EK_A_priv, IK_B_pub)  [fresh ephemeral key for forward secrecy]
/// - DH3 = DH(EK_A_priv, SPK_B_pub)
/// - X3DH_material = DH1 || DH2 || DH3
///
/// Where:
/// - IK = Identity DH Key, SPK = Signed PreKey, EK = Ephemeral Key
/// - A = sender (Alice), B = recipient (Bob)
///
/// Returns X3DH material and wrapping metadata (EK_A_pub) for the recipient.
///
/// # Errors
/// - `KeyError::InvalidSignature` if recipient bundle signature verification fails
pub(super) fn derive_sender_shared_material<R: CryptoRng + RngCore>(
    sender_keys: &SyftPrivateKeys,
    recipient_identity: &str,
    recipient_bundle: &SyftPublicKeyBundle,
    rng: &mut R,
) -> Result<(Zeroizing<Vec<u8>>, WrappingInfo)> {
    if !recipient_bundle.verify_signatures() {
        return Err(KeyError::InvalidSignature);
    }

    let mut adapter = RandCoreAdapter(rng);
    let ephemeral = StaticSecret::random_from_rng(&mut adapter);
    let ephemeral_public = X25519PublicKey::from(&ephemeral);

    let dh1 = Zeroizing::new(
        sender_keys
            .identity_dh()
            .diffie_hellman(&recipient_bundle.signed_prekey_public_key)
            .to_bytes(),
    );
    if is_all_zero(dh1.as_ref()) {
        return Err(KeyError::InvalidSharedSecret);
    }
    let dh2 = Zeroizing::new(
        ephemeral
            .diffie_hellman(&recipient_bundle.identity_dh_public_key)
            .to_bytes(),
    );
    if is_all_zero(dh2.as_ref()) {
        return Err(KeyError::InvalidSharedSecret);
    }
    let dh3 = Zeroizing::new(
        ephemeral
            .diffie_hellman(&recipient_bundle.signed_prekey_public_key)
            .to_bytes(),
    );
    if is_all_zero(dh3.as_ref()) {
        return Err(KeyError::InvalidSharedSecret);
    }

    let mut material = Zeroizing::new(Vec::with_capacity(dh1.len() + dh2.len() + dh3.len()));
    material.extend_from_slice(dh1.as_ref());
    material.extend_from_slice(dh2.as_ref());
    material.extend_from_slice(dh3.as_ref());

    let wrapping = WrappingInfo {
        recipient_identity: Some(recipient_identity.to_owned()),
        device_label: Some("default".into()),
        wrap_ephemeral_public: URL_SAFE_NO_PAD.encode(ephemeral_public.as_bytes()),
        wrap_ciphertext: String::new(),
    };

    Ok((material, wrapping))
}

/// Performs recipient-side X3DH key agreement.
///
/// Derives the same shared secret material as the sender by performing the same DH operations
/// from the recipient's perspective. The recipient (Bob) computes:
///
/// - DH1 = DH(SPK_B_priv, IK_A_pub)
/// - DH2 = DH(IK_B_priv, EK_A_pub)  [EK_A_pub received from sender]
/// - DH3 = DH(SPK_B_priv, EK_A_pub)
/// - X3DH_material = DH1 || DH2 || DH3
///
/// Where:
/// - IK = Identity DH Key, SPK = Signed PreKey, EK = Ephemeral Key
/// - A = sender (Alice), B = recipient (Bob)
///
/// Returns the same X3DH material computed by the sender.
///
/// # Errors
/// - `KeyError::InvalidFormat` if ephemeral key is malformed
pub(super) fn derive_recipient_shared_material(
    recipient_keys: &SyftPrivateKeys,
    sender_bundle: &SyftPublicKeyBundle,
    wrapping: &WrappingInfo,
) -> Result<Zeroizing<Vec<u8>>> {
    if !sender_bundle.verify_signatures() {
        return Err(KeyError::InvalidSignature);
    }
    let ephemeral_bytes = URL_SAFE_NO_PAD
        .decode(&wrapping.wrap_ephemeral_public)
        .map_err(|_| KeyError::InvalidFormat)?;
    if ephemeral_bytes.len() != X25519_PUBLIC_KEY_LEN {
        return Err(KeyError::InvalidFormat);
    }
    let mut ephemeral_key = Zeroizing::new([0u8; X25519_PUBLIC_KEY_LEN]);
    ephemeral_key.copy_from_slice(&ephemeral_bytes);
    let ephemeral_public = X25519PublicKey::from(*ephemeral_key);

    let dh1 = Zeroizing::new(
        recipient_keys
            .signed_pre_key()
            .diffie_hellman(&sender_bundle.identity_dh_public_key)
            .to_bytes(),
    );
    if is_all_zero(dh1.as_ref()) {
        return Err(KeyError::InvalidSharedSecret);
    }
    let dh2 = Zeroizing::new(
        recipient_keys
            .identity_dh()
            .diffie_hellman(&ephemeral_public)
            .to_bytes(),
    );
    if is_all_zero(dh2.as_ref()) {
        return Err(KeyError::InvalidSharedSecret);
    }
    let dh3 = Zeroizing::new(
        recipient_keys
            .signed_pre_key()
            .diffie_hellman(&ephemeral_public)
            .to_bytes(),
    );
    if is_all_zero(dh3.as_ref()) {
        return Err(KeyError::InvalidSharedSecret);
    }

    let mut material = Zeroizing::new(Vec::with_capacity(dh1.len() + dh2.len() + dh3.len()));
    material.extend_from_slice(dh1.as_ref());
    material.extend_from_slice(dh2.as_ref());
    material.extend_from_slice(dh3.as_ref());
    Ok(material)
}
