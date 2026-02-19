//! Serialization for cryptographic keys
//!
//! This module handles serialization and deserialization of keys in two formats:
//! - **DID Document**: W3C-compliant JSON format for public keys (published to network)
//! - **JWKS**: JSON Web Key Set format for private keys (stored locally)
//!
//! # DID Document Format
//! Public keys are serialized according to W3C DID specification with JWK encoding:
//! - Identity signing key in `verificationMethod` (Ed25519)
//! - Encryption keys in `keyAgreement` (X25519 identity DH + signed prekey)
//! - Base64url encoding (RFC 7515, no padding)
//!
//! # JWKS Format
//! Private keys are stored in a flat JSON structure:
//! - `identity_key`: Ed25519 keypair
//! - `identity_dh`: X25519 identity DH keypair
//! - `signed_prekey`: X25519 signed prekey keypair

use crate::error::{SerializationError, SerializationResult};
use crate::keys::{SyftPrivateKeys, SyftPublicKeyBundle};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{Value, json};
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::{Zeroize, Zeroizing};

/// Serialize public key bundle to W3C DID document format.
///
/// Creates a DID document with:
/// - `@context`: W3C DID and security suite contexts
/// - `verificationMethod`: Identity signing key (Ed25519)
/// - `keyAgreement`: Identity DH key + signed prekey (X25519)
///
/// # Arguments
/// * `bundle` - Public key bundle to serialize
/// * `did_id` - DID identifier (e.g., "did:web:syftbox.net:alice%40example.com")
///
/// # Example
/// ```
/// use syftbox_crypto_protocol::SyftRecoveryKey;
/// use syftbox_crypto_protocol::serialization::serialize_to_did_document;
///
/// let recovery_key = SyftRecoveryKey::generate();
/// let private_keys = recovery_key.derive_keys().unwrap();
/// let bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();
/// let did_doc = serialize_to_did_document(&bundle, "did:web:example.com:alice").unwrap();
/// ```
pub fn serialize_to_did_document(
    bundle: &SyftPublicKeyBundle,
    did_id: &str,
) -> SerializationResult<Value> {
    let controller = did_id;

    Ok(json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/security/suites/x25519-2020/v1"
        ],
        "id": did_id,
        "verificationMethod": [{
            "id": format!("{}#identity-key", did_id),
            "type": "Ed25519VerificationKey2020",
            "controller": controller,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(bundle.identity_signing_public_key.as_bytes()),
                "kid": "identity-key",
                "use": "sig"
            }
        }],
        "keyAgreement": [
            {
                "id": format!("{}#identity-dh", did_id),
                "type": "X25519KeyAgreementKey2020",
                "controller": controller,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": URL_SAFE_NO_PAD.encode(bundle.identity_dh_public_key.as_bytes()),
                    "kid": "identity-dh",
                    "use": "enc",
                    "signature": URL_SAFE_NO_PAD.encode(&bundle.identity_dh_signature)
                }
            },
            {
                "id": format!("{}#signed-prekey", did_id),
                "type": "X25519KeyAgreementKey2020",
                "controller": controller,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": URL_SAFE_NO_PAD.encode(bundle.signed_prekey_public_key.as_bytes()),
                    "kid": "signed-prekey",
                    "use": "enc",
                    "signature": URL_SAFE_NO_PAD.encode(&bundle.signed_prekey_signature)
                }
            }
        ]
    }))
}

/// Deserialize public key bundle from DID document.
///
/// Parses a W3C DID document and extracts:
/// - Identity signing key from `verificationMethod`
/// - Identity DH key from `keyAgreement`
/// - Signed prekey from `keyAgreement`
///
/// # Arguments
/// * `json` - DID document as JSON value
///
/// # Returns
/// * `Ok(SyftPublicKeyBundle)` if parsing succeeds and signatures are valid
/// * `Err(SerializationError)` if format is invalid or signatures don't verify
pub fn deserialize_from_did_document(json: &Value) -> SerializationResult<SyftPublicKeyBundle> {
    // Helper to decode base64url
    fn decode_base64url(s: &str) -> SerializationResult<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| SerializationError::InvalidBase64(e.to_string()))
    }

    fn decode_fixed<const N: usize>(s: &str) -> SerializationResult<[u8; N]> {
        let bytes = decode_base64url(s)?;
        if bytes.len() != N {
            return Err(SerializationError::InvalidFormat);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    // Extract identity key from verificationMethod
    let verification_methods = json["verificationMethod"]
        .as_array()
        .ok_or(SerializationError::InvalidFormat)?;

    let identity_method = verification_methods
        .iter()
        .find(|m| m["type"] == "Ed25519VerificationKey2020")
        .ok_or(SerializationError::MissingIdentityKey)?;

    let identity_key_bytes = decode_fixed::<32>(
        identity_method["publicKeyJwk"]["x"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?;
    let identity_key = VerifyingKey::from_bytes(&identity_key_bytes)
        .map_err(|_| SerializationError::InvalidFormat)?;

    // Extract encryption keys from keyAgreement
    let key_agreement = json["keyAgreement"]
        .as_array()
        .ok_or(SerializationError::InvalidFormat)?;

    let identity_dh_method = key_agreement
        .iter()
        .find(|m| m["publicKeyJwk"]["kid"] == "identity-dh")
        .ok_or(SerializationError::MissingIdentityDhKey)?;

    let identity_dh_bytes = decode_fixed::<32>(
        identity_dh_method["publicKeyJwk"]["x"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?;
    let identity_dh_signature = decode_base64url(
        identity_dh_method["publicKeyJwk"]["signature"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?
    .into_boxed_slice();
    let identity_dh_key = X25519PublicKey::from(identity_dh_bytes);

    let spk_method = key_agreement
        .iter()
        .find(|m| m["publicKeyJwk"]["kid"] == "signed-prekey")
        .ok_or(SerializationError::MissingSignedPrekey)?;

    let spk_bytes = decode_fixed::<32>(
        spk_method["publicKeyJwk"]["x"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?;
    let spk_signature = decode_base64url(
        spk_method["publicKeyJwk"]["signature"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?
    .into_boxed_slice();

    let signed_pre_key = X25519PublicKey::from(spk_bytes);

    // Create PublicKeyBundle
    let bundle = SyftPublicKeyBundle {
        identity_signing_public_key: identity_key,
        identity_dh_public_key: identity_dh_key,
        identity_dh_signature,
        signed_prekey_public_key: signed_pre_key,
        signed_prekey_signature: spk_signature,
    };

    // Verify signatures
    if !bundle.verify_signatures() {
        return Err(SerializationError::InvalidSignature);
    }

    Ok(bundle)
}

/// Serialize private keys to JWKS format.
///
/// Creates a flat JSON structure with three keys:
/// - `identity_key`: Ed25519 keypair (public + private)
/// - `identity_dh`: X25519 keypair
/// - `signed_prekey`: X25519 keypair
///
/// All keys use base64url encoding (RFC 7515, no padding).
///
/// # Example
/// ```
/// use syftbox_crypto_protocol::SyftRecoveryKey;
/// use syftbox_crypto_protocol::serialization::serialize_private_keys;
///
/// let recovery_key = SyftRecoveryKey::generate();
/// let private_keys = recovery_key.derive_keys().unwrap();
/// let jwks = serialize_private_keys(&private_keys).unwrap();
/// ```
pub fn serialize_private_keys(keys: &SyftPrivateKeys) -> SerializationResult<Value> {
    let identity_dh_public = X25519PublicKey::from(keys.identity_dh());
    let signed_pre_key_public = X25519PublicKey::from(keys.signed_pre_key());

    Ok(json!({
        "identity_key": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(keys.identity().verifying_key().as_bytes()),
            "d": URL_SAFE_NO_PAD.encode(keys.identity().to_bytes()),
            "kid": "identity-key",
            "use": "sig"
        },
        "identity_dh": {
            "kty": "OKP",
            "crv": "X25519",
            "x": URL_SAFE_NO_PAD.encode(identity_dh_public.as_bytes()),
            "d": URL_SAFE_NO_PAD.encode(keys.identity_dh().to_bytes()),
            "kid": "identity-dh",
            "use": "enc"
        },
        "signed_prekey": {
            "kty": "OKP",
            "crv": "X25519",
            "x": URL_SAFE_NO_PAD.encode(signed_pre_key_public.as_bytes()),
            "d": URL_SAFE_NO_PAD.encode(keys.signed_pre_key().to_bytes()),
            "kid": "signed-prekey",
            "use": "enc"
        }
    }))
}

/// Deserialize private keys from JWKS format.
///
/// Parses a JWKS JSON structure and reconstructs:
/// - Identity keypair (Ed25519)
/// - Identity DH keypair (X25519)
/// - Signed prekey pair (X25519)
///
/// # Arguments
/// * `json` - JWKS document as JSON value
///
/// # Returns
/// * `Ok(SyftPrivateKeys)` if parsing succeeds
/// * `Err(SerializationError)` if format is invalid or keys cannot be reconstructed
pub fn deserialize_private_keys(json: &Value) -> SerializationResult<SyftPrivateKeys> {
    // Helper to decode base64url
    fn decode_base64url(s: &str) -> SerializationResult<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| SerializationError::InvalidBase64(e.to_string()))
    }

    fn decode_fixed<const N: usize>(s: &str) -> SerializationResult<[u8; N]> {
        let bytes = decode_base64url(s)?;
        if bytes.len() != N {
            return Err(SerializationError::InvalidFormat);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    // Extract identity key
    let identity_obj = json
        .get("identity_key")
        .ok_or(SerializationError::MissingIdentityKey)?;

    let identity_private_bytes = Zeroizing::new(decode_fixed::<32>(
        identity_obj["d"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?);

    let identity_public_bytes = decode_fixed::<32>(
        identity_obj["x"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?;

    let identity_signing_key = SigningKey::from_bytes(&identity_private_bytes);
    if identity_signing_key.verifying_key().as_bytes() != &identity_public_bytes {
        return Err(SerializationError::InvalidSignature);
    }

    // Extract identity DH key
    let identity_dh_obj = json
        .get("identity_dh")
        .ok_or(SerializationError::MissingIdentityDhKey)?;

    let identity_dh_private_bytes = Zeroizing::new(decode_fixed::<32>(
        identity_dh_obj["d"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?);

    let identity_dh_public_bytes = decode_fixed::<32>(
        identity_dh_obj["x"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?;

    let identity_dh_key = x25519_dalek::StaticSecret::from(*identity_dh_private_bytes);
    let identity_dh_public = X25519PublicKey::from(&identity_dh_key);
    if identity_dh_public.as_bytes() != &identity_dh_public_bytes {
        return Err(SerializationError::InvalidSignature);
    }

    // Extract signed prekey
    let spk_obj = json
        .get("signed_prekey")
        .ok_or(SerializationError::MissingSignedPrekey)?;

    let spk_private_bytes = Zeroizing::new(decode_fixed::<32>(
        spk_obj["d"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?);

    let spk_public_bytes = decode_fixed::<32>(
        spk_obj["x"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?;

    let signed_pre_key = x25519_dalek::StaticSecret::from(*spk_private_bytes);
    let signed_pre_key_public = X25519PublicKey::from(&signed_pre_key);
    if signed_pre_key_public.as_bytes() != &spk_public_bytes {
        return Err(SerializationError::InvalidSignature);
    }

    Ok(SyftPrivateKeys::new(
        identity_signing_key,
        identity_dh_key,
        signed_pre_key,
    ))
}

/// Recursively zeroize all string data contained within a JSON value.
pub(crate) fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
        Value::String(s) => {
            // String implements Zeroize, which uses volatile writes internally
            s.zeroize();
        }
        Value::Array(items) => {
            for item in items {
                zeroize_json_value(item);
            }
        }
        Value::Object(map) => {
            for (_key, val) in map.iter_mut() {
                zeroize_json_value(val);
            }
        }
    }
}
