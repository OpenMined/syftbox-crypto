use crate::error::Result;
use crate::{
    SyftRecoveryKey,
    did_utils::generate_did_web_id_default,
    serialization::{serialize_private_keys, serialize_to_did_document, zeroize_json_value},
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub struct IdentityMaterial {
    pub fingerprint: String,
    pub did: String,
    pub recovery_key_hex: Zeroizing<String>,
    pub recovery_key_mnemonic: Zeroizing<String>,
    pub key_file: Vec<u8>,
    pub public_bundle: Value,
}

pub fn generate_identity_material(identity: &str) -> Result<IdentityMaterial> {
    let recovery_key = SyftRecoveryKey::generate();
    build_identity_material(identity, &recovery_key)
}

/// Build deterministic identity material from an existing recovery key (e.g., restored via mnemonic).
pub fn identity_material_from_recovery_key(
    identity: &str,
    recovery_key: &SyftRecoveryKey,
) -> Result<IdentityMaterial> {
    build_identity_material(identity, recovery_key)
}

fn build_identity_material(
    identity: &str,
    recovery_key: &SyftRecoveryKey,
) -> Result<IdentityMaterial> {
    let recovery_key_hex = Zeroizing::new(recovery_key.to_hex_string());
    let recovery_key_mnemonic = Zeroizing::new(recovery_key.to_mnemonic());

    let private_keys = recovery_key.derive_keys()?;
    let jwks = serialize_private_keys(&private_keys)?;

    let mut rng = rand::rng();
    let public_bundle = private_keys.to_public_bundle(&mut rng)?;
    let fingerprint = public_bundle.identity_fingerprint();
    let did = generate_did_web_id_default(identity);
    let mut did_document = serialize_to_did_document(&public_bundle, &did)?;
    if let Some(map) = did_document.as_object_mut() {
        map.insert("identity".into(), Value::String(identity.to_string()));
        map.insert(
            "identity_fingerprint".into(),
            Value::String(fingerprint.clone()),
        );
    }

    let mut key_doc = json!({
        "format": "syft-private-keys-v1",
        "identity": identity,
        "identity_fingerprint": fingerprint,
        "did": did,
        "private_keys": jwks,
    });
    let mut key_file = serde_json::to_vec_pretty(&key_doc)?;
    key_file.push(b'\n');
    zeroize_json_value(&mut key_doc);

    Ok(IdentityMaterial {
        fingerprint,
        did,
        recovery_key_hex,
        recovery_key_mnemonic,
        key_file,
        public_bundle: did_document,
    })
}
