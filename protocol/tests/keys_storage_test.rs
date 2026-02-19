use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::fs;
use syftbox_crypto_protocol::SyftRecoveryKey;
use syftbox_crypto_protocol::did_utils::generate_did_web_id;
use syftbox_crypto_protocol::storage::{
    load_did_document, load_private_keys, save_did_document, save_private_keys,
};
use tempfile::TempDir;

#[test]
fn test_private_keys_storage_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test_keys.json");

    let recovery_key = SyftRecoveryKey::generate();
    let original_keys = recovery_key.derive_keys().unwrap();

    save_private_keys(&original_keys, &key_path).expect("save keys");
    assert!(key_path.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&key_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    let loaded_keys = load_private_keys(&key_path).expect("load keys");

    assert_eq!(
        original_keys.identity().to_bytes(),
        loaded_keys.identity().to_bytes()
    );
    assert_eq!(
        original_keys.identity_dh().to_bytes(),
        loaded_keys.identity_dh().to_bytes()
    );
    assert_eq!(
        original_keys.signed_pre_key().to_bytes(),
        loaded_keys.signed_pre_key().to_bytes()
    );
}

#[test]
fn test_did_document_storage_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let did_path = temp_dir.path().join("test_did.json");

    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key.derive_keys().unwrap();
    let original_bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();

    let did_id = generate_did_web_id("alice@example.com", "example.com");

    save_did_document(&original_bundle, &did_id, &did_path).expect("save DID document");
    assert!(did_path.exists());

    let loaded_bundle = load_did_document(&did_path).expect("load DID document");

    assert_eq!(
        original_bundle.identity_signing_public_key.as_bytes(),
        loaded_bundle.identity_signing_public_key.as_bytes()
    );
    assert_eq!(
        original_bundle.identity_dh_public_key.as_bytes(),
        loaded_bundle.identity_dh_public_key.as_bytes()
    );
    assert_eq!(
        original_bundle.signed_prekey_public_key.as_bytes(),
        loaded_bundle.signed_prekey_public_key.as_bytes()
    );
}

#[test]
fn test_load_nonexistent_file() {
    let result = load_private_keys(std::path::Path::new("/nonexistent/path/keys.json"));
    assert!(result.is_err());
}

#[test]
fn test_load_invalid_json() {
    let temp_dir = TempDir::new().unwrap();
    let invalid_path = temp_dir.path().join("invalid.json");

    fs::write(&invalid_path, "not valid json").unwrap();

    let result = load_private_keys(&invalid_path);
    assert!(result.is_err());
}

#[test]
fn test_did_document_file_format() {
    let temp_dir = TempDir::new().unwrap();
    let did_path = temp_dir.path().join("test_did_format.json");

    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key.derive_keys().unwrap();
    let bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();

    let did_id = generate_did_web_id("alice@example.com", "syftbox.net");

    save_did_document(&bundle, &did_id, &did_path).unwrap();

    let contents = fs::read_to_string(&did_path).unwrap();
    let did_doc: serde_json::Value = serde_json::from_str(&contents).unwrap();

    assert_eq!(did_doc["@context"].as_array().unwrap().len(), 3);
    assert_eq!(did_doc["id"], did_id);
    assert!(did_doc["verificationMethod"].is_array());
    assert!(did_doc["keyAgreement"].is_array());

    let ka = did_doc["keyAgreement"].as_array().unwrap();
    assert_eq!(ka.len(), 2);

    let identity_dh = ka
        .iter()
        .find(|k| k["publicKeyJwk"]["kid"] == "identity-dh")
        .unwrap();
    assert_eq!(identity_dh["type"], "X25519KeyAgreementKey2020");
    assert_eq!(identity_dh["publicKeyJwk"]["crv"], "X25519");

    let signed_prekey = ka
        .iter()
        .find(|k| k["publicKeyJwk"]["kid"] == "signed-prekey")
        .unwrap();
    assert_eq!(signed_prekey["type"], "X25519KeyAgreementKey2020");
    assert_eq!(signed_prekey["publicKeyJwk"]["crv"], "X25519");

    // Ensure keys are valid length
    let identity_dh_bytes = URL_SAFE_NO_PAD
        .decode(identity_dh["publicKeyJwk"]["x"].as_str().unwrap())
        .unwrap();
    assert_eq!(identity_dh_bytes.len(), 32);
}
