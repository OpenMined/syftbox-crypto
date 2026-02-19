use syftbox_crypto_protocol::SyftRecoveryKey;
use syftbox_crypto_protocol::did_utils::generate_did_web_id;
use syftbox_crypto_protocol::serialization::{
    deserialize_from_did_document, deserialize_private_keys, serialize_private_keys,
    serialize_to_did_document,
};

#[test]
fn test_did_document_roundtrip() {
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key.derive_keys().unwrap();
    let original_bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();

    let did_id = generate_did_web_id("alice@example.com", "example.com");

    let did_doc = serialize_to_did_document(&original_bundle, &did_id).expect("serialize");
    let restored_bundle = deserialize_from_did_document(&did_doc).expect("deserialize");

    assert_eq!(
        original_bundle.identity_signing_public_key.as_bytes(),
        restored_bundle.identity_signing_public_key.as_bytes()
    );
    assert_eq!(
        original_bundle.identity_dh_public_key.as_bytes(),
        restored_bundle.identity_dh_public_key.as_bytes()
    );
    assert_eq!(
        original_bundle.signed_prekey_public_key.as_bytes(),
        restored_bundle.signed_prekey_public_key.as_bytes()
    );
}

#[test]
fn test_private_keys_roundtrip() {
    let recovery_key = SyftRecoveryKey::generate();
    let original_keys = recovery_key.derive_keys().unwrap();

    let jwks = serialize_private_keys(&original_keys).expect("serialize");
    let restored_keys = deserialize_private_keys(&jwks).expect("deserialize");

    assert_eq!(
        original_keys.identity().to_bytes(),
        restored_keys.identity().to_bytes()
    );
    assert_eq!(
        original_keys.identity_dh().to_bytes(),
        restored_keys.identity_dh().to_bytes()
    );
    assert_eq!(
        original_keys.signed_pre_key().to_bytes(),
        restored_keys.signed_pre_key().to_bytes()
    );
}

#[test]
fn test_did_document_format() {
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key.derive_keys().unwrap();
    let bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();

    let did_id = generate_did_web_id("alice@example.com", "example.com");

    let did_doc = serialize_to_did_document(&bundle, &did_id).unwrap();

    assert!(did_doc["@context"].is_array());
    assert_eq!(did_doc["id"], did_id);
    assert!(did_doc["verificationMethod"].is_array());
    assert!(did_doc["keyAgreement"].is_array());

    let vm = &did_doc["verificationMethod"][0];
    assert_eq!(vm["type"], "Ed25519VerificationKey2020");
    assert_eq!(vm["publicKeyJwk"]["kty"], "OKP");
    assert_eq!(vm["publicKeyJwk"]["crv"], "Ed25519");

    let ka = did_doc["keyAgreement"].as_array().unwrap();
    assert_eq!(ka.len(), 2);
}
