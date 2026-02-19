use syftbox_crypto_protocol::SyftRecoveryKey;
use x25519_dalek::PublicKey as X25519PublicKey;

#[test]
fn test_derive_keys_from_recovery_key() {
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key
        .derive_keys()
        .expect("Key derivation should succeed");

    assert!(!private_keys.identity().to_bytes().is_empty());
    assert!(!private_keys.identity_dh().to_bytes().is_empty());
    assert!(!private_keys.signed_pre_key().to_bytes().is_empty());
}

#[test]
fn test_deterministic_key_derivation() {
    let recovery_key = SyftRecoveryKey::generate();

    let keys1 = recovery_key.derive_keys().expect("first derivation");
    let keys2 = recovery_key.derive_keys().expect("second derivation");

    assert_eq!(keys1.identity().to_bytes(), keys2.identity().to_bytes());
    assert_eq!(
        keys1.identity_dh().to_bytes(),
        keys2.identity_dh().to_bytes()
    );
    assert_eq!(
        keys1.signed_pre_key().to_bytes(),
        keys2.signed_pre_key().to_bytes()
    );
}

#[test]
fn test_different_recovery_keys_produce_different_keys() {
    let recovery_key1 = SyftRecoveryKey::generate();
    let recovery_key2 = SyftRecoveryKey::generate();

    let keys1 = recovery_key1.derive_keys().expect("first derivation");
    let keys2 = recovery_key2.derive_keys().expect("second derivation");

    assert_ne!(keys1.identity().to_bytes(), keys2.identity().to_bytes());
    assert_ne!(
        keys1.identity_dh().to_bytes(),
        keys2.identity_dh().to_bytes()
    );
    assert_ne!(
        keys1.signed_pre_key().to_bytes(),
        keys2.signed_pre_key().to_bytes()
    );
}

#[test]
fn test_recovery_key_hex_roundtrip_with_derived_keys() {
    let recovery_key = SyftRecoveryKey::generate();
    let original_keys = recovery_key.derive_keys().expect("original derivation");

    let hex = recovery_key.to_hex_string();
    let recovered_key = SyftRecoveryKey::from_hex_string(&hex).expect("parse hex");
    let recovered_keys = recovered_key.derive_keys().expect("recovered derivation");

    assert_eq!(
        original_keys.identity().to_bytes(),
        recovered_keys.identity().to_bytes()
    );
    assert_eq!(
        original_keys.identity_dh().to_bytes(),
        recovered_keys.identity_dh().to_bytes()
    );
    assert_eq!(
        original_keys.signed_pre_key().to_bytes(),
        recovered_keys.signed_pre_key().to_bytes()
    );
}

#[test]
fn test_derived_keys_can_create_public_bundle() {
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key
        .derive_keys()
        .expect("derivation should succeed");

    let public_bundle = private_keys
        .to_public_bundle(&mut rand::rng())
        .expect("should create public bundle");

    assert!(public_bundle.verify_signatures());

    assert_eq!(
        public_bundle.identity_signing_public_key.as_bytes(),
        private_keys.identity().verifying_key().as_bytes()
    );
    assert_eq!(
        public_bundle.identity_dh_public_key.as_bytes(),
        X25519PublicKey::from(private_keys.identity_dh()).as_bytes()
    );
    assert_eq!(
        public_bundle.signed_prekey_public_key.as_bytes(),
        X25519PublicKey::from(private_keys.signed_pre_key()).as_bytes()
    );
}
