use syftbox_crypto_protocol::SyftRecoveryKey;

#[test]
fn test_public_key_bundle_creation() {
    let mut rng = rand::rng();
    let keys = SyftRecoveryKey::generate().derive_keys().unwrap();
    let bundle = keys.to_public_bundle(&mut rng).unwrap();

    assert!(bundle.verify_signatures());
    assert_eq!(bundle.identity_fingerprint().len(), 64);
}

#[test]
fn test_public_key_bundle_detects_tampered_identity_dh_signature() {
    let mut rng = rand::rng();
    let keys = SyftRecoveryKey::generate().derive_keys().unwrap();
    let mut bundle = keys.to_public_bundle(&mut rng).unwrap();

    let mut sig = bundle.identity_dh_signature.to_vec();
    sig[0] ^= 0xFF;
    bundle.identity_dh_signature = sig.into_boxed_slice();

    assert!(!bundle.verify_signatures());
}

#[test]
fn test_public_key_bundle_detects_tampered_signed_prekey_signature() {
    let mut rng = rand::rng();
    let keys = SyftRecoveryKey::generate().derive_keys().unwrap();
    let mut bundle = keys.to_public_bundle(&mut rng).unwrap();

    let mut sig = bundle.signed_prekey_signature.to_vec();
    sig[0] ^= 0xFF;
    bundle.signed_prekey_signature = sig.into_boxed_slice();

    assert!(!bundle.verify_signatures());
}

#[test]
fn test_public_key_bundle_total_size() {
    let mut rng = rand::rng();
    let keys = SyftRecoveryKey::generate().derive_keys().unwrap();
    let bundle = keys.to_public_bundle(&mut rng).unwrap();

    let expected = 32  // Ed25519 identity public key
        + 32          // X25519 identity DH public key
        + 64          // identity DH signature
        + 32          // X25519 signed prekey public key
        + 64; // signed prekey signature

    assert_eq!(bundle.total_size(), expected);
}

#[test]
fn test_public_key_bundle_clone() {
    let mut rng = rand::rng();
    let keys = SyftRecoveryKey::generate().derive_keys().unwrap();
    let bundle = keys.to_public_bundle(&mut rng).unwrap();
    let cloned = bundle.clone();

    assert_eq!(bundle.identity_fingerprint(), cloned.identity_fingerprint());
    assert!(cloned.verify_signatures());
}
