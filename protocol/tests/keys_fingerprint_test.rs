use syftbox_crypto_protocol::{SyftRecoveryKey, compute_identity_fingerprint};

#[test]
fn test_fingerprint_is_deterministic() {
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key.derive_keys().unwrap();
    let identity = private_keys.identity().verifying_key();

    let fp1 = compute_identity_fingerprint(&identity);
    let fp2 = compute_identity_fingerprint(&identity);

    assert_eq!(fp1, fp2, "Same key should produce same fingerprint");
}

#[test]
fn test_different_keys_different_fingerprints() {
    let key1 = SyftRecoveryKey::generate().derive_keys().unwrap();
    let key2 = SyftRecoveryKey::generate().derive_keys().unwrap();

    let fp1 = compute_identity_fingerprint(&key1.identity().verifying_key());
    let fp2 = compute_identity_fingerprint(&key2.identity().verifying_key());

    assert_ne!(
        fp1, fp2,
        "Different keys should have different fingerprints"
    );
}

#[test]
fn test_fingerprint_format() {
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key.derive_keys().unwrap();
    let fingerprint = compute_identity_fingerprint(&private_keys.identity().verifying_key());

    assert_eq!(
        fingerprint.len(),
        64,
        "SHA-256 fingerprint should be 64 hex chars"
    );
    assert!(
        fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
        "Should be valid hex"
    );
}

#[test]
fn test_fingerprint_is_lowercase_hex() {
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key.derive_keys().unwrap();
    let fingerprint = compute_identity_fingerprint(&private_keys.identity().verifying_key());

    // hex::encode produces lowercase hex
    assert!(
        fingerprint
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "Fingerprint should be lowercase hex"
    );
}

#[test]
fn test_fingerprint_from_recovered_key_matches() {
    // Generate key and get fingerprint
    let original_recovery = SyftRecoveryKey::generate();
    let original_keys = original_recovery.derive_keys().unwrap();
    let original_fingerprint =
        compute_identity_fingerprint(&original_keys.identity().verifying_key());

    // Convert to mnemonic and recover
    let mnemonic = original_recovery.to_mnemonic();
    let recovered_recovery = SyftRecoveryKey::from_mnemonic(&mnemonic).unwrap();
    let recovered_keys = recovered_recovery.derive_keys().unwrap();
    let recovered_fingerprint =
        compute_identity_fingerprint(&recovered_keys.identity().verifying_key());

    assert_eq!(
        original_fingerprint, recovered_fingerprint,
        "Recovered key should have same fingerprint"
    );
}

#[test]
fn test_fingerprint_matches_public_bundle() {
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key.derive_keys().unwrap();
    let public_bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();

    // Fingerprint from private key
    let fp_from_private = compute_identity_fingerprint(&private_keys.identity().verifying_key());

    // Fingerprint from public bundle
    let fp_from_public = compute_identity_fingerprint(&public_bundle.identity_signing_public_key);

    assert_eq!(
        fp_from_private, fp_from_public,
        "Fingerprint should be same whether computed from private or public key"
    );
}
