use crate::{SyftRecoveryKey, error::KeyError};
use rand::{rng, RngCore};
use super::{key_wrap, x3dh};

#[test]
fn test_x3dh_round_trip() {
    // Alice and Bob generate their keys
    let mut rng = rng();
    let alice_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("alice key derivation");
    let bob_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("bob key derivation");

    let alice_bundle = alice_keys.to_public_bundle(&mut rng).expect("alice bundle");
    let bob_bundle = bob_keys.to_public_bundle(&mut rng).expect("bob bundle");

    // Alice performs sender-side X3DH to Bob
    let (alice_material, wrapping_info) = x3dh::derive_sender_shared_material(
        &alice_keys,
        "bob@example.org",
        &bob_bundle,
        &mut rng,
    )
    .expect("alice X3DH");

    // Bob performs recipient-side X3DH from Alice
    let bob_material = x3dh::derive_recipient_shared_material(
        &bob_keys,
        &alice_bundle,
        &wrapping_info,
    )
    .expect("bob X3DH");

    // Both should derive the same shared material
    assert_eq!(
        &alice_material[..],
        &bob_material[..],
        "X3DH materials must match"
    );

    // Material should be 96 bytes (3×32 DH)
    assert!(
        alice_material.len() == 96,
        "Expected 96 bytes, got {}",
        alice_material.len()
    );
}

#[test]
fn test_x3dh_rejects_invalid_bundle() {
    let mut rng = rng();
    let alice_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("alice key derivation");

    // Create a bundle from different keys (Charlie)
    let charlie_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("charlie key derivation");
    let mut bad_bundle = charlie_keys.to_public_bundle(&mut rng).expect("charlie bundle");

    // Replace identity key with Alice's, but keep Charlie's signatures
    // This creates an invalid bundle (signatures won't match the identity key)
    bad_bundle.identity_signing_public_key = alice_keys.identity().verifying_key();

    // Attempting X3DH with invalid bundle should fail
    let result = x3dh::derive_sender_shared_material(
        &alice_keys,
        "bob@example.org",
        &bad_bundle,
        &mut rng,
    );

    assert!(
        result.is_err(),
        "X3DH should reject bundle with invalid signature"
    );

    if let Err(e) = result {
        assert!(
            matches!(e, KeyError::InvalidSignature),
            "Expected InvalidSignature error, got: {:?}",
            e
        );
    }
}

#[test]
fn test_key_wrapping_round_trip() {
    let mut rng = rng();

    // Generate X3DH material (simulate successful key agreement)
    let alice_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("alice key derivation");
    let bob_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("bob key derivation");
    let bob_bundle = bob_keys.to_public_bundle(&mut rng).expect("bob bundle");

    let (x3dh_material, _) = x3dh::derive_sender_shared_material(
        &alice_keys,
        "bob@example.org",
        &bob_bundle,
        &mut rng,
    )
    .expect("X3DH");

    // Create a random file key
    let file_key = {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        key
    };

    // Wrap the file key
    let wrapped = key_wrap::wrap_file_key(x3dh_material.as_ref(), &file_key, &mut rng)
        .expect("wrap file key");

    // Verify wrapped size is exactly 72 bytes (24 nonce + 48 ciphertext+tag)
    assert_eq!(
        wrapped.len(),
        key_wrap::WRAPPED_KEY_SIZE,
        "Wrapped key must be exactly 72 bytes"
    );

    // Unwrap the file key
    let unwrapped = key_wrap::unwrap_file_key(x3dh_material.as_ref(), &wrapped)
        .expect("unwrap file key");

    // Verify we got the original key back
    assert_eq!(
        &file_key[..],
        &unwrapped[..],
        "Unwrapped key must match original"
    );
}

#[test]
fn test_unwrap_rejects_tampered_data() {
    let mut rng = rng();

    // Generate X3DH material
    let alice_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("alice key derivation");
    let bob_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("bob key derivation");
    let bob_bundle = bob_keys.to_public_bundle(&mut rng).expect("bob bundle");

    let (x3dh_material, _) = x3dh::derive_sender_shared_material(
        &alice_keys,
        "bob@example.org",
        &bob_bundle,
        &mut rng,
    )
    .expect("X3DH");

    // Wrap a file key
    let file_key = {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        key
    };
    let mut wrapped = key_wrap::wrap_file_key(x3dh_material.as_ref(), &file_key, &mut rng)
        .expect("wrap file key");

    // Tamper with the ciphertext (flip a bit in the middle)
    wrapped[40] ^= 0x01;

    // Unwrap should fail due to authentication tag mismatch
    let result = key_wrap::unwrap_file_key(x3dh_material.as_ref(), &wrapped);

    assert!(
        result.is_err(),
        "Unwrap should reject tampered ciphertext"
    );

    if let Err(e) = result {
        assert!(
            matches!(e, KeyError::InvalidSignature),
            "Expected InvalidSignature error for tampered data, got: {:?}",
            e
        );
    }

    // Also test: wrong X3DH material should fail
    let wrong_material = vec![0u8; x3dh_material.len()]; // All zeros
    let result = key_wrap::unwrap_file_key(&wrong_material, &wrapped);

    assert!(
        result.is_err(),
        "Unwrap should reject wrong X3DH material"
    );
}
