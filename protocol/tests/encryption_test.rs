use syftbox_crypto_protocol::{
    SyftRecoveryKey, decrypt_message, encrypt_message, encryption::EncryptionRecipient,
    envelope::parse_envelope,
};

#[test]
fn encrypt_decrypt_round_trip() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    let plaintext = b"secret message from alice".to_vec();

    let envelope = encrypt_message(
        "alice@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "bob@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("note.txt"),
        &mut rand::rng(),
    )
    .expect("envelope");

    let parsed = parse_envelope(&envelope).expect("parse");

    let decrypted = decrypt_message(
        "bob@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    )
    .expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_decrypt_multi_recipient() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");

    // Create three recipients
    let alice_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("alice keys");
    let alice_bundle = alice_keys
        .to_public_bundle(&mut rand::rng())
        .expect("alice bundle");

    let bob_keys = SyftRecoveryKey::generate().derive_keys().expect("bob keys");
    let bob_bundle = bob_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bob bundle");

    let carol_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("carol keys");
    let carol_bundle = carol_keys
        .to_public_bundle(&mut rand::rng())
        .expect("carol bundle");

    let plaintext = b"secret message for multiple recipients".to_vec();

    // Encrypt for all three recipients
    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[
            EncryptionRecipient {
                identity: "alice@example.org",
                bundle: &alice_bundle,
            },
            EncryptionRecipient {
                identity: "bob@example.org",
                bundle: &bob_bundle,
            },
            EncryptionRecipient {
                identity: "carol@example.org",
                bundle: &carol_bundle,
            },
        ],
        &plaintext,
        Some("shared_secret.txt"),
        &mut rand::rng(),
    )
    .expect("envelope");

    let sender_bundle = sender_keys
        .to_public_bundle(&mut rand::rng())
        .expect("sender bundle");
    let parsed = parse_envelope(&envelope).expect("parse");

    // Verify all three recipients can decrypt
    let decrypted_by_alice =
        decrypt_message("alice@example.org", &alice_keys, &sender_bundle, &parsed)
            .expect("alice decrypt");

    let decrypted_by_bob = decrypt_message("bob@example.org", &bob_keys, &sender_bundle, &parsed)
        .expect("bob decrypt");

    let decrypted_by_carol =
        decrypt_message("carol@example.org", &carol_keys, &sender_bundle, &parsed)
            .expect("carol decrypt");

    // All recipients should get the same plaintext
    assert_eq!(decrypted_by_alice, plaintext);
    assert_eq!(decrypted_by_bob, plaintext);
    assert_eq!(decrypted_by_carol, plaintext);

    // Verify envelope size is efficient (not 3x the single-recipient size)
    // The ciphertext should be the same regardless of recipient count
    assert_eq!(parsed.ciphertext.len(), plaintext.len() + 16); // +16 for auth tag
}
