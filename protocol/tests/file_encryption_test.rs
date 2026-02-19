use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use rand::RngCore;
use std::fs::File;
use std::io::{Read, Seek, Write};
use syftbox_crypto_protocol::{
    SyftRecoveryKey, decrypt_message, encrypt_message, encryption::EncryptionRecipient,
    envelope::parse_envelope,
};
use tar::{Archive, Builder};
use tempfile::NamedTempFile;

// ============================================================================
// File Size Tests
// ============================================================================

#[test]
fn test_encrypt_empty_file() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    let plaintext = vec![];

    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("empty.bin"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let parsed = parse_envelope(&envelope).expect("parse");
    let decrypted = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    )
    .expect("decrypt");

    assert_eq!(decrypted, plaintext);
    assert_eq!(parsed.ciphertext.len(), 16); // Just the auth tag for empty file
}

#[test]
fn test_encrypt_single_byte() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    let plaintext = vec![0x42];

    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("single_byte.bin"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let parsed = parse_envelope(&envelope).expect("parse");
    let decrypted = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    )
    .expect("decrypt");

    assert_eq!(decrypted, plaintext);
    assert_eq!(parsed.ciphertext.len(), 17); // 1 byte + 16-byte auth tag
}

#[test]
fn test_encrypt_1kb_file() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    // 1KB of pseudorandom data
    let plaintext = (0..1024)
        .map(|i| u8::try_from(i % 256).unwrap())
        .collect::<Vec<_>>();

    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("1kb.bin"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let parsed = parse_envelope(&envelope).expect("parse");
    let decrypted = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    )
    .expect("decrypt");

    assert_eq!(decrypted, plaintext);
    assert_eq!(parsed.ciphertext.len(), 1024 + 16); // 1KB + 16-byte auth tag
}

#[test]
fn test_encrypt_1mb_file() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    // 1MB of pseudorandom data
    let plaintext = (0..1_048_576)
        .map(|i| u8::try_from(i % 256).unwrap())
        .collect::<Vec<_>>();

    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("1mb.bin"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let parsed = parse_envelope(&envelope).expect("parse");
    let decrypted = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    )
    .expect("decrypt");

    assert_eq!(decrypted, plaintext);
    assert_eq!(parsed.ciphertext.len(), 1_048_576 + 16); // 1MB + 16-byte auth tag
}

// ============================================================================
// Binary Data Tests
// ============================================================================

#[test]
fn test_encrypt_random_bytes() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    // 4KB of truly random data
    let mut plaintext = vec![0u8; 4096];
    rand::rng().fill_bytes(&mut plaintext);

    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("random.bin"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let parsed = parse_envelope(&envelope).expect("parse");
    let decrypted = decrypt_message(
        "recipient@example.org",
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
fn test_encrypt_all_zeros() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    // All zeros (degenerate case)
    let plaintext = vec![0u8; 1024];

    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("zeros.bin"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let parsed = parse_envelope(&envelope).expect("parse");
    let decrypted = decrypt_message(
        "recipient@example.org",
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
fn test_encrypt_all_ones() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    // All 0xFF (degenerate case)
    let plaintext = vec![0xFFu8; 1024];

    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("ones.bin"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let parsed = parse_envelope(&envelope).expect("parse");
    let decrypted = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    )
    .expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

// ============================================================================
// Deterministic Behavior Tests
// ============================================================================

#[test]
fn test_encryption_produces_different_ciphertexts() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    let plaintext = b"same message encrypted twice".to_vec();

    // Encrypt same message twice
    let envelope1 = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("test.txt"),
        &mut rand::rng(),
    )
    .expect("encrypt1");

    let envelope2 = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("test.txt"),
        &mut rand::rng(),
    )
    .expect("encrypt2");

    // Envelopes should be different due to random nonces and ephemeral keys
    assert_ne!(envelope1, envelope2, "Encryption must be non-deterministic");

    // But both should decrypt to same plaintext
    let parsed1 = parse_envelope(&envelope1).expect("parse1");
    let parsed2 = parse_envelope(&envelope2).expect("parse2");

    let sender_bundle = sender_keys
        .to_public_bundle(&mut rand::rng())
        .expect("sender bundle");

    let decrypted1 = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_bundle,
        &parsed1,
    )
    .expect("decrypt1");

    let decrypted2 = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_bundle,
        &parsed2,
    )
    .expect("decrypt2");

    assert_eq!(decrypted1, plaintext);
    assert_eq!(decrypted2, plaintext);
}

#[test]
fn test_decryption_is_deterministic() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    let plaintext = b"deterministic decryption test".to_vec();

    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("test.txt"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let parsed = parse_envelope(&envelope).expect("parse");
    let sender_bundle = sender_keys
        .to_public_bundle(&mut rand::rng())
        .expect("sender bundle");

    // Decrypt same envelope 3 times - should always get same result
    let decrypted1 = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_bundle,
        &parsed,
    )
    .expect("decrypt1");

    let decrypted2 = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_bundle,
        &parsed,
    )
    .expect("decrypt2");

    let decrypted3 = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_bundle,
        &parsed,
    )
    .expect("decrypt3");

    assert_eq!(decrypted1, plaintext);
    assert_eq!(decrypted2, plaintext);
    assert_eq!(decrypted3, plaintext);
    assert_eq!(decrypted1, decrypted2);
    assert_eq!(decrypted2, decrypted3);
}

// ============================================================================
// Tampering Detection Tests
// ============================================================================

#[test]
fn test_tampered_ciphertext_rejected() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    let plaintext = b"tamper me if you can".to_vec();

    let mut envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("test.txt"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    // Tamper with ciphertext (flip a bit near the end, before signature)
    let tamper_pos = envelope.len() - 100;
    envelope[tamper_pos] ^= 0x01;

    let parsed = parse_envelope(&envelope).expect("parse should still work");

    // Decryption should fail due to authentication tag mismatch
    let result = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    );

    assert!(result.is_err(), "Tampered ciphertext should be rejected");
}

#[test]
fn test_wrong_recipient_key_rejected() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    // Different recipient (not the intended one)
    let wrong_recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("wrong recipient keys");

    let plaintext = b"secret message".to_vec();

    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("secret.txt"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let parsed = parse_envelope(&envelope).expect("parse");

    // Try to decrypt with wrong keys
    let result = decrypt_message(
        "recipient@example.org",
        &wrong_recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    );

    assert!(result.is_err(), "Wrong recipient keys should be rejected");
}

#[test]
fn test_swapped_wrapping_rejected() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let alice_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("alice keys");
    let bob_keys = SyftRecoveryKey::generate().derive_keys().expect("bob keys");
    let alice_bundle = alice_keys
        .to_public_bundle(&mut rand::rng())
        .expect("alice bundle");
    let bob_bundle = bob_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bob bundle");

    let plaintext = b"multi-recipient message".to_vec();

    // Encrypt for both Alice and Bob
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
        ],
        &plaintext,
        Some("shared.txt"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let mut parsed = parse_envelope(&envelope).expect("parse");

    // Swap the wrappings (Alice gets Bob's wrapping and vice versa)
    parsed.prelude.wrappings.swap(0, 1);

    let sender_bundle = sender_keys
        .to_public_bundle(&mut rand::rng())
        .expect("sender bundle");

    // Try to decrypt with swapped wrappings - should fail
    let result_alice = decrypt_message("alice@example.org", &alice_keys, &sender_bundle, &parsed);
    let result_bob = decrypt_message("bob@example.org", &bob_keys, &sender_bundle, &parsed);

    assert!(
        result_alice.is_err() || result_bob.is_err(),
        "Swapped wrappings should cause at least one decryption to fail"
    );
}

#[test]
fn test_truncated_ciphertext_rejected() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    let plaintext = b"this will be truncated".to_vec();

    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("test.txt"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let mut parsed = parse_envelope(&envelope).expect("parse");

    // Truncate ciphertext (remove last 5 bytes)
    if parsed.ciphertext.len() > 5 {
        parsed.ciphertext = parsed.ciphertext[..parsed.ciphertext.len() - 5].to_vec();
    }

    // Decryption should fail
    let result = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    );

    assert!(result.is_err(), "Truncated ciphertext should be rejected");
}

// ============================================================================
// Format Validation Tests
// ============================================================================

#[test]
fn test_ciphertext_length_correct() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    let test_cases = vec![
        (0usize, "empty"),
        (1, "1 byte"),
        (100, "100 bytes"),
        (1024, "1KB"),
        (10_000, "10KB"),
    ];

    for (plaintext_len, desc) in test_cases {
        let plaintext = vec![0x42u8; plaintext_len];

        let envelope = encrypt_message(
            "sender@example.org",
            &sender_keys,
            &[EncryptionRecipient {
                identity: "recipient@example.org",
                bundle: &recipient_bundle,
            }],
            &plaintext,
            Some("test.bin"),
            &mut rand::rng(),
        )
        .expect("encrypt");

        let parsed = parse_envelope(&envelope).expect("parse");

        // XChaCha20-Poly1305 adds exactly 16 bytes (128-bit auth tag)
        assert_eq!(
            parsed.ciphertext.len(),
            plaintext_len + 16,
            "Ciphertext length incorrect for {}",
            desc
        );
    }
}

#[test]
fn test_wrapped_key_format() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    let plaintext = b"test".to_vec();

    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("test.txt"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let parsed = parse_envelope(&envelope).expect("parse");

    // Should have exactly one wrapping
    assert_eq!(parsed.prelude.wrappings.len(), 1);

    // Decode wrap_ciphertext
    let wrap_ciphertext = URL_SAFE_NO_PAD
        .decode(&parsed.prelude.wrappings[0].wrap_ciphertext)
        .expect("decode wrap_ciphertext");

    // Format: wrapped_key (72 bytes)
    assert_eq!(
        wrap_ciphertext.len(),
        72,
        "wrap_ciphertext should be exactly 72 bytes"
    );

    // The 72 bytes should be: nonce (24) + encrypted_key (32) + auth_tag (16)
    let wrapped_key = &wrap_ciphertext[..];
    assert_eq!(
        wrapped_key.len(),
        72,
        "Wrapped key should be exactly 72 bytes"
    );
}

#[test]
fn test_envelope_contains_all_fields() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    let plaintext = b"structure test".to_vec();

    let envelope = encrypt_message(
        "alice@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "bob@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("test.txt"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let parsed = parse_envelope(&envelope).expect("parse");

    // Check sender fields
    assert_eq!(parsed.prelude.sender.identity, "alice@example.org");
    assert!(!parsed.prelude.sender.ik_fingerprint.is_empty());

    // Check recipients
    assert_eq!(parsed.prelude.recipients.len(), 1);
    assert_eq!(
        parsed.prelude.recipients[0].identity.as_deref(),
        Some("bob@example.org")
    );

    // Check wrappings
    assert_eq!(parsed.prelude.wrappings.len(), 1);
    assert_eq!(
        parsed.prelude.wrappings[0].recipient_identity.as_deref(),
        Some("bob@example.org")
    );
    assert!(!parsed.prelude.wrappings[0].wrap_ephemeral_public.is_empty());
    assert!(!parsed.prelude.wrappings[0].wrap_ciphertext.is_empty());

    // Check cipher info
    assert_eq!(parsed.prelude.cipher.suite, "xchacha20poly1305-v1");
    assert!(!parsed.prelude.cipher.nonce.is_empty());

    // Check ciphertext exists
    assert!(!parsed.ciphertext.is_empty());

    // Check signature exists
    assert!(!parsed.signature.is_empty());
}

#[test]
fn test_nonce_is_24_bytes() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    let plaintext = b"nonce test".to_vec();

    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("test.txt"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    let parsed = parse_envelope(&envelope).expect("parse");

    // Decode nonce from base64
    let nonce = URL_SAFE_NO_PAD
        .decode(&parsed.prelude.cipher.nonce)
        .expect("decode nonce");

    // XChaCha20 requires 192-bit (24-byte) nonce
    assert_eq!(nonce.len(), 24, "XChaCha20 nonce must be exactly 24 bytes");
}

// ============================================================================
// Compression + Encryption Tests
// ============================================================================

#[test]
fn test_compress_then_encrypt_text_file() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    // Create temp file with highly compressible plaintext (repetitive text)
    let plaintext = "Hello World! This is a test. ".repeat(1000).into_bytes();
    let original_size = plaintext.len();

    let mut plaintext_file = NamedTempFile::new().expect("create plaintext temp file");
    plaintext_file
        .write_all(&plaintext)
        .expect("write plaintext to temp file");
    plaintext_file.flush().expect("flush plaintext");

    // Compress file to another temp file
    let compressed_file = NamedTempFile::new().expect("create compressed temp file");
    let mut encoder = GzEncoder::new(compressed_file, Compression::default());
    let mut plaintext_reader = File::open(plaintext_file.path()).expect("open plaintext file");
    std::io::copy(&mut plaintext_reader, &mut encoder).expect("compress file");
    let mut compressed_file = encoder.finish().expect("finish compression");
    compressed_file.flush().expect("flush compressed");

    // Read compressed file size
    let compressed_size = usize::try_from(
        compressed_file
            .as_file()
            .metadata()
            .expect("compressed metadata")
            .len(),
    )
    .expect("compressed size fits in usize");

    // Read compressed file for encryption
    let mut compressed_data = Vec::new();
    compressed_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("seek to start");
    compressed_file
        .read_to_end(&mut compressed_data)
        .expect("read compressed file");

    // Encrypt the compressed data
    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &compressed_data,
        Some("compressed.txt.gz"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    // Decrypt
    let parsed = parse_envelope(&envelope).expect("parse");
    let decrypted_compressed = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    )
    .expect("decrypt");

    // Write decrypted data to temp file and decompress
    let mut decrypted_file = NamedTempFile::new().expect("create decrypted temp file");
    decrypted_file
        .write_all(&decrypted_compressed)
        .expect("write decrypted");
    decrypted_file.flush().expect("flush decrypted");

    let decompressed_file = NamedTempFile::new().expect("create decompressed temp file");
    let mut decoder =
        GzDecoder::new(File::open(decrypted_file.path()).expect("open decrypted file"));
    let mut decompressed_writer = decompressed_file
        .reopen()
        .expect("reopen decompressed file");
    std::io::copy(&mut decoder, &mut decompressed_writer).expect("decompress file");
    decompressed_writer.flush().expect("flush decompressed");

    // Read back and verify complete roundtrip
    let mut decompressed = Vec::new();
    File::open(decompressed_file.path())
        .expect("open decompressed file")
        .read_to_end(&mut decompressed)
        .expect("read decompressed file");

    assert_eq!(
        decompressed, plaintext,
        "Decompressed data should match original"
    );
    assert!(
        compressed_size < original_size,
        "Compression should reduce size: {} < {}",
        compressed_size,
        original_size
    );
}

#[test]
fn test_compress_then_encrypt_binary_file() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    // Create temp file with random binary data (low compressibility)
    let mut plaintext = vec![0u8; 10240]; // 10KB
    rand::rng().fill_bytes(&mut plaintext);

    let mut plaintext_file = NamedTempFile::new().expect("create plaintext temp file");
    plaintext_file
        .write_all(&plaintext)
        .expect("write plaintext to temp file");
    plaintext_file.flush().expect("flush plaintext");

    // Compress file to another temp file (should barely compress random data)
    let compressed_file = NamedTempFile::new().expect("create compressed temp file");
    let mut encoder = GzEncoder::new(compressed_file, Compression::default());
    let mut plaintext_reader = File::open(plaintext_file.path()).expect("open plaintext file");
    std::io::copy(&mut plaintext_reader, &mut encoder).expect("compress file");
    let mut compressed_file = encoder.finish().expect("finish compression");
    compressed_file.flush().expect("flush compressed");

    // Read compressed file for encryption
    let mut compressed_data = Vec::new();
    compressed_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("seek to start");
    compressed_file
        .read_to_end(&mut compressed_data)
        .expect("read compressed file");

    // Encrypt the compressed data
    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &compressed_data,
        Some("random.bin.gz"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    // Decrypt
    let parsed = parse_envelope(&envelope).expect("parse");
    let decrypted_compressed = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    )
    .expect("decrypt");

    // Write decrypted data to temp file and decompress
    let mut decrypted_file = NamedTempFile::new().expect("create decrypted temp file");
    decrypted_file
        .write_all(&decrypted_compressed)
        .expect("write decrypted");
    decrypted_file.flush().expect("flush decrypted");

    let decompressed_file = NamedTempFile::new().expect("create decompressed temp file");
    let mut decoder =
        GzDecoder::new(File::open(decrypted_file.path()).expect("open decrypted file"));
    let mut decompressed_writer = decompressed_file
        .reopen()
        .expect("reopen decompressed file");
    std::io::copy(&mut decoder, &mut decompressed_writer).expect("decompress file");
    decompressed_writer.flush().expect("flush decompressed");

    // Read back and verify roundtrip (random data won't compress well)
    let mut decompressed = Vec::new();
    File::open(decompressed_file.path())
        .expect("open decompressed file")
        .read_to_end(&mut decompressed)
        .expect("read decompressed file");

    assert_eq!(decompressed, plaintext);
}

#[test]
fn test_compress_then_encrypt_already_compressed() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    // Create temp file with plaintext and compress it once
    let plaintext = "Test data ".repeat(100).into_bytes();
    let mut plaintext_file = NamedTempFile::new().expect("create plaintext temp file");
    plaintext_file
        .write_all(&plaintext)
        .expect("write plaintext");
    plaintext_file.flush().expect("flush plaintext");

    // First compression
    let compressed_once_file = NamedTempFile::new().expect("create first compressed temp file");
    let mut encoder1 = GzEncoder::new(compressed_once_file, Compression::default());
    let mut plaintext_reader = File::open(plaintext_file.path()).expect("open plaintext file");
    std::io::copy(&mut plaintext_reader, &mut encoder1).expect("first compression");
    let mut compressed_once_file = encoder1.finish().expect("finish first compression");
    compressed_once_file
        .flush()
        .expect("flush first compressed");

    let compressed_once_size = usize::try_from(
        compressed_once_file
            .as_file()
            .metadata()
            .expect("metadata")
            .len(),
    )
    .expect("compressed_once size fits in usize");

    // Second compression (double compression - should expand slightly)
    compressed_once_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("seek to start");
    let compressed_twice_file = NamedTempFile::new().expect("create second compressed temp file");
    let mut encoder2 = GzEncoder::new(compressed_twice_file, Compression::default());
    std::io::copy(&mut compressed_once_file, &mut encoder2).expect("second compression");
    let mut compressed_twice_file = encoder2.finish().expect("finish second compression");
    compressed_twice_file
        .flush()
        .expect("flush second compressed");

    let compressed_twice_size = usize::try_from(
        compressed_twice_file
            .as_file()
            .metadata()
            .expect("metadata")
            .len(),
    )
    .expect("compressed_twice size fits in usize");

    // Read double-compressed file for encryption
    let mut compressed_twice_data = Vec::new();
    compressed_twice_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("seek to start");
    compressed_twice_file
        .read_to_end(&mut compressed_twice_data)
        .expect("read double compressed");

    // Encrypt the double-compressed data
    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &compressed_twice_data,
        Some("double_compressed.gz.gz"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    // Decrypt
    let parsed = parse_envelope(&envelope).expect("parse");
    let decrypted_double = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    )
    .expect("decrypt");

    // Write decrypted to temp file and decompress twice
    let mut decrypted_file = NamedTempFile::new().expect("create decrypted temp file");
    decrypted_file
        .write_all(&decrypted_double)
        .expect("write decrypted");
    decrypted_file.flush().expect("flush decrypted");

    // First decompression
    let compressed_once_decoded_file =
        NamedTempFile::new().expect("create first decompressed temp file");
    let mut decoder1 = GzDecoder::new(File::open(decrypted_file.path()).expect("open decrypted"));
    let mut compressed_once_writer = compressed_once_decoded_file
        .reopen()
        .expect("reopen first decompressed");
    std::io::copy(&mut decoder1, &mut compressed_once_writer).expect("first decompress");
    compressed_once_writer
        .flush()
        .expect("flush first decompressed");

    // Second decompression
    let decompressed_file = NamedTempFile::new().expect("create final decompressed temp file");
    let mut decoder2 = GzDecoder::new(
        File::open(compressed_once_decoded_file.path()).expect("open compressed once"),
    );
    let mut decompressed_writer = decompressed_file
        .reopen()
        .expect("reopen final decompressed");
    std::io::copy(&mut decoder2, &mut decompressed_writer).expect("second decompress");
    decompressed_writer
        .flush()
        .expect("flush final decompressed");

    // Read back and verify roundtrip
    let mut decompressed = Vec::new();
    File::open(decompressed_file.path())
        .expect("open decompressed file")
        .read_to_end(&mut decompressed)
        .expect("read decompressed");

    assert_eq!(decompressed, plaintext);
    // Double compression should not help (may even expand)
    assert!(
        compressed_twice_size >= compressed_once_size,
        "Double compression should not reduce size further"
    );
}

#[test]
fn test_compress_multiple_files_tar_gz() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    // Create multiple temp files to archive
    let files = vec![
        ("file1.txt", b"First file content with some text".to_vec()),
        ("file2.bin", vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE]),
        ("dir/file3.txt", b"Nested file in subdirectory".to_vec()),
        (
            "data.json",
            b"{\"key\": \"value\", \"number\": 42}".to_vec(),
        ),
    ];

    // 1. Create tar archive in temp file
    let tar_file = NamedTempFile::new().expect("create tar temp file");
    let mut tar_builder = Builder::new(tar_file);
    for (name, content) in &files {
        let mut header = tar::Header::new_gnu();
        header.set_path(name).unwrap();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder.append(&header, &content[..]).unwrap();
    }
    tar_builder.finish().unwrap();
    let mut tar_file = tar_builder.into_inner().unwrap();
    tar_file.flush().expect("flush tar");

    // 2. Compress tar archive with GZip to another temp file
    tar_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("seek tar to start");
    let compressed_file = NamedTempFile::new().expect("create compressed temp file");
    let mut encoder = GzEncoder::new(compressed_file, Compression::default());
    std::io::copy(&mut tar_file, &mut encoder).unwrap();
    let mut compressed_file = encoder.finish().unwrap();
    compressed_file.flush().expect("flush compressed");

    // Read compressed file for encryption
    let mut compressed_data = Vec::new();
    compressed_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("seek compressed to start");
    compressed_file
        .read_to_end(&mut compressed_data)
        .expect("read compressed");

    // 3. Encrypt the tar.gz
    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &compressed_data,
        Some("archive.tar.gz"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    // 4. Decrypt
    let parsed = parse_envelope(&envelope).expect("parse");
    let decrypted_compressed = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    )
    .expect("decrypt");

    // 5. Write decrypted to temp file and decompress
    let mut decrypted_file = NamedTempFile::new().expect("create decrypted temp file");
    decrypted_file
        .write_all(&decrypted_compressed)
        .expect("write decrypted");
    decrypted_file.flush().expect("flush decrypted");

    let decompressed_tar_file = NamedTempFile::new().expect("create decompressed tar temp file");
    let mut decoder = GzDecoder::new(File::open(decrypted_file.path()).expect("open decrypted"));
    let mut decompressed_writer = decompressed_tar_file
        .reopen()
        .expect("reopen decompressed tar");
    std::io::copy(&mut decoder, &mut decompressed_writer).expect("decompress");
    decompressed_writer.flush().expect("flush decompressed tar");

    // 6. Extract tar archive from temp file
    let mut archive =
        Archive::new(File::open(decompressed_tar_file.path()).expect("open decompressed tar"));
    let mut extracted_files = Vec::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_str().unwrap().to_owned();
        let mut content = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut content).unwrap();
        extracted_files.push((path, content));
    }

    // 7. Verify all files extracted correctly
    assert_eq!(extracted_files.len(), 4, "Should extract all 4 files");

    assert_eq!(extracted_files[0].0, "file1.txt");
    assert_eq!(extracted_files[0].1, b"First file content with some text");

    assert_eq!(extracted_files[1].0, "file2.bin");
    assert_eq!(
        extracted_files[1].1,
        vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE]
    );

    assert_eq!(extracted_files[2].0, "dir/file3.txt");
    assert_eq!(extracted_files[2].1, b"Nested file in subdirectory");

    assert_eq!(extracted_files[3].0, "data.json");
    assert_eq!(
        extracted_files[3].1,
        b"{\"key\": \"value\", \"number\": 42}"
    );
}

#[test]
fn test_compress_empty_archive() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    // Create empty tar archive in temp file
    let tar_file = NamedTempFile::new().expect("create tar temp file");
    let mut tar_builder = Builder::new(tar_file);
    tar_builder.finish().unwrap();
    let mut tar_file = tar_builder.into_inner().unwrap();
    tar_file.flush().expect("flush tar");

    // Compress to another temp file
    tar_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("seek tar to start");
    let compressed_file = NamedTempFile::new().expect("create compressed temp file");
    let mut encoder = GzEncoder::new(compressed_file, Compression::default());
    std::io::copy(&mut tar_file, &mut encoder).unwrap();
    let mut compressed_file = encoder.finish().unwrap();
    compressed_file.flush().expect("flush compressed");

    // Read compressed file for encryption
    let mut compressed_data = Vec::new();
    compressed_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("seek compressed to start");
    compressed_file
        .read_to_end(&mut compressed_data)
        .expect("read compressed");

    // Encrypt
    let envelope = encrypt_message(
        "sender@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "recipient@example.org",
            bundle: &recipient_bundle,
        }],
        &compressed_data,
        Some("empty.tar.gz"),
        &mut rand::rng(),
    )
    .expect("encrypt");

    // Decrypt
    let parsed = parse_envelope(&envelope).expect("parse");
    let decrypted_compressed = decrypt_message(
        "recipient@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    )
    .expect("decrypt");

    // Write decrypted to temp file and decompress
    let mut decrypted_file = NamedTempFile::new().expect("create decrypted temp file");
    decrypted_file
        .write_all(&decrypted_compressed)
        .expect("write decrypted");
    decrypted_file.flush().expect("flush decrypted");

    let decompressed_tar_file = NamedTempFile::new().expect("create decompressed tar temp file");
    let mut decoder = GzDecoder::new(File::open(decrypted_file.path()).expect("open decrypted"));
    let mut decompressed_writer = decompressed_tar_file
        .reopen()
        .expect("reopen decompressed tar");
    std::io::copy(&mut decoder, &mut decompressed_writer).expect("decompress");
    decompressed_writer.flush().expect("flush decompressed tar");

    // Verify empty archive
    let mut archive =
        Archive::new(File::open(decompressed_tar_file.path()).expect("open decompressed tar"));
    let entry_count = archive.entries().unwrap().count();

    assert_eq!(entry_count, 0, "Empty archive should have no entries");
}

#[test]
fn test_compression_reduces_size() {
    // Test various compression ratios
    let test_cases = vec![
        ("Highly repetitive", "A".repeat(10000), 0.99), // Should compress to <1% of original
        (
            "JSON-like",
            r#"{"key":"value","array":[1,2,3]}"#.repeat(100),
            0.5,
        ), // ~50% compression
        (
            "Mixed text",
            "The quick brown fox jumps over the lazy dog. ".repeat(50),
            0.7,
        ), // ~30% compression
    ];

    for (desc, plaintext, expected_ratio_threshold) in test_cases {
        let plaintext_bytes = plaintext.into_bytes();
        let original_size = plaintext_bytes.len();

        // Write plaintext to temp file
        let mut plaintext_file = NamedTempFile::new().expect("create plaintext temp file");
        plaintext_file
            .write_all(&plaintext_bytes)
            .expect("write plaintext");
        plaintext_file.flush().expect("flush plaintext");

        // Compress to another temp file
        let compressed_file = NamedTempFile::new().expect("create compressed temp file");
        let mut encoder = GzEncoder::new(compressed_file, Compression::default());
        let mut plaintext_reader = File::open(plaintext_file.path()).expect("open plaintext");
        std::io::copy(&mut plaintext_reader, &mut encoder).expect("compress");
        let mut compressed_file = encoder.finish().expect("finish");
        compressed_file.flush().expect("flush compressed");

        let compressed_size = usize::try_from(
            compressed_file
                .as_file()
                .metadata()
                .expect("compressed metadata")
                .len(),
        )
        .expect("compressed size fits in usize");
        let compression_ratio = compressed_size as f64 / original_size as f64;

        println!(
            "{}: {} bytes → {} bytes (ratio: {:.2}%)",
            desc,
            original_size,
            compressed_size,
            compression_ratio * 100.0
        );

        assert!(
            compression_ratio < expected_ratio_threshold,
            "{} should compress to less than {:.0}% of original size",
            desc,
            expected_ratio_threshold * 100.0
        );
    }
}
