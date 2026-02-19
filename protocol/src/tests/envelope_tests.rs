use super::*;
use serde_json::Map;

#[test]
fn canonicalizes_object_key_order() {
    let mut map = Map::new();
    map.insert("b".to_string(), Value::Number(2.into()));
    map.insert("a".to_string(), Value::Number(1.into()));
    let bytes = to_jcs_bytes(&Value::Object(map)).expect("canonical json");
    assert_eq!(bytes, br#"{"a":1,"b":2}"#);
}

#[test]
fn detects_non_canonical_input() {
    let json = br#"{"b":2,"a":1}"#;
    let err = from_jcs_bytes::<Value>(json).expect_err("should reject non-canonical");
    assert!(err.to_string().contains("canonical"));
}

#[test]
fn round_trips_complex_value() {
    let value = json!({
        "array": [true, false, null, "hi"],
        "nested": {"z": 3, "y": [1, 2, 3]},
    });
    let bytes = to_jcs_bytes(&value).expect("serialize");
    let decoded: Value = from_jcs_bytes(&bytes).expect("deserialize");
    assert_eq!(decoded, value);
}

#[test]
fn envelope_builds_and_parses() {
    use crate::{SyftRecoveryKey, encrypt_message, encryption::EncryptionRecipient};

    let sender_sk = SyftRecoveryKey::generate().derive_keys().unwrap();
    let recipient_sk = SyftRecoveryKey::generate().derive_keys().unwrap();
    let recipient_bundle = recipient_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let plaintext = b"test-data";
    let envelope = encrypt_message(
        "alice@example.org",
        &sender_sk,
        &[EncryptionRecipient {
            identity: "bob@example.org",
            bundle: &recipient_bundle,
        }],
        plaintext,
        None,
        &mut rand::rng(),
    ).unwrap();

    assert!(envelope.starts_with(MAGIC));
    let parsed = parse_envelope(&envelope).expect("parse");
    assert_eq!(parsed.prelude.sender.identity, "alice@example.org");

    // Verify real signature
    crate::envelope::verify_signature(&parsed, &sender_sk.identity().verifying_key())
        .expect("signature verify");
}

#[test]
fn align_to_block_rounds_up() {
    assert_eq!(align_to_block(1, 4096).unwrap(), 4096);
    assert_eq!(align_to_block(4096, 4096).unwrap(), 4096);
    assert_eq!(align_to_block(4097, 4096).unwrap(), 8192);
}

#[test]
fn align_to_block_detects_overflow() {
    let result = align_to_block(usize::MAX, 2);
    assert!(result.is_err());
}

#[test]
fn parse_rejects_oversized_prelude() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.push(CURRENT_VERSION);
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());

    let err = parse_envelope(&bytes).expect_err("should reject oversized prelude");
    assert!(err.to_string().contains("prelude too large"));
}

#[test]
fn parse_rejects_invalid_signature_length() {
    use crate::{SyftRecoveryKey, encrypt_message, encryption::EncryptionRecipient};

    let sender_sk = SyftRecoveryKey::generate().derive_keys().unwrap();
    let recipient_sk = SyftRecoveryKey::generate().derive_keys().unwrap();
    let recipient_bundle = recipient_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let envelope = encrypt_message(
        "alice@example.org",
        &sender_sk,
        &[EncryptionRecipient {
            identity: "bob@example.org",
            bundle: &recipient_bundle,
        }],
        b"payload",
        None,
        &mut rand::rng(),
    ).unwrap();

    let mut tampered = envelope.clone();

    // Find and corrupt the signature length field
    let mut cursor = MAGIC.len() + 1;
    let prelude_len =
        u32::from_le_bytes(tampered[cursor..cursor + 4].try_into().expect("len slice")) as usize;
    cursor += 4;
    let padded_len = align_to_block(prelude_len, PRELUDE_PAD).expect("alignment");
    cursor += padded_len;

    // Set invalid signature length
    tampered[cursor..cursor + 2].copy_from_slice(&10u16.to_le_bytes());

    let err = parse_envelope(&tampered).expect_err("should reject invalid signature len");
    assert!(err.to_string().contains("invalid signature length"));
}

#[test]
fn parse_rejects_ciphertext_length_mismatch() {
    use crate::{SyftRecoveryKey, encrypt_message, encryption::EncryptionRecipient};

    let sender_sk = SyftRecoveryKey::generate().derive_keys().unwrap();
    let recipient_sk = SyftRecoveryKey::generate().derive_keys().unwrap();
    let recipient_bundle = recipient_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let mut envelope = encrypt_message(
        "alice@example.org",
        &sender_sk,
        &[EncryptionRecipient {
            identity: "bob@example.org",
            bundle: &recipient_bundle,
        }],
        b"ciphertext",
        None,
        &mut rand::rng(),
    ).unwrap();

    // Truncate ciphertext
    envelope.pop().expect("non-empty envelope");

    let err = parse_envelope(&envelope).expect_err("should reject ciphertext mismatch");
    assert!(err.to_string().contains("ciphertext length mismatch"));
}
