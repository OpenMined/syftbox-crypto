use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use syftbox_crypto_protocol::datasite::bytes::{
    BytesReadOpts, BytesWriteOpts, read_bytes, write_bytes,
};
use syftbox_crypto_protocol::datasite::context::AppContext;
use syftbox_crypto_protocol::envelope::has_sbc_magic;
use syftbox_crypto_protocol::identity::generate_identity_material;
use tempfile::tempdir;

fn setup_context() -> (tempfile::TempDir, AppContext) {
    let base = tempdir().unwrap();
    let vault = base.path().join("vault");
    let data = base.path().join("data");
    let shadow = base.path().join("shadow");
    fs::create_dir_all(&vault).unwrap();
    fs::create_dir_all(&data).unwrap();
    fs::create_dir_all(&shadow).unwrap();
    (
        base,
        AppContext {
            vault_path: vault,
            data_root: data,
            shadow_root: shadow,
        },
    )
}

fn write_identity(context: &AppContext, identity: &str) {
    let keys_dir = context.vault_path.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();
    let material = generate_identity_material(identity).unwrap();

    let key_path = keys_dir.join(format!("{}.key", identity));
    fs::write(&key_path, &material.key_file).unwrap();

    let bundles_dir = context.vault_path.join("bundles");
    fs::create_dir_all(&bundles_dir).unwrap();
    let bundle_path = bundles_dir.join(format!("{}.json", identity));
    let mut bundle = serde_json::to_vec_pretty(&material.public_bundle).unwrap();
    bundle.push(b'\n');
    fs::write(&bundle_path, bundle).unwrap();
}

#[test]
fn test_single_recipient() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice@example.org");

    let payload = b"single recipient data";

    let write_result = write_bytes(
        &context,
        &BytesWriteOpts {
            relative: PathBuf::from("docs/single.bin"),
            recipients: vec!["alice@example.org".into()],
            sender: None, // Auto-detect (only one identity in vault)
            plaintext: false,
            overwrite: false,
            hint: None,
        },
        payload,
    )
    .unwrap();

    assert!(write_result.encrypted);
    let envelope_data = fs::read(&write_result.destination).unwrap();
    assert!(has_sbc_magic(&envelope_data));

    let read_result = read_bytes(
        &context,
        &BytesReadOpts {
            relative: PathBuf::from("docs/single.bin"),
            identity: Some("alice@example.org".into()),
            require_envelope: true,
        },
    )
    .unwrap();

    assert_eq!(read_result.plaintext, payload);
}

#[test]
fn test_multi_recipient_bytes_encryption() {
    let (_tmp, context) = setup_context();

    // Alice is the sender - create her full identity
    write_identity(&context, "alice@example.org");

    // Bob and Carol are recipients - create their identities too
    // (in a real scenario, we'd only import their public bundles,
    // but for testing purposes we generate full identities)
    write_identity(&context, "bob@example.org");
    write_identity(&context, "carol@example.org");

    let payload = b"multi-recipient secret data";

    // Alice encrypts for herself, Bob, and Carol (explicitly specifying sender)
    let write_result = write_bytes(
        &context,
        &BytesWriteOpts {
            relative: PathBuf::from("docs/multi.bin"),
            recipients: vec![
                "alice@example.org".into(),
                "bob@example.org".into(),
                "carol@example.org".into(),
            ],
            sender: Some("alice@example.org".into()),
            plaintext: false,
            overwrite: false,
            hint: Some("multi-recipient test".into()),
        },
        payload,
    )
    .unwrap();

    assert!(write_result.encrypted, "should be encrypted");
    let envelope_data = fs::read(&write_result.destination).unwrap();
    assert!(has_sbc_magic(&envelope_data), "should have SBC magic");

    // Verify Alice can decrypt
    let alice_result = read_bytes(
        &context,
        &BytesReadOpts {
            relative: PathBuf::from("docs/multi.bin"),
            identity: Some("alice@example.org".into()),
            require_envelope: true,
        },
    )
    .unwrap();
    assert_eq!(
        alice_result.plaintext, payload,
        "Alice should decrypt correctly"
    );
    assert!(alice_result.envelope_used, "should use envelope");

    // Verify Bob can decrypt
    let bob_result = read_bytes(
        &context,
        &BytesReadOpts {
            relative: PathBuf::from("docs/multi.bin"),
            identity: Some("bob@example.org".into()),
            require_envelope: true,
        },
    )
    .unwrap();
    assert_eq!(
        bob_result.plaintext, payload,
        "Bob should decrypt correctly"
    );
    assert!(bob_result.envelope_used, "should use envelope");

    // Verify Carol can decrypt
    let carol_result = read_bytes(
        &context,
        &BytesReadOpts {
            relative: PathBuf::from("docs/multi.bin"),
            identity: Some("carol@example.org".into()),
            require_envelope: true,
        },
    )
    .unwrap();
    assert_eq!(
        carol_result.plaintext, payload,
        "Carol should decrypt correctly"
    );
    assert!(carol_result.envelope_used, "should use envelope");
}

#[test]
fn test_sender_cannot_decrypt_without_self_inclusion() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice@example.org");
    write_identity(&context, "bob@example.org");

    let payload = b"secret message";

    // Alice encrypts for Bob ONLY (not including herself)
    write_bytes(
        &context,
        &BytesWriteOpts {
            relative: PathBuf::from("docs/bob_only.bin"),
            recipients: vec!["bob@example.org".into()], // Alice NOT included
            sender: Some("alice@example.org".into()),
            plaintext: false,
            overwrite: false,
            hint: None,
        },
        payload,
    )
    .unwrap();

    // Bob CAN decrypt (he's in the recipients list)
    let bob_result = read_bytes(
        &context,
        &BytesReadOpts {
            relative: PathBuf::from("docs/bob_only.bin"),
            identity: Some("bob@example.org".into()),
            require_envelope: true,
        },
    );
    assert!(bob_result.is_ok(), "Bob should be able to decrypt");
    assert_eq!(
        bob_result.unwrap().plaintext,
        payload,
        "Bob should get correct plaintext"
    );

    // Alice CANNOT decrypt (she's the sender but not in recipients list)
    let alice_result = read_bytes(
        &context,
        &BytesReadOpts {
            relative: PathBuf::from("docs/bob_only.bin"),
            identity: Some("alice@example.org".into()),
            require_envelope: true,
        },
    );
    assert!(
        alice_result.is_err(),
        "Alice should NOT be able to decrypt (not in recipients list)"
    );
}

#[test]
fn test_replay_protection_rejects_older_envelope_for_same_path() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice@example.org");

    let relative = PathBuf::from("docs/replay.bin");

    // First envelope (older)
    write_bytes(
        &context,
        &BytesWriteOpts {
            relative: relative.clone(),
            recipients: vec!["alice@example.org".into()],
            sender: Some("alice@example.org".into()),
            plaintext: false,
            overwrite: false,
            hint: None,
        },
        b"older payload",
    )
    .unwrap();
    let old_cipher = fs::read(context.data_root.join(&relative)).unwrap();

    // Ensure created_at changes between envelopes.
    thread::sleep(Duration::from_secs(1));

    // Second envelope (newer)
    write_bytes(
        &context,
        &BytesWriteOpts {
            relative: relative.clone(),
            recipients: vec!["alice@example.org".into()],
            sender: Some("alice@example.org".into()),
            plaintext: false,
            overwrite: true,
            hint: None,
        },
        b"new payload",
    )
    .unwrap();

    // Reading newer payload initializes replay cache for this path.
    let newer = read_bytes(
        &context,
        &BytesReadOpts {
            relative: relative.clone(),
            identity: Some("alice@example.org".into()),
            require_envelope: true,
        },
    )
    .unwrap();
    assert_eq!(newer.plaintext, b"new payload");

    // Replay attacker swaps file back to the older envelope.
    fs::write(context.data_root.join(&relative), &old_cipher).unwrap();
    let replay_attempt = read_bytes(
        &context,
        &BytesReadOpts {
            relative,
            identity: Some("alice@example.org".into()),
            require_envelope: true,
        },
    );
    assert!(
        replay_attempt.is_err(),
        "replayed envelope should be rejected"
    );
}
