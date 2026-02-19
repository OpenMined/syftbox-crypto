use super::*;
use crate::protocol_interface;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;
use syftbox_crypto_protocol::{
    FILE_CIPHER_SUITE,
    envelope::{has_sbc_magic, parse_envelope},
};

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
    let bundles_dir = context.vault_path.join("bundles");
    fs::create_dir_all(&bundles_dir).unwrap();

    let material = protocol_interface::generate_identity_material(identity).unwrap();

    let key_path = keys_dir.join(format!("{}.key", identity));
    fs::write(&key_path, &material.key_file).unwrap();

    let bundle_path = bundles_dir.join(format!("{}.json", identity));
    let mut bundle_body = serde_json::to_vec_pretty(&material.public_bundle).unwrap();
    bundle_body.push(b'\n');
    fs::write(&bundle_path, bundle_body).unwrap();
}

#[test]
fn encrypt_relative_writes_envelope() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    write_identity(&context, "bob");
    let relative = PathBuf::from("docs/note.txt");
    let shadow_file = context.shadow_root.join(&relative);
    fs::create_dir_all(shadow_file.parent().unwrap()).unwrap();
    fs::write(&shadow_file, b"secret").unwrap();

    let args = FileEncryptArgs {
        relative: Some(relative.clone()),
        src: None,
        dest: None,
        sender: Some("alice".into()),
        recipient: Some("bob".into()),
        dry_run: false,
    };

    handle_file_command(&context, FileCommand::Encrypt(args)).unwrap();
    let envelope_bytes = fs::read(context.data_root.join(&relative)).unwrap();
    assert!(has_sbc_magic(&envelope_bytes));
    let parsed = parse_envelope(&envelope_bytes).unwrap();
    assert_eq!(parsed.prelude.sender.identity, "alice");
    assert_eq!(
        parsed.prelude.recipients[0].identity.as_deref(),
        Some("bob")
    );
    assert_eq!(parsed.prelude.cipher.suite, FILE_CIPHER_SUITE);
}

#[test]
fn encrypt_direct_mode_honors_dry_run() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    write_identity(&context, "bob");
    let src = context.shadow_root.join("input.txt");
    fs::write(&src, b"plain").unwrap();
    let dest = context.data_root.join("output.bin");

    let args = FileEncryptArgs {
        relative: None,
        src: Some(src.clone()),
        dest: Some(dest.clone()),
        sender: Some("alice".into()),
        recipient: Some("bob".into()),
        dry_run: true,
    };

    handle_file_command(&context, FileCommand::Encrypt(args)).unwrap();
    assert!(!dest.exists());
}

#[test]
fn encrypt_relative_mode_honors_dry_run() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    write_identity(&context, "bob");
    let relative = PathBuf::from("docs/note.txt");
    let shadow_file = context.shadow_root.join(&relative);
    fs::create_dir_all(shadow_file.parent().unwrap()).unwrap();
    fs::write(&shadow_file, b"secret").unwrap();

    let args = FileEncryptArgs {
        relative: Some(relative.clone()),
        src: None,
        dest: None,
        sender: Some("alice".into()),
        recipient: Some("bob".into()),
        dry_run: true,
    };

    handle_file_command(&context, FileCommand::Encrypt(args)).unwrap();
    assert!(
        !context.data_root.join(relative).exists(),
        "ciphertext should not be written during dry-run"
    );
}

#[test]
fn encrypt_direct_writes_ciphertext_with_detected_identity() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    write_identity(&context, "bob");
    let src = context.shadow_root.join("message.txt");
    fs::write(&src, b"top secret").unwrap();
    let dest = context.data_root.join("cipher.bin");

    let args = FileEncryptArgs {
        relative: None,
        src: Some(src.clone()),
        dest: Some(dest.clone()),
        sender: Some("alice".into()),
        recipient: Some("bob".into()),
        dry_run: false,
    };

    handle_file_command(&context, FileCommand::Encrypt(args)).unwrap();
    let envelope_bytes = fs::read(&dest).unwrap();
    assert!(has_sbc_magic(&envelope_bytes));
    let parsed = parse_envelope(&envelope_bytes).unwrap();
    assert_eq!(parsed.prelude.sender.identity, "alice");
    assert_eq!(parsed.prelude.cipher.suite, FILE_CIPHER_SUITE);
}

#[test]
fn encrypt_direct_requires_destination_path() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    write_identity(&context, "bob");
    let src = context.shadow_root.join("message.txt");
    fs::write(&src, b"secret").unwrap();

    let args = FileEncryptArgs {
        relative: None,
        src: Some(src),
        dest: None,
        sender: Some("alice".into()),
        recipient: Some("bob".into()),
        dry_run: false,
    };

    let err = handle_file_command(&context, FileCommand::Encrypt(args)).unwrap_err();
    assert!(
        err.to_string().contains("--dest or --relative is required"),
        "unexpected error: {err}"
    );
}

#[test]
fn decrypt_relative_recovers_plaintext() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    write_identity(&context, "bob");
    let relative = PathBuf::from("docs/note.txt");
    let shadow_file = context.shadow_root.join(&relative);
    fs::create_dir_all(shadow_file.parent().unwrap()).unwrap();
    fs::write(&shadow_file, b"cipher").unwrap();

    handle_file_command(
        &context,
        FileCommand::Encrypt(FileEncryptArgs {
            relative: Some(relative.clone()),
            src: None,
            dest: None,
            sender: Some("alice".into()),
            recipient: Some("bob".into()),
            dry_run: false,
        }),
    )
    .unwrap();

    // remove original plaintext to ensure decrypt recreates it
    fs::remove_file(&shadow_file).unwrap();

    let args = FileDecryptArgs {
        relative: Some(relative.clone()),
        src: None,
        dest: None,
        identity: Some("bob".into()),
        dry_run: false,
    };

    handle_file_command(&context, FileCommand::Decrypt(args)).unwrap();
    let plaintext = fs::read(context.shadow_root.join(&relative)).unwrap();
    assert_eq!(plaintext, b"cipher");
}

#[test]
fn decrypt_relative_dry_run_skips_writes() {
    let (_tmp, context) = setup_context();
    let relative = PathBuf::from("docs/note.txt");

    let args = FileDecryptArgs {
        relative: Some(relative.clone()),
        src: None,
        dest: None,
        identity: Some("alice".into()),
        dry_run: true,
    };

    handle_file_command(&context, FileCommand::Decrypt(args)).unwrap();
    assert!(
        !context.shadow_root.join(relative).exists(),
        "no plaintext should be written during dry-run"
    );
}

#[test]
fn decrypt_relative_warns_on_plaintext_payload() {
    let (_tmp, context) = setup_context();
    let relative = PathBuf::from("docs/note.txt");
    let data_file = context.data_root.join(&relative);
    fs::create_dir_all(data_file.parent().unwrap()).unwrap();
    fs::write(&data_file, b"unencrypted").unwrap();

    let args = FileDecryptArgs {
        relative: Some(relative.clone()),
        src: None,
        dest: None,
        identity: Some("alice".into()),
        dry_run: false,
    };

    handle_file_command(&context, FileCommand::Decrypt(args)).unwrap();
    let plaintext = fs::read(context.shadow_root.join(&relative)).unwrap();
    assert_eq!(plaintext, b"unencrypted");
}

#[test]
fn decrypt_direct_fails_without_placeholder_header() {
    let (_tmp, context) = setup_context();
    let src = context.data_root.join("enc.bin");
    let dest = context.shadow_root.join("plain.txt");
    fs::write(&src, b"no-header").unwrap();

    let args = FileDecryptArgs {
        relative: None,
        src: Some(src.clone()),
        dest: Some(dest.clone()),
        identity: Some("alice".into()),
        dry_run: false,
    };

    let err = handle_file_command(&context, FileCommand::Decrypt(args)).unwrap_err();
    assert!(
        err.to_string().contains("is not an SBC envelope"),
        "unexpected error: {}",
        err
    );
    assert!(!dest.exists());
}

#[test]
fn inspect_reads_file_metadata() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    write_identity(&context, "bob");
    let plaintext = context.shadow_root.join("note.txt");
    fs::create_dir_all(plaintext.parent().unwrap()).unwrap();
    fs::write(&plaintext, b"metadata test").unwrap();

    handle_file_command(
        &context,
        FileCommand::Encrypt(FileEncryptArgs {
            relative: Some(PathBuf::from("note.txt")),
            src: None,
            dest: None,
            sender: Some("alice".into()),
            recipient: Some("bob".into()),
            dry_run: false,
        }),
    )
    .unwrap();

    let args = FileInspectArgs {
        input: PathBuf::from("note.txt"),
        identity: Some("alice".into()),
        verbose: true,
    };

    handle_file_command(&context, FileCommand::Inspect(args)).unwrap();
}

#[test]
fn decrypt_direct_dry_run_skips_outputs() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    write_identity(&context, "bob");

    let plaintext = context.shadow_root.join("message.txt");
    fs::write(&plaintext, b"hello").unwrap();
    let cipher_path = context.data_root.join("cipher.bin");

    handle_file_command(
        &context,
        FileCommand::Encrypt(FileEncryptArgs {
            relative: None,
            src: Some(plaintext.clone()),
            dest: Some(cipher_path.clone()),
            sender: Some("alice".into()),
            recipient: Some("bob".into()),
            dry_run: false,
        }),
    )
    .unwrap();

    let dest = context.shadow_root.join("plain.txt");

    let args = FileDecryptArgs {
        relative: None,
        src: Some(cipher_path),
        dest: Some(dest.clone()),
        identity: Some("bob".into()),
        dry_run: true,
    };

    handle_file_command(&context, FileCommand::Decrypt(args)).unwrap();
    assert!(!dest.exists());
}
