use super::*;
use crate::app::bundle_path_for_identity;
use crate::protocol_interface;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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

#[test]
fn key_generate_dry_run_is_non_destructive() {
    let (_tmp, context) = setup_context();
    let args = KeyGenerateArgs {
        identity: "alice".into(),
        bundle_out: None,
        overwrite: false,
        dry_run: true,
    };
    handle_key_command(&context, KeyCommand::Generate(args)).unwrap();
    assert!(!context.vault_path.join("keys/alice.key").exists());
}

#[test]
fn key_generate_writes_key_and_bundle() {
    let (_tmp, context) = setup_context();
    let args = KeyGenerateArgs {
        identity: "bob".into(),
        bundle_out: Some(PathBuf::from("bundles/bob.json")),
        overwrite: false,
        dry_run: false,
    };
    handle_key_command(&context, KeyCommand::Generate(args)).unwrap();
    assert!(context.vault_path.join("keys/bob.key").exists());
    assert!(context.data_root.join("bundles/bob.json").exists());
}

#[cfg(unix)]
#[test]
fn key_generate_writes_private_key_with_owner_only_permissions() {
    let (_tmp, context) = setup_context();
    handle_key_command(
        &context,
        KeyCommand::Generate(KeyGenerateArgs {
            identity: "perm-test".into(),
            bundle_out: None,
            overwrite: false,
            dry_run: false,
        }),
    )
    .unwrap();

    let key_path = context.vault_path.join("keys/perm-test.key");
    let mode = fs::metadata(key_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn key_generate_creates_nested_bundle_directories() {
    let (_tmp, context) = setup_context();
    let args = KeyGenerateArgs {
        identity: "dave".into(),
        bundle_out: Some(PathBuf::from("nested/dirs/dave.json")),
        overwrite: true,
        dry_run: false,
    };
    handle_key_command(&context, KeyCommand::Generate(args)).unwrap();
    assert!(context.data_root.join("nested/dirs/dave.json").exists());
}

#[test]
fn key_generate_requires_overwrite_for_existing_material() {
    let (_tmp, context) = setup_context();
    handle_key_command(
        &context,
        KeyCommand::Generate(KeyGenerateArgs {
            identity: "carol".into(),
            bundle_out: None,
            overwrite: false,
            dry_run: false,
        }),
    )
    .unwrap();
    let err = handle_key_command(
        &context,
        KeyCommand::Generate(KeyGenerateArgs {
            identity: "carol".into(),
            bundle_out: None,
            overwrite: false,
            dry_run: false,
        }),
    )
    .unwrap_err();
    assert!(err.to_string().contains("key material already exists"));
}

#[test]
fn key_import_verify_only_does_not_write_bundle() {
    let (_tmp, context) = setup_context();
    let bundle_path = context.data_root.join("bundle.json");
    let generated = protocol_interface::generate_identity_material("alice@example.org").unwrap();
    let mut body = serde_json::to_vec_pretty(&generated.public_bundle).unwrap();
    body.push(b'\n');
    fs::write(&bundle_path, &body).unwrap();
    let args = KeyImportArgs {
        bundle: PathBuf::from("bundle.json"),
        expected_identity: Some("alice@example.org".into()),
        verify_only: true,
        force: false,
    };
    handle_key_command(&context, KeyCommand::Import(args)).unwrap();
    let cached = bundle_path_for_identity(&context.vault_path, "alice@example.org");
    assert!(!cached.exists());
}

#[test]
fn key_import_persists_bundle_when_not_verify_only() {
    let (_tmp, context) = setup_context();
    let bundle_path = context.data_root.join("bundle.json");
    let generated = protocol_interface::generate_identity_material("bob@example.org").unwrap();
    let mut body = serde_json::to_vec_pretty(&generated.public_bundle).unwrap();
    body.push(b'\n');
    fs::write(&bundle_path, &body).unwrap();
    let args = KeyImportArgs {
        bundle: PathBuf::from("bundle.json"),
        expected_identity: None,
        verify_only: false,
        force: false,
    };
    handle_key_command(&context, KeyCommand::Import(args)).unwrap();
    let cached = bundle_path_for_identity(&context.vault_path, "bob@example.org");
    assert!(cached.exists());
}

#[test]
fn key_import_identity_mismatch_requires_force() {
    let (_tmp, context) = setup_context();
    let bundle_path = context.data_root.join("bundle.json");
    let generated = protocol_interface::generate_identity_material("carol@example.org").unwrap();
    let mut body = serde_json::to_vec_pretty(&generated.public_bundle).unwrap();
    body.push(b'\n');
    fs::write(&bundle_path, &body).unwrap();

    let err = handle_key_command(
        &context,
        KeyCommand::Import(KeyImportArgs {
            bundle: PathBuf::from("bundle.json"),
            expected_identity: Some("dave@example.org".into()),
            verify_only: false,
            force: false,
        }),
    )
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("does not match expected"));

    handle_key_command(
        &context,
        KeyCommand::Import(KeyImportArgs {
            bundle: PathBuf::from("bundle.json"),
            expected_identity: Some("dave@example.org".into()),
            verify_only: false,
            force: true,
        }),
    )
    .unwrap();

    let cached = bundle_path_for_identity(&context.vault_path, "carol@example.org");
    assert!(cached.exists());
}

#[test]
fn key_import_requires_force_when_cached_fingerprint_differs() {
    let (_tmp, context) = setup_context();
    let baseline = protocol_interface::generate_identity_material("erin@example.org").unwrap();
    let base_path = context.data_root.join("erin.json");
    let mut baseline_body = serde_json::to_vec_pretty(&baseline.public_bundle).unwrap();
    baseline_body.push(b'\n');
    fs::write(&base_path, &baseline_body).unwrap();

    handle_key_command(
        &context,
        KeyCommand::Import(KeyImportArgs {
            bundle: PathBuf::from("erin.json"),
            expected_identity: None,
            verify_only: false,
            force: false,
        }),
    )
    .unwrap();

    // Generate a second bundle for the same identity (new fingerprint).
    let updated = protocol_interface::generate_identity_material("erin@example.org").unwrap();
    let mut updated_body = serde_json::to_vec_pretty(&updated.public_bundle).unwrap();
    updated_body.push(b'\n');
    let updated_path = context.data_root.join("erin-updated.json");
    fs::write(&updated_path, &updated_body).unwrap();

    let err = handle_key_command(
        &context,
        KeyCommand::Import(KeyImportArgs {
            bundle: PathBuf::from("erin-updated.json"),
            expected_identity: Some("erin@example.org".into()),
            verify_only: false,
            force: false,
        }),
    )
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("requires --force"));

    handle_key_command(
        &context,
        KeyCommand::Import(KeyImportArgs {
            bundle: PathBuf::from("erin-updated.json"),
            expected_identity: Some("erin@example.org".into()),
            verify_only: false,
            force: true,
        }),
    )
    .unwrap();

    let cached_path = bundle_path_for_identity(&context.vault_path, "erin@example.org");
    let cached_body = fs::read_to_string(cached_path).unwrap();
    let cached_json: Value = serde_json::from_str(&cached_body).unwrap();
    assert_eq!(
        cached_json
            .get("identity_fingerprint")
            .and_then(Value::as_str),
        updated
            .public_bundle
            .get("identity_fingerprint")
            .and_then(Value::as_str)
    );
}

#[test]
fn key_recover_is_non_destructive_noop() {
    let (_tmp, context) = setup_context();
    let package = context.data_root.join("package.zip");
    fs::write(&package, b"archive").unwrap();
    let args = KeyRecoverArgs {
        package,
        identity: Some("alice".into()),
        output: Some(PathBuf::from("out")),
        dry_run: true,
    };
    handle_key_command(&context, KeyCommand::Recover(args)).unwrap();
}

#[test]
fn key_list_outputs_identities_even_with_filter() {
    let (_tmp, context) = setup_context();
    ensure_vault_layout(&context.vault_path).unwrap();
    let alice = key_path_for_identity(&context.vault_path, "alice");
    let bob = key_path_for_identity(&context.vault_path, "bob");
    let alice_material = protocol_interface::generate_identity_material("alice").unwrap();
    let bob_material = protocol_interface::generate_identity_material("bob").unwrap();
    fs::write(&alice, alice_material.key_file).unwrap();
    fs::write(&bob, bob_material.key_file).unwrap();

    let list_all = KeyListArgs {
        identity: None,
        verbose: true,
    };
    handle_key_command(&context, KeyCommand::List(list_all)).unwrap();

    let list_single = KeyListArgs {
        identity: Some("alice".into()),
        verbose: false,
    };
    handle_key_command(&context, KeyCommand::List(list_single)).unwrap();
}

#[test]
fn key_list_reports_empty_vault() {
    let (_tmp, context) = setup_context();
    ensure_vault_layout(&context.vault_path).unwrap();
    let args = KeyListArgs {
        identity: None,
        verbose: false,
    };
    handle_key_command(&context, KeyCommand::List(args)).unwrap();
}

#[test]
fn key_verify_handles_json_mode() {
    let (_tmp, context) = setup_context();
    let bundle_path = context.data_root.join("bundle.json");
    let generated = protocol_interface::generate_identity_material("alice@example.org").unwrap();
    let mut body = serde_json::to_vec_pretty(&generated.public_bundle).unwrap();
    body.push(b'\n');
    fs::write(&bundle_path, &body).unwrap();
    let args = KeyVerifyArgs {
        bundle: PathBuf::from("bundle.json"),
        expected_identity: Some("alice@example.org".into()),
        verify_only: false,
        json: true,
    };
    handle_key_command(&context, KeyCommand::Verify(args)).unwrap();
}

#[test]
fn key_verify_warns_when_expected_identity_missing() {
    let (_tmp, context) = setup_context();
    let bundle_path = context.data_root.join("bundle.json");
    let generated = protocol_interface::generate_identity_material("carol@example.org").unwrap();
    let mut body = serde_json::to_vec_pretty(&generated.public_bundle).unwrap();
    body.push(b'\n');
    fs::write(&bundle_path, &body).unwrap();
    let args = KeyVerifyArgs {
        bundle: PathBuf::from("bundle.json"),
        expected_identity: Some("alice@example.org".into()),
        verify_only: false,
        json: false,
    };
    handle_key_command(&context, KeyCommand::Verify(args)).unwrap();
}

#[cfg(unix)]
#[test]
fn key_backup_and_restore_preserve_owner_only_permissions() {
    let (_tmp, context) = setup_context();
    handle_key_command(
        &context,
        KeyCommand::Generate(KeyGenerateArgs {
            identity: "alice".into(),
            bundle_out: None,
            overwrite: false,
            dry_run: false,
        }),
    )
    .unwrap();

    let backup_path = context.data_root.join("alice-backup.key");
    handle_key_command(
        &context,
        KeyCommand::Backup(KeyBackupArgs {
            identity: "alice".into(),
            output: backup_path.clone(),
            overwrite: false,
        }),
    )
    .unwrap();
    let backup_mode = fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(backup_mode, 0o600);

    // Restore as a different logical identity by overriding expected identity.
    handle_key_command(
        &context,
        KeyCommand::Restore(KeyRestoreArgs {
            input: backup_path,
            identity: Some("alice".into()),
            overwrite: true,
        }),
    )
    .unwrap();
    let restored = context.vault_path.join("keys/alice.key");
    let restored_mode = fs::metadata(restored).unwrap().permissions().mode() & 0o777;
    assert_eq!(restored_mode, 0o600);
}
