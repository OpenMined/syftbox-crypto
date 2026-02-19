use super::*;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use tar::Archive;
use tar::{Builder, EntryType, Header};
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

#[test]
fn vault_export_creates_archive_with_contents() {
    let (_tmp, context) = setup_context();
    ensure_vault_layout(&context.vault_path).unwrap();
    let key_path = context.vault_path.join("keys/demo.key");
    fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    fs::write(&key_path, b"{\"identity\":\"demo\"}").unwrap();

    let archive_path = context.data_root.join("vault.tar.gz");
    handle_vault_command(
        &context,
        VaultCommand::Export(VaultExportArgs {
            output: archive_path.clone(),
            overwrite: false,
        }),
    )
    .unwrap();
    assert!(archive_path.exists());

    let file = fs::File::open(&archive_path).unwrap();
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    let mut found_key = false;
    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().unwrap();
        if path
            .components()
            .any(|component| component.as_os_str() == "demo.key")
        {
            found_key = true;
            break;
        }
    }
    assert!(found_key, "expected demo.key to be present in archive");
}

#[test]
fn vault_import_restores_snapshot() {
    let (_tmp, context) = setup_context();
    // Seed vault and export snapshot.
    ensure_vault_layout(&context.vault_path).unwrap();
    let key_path = context.vault_path.join("keys/demo.key");
    fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    fs::write(&key_path, b"{\"identity\":\"demo\"}").unwrap();
    let archive_path = context.data_root.join("vault.tar.gz");
    handle_vault_command(
        &context,
        VaultCommand::Export(VaultExportArgs {
            output: archive_path.clone(),
            overwrite: false,
        }),
    )
    .unwrap();

    // Clear vault and import snapshot.
    fs::remove_dir_all(&context.vault_path).unwrap();
    fs::create_dir(&context.vault_path).unwrap();
    handle_vault_command(
        &context,
        VaultCommand::Import(VaultImportArgs {
            archive: archive_path.clone(),
            force: false,
        }),
    )
    .unwrap();

    assert!(context.vault_path.join("keys/demo.key").exists());
}

#[test]
fn vault_import_requires_force_when_data_exists() {
    let (_tmp, context) = setup_context();
    ensure_vault_layout(&context.vault_path).unwrap();
    let archive_path = context.data_root.join("vault.tar.gz");
    // create empty snapshot
    handle_vault_command(
        &context,
        VaultCommand::Export(VaultExportArgs {
            output: archive_path.clone(),
            overwrite: false,
        }),
    )
    .unwrap();

    // Leave a marker in the vault and attempt import.
    let probe = context.vault_path.join("keys/probe");
    fs::create_dir_all(probe.parent().unwrap()).unwrap();
    fs::write(&probe, b"probe").unwrap();

    let err = handle_vault_command(
        &context,
        VaultCommand::Import(VaultImportArgs {
            archive: archive_path,
            force: false,
        }),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("already contains data"),
        "unexpected error: {err}"
    );
}

#[test]
fn vault_import_rejects_symlink_entries() {
    let (_tmp, context) = setup_context();
    ensure_vault_layout(&context.vault_path).unwrap();
    let archive_path = context.data_root.join("malicious.tar.gz");

    let file = fs::File::create(&archive_path).unwrap();
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(encoder);

    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Symlink);
    header.set_mode(0o777);
    header.set_size(0);
    header.set_cksum();
    builder
        .append_link(&mut header, "keys/link.key", "../outside")
        .unwrap();
    let encoder = builder.into_inner().unwrap();
    encoder.finish().unwrap();

    let err = handle_vault_command(
        &context,
        VaultCommand::Import(VaultImportArgs {
            archive: archive_path,
            force: true,
        }),
    )
    .unwrap_err();
    assert!(err.to_string().contains("unsupported archive entry type"));
}
