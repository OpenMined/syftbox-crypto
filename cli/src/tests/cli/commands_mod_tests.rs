use super::*;
use crate::commands::file::{
    FileCommand as FileSubcommand, FileEncryptArgs, FileInspectArgs, handle_file_command,
};
use crate::commands::key::KeyRecoverArgs;
use crate::protocol_interface;
use std::fs;
use std::path::PathBuf;
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
fn handle_command_routes_key_variant() {
    let (_tmp, context) = setup_context();
    let args = KeyRecoverArgs {
        package: PathBuf::from("package.zip"),
        identity: None,
        output: None,
        dry_run: true,
    };
    handle_command(&context, Command::Key(KeyCommand::Recover(args))).unwrap();
}

#[test]
fn handle_command_routes_file_variant() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    write_identity(&context, "bob");

    let plaintext = context.shadow_root.join("blob.txt");
    fs::create_dir_all(plaintext.parent().unwrap()).unwrap();
    fs::write(&plaintext, b"bytes").unwrap();

    handle_file_command(
        &context,
        FileSubcommand::Encrypt(FileEncryptArgs {
            relative: Some(PathBuf::from("blob.txt")),
            src: None,
            dest: None,
            sender: Some("alice".into()),
            recipient: Some("bob".into()),
            dry_run: false,
        }),
    )
    .unwrap();

    let args = FileInspectArgs {
        input: PathBuf::from("blob.txt"),
        identity: None,
        verbose: false,
    };

    handle_command(&context, Command::File(FileCommand::Inspect(args))).unwrap();
}
