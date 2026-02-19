use super::*;
use std::fs;
use tempfile::tempdir;

fn setup_paths() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let base = tempdir().unwrap();
    let vault = base.path().join("vault");
    let data = base.path().join("data");
    let shadow = base.path().join("shadow");
    fs::create_dir_all(&vault).unwrap();
    fs::create_dir_all(&data).unwrap();
    fs::create_dir_all(&shadow).unwrap();
    (base, vault, data, shadow)
}

#[test]
fn run_with_args_executes_successful_command() {
    let (_tmp, vault, data, shadow) = setup_paths();
    let args = vec![
        "sbc",
        "--vault",
        vault.to_str().unwrap(),
        "--data-root",
        data.to_str().unwrap(),
        "--shadow-root",
        shadow.to_str().unwrap(),
        "key",
        "list",
    ];

    run_with_args(args).unwrap();
}

#[test]
fn run_with_args_propagates_command_errors() {
    let (_tmp, vault, data, shadow) = setup_paths();
    let src = data.join("cipher.bin");
    fs::write(&src, b"not encrypted").unwrap();
    let dest = shadow.join("plain.txt");

    let args = vec![
        "sbc",
        "--vault",
        vault.to_str().unwrap(),
        "--data-root",
        data.to_str().unwrap(),
        "--shadow-root",
        shadow.to_str().unwrap(),
        "file",
        "decrypt",
        "--identity",
        "alice",
        "--src",
        src.to_str().unwrap(),
        "--dest",
        dest.to_str().unwrap(),
    ];

    let err = run_with_args(args).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("is not an SBC envelope"));
}

#[test]
fn run_with_cli_uses_provided_struct() {
    let (_tmp, vault, data, shadow) = setup_paths();
    let cli = Cli::parse_from([
        "sbc",
        "--vault",
        vault.to_str().unwrap(),
        "--data-root",
        data.to_str().unwrap(),
        "--shadow-root",
        shadow.to_str().unwrap(),
        "key",
        "list",
    ]);
    run_with_cli(cli).unwrap();
}
