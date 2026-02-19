use super::*;
use std::fs;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn resolve_vault_prefers_flag_over_env() {
    let vault_flag = PathBuf::from("~/sbc-flag");
    let resolved = resolve_vault(Some(vault_flag.clone()));
    assert_eq!(resolved, expand_home(vault_flag));
}

#[test]
fn resolve_vault_defaults_to_home_directory() {
    let expected = default_vault_path();
    assert_eq!(resolve_vault(None), expected);
}

#[test]
fn resolve_roots_errors_without_any_sources() {
    let vault = tempdir().unwrap();
    let err = resolve_roots(None, None, vault.path()).unwrap_err();
    assert!(err.to_string().contains("unable to determine data root"));
}

#[test]
fn resolve_roots_requires_shadow_source() {
    let dir = tempdir().unwrap();
    let data_override = dir.path().join("data");
    let err = resolve_roots(Some(data_override), None, dir.path()).unwrap_err();
    assert!(err.to_string().contains("shadow root"));
}

#[test]
fn resolve_roots_prefers_overrides() {
    let vault = tempdir().unwrap();
    let data_override = vault.path().join("data-override");
    let shadow_override = vault.path().join("shadow-override");
    let (data_root, shadow_root) = resolve_roots(
        Some(data_override.clone()),
        Some(shadow_override.clone()),
        vault.path(),
    )
    .unwrap();
    assert_eq!(data_root, data_override);
    assert_eq!(shadow_root, shadow_override);
}

#[test]
fn resolve_roots_reads_from_config() {
    let dir = tempdir().unwrap();
    let vault = dir.path();
    let config_dir = vault.join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("datasite.json");
    let json_body = serde_json::json!({
        "encrypted_root": "encrypted",
        "shadow_root": "~/shadow"
    });
    std::fs::write(&config_path, serde_json::to_string(&json_body).unwrap()).unwrap();

    let expected_shadow_expanded = expand_home("~/shadow");
    let expected_shadow = if expected_shadow_expanded.is_absolute() {
        expected_shadow_expanded.clone()
    } else {
        vault.join(expected_shadow_expanded.clone())
    };
    let expected_shadow = std::fs::canonicalize(&expected_shadow).unwrap_or(expected_shadow);

    let (data_root, shadow_root) = resolve_roots(None, None, vault).unwrap();
    assert!(data_root.ends_with("encrypted"));
    assert_eq!(shadow_root, expected_shadow);
}

#[test]
fn ensure_vault_layout_creates_directories() {
    let vault = tempdir().unwrap();
    ensure_vault_layout(vault.path()).unwrap();
    assert!(vault.path().join("keys").is_dir());
    assert!(vault.path().join("bundles").is_dir());
    assert!(!vault.path().join("cache").exists());
}

#[test]
fn resolve_data_and_shadow_paths_support_relative_and_absolute() {
    let dir = tempdir().unwrap();
    let context = AppContext {
        vault_path: dir.path().join("vault"),
        data_root: dir.path().join("data"),
        shadow_root: dir.path().join("shadow"),
    };

    let absolute = dir.path().join("file.txt");
    assert_eq!(resolve_data_path(&context, &absolute), absolute);
    assert_eq!(
        resolve_data_path(&context, Path::new("relative.txt")),
        context.data_root.join("relative.txt")
    );
    assert_eq!(
        resolve_shadow_path(&context, Path::new("plain.txt")),
        context.shadow_root.join("plain.txt")
    );
}

#[test]
fn expand_home_supports_tilde_forms() {
    let expected_home = home_dir().unwrap_or_else(|| PathBuf::from("~"));
    if let Some(home) = home_dir() {
        assert_eq!(expand_home("~"), home);
        assert_eq!(expand_home("~/docs"), home.join("docs"));
    } else {
        assert_eq!(expand_home("~"), expected_home);
        assert_eq!(expand_home("~/docs"), PathBuf::from("~/docs"));
    }
}

#[test]
fn yes_no_returns_expected_values() {
    assert_eq!(yes_no(true), "yes");
    assert_eq!(yes_no(false), "no");
}

#[test]
fn key_path_for_identity_sanitizes_input() {
    let vault = Path::new("/tmp/vault");
    let path = key_path_for_identity(vault, "user@example.com");
    assert!(path.ends_with("user@example.com.key"));

    let sanitized = key_path_for_identity(vault, "User Name!");
    assert!(sanitized.ends_with("User_Name_.key"));
}

#[test]
fn read_identity_from_key_parses_prefixed_line() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("test.key");
    let generated = crate::protocol_interface::generate_identity_material("alice").unwrap();
    std::fs::write(&key_path, generated.key_file).unwrap();
    let identity = read_identity_from_key(key_path).unwrap();
    assert_eq!(identity, "alice");
}

#[test]
fn read_identity_from_key_errors_on_missing_prefix() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("invalid.key");
    std::fs::write(&key_path, "no-prefix").unwrap();
    let err = read_identity_from_key(key_path).unwrap_err();
    assert!(err.to_string().contains("unable to parse identity"));
}

#[test]
fn fallback_identity_from_path_uses_stem() {
    let identity = fallback_identity_from_path(PathBuf::from("/tmp/alice.key"));
    assert_eq!(identity, "alice");
}

#[test]
fn detect_single_identity_reports_expected_cases() {
    let dir = tempdir().unwrap();
    let vault = dir.path();
    ensure_vault_layout(vault).unwrap();

    let err = detect_single_identity(vault).unwrap_err();
    assert!(err.to_string().contains("no identities found"));

    let alice_path = key_path_for_identity(vault, "alice");
    let alice_generated = crate::protocol_interface::generate_identity_material("alice").unwrap();
    std::fs::write(&alice_path, alice_generated.key_file).unwrap();
    let identity = detect_single_identity(vault).unwrap();
    assert_eq!(identity, "alice");

    let bob_path = key_path_for_identity(vault, "bob");
    let bob_generated = crate::protocol_interface::generate_identity_material("bob").unwrap();
    std::fs::write(&bob_path, bob_generated.key_file).unwrap();
    let err = detect_single_identity(vault).unwrap_err();
    assert!(err.to_string().contains("multiple identities"));
}

#[test]
fn detect_single_identity_uses_fallback_when_parse_fails() {
    let dir = tempdir().unwrap();
    let vault = dir.path();
    fs::create_dir_all(vault.join("keys")).unwrap();
    let key_path = vault.join("keys/raw.key");
    std::fs::write(&key_path, b"garbage").unwrap();
    let identity = detect_single_identity(vault).unwrap();
    assert_eq!(identity, "raw");
}

#[test]
fn atomic_write_replaces_existing_content() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("data.bin");
    atomic_write(&file_path, b"first").unwrap();
    atomic_write(&file_path, b"second").unwrap();
    let contents = std::fs::read(&file_path).unwrap();
    assert_eq!(contents, b"second");
}

#[test]
fn atomic_write_creates_parent_directories() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("nested/deeper/output.txt");
    atomic_write(&file_path, b"bytes").unwrap();
    assert_eq!(std::fs::read(&file_path).unwrap(), b"bytes");
}

#[test]
fn read_datasite_config_handles_missing_file() {
    let dir = tempdir().unwrap();
    let config = read_datasite_config(dir.path()).unwrap();
    assert!(config.is_none());
}

#[test]
fn read_datasite_config_parses_paths() {
    let dir = tempdir().unwrap();
    let vault = dir.path();
    let config_dir = vault.join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("datasite.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "encrypted_root": "encrypted",
            "shadow_root": "shadow"
        }))
        .unwrap(),
    )
    .unwrap();

    let cfg = read_datasite_config(vault).unwrap().unwrap();
    assert!(cfg.encrypted_root.ends_with("encrypted"));
    assert!(cfg.shadow_root.ends_with("shadow"));
}

#[test]
fn resolve_config_path_supports_relative_and_absolute() {
    let dir = tempdir().unwrap();
    let vault = dir.path();
    let relative = PathBuf::from("relative/path");
    let resolved_relative = resolve_config_path(vault, relative.clone()).unwrap();
    assert!(resolved_relative.ends_with("relative/path"));

    let absolute = dir.path().join("abs");
    std::fs::create_dir_all(&absolute).unwrap();
    let file = absolute.join("f.txt");
    let mut handle = std::fs::File::create(&file).unwrap();
    writeln!(handle, "hello").unwrap();
    let resolved_absolute = resolve_config_path(vault, file.clone()).unwrap();
    assert_eq!(resolved_absolute, std::fs::canonicalize(&file).unwrap());
}

#[test]
fn default_vault_path_uses_home_when_available() {
    let expected = home_dir()
        .map(|home| home.join(".sbc"))
        .unwrap_or_else(|| PathBuf::from(".sbc"));
    assert_eq!(default_vault_path(), expected);
}

#[test]
fn sanitize_identity_replaces_unsupported_characters() {
    assert_eq!(sanitize_identity("Alice!"), "Alice_");
    assert_eq!(sanitize_identity("bob_smith"), "bob_smith");
}

#[test]
fn make_temp_path_places_file_next_to_target() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("output.bin");
    let temp = make_temp_path(&target);
    assert_eq!(temp.parent(), Some(dir.path()));
    assert!(
        temp.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".output.bin.")
    );
}
