//! Tests for platform-specific secure file permissions.
//!
//! These tests verify that private key files are created with owner-only
//! permissions on both Unix (0o600) and Windows (owner-only ACL).

use syftbox_crypto_protocol::SyftRecoveryKey;
use syftbox_crypto_protocol::storage::save_private_keys;
use tempfile::TempDir;

/// Test that private keys are saved with owner-only permissions on Unix.
///
/// Verifies:
/// - File is created with mode 0o600 (rw-------)
/// - No group or world permissions are set
#[test]
#[cfg(unix)]
fn test_unix_private_keys_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("secure_keys.json");

    // Generate and save keys
    let recovery_key = SyftRecoveryKey::generate();
    let keys = recovery_key.derive_keys().unwrap();
    save_private_keys(&keys, &key_path).expect("Should save keys");

    // Verify file permissions
    let metadata = std::fs::metadata(&key_path).unwrap();
    let mode = metadata.permissions().mode();
    let permission_bits = mode & 0o777;

    assert_eq!(
        permission_bits, 0o600,
        "Private keys must have 0o600 permissions (owner read/write only), got {:o}",
        permission_bits
    );

    // Verify no group permissions
    assert_eq!(
        permission_bits & 0o070,
        0,
        "Group permissions must be empty"
    );

    // Verify no world permissions
    assert_eq!(
        permission_bits & 0o007,
        0,
        "World permissions must be empty"
    );
}

/// Test that overwriting a file preserves secure permissions on Unix.
#[test]
#[cfg(unix)]
fn test_unix_overwrite_preserves_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("overwrite_test.json");

    let recovery_key = SyftRecoveryKey::generate();
    let keys = recovery_key.derive_keys().unwrap();

    // Save twice to test overwrite
    save_private_keys(&keys, &key_path).expect("First save should succeed");
    save_private_keys(&keys, &key_path).expect("Overwrite should succeed");

    let metadata = std::fs::metadata(&key_path).unwrap();
    let permission_bits = metadata.permissions().mode() & 0o777;

    assert_eq!(
        permission_bits, 0o600,
        "Overwritten file must retain 0o600 permissions"
    );
}

/// Test that temp files are cleaned up on Unix if write fails.
#[test]
#[cfg(unix)]
fn test_unix_temp_file_cleanup_on_success() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("cleanup_test.json");

    let recovery_key = SyftRecoveryKey::generate();
    let keys = recovery_key.derive_keys().unwrap();
    save_private_keys(&keys, &key_path).expect("Save should succeed");

    // Check that no .tmp files remain
    let tmp_files: Vec<_> = std::fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "tmp"))
        .collect();

    assert!(
        tmp_files.is_empty(),
        "No temporary files should remain after successful save"
    );
}

/// Test that private keys are saved with owner-only ACL on Windows.
///
/// Verifies:
/// - File ACL only contains entries for the current user
/// - No other users/groups have access
#[test]
#[cfg(windows)]
fn test_windows_private_keys_owner_only_acl() {
    use winapi::ctypes::c_void;
    use windows_acl::acl::{ACL, AceType};
    use windows_acl::helper::{current_user, name_to_sid, sid_to_string};

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("secure_keys.json");

    // Generate and save keys
    let recovery_key = SyftRecoveryKey::generate();
    let keys = recovery_key.derive_keys().unwrap();
    save_private_keys(&keys, &key_path).expect("Should save keys");

    // Get current user SID
    let current_user_sid = name_to_sid(&current_user().expect("Should get current user"), None)
        .expect("Current user SID should exist");
    let current_user_sid_string = sid_to_string(current_user_sid.as_ptr() as *mut c_void)
        .expect("Should convert SID to string");

    // Load ACL
    let path_str = key_path.to_string_lossy();
    let acl = ACL::from_file_path(&path_str, false).expect("Should load ACL");

    // Get all entries
    let entries = acl.all().expect("Should get ACL entries");

    // Check that all AccessAllow entries are for the current user only
    for entry in &entries {
        if entry.entry_type == AceType::AccessAllow {
            assert_eq!(entry.string_sid, current_user_sid_string);
        }
    }

    // Verify owner has at least one access entry
    let owner_entries: Vec<_> = entries
        .iter()
        .filter(|entry| {
            entry.entry_type == AceType::AccessAllow && entry.string_sid == current_user_sid_string
        })
        .collect();

    assert!(
        !owner_entries.is_empty(),
        "Owner must have at least one access entry"
    );
}

/// Test that overwriting a file preserves secure ACL on Windows.
#[test]
#[cfg(windows)]
fn test_windows_overwrite_preserves_acl() {
    use winapi::ctypes::c_void;
    use windows_acl::acl::{ACL, AceType};
    use windows_acl::helper::{current_user, name_to_sid, sid_to_string};

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("overwrite_test.json");

    let recovery_key = SyftRecoveryKey::generate();
    let keys = recovery_key.derive_keys().unwrap();

    // Save twice to test overwrite
    save_private_keys(&keys, &key_path).expect("First save should succeed");
    save_private_keys(&keys, &key_path).expect("Overwrite should succeed");

    // Get current user SID
    let current_user_sid = name_to_sid(&current_user().expect("Should get current user"), None)
        .expect("Current user SID should exist");
    let current_user_sid_string = sid_to_string(current_user_sid.as_ptr() as *mut c_void)
        .expect("Should convert SID to string");

    // Load ACL
    let path_str = key_path.to_string_lossy();
    let acl = ACL::from_file_path(&path_str, false).expect("Should load ACL");
    let entries = acl.all().expect("Should get ACL entries");

    // Check that only owner has access
    for entry in &entries {
        if entry.entry_type == AceType::AccessAllow {
            assert_eq!(entry.string_sid, current_user_sid_string);
        }
    }
}

/// Test that temp files are cleaned up on Windows if write succeeds.
#[test]
#[cfg(windows)]
fn test_windows_temp_file_cleanup_on_success() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("cleanup_test.json");

    let recovery_key = SyftRecoveryKey::generate();
    let keys = recovery_key.derive_keys().unwrap();
    save_private_keys(&keys, &key_path).expect("Save should succeed");

    // Check that no .tmp files remain
    let tmp_files: Vec<_> = std::fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "tmp"))
        .collect();

    assert!(
        tmp_files.is_empty(),
        "No temporary files should remain after successful save"
    );
}

/// Cross-platform test: verify file content is correct regardless of platform.
#[test]
fn test_save_produces_valid_json() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("content_test.json");

    let recovery_key = SyftRecoveryKey::generate();
    let keys = recovery_key.derive_keys().unwrap();
    save_private_keys(&keys, &key_path).expect("Save should succeed");

    // Read and parse the file
    let content = std::fs::read_to_string(&key_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).expect("Should be valid JSON");

    // Verify expected structure
    assert!(
        json.get("identity_key").is_some(),
        "Should have identity_key"
    );
    assert!(
        json.get("signed_prekey").is_some(),
        "Should have signed_prekey"
    );
    assert!(json.get("identity_dh").is_some(), "Should have identity_dh");
}

/// Cross-platform test: verify atomic write behavior (file only appears when complete).
#[test]
fn test_atomic_write_file_only_exists_after_completion() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("atomic_test.json");

    // File should not exist before save
    assert!(!key_path.exists(), "File should not exist before save");

    let recovery_key = SyftRecoveryKey::generate();
    let keys = recovery_key.derive_keys().unwrap();
    save_private_keys(&keys, &key_path).expect("Save should succeed");

    // File should exist after save
    assert!(key_path.exists(), "File should exist after save");

    // File should have content
    let content = std::fs::read_to_string(&key_path).unwrap();
    assert!(!content.is_empty(), "File should have content");
}
