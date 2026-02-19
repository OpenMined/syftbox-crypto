use crate::error::KeyError;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use winapi::ctypes::c_void;
use windows_acl::acl::{ACL, ACLEntry, AceType};
use windows_acl::helper::{current_user, name_to_sid, sid_to_string, string_to_sid};

/// File access mask for full control (read, write, execute, delete, etc.)
const FILE_ALL_ACCESS: u32 = 0x1F01FF;

/// Writes JWKS data to a secure file with owner-only permissions.
///
/// This implementation:
/// 1. Creates a temporary file in the same directory
/// 2. Writes the JSON content
/// 3. Restricts ACL to owner-only (removes all other access)
/// 4. Atomically renames to the target path
/// 5. Cleans up temp file on failure
pub(crate) fn save_private_keys_platform(jwks: &Value, path: &Path) -> Result<(), KeyError> {
    let (mut file, temp_path, mut guard) = create_temp_file(path)?;

    // Restrict ACL immediately after creation to minimize exposure window
    restrict_to_owner(&temp_path)?;

    // Write content
    {
        let mut writer = BufWriter::new(&mut file);
        serde_json::to_writer_pretty(&mut writer, jwks)?;
        writer.flush()?;
    }
    file.sync_all()?;
    drop(file);

    // Atomic rename
    fs::rename(&temp_path, path)?;
    guard.persist();

    Ok(())
}

/// Creates a temporary file in the same directory as the target path.
fn create_temp_file(path: &Path) -> Result<(File, PathBuf, TempFileGuard), KeyError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "keys".to_string());

    for _ in 0..16 {
        let suffix = next_temp_suffix();
        let candidate = parent.join(format!(
            "{}.{}.{suffix:016x}.tmp",
            file_name,
            std::process::id()
        ));

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                let guard = TempFileGuard::new(candidate.clone());
                return Ok((file, candidate, guard));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "Unable to create unique temporary key file",
    )
    .into())
}

/// Restricts file ACL to owner-only access.
///
/// This removes all existing DACL entries except for the current user,
/// then grants full access only to the current user.
fn restrict_to_owner(path: &Path) -> Result<(), KeyError> {
    let path_str = path.to_string_lossy();

    let username = current_user().ok_or_else(|| {
        KeyError::StorageError(io::Error::new(
            io::ErrorKind::Other,
            "Failed to get current user name",
        ))
    })?;

    let current_user_sid = name_to_sid(&username, None).map_err(|e| {
        KeyError::StorageError(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to convert username to SID: {e}"),
        ))
    })?;

    let mut acl = ACL::from_file_path(&path_str, false).map_err(|e| {
        KeyError::StorageError(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to load ACL: {}", e),
        ))
    })?;

    let entries: Vec<ACLEntry> = acl.all().map_err(|e| {
        KeyError::StorageError(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to read ACL entries: {}", e),
        ))
    })?;

    for entry in entries {
        if entry.entry_type == AceType::AccessAllow || entry.entry_type == AceType::AccessDeny {
            let sid_bytes = string_to_sid(&entry.string_sid).map_err(|e| {
                KeyError::StorageError(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to parse entry SID: {e}"),
                ))
            })?;

            acl.remove(
                sid_bytes.as_ptr() as *mut c_void,
                Some(entry.entry_type),
                Some(false),
            )
            .map_err(|e| {
                KeyError::StorageError(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to remove existing ACL entry: {e}"),
                ))
            })?;
        }
    }

    acl.allow(
        current_user_sid.as_ptr() as *mut c_void,
        false,
        FILE_ALL_ACCESS,
    )
    .map_err(|e| {
        KeyError::StorageError(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to set owner ACL: {}", e),
        ))
    })?;

    // Ensure the owner entry actually exists after modifications
    let owner_entries = acl
        .get(
            current_user_sid.as_ptr() as *mut c_void,
            Some(AceType::AccessAllow),
        )
        .map_err(|e| {
            KeyError::StorageError(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to verify owner ACL: {e}"),
            ))
        })?;

    if owner_entries.is_empty() {
        return Err(KeyError::StorageError(io::Error::new(
            io::ErrorKind::Other,
            "Owner ACL entry missing after update",
        )));
    }

    // Final verification: confirm only the owner has AccessAllow entries
    let owner_sid_string =
        sid_to_string(current_user_sid.as_ptr() as *mut c_void).map_err(|e| {
            KeyError::StorageError(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to stringify owner SID: {e}"),
            ))
        })?;

    let final_entries: Vec<ACLEntry> = acl.all().map_err(|e| {
        KeyError::StorageError(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to enumerate ACL after update: {}", e),
        ))
    })?;

    for entry in final_entries {
        if entry.entry_type == AceType::AccessAllow && entry.string_sid != owner_sid_string {
            return Err(KeyError::StorageError(io::Error::new(
                io::ErrorKind::Other,
                "Non-owner AccessAllow entry detected after ACL update",
            )));
        }
    }

    Ok(())
}

fn next_temp_suffix() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

struct TempFileGuard {
    path: PathBuf,
    persisted: bool,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            persisted: false,
        }
    }

    fn persist(&mut self) {
        self.persisted = true;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if !self.persisted {
            let _ = fs::remove_file(&self.path);
        }
    }
}
