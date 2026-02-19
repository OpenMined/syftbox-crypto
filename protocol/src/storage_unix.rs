use crate::error::KeyError;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) fn save_private_keys_platform(jwks: &Value, path: &Path) -> Result<(), KeyError> {
    let (mut file, mut guard) = create_secure_temp_file(path)?;
    {
        let mut writer = BufWriter::new(&mut file);
        serde_json::to_writer_pretty(&mut writer, jwks)?;
        writer.flush()?;
    }
    file.sync_all()?;
    drop(file);
    fs::rename(guard.path(), path)?;
    guard.persist();
    Ok(())
}

fn create_secure_temp_file(path: &Path) -> Result<(File, TempFileGuard), KeyError> {
    use std::io::ErrorKind;

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
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => return Ok((file, TempFileGuard::new(candidate))),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Err(io::Error::new(
        ErrorKind::AlreadyExists,
        "Unable to create unique temporary key file",
    )
    .into())
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

    fn path(&self) -> &Path {
        &self.path
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
