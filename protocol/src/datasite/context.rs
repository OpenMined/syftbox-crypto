use crate::envelope::ParsedEnvelope;
use crate::serialization::zeroize_json_value;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const REPLAY_CACHE_VERSION: u32 = 1;
const REPLAY_CACHE_MAX_ENTRIES: usize = 10_000;

/// Shared application context derived from global CLI arguments.
#[derive(Debug, Clone)]
pub struct AppContext {
    pub vault_path: PathBuf,
    pub data_root: PathBuf,
    pub shadow_root: PathBuf,
}

pub fn resolve_vault(vault: Option<PathBuf>) -> PathBuf {
    let from_flag = vault;
    let from_env = env::var_os("SBC_VAULT").map(PathBuf::from);

    let candidate = from_flag.or(from_env).unwrap_or_else(default_vault_path);

    expand_home(candidate)
}

pub fn resolve_roots(
    data_override: Option<PathBuf>,
    shadow_override: Option<PathBuf>,
    vault: &Path,
) -> Result<(PathBuf, PathBuf)> {
    let data_env = env::var_os("SBC_DATA_ROOT").map(PathBuf::from);
    let shadow_env = env::var_os("SBC_SHADOW_ROOT").map(PathBuf::from);

    let config = read_datasite_config(vault)?;

    let data_candidate = data_override
        .or(data_env)
        .or_else(|| config.as_ref().map(|cfg| cfg.encrypted_root.clone()));

    let shadow_candidate = shadow_override
        .or(shadow_env)
        .or_else(|| config.as_ref().map(|cfg| cfg.shadow_root.clone()));

    let data_root = data_candidate.ok_or_else(|| {
        anyhow::anyhow!("unable to determine data root – provide --data-root, set SBC_DATA_ROOT, or add encrypted_root to vault config")
    })?;

    let shadow_root = shadow_candidate.ok_or_else(|| {
        anyhow::anyhow!("unable to determine shadow root – provide --shadow-root, set SBC_SHADOW_ROOT, or add shadow_root to vault config")
    })?;

    Ok((expand_home(data_root), expand_home(shadow_root)))
}

pub fn ensure_vault_layout(vault: &Path) -> Result<()> {
    fs::create_dir_all(vault.join("keys"))?;
    fs::create_dir_all(vault.join("bundles"))?;
    fs::create_dir_all(vault.join("config")).ok();
    Ok(())
}

pub fn resolve_data_path(context: &AppContext, input: &Path) -> PathBuf {
    resolve_under_root(&context.data_root, input)
}

pub fn resolve_shadow_path(context: &AppContext, input: &Path) -> PathBuf {
    resolve_under_root(&context.shadow_root, input)
}

fn resolve_under_root(root: &Path, input: &Path) -> PathBuf {
    let expanded = expand_home(input);
    if expanded.is_absolute() {
        expanded
    } else {
        root.join(expanded)
    }
}

pub fn expand_home<P: AsRef<Path>>(input: P) -> PathBuf {
    let path = input.as_ref();
    let path_str = path.to_string_lossy();

    if path_str == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from("~"));
    }

    if let Some(stripped) = path_str.strip_prefix("~/") {
        return home_dir()
            .map(|home| home.join(stripped))
            .unwrap_or_else(|| PathBuf::from(path));
    }

    path.to_path_buf()
}

pub fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

pub fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

pub fn bundle_path_for_identity(vault: &Path, identity: &str) -> PathBuf {
    let slug = sanitize_identity(identity);
    vault.join("bundles").join(format!("{slug}.json"))
}

pub fn key_path_for_identity(vault: &Path, identity: &str) -> PathBuf {
    let slug = sanitize_identity(identity);
    vault.join("keys").join(format!("{slug}.key"))
}

pub fn load_identity_label(path: &Path) -> Result<String> {
    let mut contents = fs::read_to_string(path)?;
    let mut value: serde_json::Value = serde_json::from_str(&contents)?;
    contents.zeroize();

    let identity = value
        .get("identity")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);

    zeroize_json_value(&mut value);

    identity.ok_or_else(|| anyhow!("unable to parse identity from {}", path.display()))
}

pub fn read_identity_from_key(path: PathBuf) -> Result<String> {
    load_identity_label(&path)
}

pub fn fallback_identity_from_path(path: PathBuf) -> String {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn detect_single_identity(vault: &Path) -> Result<String> {
    let keys_dir = vault.join("keys");
    let mut identities = Vec::new();

    if keys_dir.exists() {
        for entry in fs::read_dir(&keys_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let identity = read_identity_from_key(entry.path())
                    .unwrap_or_else(|_| fallback_identity_from_path(entry.path()));
                identities.push(identity);
            }
        }
    }

    match identities.len() {
        0 => Err(anyhow::anyhow!(
            "no identities found in vault (run `sbc key generate` first)"
        )),
        1 => Ok(identities.remove(0)),
        _ => Err(anyhow::anyhow!(
            "multiple identities present – specify --sender/--identity"
        )),
    }
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = make_temp_path(path);
    fs::write(&tmp_path, data)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Atomically write sensitive data with owner-only permissions on supported platforms.
pub fn atomic_write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    for _ in 0..16 {
        let tmp_path = make_temp_path(path);
        match write_temp_private(&tmp_path, data) {
            Ok(()) => {
                if path.exists() {
                    fs::remove_file(path)?;
                }
                fs::rename(&tmp_path, path)?;
                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }

    Err(anyhow!(
        "unable to create unique private temp file for {}",
        path.display()
    ))
}

#[cfg(unix)]
fn write_temp_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_temp_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(data)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

pub fn enforce_replay_protection(
    vault: &Path,
    source_path: &Path,
    envelope: &ParsedEnvelope,
) -> Result<()> {
    let cache_path = vault.join("config").join("replay_cache.json");
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut cache = load_replay_cache(&cache_path)?;
    let key = replay_cache_key(source_path, &envelope.prelude.sender.identity);
    let digest = replay_digest(envelope);
    let created_at = envelope.prelude.created_at;

    if let Some(previous) = cache.entries.get(&key) {
        if previous.envelope_digest == digest {
            return Ok(());
        }
        if created_at < previous.created_at {
            return Err(anyhow!(
                "replay detected for {} from {} (created_at {} < {})",
                source_path.display(),
                envelope.prelude.sender.identity,
                created_at,
                previous.created_at
            ));
        }
    }

    cache.entries.insert(
        key,
        ReplayEntry {
            created_at,
            envelope_digest: digest,
            seen_at: now_unix_secs(),
        },
    );
    trim_replay_cache(&mut cache);

    let body = serde_json::to_vec_pretty(&cache)?;
    atomic_write(&cache_path, &body)?;
    Ok(())
}

pub fn read_datasite_config(vault: &Path) -> Result<Option<DatasiteConfig>> {
    let config_path = vault.join("config").join("datasite.json");
    if !config_path.exists() {
        return Ok(None);
    }

    let contents = fs::read_to_string(&config_path)?;
    let raw: DatasiteConfigRaw = serde_json::from_str(&contents)?;
    let encrypted_root = resolve_config_path(vault, raw.encrypted_root)?;
    let shadow_root = resolve_config_path(vault, raw.shadow_root)?;

    Ok(Some(DatasiteConfig {
        encrypted_root,
        shadow_root,
    }))
}

fn resolve_config_path(vault: &Path, candidate: PathBuf) -> Result<PathBuf> {
    let expanded = expand_home(candidate);
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        vault.join(expanded)
    };

    Ok(fs::canonicalize(&absolute).unwrap_or(absolute))
}

fn default_vault_path() -> PathBuf {
    home_dir()
        .map(|home| home.join(".sbc"))
        .unwrap_or_else(|| PathBuf::from(".sbc"))
}

/// Convert arbitrary identity strings into filesystem-safe slugs for bundle/key paths.
pub fn sanitize_identity(identity: &str) -> String {
    identity
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '@' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .collect()
}

pub fn resolve_identity(provided: Option<&str>, vault: &Path) -> Result<String> {
    match provided {
        Some(identity) => Ok(identity.to_owned()),
        None => detect_single_identity(vault),
    }
}

fn make_temp_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path.file_name().and_then(|n| n.to_str()).unwrap_or("temp");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let suffix = next_temp_suffix();
    parent.join(format!(".{stem}.{nanos}.{suffix:016x}.tmp"))
}

fn next_temp_suffix() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn load_replay_cache(path: &Path) -> Result<ReplayCache> {
    if !path.exists() {
        return Ok(ReplayCache::default());
    }

    let contents = fs::read_to_string(path)?;
    let mut cache: ReplayCache = serde_json::from_str(&contents)?;
    if cache.version != REPLAY_CACHE_VERSION {
        cache = ReplayCache::default();
    }
    Ok(cache)
}

fn replay_cache_key(source_path: &Path, sender_identity: &str) -> String {
    let source = fs::canonicalize(source_path).unwrap_or_else(|_| source_path.to_path_buf());
    format!("{}|{}", source.display(), sender_identity)
}

fn replay_digest(envelope: &ParsedEnvelope) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(&envelope.prelude_bytes);
    hasher.update(&envelope.signature);
    hasher.update(&envelope.ciphertext);
    hex::encode(hasher.finalize())
}

fn trim_replay_cache(cache: &mut ReplayCache) {
    if cache.entries.len() <= REPLAY_CACHE_MAX_ENTRIES {
        return;
    }

    let mut ordered: Vec<(String, u64)> = cache
        .entries
        .iter()
        .map(|(key, entry)| (key.clone(), entry.seen_at))
        .collect();
    ordered.sort_by_key(|(_, seen_at)| *seen_at);
    let remove_count = cache.entries.len() - REPLAY_CACHE_MAX_ENTRIES;
    for (key, _) in ordered.into_iter().take(remove_count) {
        cache.entries.remove(&key);
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Deserialize, Debug, Clone)]
pub struct DatasiteConfigRaw {
    pub encrypted_root: PathBuf,
    pub shadow_root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct DatasiteConfig {
    pub encrypted_root: PathBuf,
    pub shadow_root: PathBuf,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ReplayCache {
    #[serde(default = "replay_cache_version")]
    version: u32,
    #[serde(default)]
    entries: std::collections::HashMap<String, ReplayEntry>,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self {
            version: REPLAY_CACHE_VERSION,
            entries: std::collections::HashMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ReplayEntry {
    created_at: u64,
    envelope_digest: String,
    seen_at: u64,
}

fn replay_cache_version() -> u32 {
    REPLAY_CACHE_VERSION
}
