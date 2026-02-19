//! Storage for cryptographic keys and DID documents
//!
//! This module handles secure file I/O for:
//! - **Private keys**: Stored in JWKS format with restricted permissions (0o600)
//! - **DID documents**: Public key bundles in W3C DID format
//!
//! # Security
//! Private key files are created with Unix permissions 0o600 (owner read/write only)
//! to prevent unauthorized access.
//!
//! # Example
//! ```no_run
//! use syftbox_crypto_protocol::SyftRecoveryKey;
//! use syftbox_crypto_protocol::storage::{save_private_keys, load_private_keys};
//! use std::path::Path;
//!
//! let recovery_key = SyftRecoveryKey::generate();
//! let private_keys = recovery_key.derive_keys().unwrap();
//!
//! // Save with secure permissions
//! save_private_keys(&private_keys, Path::new("keys.json")).unwrap();
//!
//! // Load back
//! let loaded_keys = load_private_keys(Path::new("keys.json")).unwrap();
//! ```

use crate::error::KeyError;
use crate::keys::{SyftPrivateKeys, SyftPublicKeyBundle};
use crate::serialization::{
    deserialize_from_did_document, deserialize_private_keys, serialize_private_keys,
    serialize_to_did_document, zeroize_json_value,
};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;

#[cfg(unix)]
#[path = "storage_unix.rs"]
mod storage_unix;
#[cfg(unix)]
use storage_unix::save_private_keys_platform as platform_save_private_keys;

#[cfg(windows)]
#[path = "storage_windows.rs"]
mod storage_windows;
#[cfg(windows)]
use storage_windows::save_private_keys_platform as platform_save_private_keys;

#[cfg(not(any(unix, windows)))]
fn platform_save_private_keys(_: &serde_json::Value, _: &Path) -> Result<(), KeyError> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "secure private key storage is only supported on Unix and Windows",
    )
    .into())
}

/// Save private keys to disk with secure permissions where available.
///
/// On Unix the file is created atomically with mode `0o600`. On Windows the
/// file is created with an ACL restricted to owner-only access.
///
/// The keys are serialized to JWKS format and written to the specified path.
///
/// # Arguments
/// * `keys` - The private keys to save
/// * `path` - Destination file path
///
/// # Errors
/// * `KeyError::JsonError` if serialization fails
/// * `KeyError::StorageError` if file I/O fails
///
/// # Example
/// ```no_run
/// use syftbox_crypto_protocol::SyftRecoveryKey;
/// use syftbox_crypto_protocol::storage::save_private_keys;
/// use std::path::Path;
///
/// let recovery_key = SyftRecoveryKey::generate();
/// let keys = recovery_key.derive_keys().unwrap();
/// save_private_keys(&keys, Path::new("my_keys.json")).unwrap();
/// ```
pub fn save_private_keys(keys: &SyftPrivateKeys, path: &Path) -> Result<(), KeyError> {
    let mut jwks = serialize_private_keys(keys).map_err(|e| {
        KeyError::SerializationError(format!("Failed to serialize private keys: {}", e))
    })?;

    let result = platform_save_private_keys(&jwks, path);

    zeroize_json_value(&mut jwks);
    result
}

/// Load private keys from disk.
///
/// Reads a JWKS file and deserializes the private keys.
///
/// # Arguments
/// * `path` - Path to the JWKS file
///
/// # Returns
/// * `Ok(SyftPrivateKeys)` if successful
/// * `Err(KeyError)` if file reading or deserialization fails
///
/// # Example
/// ```no_run
/// use syftbox_crypto_protocol::storage::load_private_keys;
/// use std::path::Path;
///
/// let keys = load_private_keys(Path::new("my_keys.json")).unwrap();
/// ```
pub fn load_private_keys(path: &Path) -> Result<SyftPrivateKeys, KeyError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut jwks: serde_json::Value = serde_json::from_reader(reader)?;

    let result = deserialize_private_keys(&jwks).map_err(|e| {
        KeyError::SerializationError(format!("Failed to deserialize private keys: {}", e))
    });

    zeroize_json_value(&mut jwks);
    result
}

/// Save DID document to disk.
///
/// Serializes a public key bundle to W3C DID document format and writes to file.
/// This is public data, so no special permissions are set.
///
/// # Arguments
/// * `bundle` - The public key bundle to save
/// * `did_id` - The DID identifier (e.g., "did:web:syftbox.net:alice%40example.com")
/// * `path` - Destination file path
///
/// # Errors
/// * `KeyError::JsonError` if serialization fails
/// * `KeyError::StorageError` if file I/O fails
///
/// # Example
/// ```no_run
/// use syftbox_crypto_protocol::SyftRecoveryKey;
/// use syftbox_crypto_protocol::storage::save_did_document;
/// use std::path::Path;
///
/// let recovery_key = SyftRecoveryKey::generate();
/// let private_keys = recovery_key.derive_keys().unwrap();
/// let bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();
/// save_did_document(&bundle, "did:web:example.com:alice", Path::new("did.json")).unwrap();
/// ```
pub fn save_did_document(
    bundle: &SyftPublicKeyBundle,
    did_id: &str,
    path: &Path,
) -> Result<(), KeyError> {
    // Serialize to DID document format
    let did_doc = serialize_to_did_document(bundle, did_id).map_err(|e| {
        KeyError::SerializationError(format!("Failed to serialize DID document: {}", e))
    })?;

    // Convert to pretty-printed JSON string
    let json_string = serde_json::to_string_pretty(&did_doc)?;

    // Write to file
    let mut file = File::create(path)?;
    file.write_all(json_string.as_bytes())?;

    Ok(())
}

/// Load DID document from disk.
///
/// Reads a W3C DID document file and deserializes the public key bundle.
/// Verifies signatures during deserialization.
///
/// # Arguments
/// * `path` - Path to the DID document file
///
/// # Returns
/// * `Ok(SyftPublicKeyBundle)` if successful and signatures are valid
/// * `Err(KeyError)` if file reading, deserialization, or signature verification fails
///
/// # Example
/// ```no_run
/// use syftbox_crypto_protocol::storage::load_did_document;
/// use std::path::Path;
///
/// let bundle = load_did_document(Path::new("did.json")).unwrap();
/// ```
pub fn load_did_document(path: &Path) -> Result<SyftPublicKeyBundle, KeyError> {
    // Read file contents
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Parse JSON
    let did_doc: serde_json::Value = serde_json::from_str(&contents)?;

    // Deserialize and verify signatures
    let bundle = deserialize_from_did_document(&did_doc).map_err(|e| {
        KeyError::SerializationError(format!("Failed to deserialize DID document: {}", e))
    })?;

    Ok(bundle)
}
