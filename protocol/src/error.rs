//! Error types for syftbox-crypto-protocol
//!
//! This module defines comprehensive error types for all cryptographic operations
//! in the protocol layer, including key generation, serialization, and storage.

use std::{io, num::TryFromIntError};

/// Main error type for the protocol layer
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Error during key generation
    #[error("Key generation failed: {0}")]
    GenerationError(String),

    /// Error during deterministic key derivation from recovery key
    #[error("Key derivation failed")]
    DerivationFailed,

    /// Invalid signature detected
    #[error("Invalid signature")]
    InvalidSignature,

    /// Decryption failed - message was encrypted with different key material
    #[error(
        "Decryption failed: message was encrypted for a different key (recipient may have regenerated keys)"
    )]
    DecryptionFailed,

    /// Recipient identity not found in envelope
    #[error("Recipient not found: this message was not encrypted for your identity")]
    RecipientNotFound,

    /// Serialization or deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// File I/O error
    #[error("Storage error: {0}")]
    StorageError(#[from] io::Error),

    /// Invalid key format
    #[error("Invalid key format")]
    InvalidFormat,

    /// Invalid shared secret derived from DH
    #[error("Invalid shared secret")]
    InvalidSharedSecret,

    /// Key rotation error
    #[error("Key rotation failed: {0}")]
    RotationError(String),

    /// JSON serialization error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// HKDF key derivation error
    #[error("HKDF error: output length invalid")]
    HkdfError,
}

impl From<&str> for KeyError {
    fn from(value: &str) -> Self {
        KeyError::SerializationError(value.to_string())
    }
}

impl From<String> for KeyError {
    fn from(value: String) -> Self {
        KeyError::SerializationError(value)
    }
}

impl From<TryFromIntError> for KeyError {
    fn from(error: TryFromIntError) -> Self {
        KeyError::SerializationError(error.to_string())
    }
}

impl From<RecoveryError> for KeyError {
    fn from(error: RecoveryError) -> Self {
        match error {
            RecoveryError::DerivationFailed => KeyError::DerivationFailed,
            other => KeyError::GenerationError(other.to_string()),
        }
    }
}

/// Error types specific to recovery key operations
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// Invalid recovery key length
    #[error("Invalid recovery key length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// Invalid hex encoding in recovery key
    #[error("Invalid hex encoding: {0}")]
    InvalidHex(String),

    /// BIP39 mnemonic error
    #[error("Mnemonic error: {0}")]
    MnemonicError(String),

    /// Key derivation failed during recovery
    #[error("Key derivation failed during recovery")]
    DerivationFailed,

    /// Recovery key failed entropy validation
    #[error("Recovery key has insufficient entropy")]
    InsufficientEntropy,

    /// Recovered keys don't match published DID document
    #[error("Key mismatch: {detail}")]
    KeyMismatch { detail: String },

    /// Backup operation failed
    #[error("Backup error: {0}")]
    BackupError(String),

    /// I/O error during recovery operations
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    /// Serialization error during recovery
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),

    /// General key error during recovery
    #[error("Key error: {0}")]
    KeyError(#[from] KeyError),
}

impl From<SerializationError> for KeyError {
    fn from(error: SerializationError) -> Self {
        KeyError::SerializationError(error.to_string())
    }
}

/// Error types for serialization operations
#[derive(Debug, thiserror::Error)]
pub enum SerializationError {
    /// Invalid DID document format
    #[error("Invalid DID document format")]
    InvalidFormat,

    /// Missing identity key in DID document
    #[error("Missing identity key in DID document")]
    MissingIdentityKey,

    /// Missing signed prekey in DID document
    #[error("Missing signed prekey in DID document")]
    MissingSignedPrekey,

    /// Missing identity DH key in DID document
    #[error("Missing identity DH key in DID document")]
    MissingIdentityDhKey,

    /// Invalid base64 encoding
    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

    /// Invalid signature in key bundle
    #[error("Invalid signature in key bundle")]
    InvalidSignature,

    /// Invalid prekey ID format
    #[error("Invalid prekey ID format")]
    InvalidPrekeyId,

    /// JSON error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Result type alias for KeyError
pub type Result<T> = std::result::Result<T, KeyError>;

/// Result type alias for RecoveryError
pub type RecoveryResult<T> = std::result::Result<T, RecoveryError>;

/// Result type alias for SerializationError
pub type SerializationResult<T> = std::result::Result<T, SerializationError>;
