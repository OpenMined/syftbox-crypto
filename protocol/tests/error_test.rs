//! Public API tests for error types
//!
//! These tests validate error creation, conversion, and display functionality.

use std::io;
use syftbox_crypto_protocol::{KeyError, RecoveryError, SerializationError};

#[test]
fn test_key_error_creation() {
    let err = KeyError::DerivationFailed;
    assert_eq!(err.to_string(), "Key derivation failed");
}

#[test]
fn test_key_error_with_context() {
    let err = KeyError::GenerationError("test failure".to_string());
    assert_eq!(err.to_string(), "Key generation failed: test failure");
}

#[test]
fn test_recovery_error_invalid_length() {
    let err = RecoveryError::InvalidLength {
        expected: 32,
        actual: 16,
    };
    assert_eq!(
        err.to_string(),
        "Invalid recovery key length: expected 32, got 16"
    );
}

#[test]
fn test_recovery_error_insufficient_entropy() {
    let err = RecoveryError::InsufficientEntropy;
    assert_eq!(err.to_string(), "Recovery key has insufficient entropy");
}

#[test]
fn test_serialization_error() {
    let err = SerializationError::MissingIdentityKey;
    assert_eq!(err.to_string(), "Missing identity key in DID document");
}

#[test]
fn test_error_conversion() {
    let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
    let key_err: KeyError = io_err.into();
    assert!(matches!(key_err, KeyError::StorageError(_)));
}

#[test]
fn test_error_message_serialization_roundtrip() {
    let err = RecoveryError::InvalidLength {
        expected: 64,
        actual: 10,
    };
    let serialized = serde_json::to_string(&err.to_string()).unwrap();
    let restored: String = serde_json::from_str(&serialized).unwrap();
    assert_eq!(restored, err.to_string());
}
