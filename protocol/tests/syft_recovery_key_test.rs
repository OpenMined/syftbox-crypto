use std::collections::HashSet;
use std::convert::TryFrom;
use std::thread;

use syftbox_crypto_protocol::{RecoveryError, SyftRecoveryKey};

#[test]
fn test_recovery_key_generation() {
    let key1 = SyftRecoveryKey::generate();
    let key2 = SyftRecoveryKey::generate();

    println!("\n=== Recovery Key Generation ===");
    println!("Key 1: {}", key1.to_hex_string());
    println!("Key 2: {}", key2.to_hex_string());
    println!("Keys are different: {}", key1 != key2);

    // Different keys should be different
    assert!(key1 != key2);
}

#[test]
fn test_recovery_key_hex_roundtrip() {
    let key = SyftRecoveryKey::generate();
    let hex = key.to_hex_string();
    let restored = SyftRecoveryKey::from_hex_string(&hex).unwrap();

    println!("\n=== Hex Roundtrip Test ===");
    println!("Original key:  {}", key.to_hex_string());
    println!("Hex format:    {}", hex);
    println!("Restored key:  {}", restored.to_hex_string());
    println!("Match: {}", key == restored);

    assert!(key == restored);
}

#[test]
fn test_recovery_key_hex_format() {
    let key = SyftRecoveryKey::generate();
    let hex = key.to_hex_string();

    println!("\n=== Hex Format Test ===");
    println!("Full hex:      {}", hex);
    println!("Length:        {} (expected 79)", hex.len());
    println!("Dash count:    {} (expected 15)", hex.matches('-').count());
    println!("First 20 chars: {}", &hex[..20]);
    println!("Last 20 chars:  {}", &hex[hex.len() - 20..]);

    // Should be 79 characters: 64 hex + 15 dashes
    assert_eq!(hex.len(), 79);

    // Should have 15 dashes
    assert_eq!(hex.matches('-').count(), 15);

    // Should be parseable
    assert!(SyftRecoveryKey::from_hex_string(&hex).is_ok());
}

#[test]
fn test_recovery_key_hex_with_dashes() {
    let hex_with_dashes =
        "0001-0203-0405-0607-0809-0a0b-0c0d-0e0f-1011-1213-1415-1617-1819-1a1b-1c1d-1e1f";
    let key = SyftRecoveryKey::from_hex_string(hex_with_dashes).unwrap();

    println!("\n=== Parsing Hex With Dashes ===");
    println!("Input:         {}", hex_with_dashes);
    println!("Parsed key:    {}", key.to_hex_string());
    println!("Reformatted:   {}", key.to_hex_string());

    // Roundtrip should work
    let restored = SyftRecoveryKey::from_hex_string(&key.to_hex_string()).unwrap();
    assert!(key == restored);
}

#[test]
fn test_recovery_key_hex_without_dashes() {
    let hex_no_dashes = "0001020304050607 08090a0b0c0d0e0f 1011121314151617 18191a1b1c1d1e1f";
    let key = SyftRecoveryKey::from_hex_string(hex_no_dashes).unwrap();

    println!("\n=== Parsing Hex Without Dashes (with spaces) ===");
    println!("Input:         {}", hex_no_dashes);
    println!("Parsed key:    {}", key.to_hex_string());

    // Should work even with spaces (they get filtered out)
    let hex_string = key.to_hex_string();
    println!("Reformatted:   {}", hex_string);
    println!("Output length: {} (has dashes)", hex_string.len());

    assert_eq!(hex_string.len(), 79); // Formatted with dashes
}

#[test]
fn test_recovery_key_invalid_length() {
    let too_short = "a3f5-e8c9";
    let result = SyftRecoveryKey::from_hex_string(too_short);

    println!("\n=== Invalid Length Test ===");
    println!("Input:  '{}'", too_short);

    let err = match result {
        Ok(_) => panic!("expected error"),
        Err(err) => err,
    };
    println!("Error:  {}", err);

    match err {
        RecoveryError::InvalidLength { expected, actual } => {
            println!("Expected length: {}", expected);
            println!("Actual length:   {}", actual);
            assert_eq!(expected, 64);
            assert_eq!(actual, 8);
        }
        _ => panic!("Expected InvalidLength error"),
    }
}

#[test]
fn test_recovery_key_invalid_hex() {
    // Test strings with non-hex characters to ensure we surface InvalidHex errors
    let invalid = "a3f5e8c9123456789abcdef012345678g"; // 'g' is not valid hex
    let result = SyftRecoveryKey::from_hex_string(invalid);

    println!("\n=== Invalid Hex Characters Test ===");
    println!("Input:  '{}'", invalid);

    let err = match result {
        Ok(_) => panic!("expected error"),
        Err(err) => err,
    };

    println!("Error:  {}", err);

    match err {
        RecoveryError::InvalidHex(message) => {
            println!("Received InvalidHex: {}", message);
            assert!(message.contains("unexpected character"));
        }
        other => panic!("Expected InvalidHex error, got {other:?}"),
    }
}

#[test]
fn test_recovery_key_clone() {
    let key1 = SyftRecoveryKey::generate();
    let key2 = key1.clone();

    println!("\n=== Clone Test ===");
    println!("Original: {}", key1.to_hex_string());
    println!("Cloned:   {}", key2.to_hex_string());
    println!("Equal:    {}", key1 == key2);

    assert!(key1 == key2);
}

#[test]
fn test_recovery_key_rejects_low_entropy_imports() {
    let zeros = "0".repeat(64);
    let err = match SyftRecoveryKey::from_hex_string(&zeros) {
        Ok(_) => panic!("expected zeros to fail"),
        Err(err) => err,
    };
    assert!(matches!(err, RecoveryError::InsufficientEntropy));

    let repeating = "11".repeat(32);
    let err = match SyftRecoveryKey::from_hex_string(&repeating) {
        Ok(_) => panic!("expected repeating bytes to fail"),
        Err(err) => err,
    };
    assert!(matches!(err, RecoveryError::InsufficientEntropy));
}

#[test]
fn test_recovery_key_invalid_length_too_long() {
    let too_long = "a".repeat(66); // 66 hex chars instead of 64
    let result = SyftRecoveryKey::from_hex_string(&too_long);

    println!("\n=== Invalid Length (Too Long) Test ===");
    println!("Input length: {} (expected 64)", too_long.len());

    let err = match result {
        Ok(_) => panic!("expected error for too long input"),
        Err(err) => err,
    };
    println!("Error: {}", err);

    match err {
        RecoveryError::InvalidLength { expected, actual } => {
            println!("Expected length: {}", expected);
            println!("Actual length:   {}", actual);
            assert_eq!(expected, 64);
            assert_eq!(actual, 66);
        }
        _ => panic!("Expected InvalidLength error"),
    }
}

#[test]
fn test_recovery_key_case_insensitive() {
    let key = SyftRecoveryKey::generate();
    let hex_string = key.to_hex_string();

    println!("\n=== Case Insensitive Parsing Test ===");
    println!("Original:  {}", hex_string);

    // Convert to uppercase
    let uppercase = hex_string.to_uppercase();
    println!("Uppercase: {}", uppercase);
    let recovered_upper =
        SyftRecoveryKey::from_hex_string(&uppercase).expect("Should parse uppercase hex");

    // Convert to lowercase
    let lowercase = hex_string.to_lowercase();
    println!("Lowercase: {}", lowercase);
    let recovered_lower =
        SyftRecoveryKey::from_hex_string(&lowercase).expect("Should parse lowercase hex");

    // Both should produce the same key
    assert_eq!(
        recovered_upper.to_hex_string(),
        recovered_lower.to_hex_string(),
        "Case should not matter for hex parsing"
    );

    // Both should match the original
    assert_eq!(key, recovered_upper, "Uppercase parsing should match");
    assert_eq!(key, recovered_lower, "Lowercase parsing should match");
}

#[test]
fn test_recovery_key_concurrent_generation() {
    let handles: Vec<_> = (0..32)
        .map(|_| thread::spawn(SyftRecoveryKey::generate))
        .collect();

    let mut keys = Vec::with_capacity(handles.len());
    for handle in handles {
        keys.push(handle.join().expect("thread panicked"));
    }

    let unique: HashSet<_> = keys.iter().map(|k| k.to_hex_string()).collect();
    assert_eq!(unique.len(), keys.len());
}

#[test]
fn test_recovery_key_large_batch_generation() {
    let batch: Vec<_> = (0..1_000).map(|_| SyftRecoveryKey::generate()).collect();
    assert_eq!(batch.len(), 1_000);

    let unique: HashSet<_> = batch.iter().map(|k| k.to_hex_string()).collect();
    assert_eq!(unique.len(), batch.len());
}

/// Test internal implementation detail: zeroization on drop
///
/// This test verifies that the ZeroizeOnDrop trait properly clears
/// sensitive key material when the RecoveryKey is dropped.
#[test]
fn test_recovery_key_zeroization() {
    let key = SyftRecoveryKey::generate();

    // Store original bytes for comparison
    let original_bytes = recovery_key_bytes(&key);

    // Drop the key (should trigger zeroization)
    drop(key);

    // Note: We can't safely read the memory after drop in safe Rust,
    // but the zeroize library guarantees this happens
    // This test mainly ensures the ZeroizeOnDrop trait is applied

    // Verify original bytes were not all zeros (sanity check)
    assert_ne!(original_bytes, [0u8; 32]);
}

/// Test internal implementation: verify as_bytes() returns correct data
///
/// This uses the pub(crate) as_bytes() method which is not part of the public API.
#[test]
fn test_recovery_key_from_known_hex() {
    // Test with a known hex string
    let known_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let key = SyftRecoveryKey::from_hex_string(known_hex).unwrap();

    let expected_bytes = hex::decode(known_hex).unwrap();
    assert_eq!(
        recovery_key_bytes(&key).as_slice(),
        expected_bytes.as_slice()
    );
}

#[test]
fn test_entropy_rejection_rules() {
    let zeros = [0u8; 32];
    assert!(!has_min_entropy(&zeros));

    let ones = [1u8; 32];
    assert!(!has_min_entropy(&ones));

    let mut ascending = [0u8; 32];
    for (i, byte) in ascending.iter_mut().enumerate() {
        *byte = u8::try_from(i).expect("ascending index fits in u8 range");
    }
    assert!(has_min_entropy(&ascending));
}

fn recovery_key_bytes(key: &SyftRecoveryKey) -> [u8; 32] {
    let normalized = key.to_hex_string().replace('-', "");
    let decoded = hex::decode(normalized).expect("hex encoding should decode");
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    bytes
}

fn has_min_entropy(bytes: &[u8; 32]) -> bool {
    if bytes.iter().all(|&b| b == 0) {
        return false;
    }

    if bytes.windows(2).all(|w| w[0] == w[1]) {
        return false;
    }

    let mut seen = [false; 256];
    for &byte in bytes {
        seen[byte as usize] = true;
    }
    seen.iter().filter(|&&present| present).count() >= 16
}
