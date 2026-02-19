use syftbox_crypto_protocol::SyftRecoveryKey;

#[test]
fn test_mnemonic_generation() {
    let recovery_key = SyftRecoveryKey::generate();
    let mnemonic = recovery_key.to_mnemonic();

    // Should be 24 words
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 24, "Mnemonic should have 24 words");

    // All words should be lowercase and alphabetic
    for word in &words {
        assert!(word.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }
}

#[test]
fn test_mnemonic_roundtrip() {
    let original_key = SyftRecoveryKey::generate();
    let mnemonic = original_key.to_mnemonic();

    // Convert back from mnemonic
    let recovered_key =
        SyftRecoveryKey::from_mnemonic(&mnemonic).expect("Should parse valid mnemonic");

    // Direct comparison of recovery keys
    assert_eq!(original_key, recovered_key, "Recovery keys should match");

    // Should derive the same keys
    let original_keys = original_key.derive_keys().unwrap();
    let recovered_keys = recovered_key.derive_keys().unwrap();

    assert_eq!(
        original_keys.identity().to_bytes(),
        recovered_keys.identity().to_bytes(),
        "Identity keys should match after mnemonic roundtrip"
    );
}

#[test]
fn test_mnemonic_deterministic() {
    let recovery_key = SyftRecoveryKey::generate();

    // Same key should produce same mnemonic
    let mnemonic1 = recovery_key.to_mnemonic();
    let mnemonic2 = recovery_key.to_mnemonic();

    assert_eq!(
        mnemonic1, mnemonic2,
        "Same key should produce same mnemonic"
    );
}

#[test]
fn test_mnemonic_invalid_word() {
    let invalid_mnemonic = "abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon invalidword";

    let result = SyftRecoveryKey::from_mnemonic(invalid_mnemonic);
    assert!(result.is_err(), "Should reject mnemonic with invalid word");
}

#[test]
fn test_mnemonic_invalid_checksum() {
    // Valid words but incorrect checksum (last word changed)
    let invalid_mnemonic = "abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon able";

    let result = SyftRecoveryKey::from_mnemonic(invalid_mnemonic);
    assert!(
        result.is_err(),
        "Should reject mnemonic with invalid checksum"
    );
}

#[test]
fn test_mnemonic_wrong_length_too_short() {
    let short_mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";

    let result = SyftRecoveryKey::from_mnemonic(short_mnemonic);
    assert!(result.is_err(), "Should reject mnemonic with too few words");
}

#[test]
fn test_mnemonic_wrong_length_too_long() {
    let long_mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon art";

    let result = SyftRecoveryKey::from_mnemonic(long_mnemonic);
    assert!(
        result.is_err(),
        "Should reject mnemonic with too many words"
    );
}

#[test]
fn test_mnemonic_case_insensitive() {
    let recovery_key = SyftRecoveryKey::generate();
    let mnemonic = recovery_key.to_mnemonic();

    // Test uppercase
    let uppercase_mnemonic = mnemonic.to_uppercase();
    let recovered_upper = SyftRecoveryKey::from_mnemonic(&uppercase_mnemonic)
        .expect("Should parse uppercase mnemonic");

    // Test mixed case
    let words: Vec<String> = mnemonic
        .split_whitespace()
        .enumerate()
        .map(|(i, word)| {
            if i % 2 == 0 {
                word.to_uppercase()
            } else {
                word.to_string()
            }
        })
        .collect();
    let mixed_mnemonic = words.join(" ");
    let recovered_mixed =
        SyftRecoveryKey::from_mnemonic(&mixed_mnemonic).expect("Should parse mixed case mnemonic");

    // Direct comparison of recovery keys
    assert_eq!(recovery_key, recovered_upper, "Recovery keys should match");
    assert_eq!(recovery_key, recovered_mixed, "Recovery keys should match");

    // All should derive the same keys
    let original_keys = recovery_key.derive_keys().unwrap();
    let upper_keys = recovered_upper.derive_keys().unwrap();
    let mixed_keys = recovered_mixed.derive_keys().unwrap();

    assert_eq!(
        original_keys.identity().to_bytes(),
        upper_keys.identity().to_bytes()
    );
    assert_eq!(
        original_keys.identity().to_bytes(),
        mixed_keys.identity().to_bytes()
    );
}

#[test]
fn test_mnemonic_extra_whitespace() {
    let recovery_key = SyftRecoveryKey::generate();
    let mnemonic = recovery_key.to_mnemonic();

    // Add extra spaces, tabs, newlines
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let messy_mnemonic = format!(
        "  {}  \n\t{}   {} {}  \n  {}  ",
        words[0..6].join("  "),
        words[6..12].join("\t"),
        words[12..18].join("   "),
        words[18..24].join(" "),
        ""
    );

    let recovered =
        SyftRecoveryKey::from_mnemonic(&messy_mnemonic).expect("Should handle extra whitespace");

    let original_keys = recovery_key.derive_keys().unwrap();
    let recovered_keys = recovered.derive_keys().unwrap();

    // Direct comparison of recovery keys
    assert_eq!(recovery_key, recovered, "Recovery keys should match");

    assert_eq!(
        original_keys.identity().to_bytes(),
        recovered_keys.identity().to_bytes(),
        "Should handle extra whitespace correctly"
    );
}

#[test]
fn test_mnemonic_derives_same_keys_as_original() {
    // Generate key and derive keys directly
    let recovery_key = SyftRecoveryKey::generate();
    let original_keys = recovery_key.derive_keys().unwrap();
    let original_bundle = original_keys.to_public_bundle(&mut rand::rng()).unwrap();

    // Convert to mnemonic and back
    let mnemonic = recovery_key.to_mnemonic();
    let recovered_key = SyftRecoveryKey::from_mnemonic(&mnemonic).unwrap();

    // Direct comparison of recovery keys
    assert_eq!(
        recovery_key, recovered_key,
        "Recovery keys should match after mnemonic roundtrip"
    );

    let recovered_keys = recovered_key.derive_keys().unwrap();
    let recovered_bundle = recovered_keys.to_public_bundle(&mut rand::rng()).unwrap();

    // Verify all keys match
    assert_eq!(
        original_bundle.identity_signing_public_key.as_bytes(),
        recovered_bundle.identity_signing_public_key.as_bytes(),
        "Identity public keys should match"
    );
    assert_eq!(
        original_bundle.identity_dh_public_key.as_bytes(),
        recovered_bundle.identity_dh_public_key.as_bytes(),
        "Identity DH keys should match"
    );
    assert_eq!(
        original_keys.signed_pre_key().to_bytes(),
        recovered_keys.signed_pre_key().to_bytes(),
        "Signed prekeys should match"
    );
}

#[test]
fn test_mnemonic_format_and_parsing() {
    // Generate a key, convert to mnemonic, verify format and parsing
    let recovery_key = SyftRecoveryKey::generate();
    let mnemonic = recovery_key.to_mnemonic();

    // Verify it's a valid 24-word mnemonic
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 24);

    // Should be able to parse it back
    let parsed_key =
        SyftRecoveryKey::from_mnemonic(&mnemonic).expect("Should parse generated mnemonic");

    // Direct comparison of recovery keys
    assert_eq!(
        recovery_key, parsed_key,
        "Parsed recovery key should match original"
    );

    // Should derive the same keys
    let original_keys = recovery_key.derive_keys().unwrap();
    let parsed_keys = parsed_key.derive_keys().unwrap();

    assert_eq!(
        original_keys.identity().to_bytes(),
        parsed_keys.identity().to_bytes(),
        "Parsed mnemonic should produce same keys"
    );
}

#[test]
fn test_mnemonic_different_keys_different_phrases() {
    let key1 = SyftRecoveryKey::generate();
    let key2 = SyftRecoveryKey::generate();

    let mnemonic1 = key1.to_mnemonic();
    let mnemonic2 = key2.to_mnemonic();

    assert_ne!(
        mnemonic1, mnemonic2,
        "Different keys should produce different mnemonics"
    );
}

#[test]
fn test_mnemonic_empty_string() {
    let result = SyftRecoveryKey::from_mnemonic("");
    assert!(result.is_err(), "Should reject empty mnemonic");
}

#[test]
fn test_mnemonic_display_format() {
    let recovery_key = SyftRecoveryKey::generate();
    let mnemonic = recovery_key.to_mnemonic();

    // Verify it's a single line with space-separated words
    assert!(
        !mnemonic.contains('\n'),
        "Mnemonic should not contain newlines"
    );
    assert!(mnemonic.contains(' '), "Mnemonic should contain spaces");

    // Count spaces (should be 23 for 24 words)
    let space_count = mnemonic.chars().filter(|&c| c == ' ').count();
    assert_eq!(space_count, 23, "Should have 23 spaces between 24 words");
}
