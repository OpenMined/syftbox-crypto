use syftbox_crypto_protocol::did_utils::{generate_did_web_id, generate_did_web_id_default};

#[test]
fn test_generate_did_web_id_basic() {
    let did = generate_did_web_id("test@example.com", "syftbox.net");
    assert_eq!(did, "did:web:syftbox.net:test%40example.com");
}

#[test]
fn test_generate_did_web_id_with_special_characters() {
    // Test with special characters matching Python test case
    let did = generate_did_web_id("test+user@example.com", "custom.domain");
    assert_eq!(did, "did:web:custom.domain:test%2Buser%40example.com");
}

#[test]
fn test_generate_did_web_id_default_domain() {
    let did = generate_did_web_id_default("alice@example.com");
    assert_eq!(did, "did:web:syftbox.net:alice%40example.com");
}

#[test]
fn test_url_encoding_all_special_chars() {
    // Comprehensive test with multiple special characters
    // Note: periods (.) are NOT encoded by urllib.parse.quote(safe="")
    let did = generate_did_web_id("test.user+tag@sub.example.com", "domain.io");
    assert_eq!(did, "did:web:domain.io:test.user%2Btag%40sub.example.com");
}

#[test]
fn test_matches_python_implementation() {
    // These test cases exactly match the Python implementation in syft-extras
    // From: packages/syftbox-crypto/tests/bootstrap_test.py::test_generate_did_web_id

    // Test case 1: line 269
    let did = generate_did_web_id("test@example.com", "syftbox.net");
    assert_eq!(did, "did:web:syftbox.net:test%40example.com");

    // Test case 2: line 273
    let did = generate_did_web_id("test+user@example.com", "custom.domain");
    assert_eq!(did, "did:web:custom.domain:test%2Buser%40example.com");
}

#[test]
fn test_deterministic() {
    // Same input should always produce same output
    let did1 = generate_did_web_id("alice@example.com", "syftbox.net");
    let did2 = generate_did_web_id("alice@example.com", "syftbox.net");
    assert_eq!(did1, did2);
}

#[test]
fn test_different_emails_different_dids() {
    let did1 = generate_did_web_id("alice@example.com", "syftbox.net");
    let did2 = generate_did_web_id("bob@example.com", "syftbox.net");
    assert_ne!(did1, did2);
}

#[test]
fn test_different_domains_different_dids() {
    let did1 = generate_did_web_id("alice@example.com", "syftbox.net");
    let did2 = generate_did_web_id("alice@example.com", "other.domain");
    assert_ne!(did1, did2);
}

#[test]
fn test_real_world_examples() {
    // Real-world examples that would be used in SyftBox
    let did = generate_did_web_id("alice@openmined.org", "syftbox.net");
    assert_eq!(did, "did:web:syftbox.net:alice%40openmined.org");

    // Note: periods are NOT encoded (matches Python urllib.parse.quote behavior)
    let did = generate_did_web_id("user.name+tag@company.com", "syftbox.net");
    assert_eq!(did, "did:web:syftbox.net:user.name%2Btag%40company.com");
}
