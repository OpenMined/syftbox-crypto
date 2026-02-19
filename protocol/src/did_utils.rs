//! DID (Decentralized Identifier) utilities
pub fn generate_did_web_id(email: &str, domain: &str) -> String {
    let encoded_email = urlencoding::encode(email);
    format!("did:web:{}:{}", domain, encoded_email)
}

/// Generate a `did:web` identifier using the default SyftBox domain.
pub fn generate_did_web_id_default(email: &str) -> String {
    generate_did_web_id(email, "syftbox.net")
}
