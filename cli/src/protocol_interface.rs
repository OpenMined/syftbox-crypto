use syftbox_crypto_protocol::envelope::has_sbc_magic;

pub use syftbox_crypto_protocol::identity::generate_identity_material;

/// Information extracted during ciphertext inspection.
pub(crate) struct CipherInspection {
    pub(crate) envelope: CipherEnvelope,
    pub(crate) length: usize,
}

/// Indicates whether bytes were wrapped using an SBC envelope or left as plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CipherEnvelope {
    Wrapped,
    Plaintext,
}

impl CipherEnvelope {
    pub(crate) fn is_wrapped(self) -> bool {
        matches!(self, CipherEnvelope::Wrapped)
    }
}

pub(crate) fn inspect_ciphertext(ciphertext: &[u8]) -> CipherInspection {
    let envelope = if has_sbc_magic(ciphertext) {
        CipherEnvelope::Wrapped
    } else {
        CipherEnvelope::Plaintext
    };

    CipherInspection {
        envelope,
        length: ciphertext.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syftbox_crypto_protocol::datasite::crypto::parse_public_bundle;

    #[test]
    fn inspect_ciphertext_marks_plaintext() {
        let inspection = inspect_ciphertext(b"no envelope");
        assert_eq!(inspection.envelope, CipherEnvelope::Plaintext);
        assert_eq!(inspection.length, 11);
    }

    #[test]
    fn parse_public_bundle_extracts_identity_and_fingerprint() {
        let generated = generate_identity_material("alice@example.org").unwrap();
        let body = serde_json::to_string(&generated.public_bundle).unwrap();
        let parsed = parse_public_bundle(&body).unwrap();
        assert_eq!(parsed.identity, "alice@example.org");
        assert_eq!(parsed.fingerprint.len(), 64);
        assert!(
            parsed
                .did
                .as_deref()
                .unwrap_or_default()
                .starts_with("did:web:")
        );
    }
}
