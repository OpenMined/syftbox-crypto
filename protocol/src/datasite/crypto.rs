use crate::datasite::context::{
    AppContext, atomic_write_private, bundle_path_for_identity, key_path_for_identity,
};
use crate::{
    EncryptionRecipient, SyftPrivateKeys, SyftPublicKeyBundle, decrypt_message, encrypt_message,
    envelope::{ParsedEnvelope, has_sbc_magic, parse_envelope},
    serialization::{
        deserialize_from_did_document, deserialize_private_keys, serialize_private_keys,
        zeroize_json_value,
    },
};
use anyhow::{Context, Result, anyhow, bail};
use rand::rng;
use serde_json::{self, Map, Value};
use std::fs;
use std::path::Path;
use urlencoding;
use zeroize::Zeroize;

pub struct PublicBundleInfo {
    pub identity: String,
    pub fingerprint: String,
    pub did: Option<String>,
    pub bundle: SyftPublicKeyBundle,
    pub value: Value,
}

pub fn load_private_keys_for_identity(
    context: &AppContext,
    identity: &str,
) -> Result<SyftPrivateKeys> {
    let key_path = key_path_for_identity(&context.vault_path, identity);
    if !key_path.exists() {
        bail!("key material not found in vault (run `sbc key generate`)");
    }
    load_private_keys_from_file(&key_path)
}

pub fn load_cached_bundle(
    context: &AppContext,
    identity: &str,
) -> Result<Option<PublicBundleInfo>> {
    let path = bundle_path_for_identity(&context.vault_path, identity);
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(path)?;
    let info = parse_public_bundle(&body)?;
    Ok(Some(info))
}

pub fn resolve_recipient_bundle(
    context: &AppContext,
    sender_keys: &SyftPrivateKeys,
    sender_identity: &str,
    recipient_identity: &str,
) -> Result<SyftPublicKeyBundle> {
    if let Some(info) = load_cached_bundle(context, recipient_identity)? {
        Ok(info.bundle)
    } else if sender_identity == recipient_identity {
        sender_keys
            .to_public_bundle(&mut rng())
            .map_err(|e| anyhow!("failed to derive sender public bundle: {e}"))
    } else {
        bail!("recipient bundle not cached (run `sbc key import --bundle ...`)");
    }
}

pub fn resolve_sender_bundle_for_decrypt(
    context: &AppContext,
    parsed: &ParsedEnvelope,
) -> Result<SyftPublicKeyBundle> {
    let sender_identity = &parsed.prelude.sender.identity;
    if let Some(info) = load_cached_bundle(context, sender_identity)? {
        Ok(info.bundle)
    } else {
        bail!("sender bundle not cached (run `sbc key import`)");
    }
}

pub fn encrypt_envelope_for_recipient(
    sender_identity: &str,
    sender_keys: &SyftPrivateKeys,
    recipient_identity: &str,
    recipient_bundle: &SyftPublicKeyBundle,
    plaintext: &[u8],
    hint: Option<&str>,
) -> Result<Vec<u8>> {
    let mut rng = rng();
    let recipient = EncryptionRecipient {
        identity: recipient_identity,
        bundle: recipient_bundle,
    };
    let ciphertext = encrypt_message(
        sender_identity,
        sender_keys,
        &[recipient],
        plaintext,
        hint,
        &mut rng,
    )?;
    Ok(ciphertext)
}

pub fn decrypt_envelope_for_recipient(
    recipient_identity: &str,
    recipient_keys: &SyftPrivateKeys,
    sender_bundle: &SyftPublicKeyBundle,
    envelope: &ParsedEnvelope,
) -> Result<Vec<u8>> {
    let plaintext = decrypt_message(recipient_identity, recipient_keys, sender_bundle, envelope)?;
    Ok(plaintext)
}

pub fn parse_optional_envelope(bytes: &[u8]) -> Result<Option<ParsedEnvelope>> {
    if has_sbc_magic(bytes) {
        let parsed = parse_envelope(bytes)?;
        Ok(Some(parsed))
    } else {
        Ok(None)
    }
}

pub fn parse_public_bundle(body: &str) -> Result<PublicBundleInfo> {
    let value: Value = serde_json::from_str(body)?;
    let bundle =
        deserialize_from_did_document(&value).map_err(|e| anyhow!("invalid DID document: {e}"))?;
    let fingerprint = bundle.identity_fingerprint();
    let identity = extract_identity(&value)
        .ok_or_else(|| anyhow!("bundle missing identity metadata or DID id"))?;
    let did = value
        .get("id")
        .and_then(Value::as_str)
        .map(|s| s.to_string());

    Ok(PublicBundleInfo {
        identity,
        fingerprint,
        did,
        bundle,
        value,
    })
}

fn extract_identity(value: &Value) -> Option<String> {
    if let Some(identity) = value.get("identity").and_then(Value::as_str) {
        return Some(identity.to_string());
    }
    value
        .get("id")
        .and_then(Value::as_str)
        .and_then(identity_from_did_id)
}

fn identity_from_did_id(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:web:")?;
    let decoded = urlencoding::decode(rest).ok()?;
    let path = decoded
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let mut parts = path.split('/');
    parts.next()?; // domain
    parts.next().map(|s| s.to_string())
}

pub fn load_private_keys_from_file(path: &Path) -> Result<SyftPrivateKeys> {
    let mut body = fs::read_to_string(path)?;
    let mut value: Value = serde_json::from_str(&body)?;
    body.zeroize();

    let result = (|| {
        let jwks = value
            .get("private_keys")
            .ok_or_else(|| anyhow!("key file missing private_keys section"))?;
        deserialize_private_keys(jwks).context("failed to parse sbc private keys")
    })();

    zeroize_json_value(&mut value);
    result
}

pub fn serialize_private_keys_to_file(path: &Path, keys: &SyftPrivateKeys) -> Result<()> {
    let jwks = serialize_private_keys(keys)?;
    let mut map = Map::new();
    map.insert("private_keys".into(), jwks);
    let mut body = serde_json::to_vec_pretty(&Value::Object(map))?;
    atomic_write_private(path, &body)?;
    body.zeroize();
    Ok(())
}
