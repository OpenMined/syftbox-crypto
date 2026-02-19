use crate::datasite::context::{
    AppContext, atomic_write, enforce_replay_protection, resolve_data_path, resolve_identity,
};
use crate::datasite::crypto::{
    decrypt_envelope_for_recipient, load_private_keys_for_identity, parse_optional_envelope,
    resolve_recipient_bundle, resolve_sender_bundle_for_decrypt,
};
use crate::{EncryptionRecipient, encrypt_message};
use anyhow::{Result, bail};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct BytesWriteOpts {
    pub relative: PathBuf,
    pub recipients: Vec<String>,
    pub sender: Option<String>,
    pub plaintext: bool,
    pub overwrite: bool,
    pub hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BytesReadOpts {
    pub relative: PathBuf,
    pub identity: Option<String>,
    pub require_envelope: bool,
}

#[derive(Debug, Clone)]
pub struct BytesWriteOutcome {
    pub destination: PathBuf,
    pub bytes_written: usize,
    pub encrypted: bool,
}

#[derive(Debug, Clone)]
pub struct BytesReadOutput {
    pub source: PathBuf,
    pub plaintext: Vec<u8>,
    pub envelope_used: bool,
}

/// Writes plaintext or encrypted bytes to a datasite path.
///
/// When recipients are specified, encrypts data using X3DH multi-recipient encryption
/// where the payload is encrypted once and the key is wrapped separately for each recipient.
/// All recipients can independently decrypt using their private keys.
///
/// # Arguments
/// * `context` - Application context containing vault and data root paths
/// * `opts` - Write options including sender (auto-detected if None), recipients, plaintext flag, and overwrite behavior
/// * `data` - Raw bytes to write (plaintext or to be encrypted)
///
/// # Returns
/// `BytesWriteOutcome` containing destination path, bytes written, and encryption status
///
/// # Errors
/// - File already exists and `overwrite` is false
/// - Sender identity cannot be resolved (multiple identities present) or keys not found
/// - Recipient bundle not cached in vault
pub fn write_bytes(
    context: &AppContext,
    opts: &BytesWriteOpts,
    data: &[u8],
) -> Result<BytesWriteOutcome> {
    let encrypted = !opts.recipients.is_empty() && !opts.plaintext;
    let data_path = resolve_data_path(context, &opts.relative);
    if data_path.exists() && !opts.overwrite {
        bail!(
            "path {} already exists (use --overwrite to replace)",
            data_path.display()
        );
    }

    let payload = if encrypted {
        let sender_identity = resolve_identity(opts.sender.as_deref(), &context.vault_path)?;
        let sender_keys = load_private_keys_for_identity(context, &sender_identity)?;

        // Resolve bundles for all recipients
        let mut bundles = Vec::with_capacity(opts.recipients.len());
        for recipient_identity in &opts.recipients {
            let bundle = resolve_recipient_bundle(
                context,
                &sender_keys,
                &sender_identity,
                recipient_identity,
            )?;
            bundles.push(bundle);
        }

        // Build EncryptionRecipient references
        let recipients: Vec<EncryptionRecipient> = opts
            .recipients
            .iter()
            .zip(bundles.iter())
            .map(|(identity, bundle)| EncryptionRecipient {
                identity: identity.as_str(),
                bundle,
            })
            .collect();

        let hint = opts.hint.clone().or_else(|| {
            opts.relative
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        });

        let mut rng = rand::rng();
        encrypt_message(
            &sender_identity,
            &sender_keys,
            &recipients,
            data,
            hint.as_deref(),
            &mut rng,
        )?
    } else {
        data.to_vec()
    };

    atomic_write(&data_path, &payload)?;
    Ok(BytesWriteOutcome {
        destination: data_path,
        bytes_written: payload.len(),
        encrypted,
    })
}

pub fn read_bytes(context: &AppContext, opts: &BytesReadOpts) -> Result<BytesReadOutput> {
    let data_path = resolve_data_path(context, &opts.relative);
    if !data_path.exists() {
        bail!("{} does not exist", data_path.display());
    }
    let bytes = fs::read(&data_path)?;

    let identity = resolve_identity(opts.identity.as_deref(), &context.vault_path)?;

    let (plaintext, envelope_used) = match parse_optional_envelope(&bytes)? {
        Some(envelope) => {
            enforce_replay_protection(&context.vault_path, &data_path, &envelope)?;
            let recipient_keys = load_private_keys_for_identity(context, &identity)?;
            let sender_bundle = resolve_sender_bundle_for_decrypt(context, &envelope)?;
            let plaintext = decrypt_envelope_for_recipient(
                &identity,
                &recipient_keys,
                &sender_bundle,
                &envelope,
            )?;
            (plaintext, true)
        }
        None => {
            if opts.require_envelope {
                bail!("{} does not contain an SBC envelope", data_path.display());
            }
            (bytes, false)
        }
    };

    Ok(BytesReadOutput {
        source: data_path,
        plaintext,
        envelope_used,
    })
}
