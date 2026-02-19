use crate::app::{
    AppContext, atomic_write, enforce_replay_protection, ensure_vault_layout, resolve_data_path,
    resolve_shadow_path, yes_no,
};
use crate::commands::{PlanPrinter, resolve_identity};
use crate::protocol_interface::inspect_ciphertext;
use crate::result::Result;
use clap::{Args, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use syftbox_crypto_protocol::datasite::crypto::{
    decrypt_envelope_for_recipient, encrypt_envelope_for_recipient, load_cached_bundle,
    load_private_keys_for_identity, parse_optional_envelope, resolve_recipient_bundle,
    resolve_sender_bundle_for_decrypt,
};
use syftbox_crypto_protocol::envelope::{CURRENT_VERSION, MAGIC, ParsedEnvelope, verify_signature};

/// File and path subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum FileCommand {
    /// Encrypt a source file into a destination file without touching datasite roots
    Encrypt(FileEncryptArgs),

    /// Decrypt a ciphertext file into a destination file without touching datasite roots
    Decrypt(FileDecryptArgs),

    /// Inspect an encrypted blob without modifying it
    Inspect(FileInspectArgs),
}

pub(crate) fn handle_file_command(context: &AppContext, command: FileCommand) -> Result<()> {
    match command {
        FileCommand::Encrypt(args) => handle_file_encrypt(context, args),
        FileCommand::Decrypt(args) => handle_file_decrypt(context, args),
        FileCommand::Inspect(args) => handle_file_inspect(context, args),
    }
}

/// Arguments for `sbc file encrypt`.
#[derive(Args, Debug)]
pub(crate) struct FileEncryptArgs {
    /// Relative path within datasite/shadow trees (mirrors encrypt/decrypt automatically)
    #[arg(short = 'p', long, value_name = "RELATIVE")]
    pub(crate) relative: Option<PathBuf>,

    /// Path to the plaintext file to encrypt (direct mode)
    #[arg(short, long, value_name = "FILE")]
    pub(crate) src: Option<PathBuf>,

    /// Destination path for the encrypted output (direct mode)
    #[arg(short, long, value_name = "FILE")]
    pub(crate) dest: Option<PathBuf>,

    /// Identity to tag as sender (metadata only in placeholder mode)
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) sender: Option<String>,

    /// Identity to tag as recipient (metadata only in placeholder mode)
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) recipient: Option<String>,

    /// Simulate the encryption without writing output
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// Arguments for `sbc file decrypt`.
#[derive(Args, Debug)]
pub(crate) struct FileDecryptArgs {
    /// Relative path within datasite/shadow trees (mirrors encrypt/decrypt automatically)
    #[arg(short = 'p', long, value_name = "RELATIVE")]
    pub(crate) relative: Option<PathBuf>,

    /// Encrypted input file (direct mode)
    #[arg(short, long, value_name = "FILE")]
    pub(crate) src: Option<PathBuf>,

    /// Destination for decrypted plaintext (direct mode)
    #[arg(short, long, value_name = "FILE")]
    pub(crate) dest: Option<PathBuf>,

    /// Identity expected to own the decryption keys (auto-detect if omitted)
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) identity: Option<String>,

    /// Simulate the operation without writing output
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// Arguments for `sbc file inspect`.
#[derive(Args, Debug)]
pub(crate) struct FileInspectArgs {
    /// Encrypted file to inspect (relative paths resolve under data root)
    #[arg(short, long, value_name = "FILE")]
    pub(crate) input: PathBuf,

    /// Identity to resolve in the vault when checking key availability
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) identity: Option<String>,

    /// Print extended debugging info about headers and schema
    #[arg(long)]
    pub(crate) verbose: bool,
}

fn handle_file_encrypt(context: &AppContext, args: FileEncryptArgs) -> Result<()> {
    let plan = PlanPrinter::new("file encrypt");
    plan.bool("dry-run", args.dry_run);

    let operation = resolve_encrypt_plan(context, &args, &plan)?;
    let Some(operation) = operation else {
        return Ok(());
    };

    let sender_identity = resolve_identity(args.sender.as_deref(), &context.vault_path)?;
    plan.field("using sender identity", &sender_identity);

    let recipient_identity = args.recipient.clone().ok_or_else(|| {
        "--recipient is required when encrypting files (target identity missing)".to_string()
    })?;
    plan.field("recipient", &recipient_identity);

    let sender_keys = load_private_keys_for_identity(context, &sender_identity)?;
    let recipient_bundle =
        resolve_recipient_bundle(context, &sender_keys, &sender_identity, &recipient_identity)?;

    let filename_hint = match operation.mode {
        OperationMode::Relative => args
            .relative
            .as_ref()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        OperationMode::Direct => operation
            .input_path()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned()),
    };

    let plaintext = fs::read(operation.input_path())?;
    let envelope = encrypt_envelope_for_recipient(
        &sender_identity,
        &sender_keys,
        &recipient_identity,
        &recipient_bundle,
        &plaintext,
        filename_hint.as_deref(),
    )?;

    atomic_write(operation.output_path(), &envelope)?;
    match operation.mode {
        OperationMode::Relative => println!(
            "  wrote SBC envelope atomically to {}",
            operation.output_path().display()
        ),
        OperationMode::Direct => println!(
            "  wrote SBC envelope to {}",
            operation.output_path().display()
        ),
    }

    Ok(())
}

fn handle_file_decrypt(context: &AppContext, args: FileDecryptArgs) -> Result<()> {
    let plan = PlanPrinter::new("file decrypt");
    plan.bool("dry-run", args.dry_run);

    let operation = resolve_decrypt_plan(context, &args, &plan)?;
    let Some(operation) = operation else {
        return Ok(());
    };

    let active_identity = resolve_identity(args.identity.as_deref(), &context.vault_path)?;
    plan.field("using identity", &active_identity);

    let encrypted_path = operation.input_path();
    let file_bytes = fs::read(encrypted_path)?;
    let parsed_envelope = parse_optional_envelope(&file_bytes)?;
    let parsed_envelope = match parsed_envelope {
        Some(parsed) => Some(parsed),
        None => {
            handle_missing_envelope(operation.mode, encrypted_path)?;
            None
        }
    };

    let plaintext = if let Some(parsed) = parsed_envelope.as_ref() {
        enforce_replay_protection(&context.vault_path, encrypted_path, parsed)?;
        let recipient_keys = load_private_keys_for_identity(context, &active_identity)?;
        let sender_bundle = resolve_sender_bundle_for_decrypt(context, parsed)?;
        decrypt_envelope_for_recipient(&active_identity, &recipient_keys, &sender_bundle, parsed)?
    } else {
        file_bytes.clone()
    };

    atomic_write(operation.output_path(), &plaintext)?;
    match operation.mode {
        OperationMode::Relative => println!(
            "  wrote decrypted output atomically to {}",
            operation.output_path().display()
        ),
        OperationMode::Direct => println!(
            "  wrote decrypted output to {}",
            operation.output_path().display()
        ),
    }

    Ok(())
}

fn resolve_encrypt_plan(
    context: &AppContext,
    args: &FileEncryptArgs,
    plan: &PlanPrinter,
) -> Result<Option<OperationPaths>> {
    if let Some(relative) = &args.relative {
        plan.field("mode", "datasite/shadow (relative)")
            .field("vault", context.vault_path.display())
            .field("data root", context.data_root.display())
            .field("shadow root", context.shadow_root.display())
            .field("relative path", relative.display())
            .opt("recipient", args.recipient.as_deref())
            .opt("sender identity", args.sender.as_deref());

        if args.dry_run {
            plan.info("dry-run complete: no ciphertext produced");
            return Ok(None);
        }

        ensure_vault_layout(&context.vault_path)?;
        let shadow_path = resolve_shadow_path(context, relative);
        let data_path = resolve_data_path(context, relative);
        plan.field("shadow source", shadow_path.display())
            .field("datasite destination", data_path.display());

        Ok(Some(OperationPaths {
            mode: OperationMode::Relative,
            input: shadow_path,
            output: data_path,
        }))
    } else {
        let src = args
            .src
            .as_ref()
            .ok_or_else(|| "--src or --relative is required".to_string())?;
        let dest = args
            .dest
            .as_ref()
            .ok_or_else(|| "--dest or --relative is required".to_string())?;

        plan.field("mode", "direct file")
            .field("source", src.display())
            .field("destination", dest.display())
            .opt("sender identity", args.sender.as_deref())
            .opt("recipient identity", args.recipient.as_deref());

        if args.dry_run {
            plan.info("dry-run complete: no ciphertext produced");
            return Ok(None);
        }

        Ok(Some(OperationPaths {
            mode: OperationMode::Direct,
            input: src.to_path_buf(),
            output: dest.to_path_buf(),
        }))
    }
}

fn resolve_decrypt_plan(
    context: &AppContext,
    args: &FileDecryptArgs,
    plan: &PlanPrinter,
) -> Result<Option<OperationPaths>> {
    if let Some(relative) = &args.relative {
        plan.field("mode", "datasite/shadow (relative)")
            .field("vault", context.vault_path.display())
            .field("data root", context.data_root.display())
            .field("shadow root", context.shadow_root.display())
            .field("relative path", relative.display());
        match &args.identity {
            Some(identity) => {
                plan.field("preferred identity", identity);
            }
            None => {
                plan.field("preferred identity", "auto-detect");
            }
        }
        if args.dry_run {
            plan.info("dry-run complete: no plaintext extracted");
            return Ok(None);
        }

        ensure_vault_layout(&context.vault_path)?;
        let data_path = resolve_data_path(context, relative);
        let shadow_path = resolve_shadow_path(context, relative);
        plan.field("datasite source", data_path.display())
            .field("shadow destination", shadow_path.display());

        Ok(Some(OperationPaths {
            mode: OperationMode::Relative,
            input: data_path,
            output: shadow_path,
        }))
    } else {
        let src = args
            .src
            .as_ref()
            .ok_or_else(|| "--src or --relative is required".to_string())?;
        let dest = args
            .dest
            .as_ref()
            .ok_or_else(|| "--dest or --relative is required".to_string())?;

        plan.field("mode", "direct file")
            .field("source", src.display())
            .field("destination", dest.display());
        match &args.identity {
            Some(identity) => {
                plan.field("preferred identity", identity);
            }
            None => {
                plan.field("preferred identity", "auto-detect");
            }
        }

        if args.dry_run {
            plan.info("dry-run complete: no plaintext extracted");
            return Ok(None);
        }

        Ok(Some(OperationPaths {
            mode: OperationMode::Direct,
            input: src.to_path_buf(),
            output: dest.to_path_buf(),
        }))
    }
}

fn handle_missing_envelope(mode: OperationMode, path: &Path) -> Result<()> {
    match mode {
        OperationMode::Relative => {
            println!("  SBC envelope missing – treating payload as plaintext (relative mode)");
            Ok(())
        }
        OperationMode::Direct => Err(format!(
            "input {} is not an SBC envelope (magic missing)",
            path.display()
        )
        .into()),
    }
}

#[derive(Clone, Copy)]
enum OperationMode {
    Relative,
    Direct,
}

struct OperationPaths {
    mode: OperationMode,
    input: PathBuf,
    output: PathBuf,
}

impl OperationPaths {
    fn input_path(&self) -> &Path {
        &self.input
    }

    fn output_path(&self) -> &Path {
        &self.output
    }
}

fn handle_file_inspect(context: &AppContext, args: FileInspectArgs) -> Result<()> {
    println!("[plan] inspect encrypted blob");
    println!("  vault: {}", context.vault_path.display());
    let ciphertext_path = resolve_data_path(context, &args.input);
    println!("  input (encrypted): {}", ciphertext_path.display());
    if let Some(identity) = &args.identity {
        println!("  identity: {}", identity);
    }
    println!("  verbose: {}", yes_no(args.verbose));
    let bytes = fs::read(&ciphertext_path)?;
    if let Some(parsed) = parse_optional_envelope(&bytes)? {
        println!(
            "  envelope magic: {} (version {})",
            std::str::from_utf8(MAGIC).unwrap_or("SBC1"),
            CURRENT_VERSION
        );
        println!("  created_at: {}", parsed.prelude.created_at);
        println!(
            "  sender: {} (ik_fingerprint: {})",
            parsed.prelude.sender.identity, parsed.prelude.sender.ik_fingerprint
        );
        report_sender_consistency(context, &parsed)?;
        match resolve_sender_bundle_for_decrypt(context, &parsed) {
            Ok(bundle) => match verify_signature(&parsed, &bundle.identity_signing_public_key) {
                Ok(()) => println!("  signature: valid (sender bundle cached)"),
                Err(_) => println!("  signature: INVALID (signature mismatch)"),
            },
            Err(err) => {
                println!(
                    "  signature: unable to verify ({}); run `sbc key import` for sender?",
                    err
                );
            }
        }
        println!("  recipients ({}):", parsed.prelude.recipients.len());
        for recipient in &parsed.prelude.recipients {
            let identity = recipient
                .identity
                .as_deref()
                .unwrap_or("<unspecified-identity>");
            let device = recipient
                .device_label
                .as_deref()
                .unwrap_or("<unspecified-device>");
            println!(
                "    - {} [{}] spk={}",
                identity,
                device,
                recipient.spk_fingerprint.as_deref().unwrap_or("<none>")
            );
        }
        println!(
            "  cipher: suite={} segments={} last_segment_bytes={} ciphertext_len={}",
            parsed.prelude.cipher.suite,
            parsed.prelude.cipher.segment_count,
            parsed.prelude.cipher.last_segment_bytes,
            parsed.prelude.cipher.ciphertext_len
        );
        if let Some(meta) = &parsed.prelude.public_meta
            && let Some(filename_hint) = &meta.filename_hint
        {
            println!("  filename hint: {}", filename_hint);
        }
        println!("  prelude size: {} bytes", parsed.prelude_bytes.len());
        println!("  signature size: {} bytes", parsed.signature.len());
        println!("  payload bytes: {}", parsed.ciphertext.len());
    } else {
        let info = inspect_ciphertext(&bytes);
        println!("  not an SBC envelope – treating input as plaintext");
        println!(
            "  ciphertext marker present: {}",
            yes_no(info.envelope.is_wrapped())
        );
        println!("  file size: {} bytes", info.length);
    }

    Ok(())
}

fn report_sender_consistency(context: &AppContext, parsed: &ParsedEnvelope) -> Result<()> {
    let sender_identity = &parsed.prelude.sender.identity;
    if sender_identity.is_empty() {
        return Ok(());
    }

    match load_cached_bundle(context, sender_identity)? {
        Some(info) => {
            if info.fingerprint == parsed.prelude.sender.ik_fingerprint {
                println!("  cached sender fingerprint matches ({})", info.fingerprint);
            } else {
                println!(
                    "  warning: cached sender fingerprint {} differs from envelope {} (TOFU violation)",
                    info.fingerprint, parsed.prelude.sender.ik_fingerprint
                );
            }
        }
        None => {
            println!(
                "  note: sender identity {} has no cached bundle – consider `sbc key import`",
                sender_identity
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/cli/file_command_tests.rs"
    ));
}
