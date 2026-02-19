use crate::app::{
    AppContext, atomic_write_private, bundle_path_for_identity, ensure_vault_layout, expand_home,
    fallback_identity_from_path, key_path_for_identity, read_identity_from_key, resolve_data_path,
};
use crate::commands::PlanPrinter;
use crate::protocol_interface::generate_identity_material;
use crate::result::Result;
use clap::{Args, Subcommand};
use serde_json::{Value, json, to_string_pretty};
use std::fs;
use std::path::PathBuf;
use syftbox_crypto_protocol::datasite::crypto::parse_public_bundle;
use zeroize::Zeroize;

/// Identity and key-management subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum KeyCommand {
    /// Generate a new identity and signed pre-key set
    Generate(KeyGenerateArgs),

    /// Import an existing bundle into the local vault after verifying signatures
    Import(KeyImportArgs),

    /// Restore identity material from a recovery package
    Recover(KeyRecoverArgs),

    /// List identities currently tracked in the local vault
    List(KeyListArgs),

    /// Validate bundle signatures and report metadata
    Verify(KeyVerifyArgs),

    /// Export private key material for safekeeping
    Backup(KeyBackupArgs),

    /// Restore private key material from a backup file
    Restore(KeyRestoreArgs),
}

pub(crate) fn handle_key_command(context: &AppContext, command: KeyCommand) -> Result<()> {
    match command {
        KeyCommand::Generate(args) => handle_key_generate(context, args),
        KeyCommand::Import(args) => handle_key_import(context, args),
        KeyCommand::Recover(args) => handle_key_recover(context, args),
        KeyCommand::List(args) => handle_key_list(context, args),
        KeyCommand::Verify(args) => handle_key_verify(context, args),
        KeyCommand::Backup(args) => handle_key_backup(context, args),
        KeyCommand::Restore(args) => handle_key_restore(context, args),
    }
}

/// Arguments for `sbc key generate`.
#[derive(Args, Debug)]
pub(crate) struct KeyGenerateArgs {
    /// Identifier for the new identity (email, DID, etc.)
    #[arg(short, long, value_name = "IDENTITY")]
    pub(crate) identity: String,

    /// Optional path to export the public bundle alongside the private material
    #[arg(long, value_name = "FILE")]
    pub(crate) bundle_out: Option<PathBuf>,

    /// Allow replacing an existing identity when generating new material
    #[arg(long)]
    pub(crate) overwrite: bool,

    /// Simulate the operation without writing key material
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// Arguments for `sbc key import`.
#[derive(Args, Debug)]
pub(crate) struct KeyImportArgs {
    /// Path to the bundle to import
    #[arg(short, long, value_name = "FILE")]
    pub(crate) bundle: PathBuf,

    /// Expected identity string; warn if the bundle claims a different identity
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) expected_identity: Option<String>,

    /// Perform verification only without writing to the vault
    #[arg(long)]
    pub(crate) verify_only: bool,

    /// Replace any existing identity without confirmation (bypasses TOFU)
    #[arg(long)]
    pub(crate) force: bool,
}

/// Arguments for `sbc key recover`.
#[derive(Args, Debug)]
pub(crate) struct KeyRecoverArgs {
    /// Recovery package containing encrypted identity material
    #[arg(short, long, value_name = "FILE")]
    pub(crate) package: PathBuf,

    /// Identity label to associate with the recovered material
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) identity: Option<String>,

    /// Optional output location for decrypted artifacts
    #[arg(long, value_name = "DIR")]
    pub(crate) output: Option<PathBuf>,

    /// Simulate recovery without writing files
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// Arguments for `sbc key list`.
#[derive(Args, Debug)]
pub(crate) struct KeyListArgs {
    /// Filter results to a single identity label
    #[arg(short, long, value_name = "IDENTITY")]
    pub(crate) identity: Option<String>,

    /// Include derived metadata such as key fingerprints
    #[arg(long)]
    pub(crate) verbose: bool,
}

/// Arguments for `sbc key verify`.
#[derive(Args, Debug)]
pub(crate) struct KeyVerifyArgs {
    /// Path to the bundle to verify
    #[arg(short, long, value_name = "FILE")]
    pub(crate) bundle: PathBuf,

    /// Expected identity string; warn if the bundle claims a different identity
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) expected_identity: Option<String>,

    /// Perform verification without touching the key vault
    #[arg(long)]
    pub(crate) verify_only: bool,

    /// Emit structured JSON describing the bundle
    #[arg(long)]
    pub(crate) json: bool,
}

/// Arguments for `sbc key backup`.
#[derive(Args, Debug)]
pub(crate) struct KeyBackupArgs {
    /// Identity whose private key should be exported
    #[arg(short, long, value_name = "IDENTITY")]
    pub(crate) identity: String,

    /// Destination file path for the exported key
    #[arg(short, long, value_name = "FILE")]
    pub(crate) output: PathBuf,

    /// Allow replacing an existing output file
    #[arg(long)]
    pub(crate) overwrite: bool,
}

/// Arguments for `sbc key restore`.
#[derive(Args, Debug)]
pub(crate) struct KeyRestoreArgs {
    /// Backup file created by `key backup`
    #[arg(short, long, value_name = "FILE")]
    pub(crate) input: PathBuf,

    /// Expected identity label; inferred from file when omitted
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) identity: Option<String>,

    /// Replace existing key material without prompting
    #[arg(long)]
    pub(crate) overwrite: bool,
}

fn handle_key_generate(context: &AppContext, args: KeyGenerateArgs) -> Result<()> {
    let plan = PlanPrinter::new("generate identity material");
    plan.field("vault", context.vault_path.display())
        .field("identity", &args.identity)
        .bool("overwrite existing", args.overwrite);
    if let Some(bundle_out) = &args.bundle_out {
        let resolved = resolve_data_path(context, bundle_out);
        plan.field("export public bundle to", resolved.display());
    }
    if args.dry_run {
        plan.info("dry-run: no files will be written");
    }
    plan.info("derive recovery key + X3DH material via syftbox-crypto-protocol")
        .info("persist private JWKS into the vault and emit DID bundle artifacts");

    if args.dry_run {
        plan.info("dry-run complete: no changes were made");
        return Ok(());
    }

    ensure_vault_layout(&context.vault_path)?;
    let key_path = key_path_for_identity(&context.vault_path, &args.identity);

    if key_path.exists() && !args.overwrite {
        return Err(format!(
            "key material already exists at {} (use --overwrite to replace)",
            key_path.display()
        )
        .into());
    }

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut generated = generate_identity_material(&args.identity)?;

    atomic_write_private(&key_path, &generated.key_file)?;
    println!(
        "  wrote private key material for {}: {}",
        args.identity,
        key_path.display()
    );
    println!("  identity fingerprint: {}", generated.fingerprint);
    println!("  DID identifier: {}", generated.did);
    println!(
        "  recovery key (hex): {}\n  recovery mnemonic: {}",
        generated.recovery_key_hex.as_str(),
        generated.recovery_key_mnemonic.as_str()
    );
    println!("  write the recovery key down – it regenerates all private keys.");

    if let Some(bundle_out) = &args.bundle_out {
        let resolved = resolve_data_path(context, bundle_out);
        if let Some(parent) = resolved.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut bundle_body = to_string_pretty(&generated.public_bundle)?;
        bundle_body.push('\n');
        fs::write(&resolved, bundle_body)?;
        println!(
            "  exported DID document for {} to {}",
            args.identity,
            resolved.display()
        );
    }

    generated.key_file.fill(0);

    Ok(())
}

fn handle_key_import(context: &AppContext, args: KeyImportArgs) -> Result<()> {
    let plan = PlanPrinter::new("import bundle into vault");
    plan.field("vault", context.vault_path.display());
    let bundle_path = resolve_data_path(context, &args.bundle);
    plan.field("bundle", bundle_path.display());
    match &args.expected_identity {
        Some(identity) => {
            plan.field("expected identity (TOFU guard)", identity);
        }
        None => {
            plan.field("expected identity", "auto-detect");
        }
    }
    plan.bool("verification only", args.verify_only)
        .bool("force overwrite", args.force)
        .info("verify bundle signatures + identity metadata");

    let bundle_body = fs::read_to_string(&bundle_path)?;
    let bundle_info = parse_public_bundle(&bundle_body)?;
    plan.field("bundle identity", &bundle_info.identity)
        .field("bundle fingerprint", &bundle_info.fingerprint);
    if let Some(did) = &bundle_info.did {
        plan.field("bundle DID", did);
    }

    if let Some(expected) = args.expected_identity.as_deref()
        && expected != bundle_info.identity
    {
        if args.force {
            println!(
                "  warning: bundle identity '{}' differs from expected '{}'; proceeding due to --force",
                bundle_info.identity, expected
            );
        } else {
            return Err(format!(
                "bundle identity '{}' does not match expected '{}' (use --force to override)",
                bundle_info.identity, expected
            )
            .into());
        }
    }

    if args.verify_only {
        plan.info("verification complete – bundle not stored");
        return Ok(());
    }

    ensure_vault_layout(&context.vault_path)?;
    let dest = bundle_path_for_identity(&context.vault_path, &bundle_info.identity);
    if dest.exists() {
        let existing_body = fs::read_to_string(&dest)?;
        let existing_info = parse_public_bundle(&existing_body)?;
        if existing_info.fingerprint == bundle_info.fingerprint {
            println!(
                "  cached bundle already matches fingerprint {} – leaving file untouched",
                bundle_info.fingerprint
            );
            if args.force {
                println!("  note: --force ignored because bundle is unchanged");
            }
            return Ok(());
        }

        if !args.force {
            return Err(format!(
                "bundle for {} already cached with fingerprint {} – new fingerprint {} requires --force",
                bundle_info.identity, existing_info.fingerprint, bundle_info.fingerprint
            )
            .into());
        }

        println!(
            "  warning: overwriting cached bundle for {} ({} -> {})",
            bundle_info.identity, existing_info.fingerprint, bundle_info.fingerprint
        );
    } else {
        println!(
            "  no cached bundle for {}; will store at {}",
            bundle_info.identity,
            dest.display()
        );
    }

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut formatted = serde_json::to_vec_pretty(&bundle_info.value)?;
    formatted.push(b'\n');
    fs::write(&dest, formatted)?;
    println!("  stored bundle copy at {}", dest.display());
    Ok(())
}

fn handle_key_recover(context: &AppContext, args: KeyRecoverArgs) -> Result<()> {
    let plan = PlanPrinter::new("recover identity from package");
    plan.field("vault", context.vault_path.display())
        .field("package", args.package.display());
    if let Some(identity) = &args.identity {
        plan.field("target identity label", identity);
    } else {
        plan.field("target identity label", "derive from package");
    }
    if let Some(output) = &args.output {
        plan.field("staging output directory", output.display());
    }
    plan.bool("dry-run", args.dry_run)
        .info("TODO: decrypt recovery package and rehydrate key material")
        .info("TODO: verify signatures before committing recovered keys to vault");
    if args.dry_run {
        plan.info("dry-run complete: no changes were made");
    }
    Ok(())
}

fn handle_key_list(context: &AppContext, args: KeyListArgs) -> Result<()> {
    let plan = PlanPrinter::new("list known identities");
    plan.field("vault", context.vault_path.display());
    if let Some(identity) = &args.identity {
        plan.field("filter", identity);
    }
    plan.bool("verbose", args.verbose);

    ensure_vault_layout(&context.vault_path)?;
    let keys_dir = context.vault_path.join("keys");
    let mut found_any = false;

    if keys_dir.exists() {
        for entry in fs::read_dir(&keys_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let identity = read_identity_from_key(entry.path())
                    .unwrap_or_else(|_| fallback_identity_from_path(entry.path()));

                if let Some(filter) = &args.identity
                    && filter != &identity
                {
                    continue;
                }

                found_any = true;
                if args.verbose {
                    let size = fs::metadata(entry.path())?.len();
                    println!("  - {} ({} bytes)", identity, size);
                } else {
                    println!("  - {}", identity);
                }
            }
        }
    }

    if !found_any {
        println!("  (no identities found)");
    }

    Ok(())
}

fn handle_key_verify(context: &AppContext, args: KeyVerifyArgs) -> Result<()> {
    let plan = PlanPrinter::new("verify bundle");
    plan.field("vault (for context only)", context.vault_path.display());
    let bundle_path = resolve_data_path(context, &args.bundle);
    plan.field("bundle", bundle_path.display());
    if let Some(identity) = &args.expected_identity {
        plan.field("expected identity", identity);
    }
    plan.bool("verify only", args.verify_only)
        .bool("emit json", args.json)
        .info("verify DID signatures + surface metadata");

    let body = fs::read_to_string(&bundle_path)?;
    let bundle_info = parse_public_bundle(&body)?;

    if let Some(expected) = args.expected_identity.as_deref()
        && expected != bundle_info.identity
    {
        println!(
            "  warning: bundle identity '{}' differs from expected '{}'",
            bundle_info.identity, expected
        );
    }

    if args.json {
        let summary = json!({
            "bundle_path": bundle_path.display().to_string(),
            "identity": bundle_info.identity,
            "identity_fingerprint": bundle_info.fingerprint,
            "did": bundle_info.did,
            "length": body.len()
        });
        println!("{}", summary);
    } else {
        println!("  identity: {}", bundle_info.identity);
        if let Some(did) = &bundle_info.did {
            println!("  did: {}", did);
        }
        println!("  fingerprint: {}", bundle_info.fingerprint);
        println!("  bundle size: {} bytes", body.len());
    }

    Ok(())
}

fn handle_key_backup(context: &AppContext, args: KeyBackupArgs) -> Result<()> {
    let plan = PlanPrinter::new("backup private key");
    let output_path = expand_home(&args.output);
    plan.field("vault", context.vault_path.display())
        .field("identity", &args.identity)
        .field("output file", output_path.display())
        .bool("overwrite existing", args.overwrite);

    ensure_vault_layout(&context.vault_path)?;
    let source = key_path_for_identity(&context.vault_path, &args.identity);
    if !source.exists() {
        return Err(format!(
            "key material for {} not found at {}",
            args.identity,
            source.display()
        )
        .into());
    }

    if output_path.exists() && !args.overwrite {
        return Err(format!(
            "output {} already exists (use --overwrite to replace)",
            output_path.display()
        )
        .into());
    }

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut private_key_bytes = fs::read(&source)?;
    atomic_write_private(&output_path, &private_key_bytes)?;
    private_key_bytes.fill(0);
    plan.info("backup complete");
    Ok(())
}

fn handle_key_restore(context: &AppContext, args: KeyRestoreArgs) -> Result<()> {
    let plan = PlanPrinter::new("restore private key from backup");
    let input_path = expand_home(&args.input);
    plan.field("vault", context.vault_path.display())
        .field("input file", input_path.display())
        .bool("overwrite existing", args.overwrite);

    if !input_path.exists() {
        return Err(format!("input {} not found", input_path.display()).into());
    }

    let inferred_identity = read_identity_from_key(input_path.clone())
        .or_else(|_| infer_identity_from_backup(&input_path))?;
    let identity = match &args.identity {
        Some(expected) => {
            if expected != &inferred_identity {
                return Err(format!(
                    "backup identity '{}' does not match expected '{}'",
                    inferred_identity, expected
                )
                .into());
            }
            expected.clone()
        }
        None => inferred_identity,
    };

    ensure_vault_layout(&context.vault_path)?;
    let dest = key_path_for_identity(&context.vault_path, &identity);
    if dest.exists() && !args.overwrite {
        return Err(format!(
            "key for {} already exists at {} (use --overwrite to replace)",
            identity,
            dest.display()
        )
        .into());
    }

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut private_key_bytes = fs::read(&input_path)?;
    atomic_write_private(&dest, &private_key_bytes)?;
    private_key_bytes.fill(0);
    plan.info(&format!("restored key material for {}", identity));
    Ok(())
}

fn infer_identity_from_backup(path: &PathBuf) -> Result<String> {
    let mut body = fs::read_to_string(path)?;
    let mut value: Value = serde_json::from_str(&body)?;
    body.zeroize();
    let identity = value
        .get("identity")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .ok_or_else(|| "unable to infer identity from key backup".into());
    zeroize_json_value(&mut value);
    identity
}

fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
        Value::String(s) => s.zeroize(),
        Value::Array(items) => {
            for item in items {
                zeroize_json_value(item);
            }
        }
        Value::Object(map) => {
            for (_, val) in map.iter_mut() {
                zeroize_json_value(val);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/cli/key_command_tests.rs"
    ));
}
