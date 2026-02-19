use crate::app::{AppContext, ensure_vault_layout, expand_home};
use crate::commands::PlanPrinter;
use crate::result::Result;
use clap::{Args, Subcommand};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::fs;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};
use tar::{Archive, Builder};

#[derive(Subcommand, Debug)]
pub(crate) enum VaultCommand {
    /// Create a gzip-compressed tarball containing the entire vault
    Export(VaultExportArgs),

    /// Restore a vault snapshot produced by `vault export`
    Import(VaultImportArgs),
}

#[derive(Args, Debug)]
pub(crate) struct VaultExportArgs {
    /// Destination archive path (tar.gz)
    #[arg(short, long, value_name = "FILE")]
    pub(crate) output: PathBuf,

    /// Overwrite an existing archive
    #[arg(long)]
    pub(crate) overwrite: bool,
}

#[derive(Args, Debug)]
pub(crate) struct VaultImportArgs {
    /// Snapshot archive produced by `vault export`
    #[arg(short, long, value_name = "FILE")]
    pub(crate) archive: PathBuf,

    /// Allow replacing an existing vault directory
    #[arg(long)]
    pub(crate) force: bool,
}

pub(crate) fn handle_vault_command(context: &AppContext, command: VaultCommand) -> Result<()> {
    match command {
        VaultCommand::Export(args) => handle_vault_export(context, args),
        VaultCommand::Import(args) => handle_vault_import(context, args),
    }
}

fn handle_vault_export(context: &AppContext, args: VaultExportArgs) -> Result<()> {
    let plan = PlanPrinter::new("export vault snapshot");
    let output_path = expand_home(&args.output);
    plan.field("vault", context.vault_path.display())
        .field("output archive", output_path.display())
        .bool("overwrite existing", args.overwrite);

    if output_path.exists() && !args.overwrite {
        return Err(format!(
            "archive {} already exists (use --overwrite to replace)",
            output_path.display()
        )
        .into());
    }

    ensure_vault_layout(&context.vault_path)?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(&output_path)?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(encoder);
    builder.append_dir_all(".", &context.vault_path)?;
    let encoder = builder.into_inner()?;
    encoder.finish()?;

    plan.info("snapshot complete");
    Ok(())
}

fn handle_vault_import(context: &AppContext, args: VaultImportArgs) -> Result<()> {
    let plan = PlanPrinter::new("import vault snapshot");
    let archive_path = expand_home(&args.archive);
    plan.field("vault", context.vault_path.display())
        .field("archive", archive_path.display())
        .bool("force overwrite", args.force);

    if !archive_path.exists() {
        return Err(format!("archive {} not found", archive_path.display()).into());
    }

    ensure_vault_layout(&context.vault_path)?;

    if !args.force && vault_contains_data(&context.vault_path)? {
        return Err(format!(
            "vault {} already contains data; rerun with --force to replace",
            context.vault_path.display()
        )
        .into());
    }

    if args.force {
        clear_vault(&context.vault_path)?;
    }

    let file = File::open(&archive_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    archive.set_unpack_xattrs(false);
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);
    import_archive_entries(&mut archive, &context.vault_path)?;

    plan.info("import complete");
    Ok(())
}

fn import_archive_entries<R: io::Read>(archive: &mut Archive<R>, vault_path: &Path) -> Result<()> {
    let target_root = vault_path
        .canonicalize()
        .unwrap_or_else(|_| vault_path.to_path_buf());

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();
        if !(entry_type.is_file() || entry_type.is_dir()) {
            return Err(format!("unsupported archive entry type: {:?}", entry_type).into());
        }

        let entry_path = entry.path()?.into_owned();
        validate_archive_entry_path(&entry_path)?;

        let unpacked = entry.unpack_in(&target_root)?;
        if !unpacked {
            return Err(
                format!("archive entry rejected as unsafe: {}", entry_path.display()).into(),
            );
        }
    }

    Ok(())
}

fn validate_archive_entry_path(path: &Path) -> Result<()> {
    for part in path.components() {
        match part {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("unsafe archive entry path: {}", path.display()).into());
            }
            Component::CurDir | Component::Normal(_) => {}
        }
    }
    Ok(())
}

fn vault_contains_data(path: &Path) -> io::Result<bool> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        let entry_path = entry.path();
        if entry.file_type()?.is_dir() {
            if fs::read_dir(&entry_path)?.next().is_some() {
                return Ok(true);
            } else {
                continue;
            }
        } else {
            return Ok(true);
        }
    }
    Ok(false)
}

fn clear_vault(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry_path)?;
        } else {
            fs::remove_file(entry_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/cli/vault_command_tests.rs"
    ));
}
