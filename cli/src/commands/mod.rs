pub mod bytes;
mod file;
mod key;
mod vault;

use clap::{Parser, Subcommand};
use std::fmt::{self, Display};
use std::path::PathBuf;

use crate::app::{AppContext, yes_no};
use crate::result::Result;

pub(crate) use bytes::BytesCommand;
pub(crate) use file::FileCommand;
pub(crate) use key::KeyCommand;
pub(crate) use syftbox_crypto_protocol::datasite::context::resolve_identity;
pub(crate) use vault::VaultCommand;

/// SyftBox Crypto (sbc) CLI – manage X3DH keys and files.
#[derive(Parser, Debug)]
#[command(name = "sbc", version, about = "SyftBox Crypto CLI (sbc)")]
pub struct Cli {
    /// Override the default vault directory (~/.sbc)
    #[arg(
        global = true,
        long,
        value_name = "DIR",
        help = "Path to the sbc vault (default: ~/.sbc)"
    )]
    pub(crate) vault: Option<PathBuf>,

    /// Override the encrypted data root (defaults from vault config or env)
    #[arg(
        global = true,
        long,
        value_name = "DIR",
        help = "Root directory that SyftBox syncs (defaults via config or SBC_DATA_ROOT)"
    )]
    pub(crate) data_root: Option<PathBuf>,

    /// Override the plaintext shadow root (defaults from vault config or env)
    #[arg(
        global = true,
        long,
        value_name = "DIR",
        help = "Shadow directory for decrypted data (defaults via config or SBC_SHADOW_ROOT)"
    )]
    pub(crate) shadow_root: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Command,
}

/// Top-level commands exposed by the CLI.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Stream plaintext bytes into/out of the datasite
    #[command(subcommand)]
    Bytes(BytesCommand),

    /// Manage identity material, bundles, and recovery artifacts
    #[command(subcommand)]
    Key(KeyCommand),

    /// Encrypt, decrypt, and inspect sealed blobs
    #[command(subcommand)]
    File(FileCommand),

    /// Export or restore vault snapshots
    #[command(subcommand)]
    Vault(VaultCommand),
}

pub(crate) fn handle_command(context: &AppContext, command: Command) -> Result<()> {
    match command {
        Command::Bytes(cmd) => bytes::handle_bytes_command(context, cmd),
        Command::Key(cmd) => key::handle_key_command(context, cmd),
        Command::File(cmd) => file::handle_file_command(context, cmd),
        Command::Vault(cmd) => vault::handle_vault_command(context, cmd),
    }
}

#[derive(Clone, Copy)]
enum PlanChannel {
    Stdout,
    Stderr,
}

pub(crate) struct PlanPrinter {
    channel: PlanChannel,
}

impl PlanPrinter {
    pub(crate) fn new(title: &str) -> Self {
        Self::stdout(title)
    }

    pub(crate) fn stdout(title: &str) -> Self {
        let printer = Self {
            channel: PlanChannel::Stdout,
        };
        printer.emit(format_args!("[plan] {}", title));
        printer
    }

    pub(crate) fn stderr(title: &str) -> Self {
        let printer = Self {
            channel: PlanChannel::Stderr,
        };
        printer.emit(format_args!("[plan] {}", title));
        printer
    }

    fn emit(&self, args: fmt::Arguments<'_>) {
        match self.channel {
            PlanChannel::Stdout => println!("{}", args),
            PlanChannel::Stderr => eprintln!("{}", args),
        }
    }

    pub(crate) fn field<T: Display>(&self, name: &str, value: T) -> &Self {
        self.emit(format_args!("  {}: {}", name, value));
        self
    }

    pub(crate) fn bool(&self, name: &str, value: bool) -> &Self {
        self.field(name, yes_no(value))
    }

    pub(crate) fn opt<T: Display>(&self, name: &str, value: Option<T>) -> &Self {
        if let Some(value) = value {
            self.field(name, value);
        }
        self
    }

    pub(crate) fn info(&self, message: &str) -> &Self {
        self.emit(format_args!("  {}", message));
        self
    }
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/cli/commands_mod_tests.rs"
    ));
}
