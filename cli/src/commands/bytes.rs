use crate::app::{AppContext, atomic_write};
use crate::commands::PlanPrinter;
use crate::result::Result;
use clap::{Args, Subcommand};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use syftbox_crypto_protocol::datasite::bytes::{
    BytesReadOpts, BytesWriteOpts, read_bytes, write_bytes,
};

#[derive(Subcommand, Debug)]
pub(crate) enum BytesCommand {
    /// Write plaintext or encrypted bytes to the datasite tree
    Write(BytesWriteArgs),
    /// Read plaintext from a datasite path, automatically decrypting when needed
    Read(BytesReadArgs),
}

#[derive(Args, Debug)]
pub(crate) struct BytesWriteArgs {
    /// Relative path within the datasite tree
    #[arg(short = 'p', long, value_name = "RELATIVE")]
    pub(crate) relative: PathBuf,

    /// Recipient identities to encrypt for; omit to store plaintext
    #[arg(long = "recipient", value_name = "IDENTITY")]
    pub(crate) recipients: Vec<String>,

    /// Source file to read from (defaults to stdin)
    #[arg(long, value_name = "FILE")]
    pub(crate) input: Option<PathBuf>,

    /// Force plaintext storage even if recipients are supplied
    #[arg(long)]
    pub(crate) plaintext: bool,

    /// Allow replacing an existing file
    #[arg(long)]
    pub(crate) overwrite: bool,

    /// Optional filename hint stored in the envelope metadata
    #[arg(long, value_name = "TEXT")]
    pub(crate) hint: Option<String>,
}

impl From<&BytesWriteArgs> for BytesWriteOpts {
    fn from(args: &BytesWriteArgs) -> Self {
        Self {
            relative: args.relative.clone(),
            recipients: args.recipients.clone(),
            sender: None, // Auto-detect sender identity
            plaintext: args.plaintext,
            overwrite: args.overwrite,
            hint: args.hint.clone(),
        }
    }
}

#[derive(Args, Debug)]
pub(crate) struct BytesReadArgs {
    /// Relative path within the datasite tree
    #[arg(short = 'p', long, value_name = "RELATIVE")]
    pub(crate) relative: PathBuf,

    /// Identity used to decrypt (auto-detect when omitted)
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) identity: Option<String>,

    /// Fail if the target is plaintext (defaults to lenient mode)
    #[arg(long)]
    pub(crate) require_envelope: bool,

    /// Destination file for the plaintext (defaults to stdout)
    #[arg(long, value_name = "FILE")]
    pub(crate) output: Option<PathBuf>,
}

impl From<&BytesReadArgs> for BytesReadOpts {
    fn from(args: &BytesReadArgs) -> Self {
        Self {
            relative: args.relative.clone(),
            identity: args.identity.clone(),
            require_envelope: args.require_envelope,
        }
    }
}

pub(crate) fn handle_bytes_command(context: &AppContext, command: BytesCommand) -> Result<()> {
    match command {
        BytesCommand::Write(args) => handle_bytes_write(context, args),
        BytesCommand::Read(args) => handle_bytes_read(context, args),
    }
}

fn handle_bytes_write(context: &AppContext, args: BytesWriteArgs) -> Result<()> {
    let plan = PlanPrinter::stderr("bytes write");
    let opts = BytesWriteOpts::from(&args);
    let data = read_write_input(&args, &plan)?;
    plan.field("relative path", opts.relative.display())
        .field(
            "mode",
            if !opts.recipients.is_empty() && !opts.plaintext {
                "encrypted"
            } else {
                "plaintext"
            },
        )
        .bool("overwrite existing", opts.overwrite);

    let outcome = write_bytes(context, &opts, &data)?;
    plan.field("bytes written", outcome.bytes_written)
        .field("destination", outcome.destination.display());
    Ok(())
}

fn handle_bytes_read(context: &AppContext, args: BytesReadArgs) -> Result<()> {
    let plan = PlanPrinter::stderr("bytes read");
    let opts = BytesReadOpts::from(&args);
    plan.field("relative path", opts.relative.display());
    let output = read_bytes(context, &opts)?;
    plan.field("datasite source", output.source.display())
        .info(if output.envelope_used {
            "decrypted envelope"
        } else {
            "read plaintext"
        });

    match &args.output {
        Some(path) => {
            atomic_write(path, &output.plaintext)?;
            plan.field("wrote output to", path.display());
        }
        None => {
            plan.info("writing plaintext to stdout");
            io::stdout().write_all(&output.plaintext)?;
        }
    }

    Ok(())
}

fn read_write_input(args: &BytesWriteArgs, plan: &PlanPrinter) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    match &args.input {
        Some(path) => {
            plan.field("input", path.display());
            data = fs::read(path)?;
        }
        None => {
            plan.info("reading from stdin");
            io::stdin().read_to_end(&mut data)?;
        }
    }

    if data.is_empty() {
        plan.info("warning: zero-byte payload");
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/cli/bytes_command_tests.rs"
    ));
}
