mod app;
mod commands;
mod protocol_interface;
mod result;

use app::{AppContext, resolve_roots, resolve_vault};
use clap::Parser;
use commands::{Cli, handle_command};
use result::Result;

fn main() {
    if let Err(error) = run() {
        eprintln!("sbc: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    run_with_cli(cli)
}

pub fn run_with_args<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    run_with_cli(cli)
}

fn run_with_cli(cli: Cli) -> Result<()> {
    let Cli {
        vault,
        data_root,
        shadow_root,
        command,
    } = cli;

    let vault_path = resolve_vault(vault);
    let (data_root, shadow_root) = resolve_roots(data_root, shadow_root, &vault_path)?;

    let context = AppContext {
        vault_path,
        data_root,
        shadow_root,
    };

    handle_command(&context, command)
}

#[cfg(test)]
#[path = "tests/cli/main_tests.rs"]
mod tests;
