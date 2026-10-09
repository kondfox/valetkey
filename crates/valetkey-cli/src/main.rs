//! `valetkey`: the binary. This is the only place concrete implementations are wired together
//! (§4).

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use valetkey_core::{Platform, Registry, ValetkeyRoot};

mod commands;
mod output;

/// Let AI agents use credentials without seeing them.
#[derive(Debug, Parser)]
#[command(name = "valetkey", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a starter valetkey.toml in the current directory.
    Init,
    /// Review the project's valetkey.toml and approve it. Must run in a normal terminal.
    Allow,
    /// Check this machine and project, and say what to fix.
    Doctor,
    /// Record which vendor CLIs (gcloud) the broker may run. Must run in a normal terminal.
    Setup,
    /// Manage local:// secrets.
    #[command(subcommand)]
    Secret(commands::secret::SecretCommand),
    /// Review and approve a pending write; without an id, list pending writes. Must run in a
    /// normal terminal.
    Approve {
        /// The request id the agent's call printed (e.g. 17-k3f9).
        id: Option<String>,
        /// Show the whole statement and every parameter in full (needed to approve a long one).
        #[arg(long)]
        full: bool,
    },
    /// Show the audit log of SQL tool calls.
    Log {
        /// Keep printing new records as they arrive.
        #[arg(long, short)]
        follow: bool,
    },
    /// Run the MCP server on stdin/stdout. The agent client starts this; humans don't.
    Mcp,
    /// Print the JSON Schema for valetkey.toml.
    Schema,
}

/// Every target kind this build supports.
pub(crate) fn registry() -> Registry {
    Registry::default().with(valetkey_postgres::PostgresKind)
}

pub(crate) fn platform() -> Platform {
    Platform::current()
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Init => commands::init::run(),
        Command::Allow => commands::allow::run(),
        Command::Doctor => commands::doctor::run(),
        Command::Setup => commands::setup::run(),
        Command::Secret(cmd) => commands::secret::run(cmd),
        Command::Approve { id, full } => commands::approve::run(id, full),
        Command::Log { follow } => commands::log::run(follow),
        Command::Mcp => commands::mcp::run(),
        Command::Schema => commands::schema::run(),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("valetkey: {e:#}");
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn resolve_root() -> anyhow::Result<ValetkeyRoot> {
    Ok(ValetkeyRoot::resolve()?)
}
