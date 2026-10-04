//! `valetkey secret set|rm|ls`: manage `local://` secrets (§6.0). Values are typed with no echo
//! and are never printed.

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::Subcommand;
use secrecy::SecretString;
use valetkey_secrets::cache::DEFAULT_TTL;
use valetkey_secrets::sources::LocalSource;

use crate::output;

#[derive(Debug, Subcommand)]
pub(crate) enum SecretCommand {
    /// Store a secret, typed with no echo. Refuses to overwrite unless --replace.
    Set {
        /// The id, as in `local://<id>`.
        id: String,
        /// Overwrite an existing secret.
        #[arg(long)]
        replace: bool,
    },
    /// Delete a secret.
    Rm { id: String },
    /// List stored secret ids (never values).
    Ls,
}

pub(crate) fn run(cmd: SecretCommand) -> anyhow::Result<ExitCode> {
    let root = crate::resolve_root()?;
    match cmd {
        SecretCommand::Set { id, replace } => {
            if !std::io::stdin().is_terminal() {
                output::fail(
                    "valetkey secret set needs an interactive terminal, so the value is typed, not piped or logged",
                );
                return Ok(ExitCode::FAILURE);
            }
            // Validate before the human types the value.
            LocalSource::validate_id(&id)?;
            let value = rpassword::prompt_password(format!("Value for local://{id} (not shown): "))?;
            if value.is_empty() {
                output::fail("empty value; nothing stored");
                return Ok(ExitCode::FAILURE);
            }
            LocalSource::store(&root, &id, &SecretString::from(value), replace)?;
            output::ok(format!("stored local://{id}"));
            if replace {
                output::warn(format!(
                    "a running broker may keep using the previous value for up to {} minutes",
                    DEFAULT_TTL.as_secs() / 60
                ));
            }
        }
        SecretCommand::Rm { id } => {
            if LocalSource::remove(&root, &id)? {
                output::ok(format!("removed local://{id}"));
            } else {
                output::warn(format!("local://{id} doesn't exist"));
            }
        }
        SecretCommand::Ls => {
            for id in LocalSource::list(&root)? {
                output::line(format!("local://{id}"));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
