//! `valetkey init`: a starter `valetkey.toml`. Fence generation joins it in M4 (§2.3).

use std::io::Write;
use std::process::ExitCode;

use anyhow::Context;
use valetkey_core::config::CONFIG_FILE_NAME;

use crate::output;

const TEMPLATE: &str = r#"#:schema https://raw.githubusercontent.com/kondfox/valetkey/main/schema/valetkey.schema.json
#
# valetkey.toml: the targets an AI agent may use through valetkey without seeing their secrets.
# Commit it. Never put a secret here: `secret` is a *reference* to where the secret lives.
# After every change, a human approves the file in a normal terminal: `valetkey allow`.

# min_version = "0.1"
# require_fence = true   # default: protected secrets are only used when the agent is fenced

# A local development database. Its password sits in a .env file the agent can read anyway
# ("exposed"), so plain TCP is allowed.
#
# [targets.local-app]
# kind     = "postgres"
# host     = "localhost"
# database = "app"
# user     = "app"
# secret   = "env-file://.env#POSTGRES_PASSWORD"
# writable = true

# A deployed database behind a proxy socket. The password is "protected": the agent can't read
# it, so it only ever travels over a socket the agent can't reach. `valetkey doctor` prints the
# exact proxy command.
#
# [targets.staging-app]
# kind     = "postgres"
# socket   = "stage-core"
# database = "app"
# user     = "vk_reader"            # a dedicated role, never the application's own
# secret   = "gcp-sm://acme-stage/DB_PASSWORD"
"#;

pub(crate) fn run() -> anyhow::Result<ExitCode> {
    let path = std::env::current_dir()?.join(CONFIG_FILE_NAME);
    let mut file = match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            output::fail(format!("{} already exists; edit it instead", path.display()));
            return Ok(ExitCode::FAILURE);
        }
        Err(e) => return Err(e).with_context(|| format!("can't create {}", path.display())),
    };
    file.write_all(TEMPLATE.as_bytes())?;
    output::ok(format!("created {}", path.display()));
    output::line("Next:");
    output::line("  1. Uncomment and edit the targets you need.");
    output::line(format!(
        "  2. In a normal terminal, approve it: {} allow",
        output::self_path()
    ));
    output::line(format!("  3. Check the setup: {} doctor", output::self_path()));
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use valetkey_core::{NormalizeCx, Platform, ValetkeyRoot};

    #[test]
    fn template_parses_and_its_examples_are_valid() {
        let root = ValetkeyRoot::at("/Users/dev/.valetkey");
        let cx = NormalizeCx {
            root: &root,
            platform: Platform::MacOs,
        };
        let empty = crate::registry().parse(super::TEMPLATE, &cx).unwrap();
        assert!(empty.targets.is_empty());

        let uncommented: String = super::TEMPLATE
            .lines()
            .map(|l| {
                l.strip_prefix("# ")
                    .filter(|r| r.starts_with('[') || r.contains(" = ") || r.contains("= "))
                    .unwrap_or(l)
            })
            .collect::<Vec<_>>()
            .join("\n");
        let full = crate::registry().parse(&uncommented, &cx).unwrap();
        assert_eq!(full.targets.len(), 2);
        assert!(full.require_fence);
    }
}
