//! `valetkey schema`: the JSON Schema for `valetkey.toml`, for editor completion and validation.
//! `schema/valetkey.schema.json` in the repository is this output; a test keeps it current.

use std::collections::BTreeMap;
use std::process::ExitCode;

use schemars::JsonSchema;
use valetkey_postgres::PostgresTarget;

use crate::output;

/// valetkey.toml: the targets an AI agent may use through valetkey without seeing their secrets.
#[derive(JsonSchema)]
#[schemars(title = "valetkey.toml", deny_unknown_fields)]
#[allow(dead_code)] // only its schema is used
struct ValetkeyToml {
    /// The oldest valetkey version this file works with, e.g. "0.1".
    min_version: Option<String>,
    /// Use protected secrets only when the agent is fenced (default true).
    require_fence: Option<bool>,
    /// Targets by id (1–63 characters of a-z, 0-9, '.', '_', '-').
    targets: Option<BTreeMap<String, Target>>,
}

#[derive(JsonSchema)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[allow(dead_code)]
enum Target {
    /// A Postgres database.
    Postgres(PostgresTarget),
}

pub(crate) fn render() -> String {
    let schema = schemars::schema_for!(ValetkeyToml);
    format!(
        "{}\n",
        serde_json::to_string_pretty(&schema).expect("a schema always serializes")
    )
}

pub(crate) fn run() -> anyhow::Result<ExitCode> {
    output::line(render().trim_end());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    #[test]
    fn checked_in_schema_is_current() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schema/valetkey.schema.json");
        let checked_in = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            checked_in == super::render(),
            "schema/valetkey.schema.json is stale; regenerate it with: cargo run -q -p valetkey-cli -- schema > schema/valetkey.schema.json"
        );
    }
}
