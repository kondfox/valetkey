//! The Postgres adapter (§6.9). M1 implements only the target's config: its schema, validation and
//! canonical form. The driver, the read path and the guards arrive in M2.

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use valetkey_core::{Exposure, NormalizeCx, NormalizedTarget, Problem, SecretRef, TargetId, TargetKind};

/// Postgres's socket file name inside a socket directory.
pub const SOCKET_FILE: &str = ".s.PGSQL.5432";

const DEFAULT_PORT: u16 = 5432;

/// A `kind = "postgres"` target in `valetkey.toml`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PostgresTarget {
    /// TCP host. Only for targets whose secret is exposed (e.g. `env-file://`); a protected secret
    /// must use `socket` (§6.2).
    pub host: Option<String>,
    /// TCP port (default 5432). Only with `host`.
    pub port: Option<u16>,
    /// Socket alias: the proxy listens on `~/.valetkey/sockets/<alias>/.s.PGSQL.5432`.
    pub socket: Option<String>,
    /// The database name. The broker verifies it with `current_database()` on every connect.
    pub database: String,
    /// The login role. Use a dedicated role per target, never the application's (§6.9).
    pub user: String,
    /// Where the password comes from.
    pub secret: SecretRef,
    /// Whether `sql_execute` may write. Default `false`.
    #[serde(default)]
    pub writable: bool,
    /// Free text for humans and the agent.
    pub description: Option<String>,
}

/// Registers `kind = "postgres"`.
#[derive(Debug, Default)]
pub struct PostgresKind;

impl TargetKind for PostgresKind {
    fn kind(&self) -> &'static str {
        "postgres"
    }

    fn normalize(
        &self,
        id: &TargetId,
        fields: toml::Table,
        cx: &NormalizeCx<'_>,
    ) -> Result<NormalizedTarget, Vec<Problem>> {
        let t: PostgresTarget = toml::Value::Table(fields)
            .try_into()
            .map_err(|e: toml::de::Error| vec![Problem::target(id.as_str(), e.message().to_owned())])?;
        let problem = |m: String| Problem::target(id.as_str(), m);
        let mut problems = Vec::new();
        let exposure = t.secret.exposure(cx.platform);

        let connection = match (&t.host, &t.socket) {
            (Some(host), None) => {
                if host.is_empty() || host.chars().any(|c| c.is_whitespace() || c.is_control() || c == '/') {
                    problems.push(problem(format!("invalid host `{}`", host.escape_debug())));
                }
                if exposure == Exposure::Protected {
                    problems.push(problem(format!(
                        "a protected secret ({}) can't be sent over plain TCP, which the agent could intercept; use `socket` (verified TLS arrives in M2)",
                        t.secret.scheme()
                    )));
                }
                json!({ "host": host, "port": t.port.unwrap_or(DEFAULT_PORT), "database": t.database, "user": t.user })
            }
            (None, Some(alias)) => {
                if t.port.is_some() {
                    problems.push(problem("`port` only applies to `host`".into()));
                }
                if !is_alias(alias) {
                    problems.push(problem(format!(
                        "invalid socket alias `{}`: use 1–40 characters of `a-z`, `0-9`, `-`",
                        alias.escape_debug()
                    )));
                } else {
                    let path = cx.root.socket_dir(alias).join(SOCKET_FILE);
                    let len = path.as_os_str().len();
                    let max = cx.platform.max_socket_path_len();
                    if len > max {
                        problems.push(problem(format!(
                            "the socket path {} is {len} bytes; this platform allows {max}. Use a shorter alias",
                            path.display()
                        )));
                    }
                }
                json!({ "socket": alias, "database": t.database, "user": t.user })
            }
            (Some(_), Some(_)) => {
                problems.push(problem("set either `host` or `socket`, not both".into()));
                json!(null)
            }
            (None, None) => {
                problems.push(problem("set `host` (exposed secrets only) or `socket`".into()));
                json!(null)
            }
        };
        for (field, value) in [("database", &t.database), ("user", &t.user)] {
            if value.is_empty() || value.chars().any(char::is_control) {
                problems.push(problem(format!("invalid {field} `{}`", value.escape_debug())));
            }
        }

        if !problems.is_empty() {
            return Err(problems);
        }
        Ok(NormalizedTarget {
            kind: "postgres".into(),
            secret: Some(t.secret),
            exposure: Some(exposure),
            writable: t.writable,
            connection,
            settings: json!({ "description": t.description }),
        })
    }
}

fn is_alias(s: &str) -> bool {
    (1..=40).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use valetkey_core::{Platform, Registry, ValetkeyRoot};

    fn parse_on(text: &str, platform: Platform, root: &str) -> Result<valetkey_core::ProjectConfig, Vec<Problem>> {
        let root = ValetkeyRoot::at(root);
        Registry::default()
            .with(PostgresKind)
            .parse(text, &NormalizeCx { root: &root, platform })
    }

    fn parse(text: &str) -> Result<valetkey_core::ProjectConfig, Vec<Problem>> {
        parse_on(text, Platform::MacOs, "/Users/dev/.valetkey")
    }

    fn messages(text: &str) -> Vec<String> {
        parse(text).unwrap_err().iter().map(ToString::to_string).collect()
    }

    const LOCAL: &str = "[targets.local-app]\nkind = \"postgres\"\nhost = \"localhost\"\ndatabase = \"app\"\nuser = \"app\"\nsecret = \"env-file://.env#POSTGRES_PASSWORD\"\nwritable = true\n";
    const STAGING: &str = "[targets.staging-app]\nkind = \"postgres\"\nsocket = \"stage-core\"\ndatabase = \"app\"\nuser = \"vk_reader\"\nsecret = \"gcp-sm://acme-stage/DB_PASSWORD\"\n";

    #[test]
    fn accepts_the_documented_examples() {
        let c = parse(&format!("{LOCAL}{STAGING}")).unwrap();
        let local = &c.targets["local-app"];
        assert_eq!(local.exposure, Some(Exposure::Exposed));
        assert_eq!(local.connection["port"], 5432);
        assert!(local.writable);
        let staging = &c.targets["staging-app"];
        assert_eq!(staging.exposure, Some(Exposure::Protected));
        assert_eq!(staging.connection["socket"], "stage-core");
        assert!(!staging.writable);
    }

    #[test]
    fn protected_secret_over_tcp_is_refused() {
        let text = LOCAL.replace("env-file://.env#POSTGRES_PASSWORD", "local://local-app");
        assert!(
            messages(&text)
                .iter()
                .any(|m| m.contains("can't be sent over plain TCP"))
        );
    }

    #[test]
    fn keyring_is_exposed_on_macos_but_protected_on_linux() {
        let text = LOCAL.replace("env-file://.env#POSTGRES_PASSWORD", "keyring://valetkey/local-app");
        assert!(parse_on(&text, Platform::MacOs, "/Users/dev/.valetkey").is_ok());
        assert!(parse_on(&text, Platform::Linux, "/home/dev/.valetkey").is_err());
    }

    #[test]
    fn host_and_socket_are_exclusive() {
        let both = STAGING.replace("socket = \"stage-core\"", "socket = \"stage-core\"\nhost = \"h\"");
        assert!(messages(&both).iter().any(|m| m.contains("either `host` or `socket`")));
        let neither = STAGING.replace("socket = \"stage-core\"\n", "");
        assert!(messages(&neither).iter().any(|m| m.contains("set `host`")));
    }

    #[test]
    fn socket_alias_and_length_are_checked() {
        assert!(
            messages(&STAGING.replace("stage-core", "Stage/../x"))
                .iter()
                .any(|m| m.contains("invalid socket alias"))
        );
        let long_root = format!("/Users/{}/.valetkey", "u".repeat(40));
        let long_alias = STAGING.replace("stage-core", &"a".repeat(30));
        let err = parse_on(&long_alias, Platform::MacOs, &long_root).unwrap_err();
        assert!(
            err.iter().any(|p| p.message.contains("this platform allows 103")),
            "{err:?}"
        );
        assert!(
            parse_on(STAGING, Platform::MacOs, &long_root).is_ok(),
            "a short alias still fits"
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(
            messages(&format!("{STAGING}pasword = \"x\"\n"))
                .iter()
                .any(|m| m.contains("pasword"))
        );
    }
}
