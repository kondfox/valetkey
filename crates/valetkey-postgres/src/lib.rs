//! The Postgres adapter (§6.9): the target's config (schema, validation, canonical form), the
//! connection guard, the read path ([`read`]) and the write path ([`write`]).

pub mod checks;
pub mod guard;
pub mod read;
pub mod values;
pub mod write;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use valetkey_core::{Exposure, NormalizeCx, NormalizedTarget, Problem, SecretRef, TargetId, TargetKind};

/// Postgres's socket file name inside a socket directory.
pub const SOCKET_FILE: &str = ".s.PGSQL.5432";

const DEFAULT_PORT: u16 = 5432;

/// Version of this kind's normalized form; see `NormalizedTarget::kind_version`.
const KIND_VERSION: u32 = 3;

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
    /// Extensions allowed beyond the safe defaults (protected targets refuse others). A HIGH
    /// change in `allow`: e.g. `dblink` can write through a read-only transaction.
    #[serde(default)]
    pub allow_extensions: Vec<String>,
    /// Skip the check for built-in functions granted beyond their defaults (catalog query C), for
    /// deliberately hardened databases. A HIGH change in `allow`.
    #[serde(default)]
    pub allow_grant_drift: bool,
    /// Allow a server with `max_prepared_transactions > 0` (e.g. a local DB with two-phase commit
    /// on). A read-only statement could then leave a prepared transaction and its locks behind, so
    /// only exposed targets may set it. A HIGH change in `allow`.
    #[serde(default)]
    pub allow_prepared_transactions: bool,
    /// Most rows returned per call (default 1000, at most 10000).
    pub max_rows: Option<u32>,
    /// Most result bytes per call (default 1 MiB, at most 16 MiB).
    pub max_bytes: Option<u32>,
    /// Statement timeout in milliseconds (default 30000, at most 300000).
    pub statement_timeout_ms: Option<u32>,
    /// Not supported yet: verified TLS arrives in M3. Present only to give a clear error.
    #[schemars(skip)]
    pub tls: Option<toml::Value>,
    /// Not supported yet: verified TLS arrives in M3. Present only to give a clear error.
    #[schemars(skip)]
    pub sslmode: Option<toml::Value>,
}

/// Defaults and bounds of the per-target limits.
pub const DEFAULT_MAX_ROWS: u32 = 1000;
pub const MAX_MAX_ROWS: u32 = 10_000;
pub const DEFAULT_MAX_BYTES: u32 = 1024 * 1024;
pub const MAX_MAX_BYTES: u32 = 16 * 1024 * 1024;
pub const DEFAULT_STATEMENT_TIMEOUT_MS: u32 = 30_000;
pub const MAX_STATEMENT_TIMEOUT_MS: u32 = 300_000;

/// A normalized target, read back for a call: what the broker needs to build a request.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct TargetSpec {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub socket: Option<String>,
    pub socket_path: Option<String>,
    pub database: String,
    pub user: String,
    pub allow_extensions: Vec<String>,
    pub allow_grant_drift: bool,
    #[serde(default)]
    pub allow_prepared_transactions: bool,
    pub max_rows: u32,
    pub max_bytes: u32,
    pub statement_timeout_ms: u32,
}

impl TargetSpec {
    /// Reads the connection and settings of a normalized postgres target.
    pub fn from_normalized(t: &NormalizedTarget) -> Result<Self, String> {
        if t.kind != "postgres" {
            return Err(format!("not a postgres target (kind `{}`)", t.kind));
        }
        let mut merged = t.connection.as_object().cloned().ok_or("malformed connection")?;
        merged.extend(t.settings.as_object().cloned().ok_or("malformed settings")?);
        serde_json::from_value(serde_json::Value::Object(merged)).map_err(|e| e.to_string())
    }

    /// Where to connect.
    pub fn endpoint(&self) -> Result<read::Endpoint, String> {
        match (&self.socket_path, &self.host) {
            (Some(path), None) => Ok(read::Endpoint::Socket(path.into())),
            (None, Some(host)) => Ok(read::Endpoint::Tcp {
                host: host.clone(),
                port: self.port.unwrap_or(DEFAULT_PORT),
            }),
            _ => Err("malformed endpoint".into()),
        }
    }

    pub fn limits(&self) -> read::Limits {
        read::Limits {
            max_rows: self.max_rows,
            max_bytes: self.max_bytes as usize,
            statement_timeout: std::time::Duration::from_millis(u64::from(self.statement_timeout_ms)),
            ..read::Limits::default()
        }
    }
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
                if !is_host(host) {
                    problems.push(problem(format!(
                        "invalid host `{}`: use a hostname or an IP address (put the port in `port`)",
                        host.escape_debug()
                    )));
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
                }
                // The resolved path is part of the canonical form (§6.2.1): if the root differs
                // between `allow` and the broker, the hash differs instead of silently
                // retargeting the socket.
                let path = cx.root.socket_dir(alias).join(SOCKET_FILE);
                if is_alias(alias) {
                    let len = path.as_os_str().len();
                    let max = cx.platform.max_socket_path_len();
                    if len > max {
                        problems.push(problem(format!(
                            "the socket path {} is {len} bytes; this platform allows {max}. Use a shorter alias",
                            path.display()
                        )));
                    }
                }
                json!({ "socket": alias, "socket_path": path.display().to_string(), "database": t.database, "user": t.user })
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
        if t.allow_prepared_transactions && exposure == Exposure::Protected {
            problems.push(problem(
                "allow_prepared_transactions is only for exposed targets: a protected target never uses a server that allows prepared transactions".into(),
            ));
        }
        if t.tls.is_some() || t.sslmode.is_some() {
            problems.push(problem(
                "TLS settings aren't supported yet (verified TLS arrives in M3); a protected target uses `socket`, and this target won't fall back to plain TCP".into(),
            ));
        }
        for ext in &t.allow_extensions {
            if ext.is_empty() || !ext.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                problems.push(problem(format!("invalid extension name `{}`", ext.escape_debug())));
            }
        }
        let bounded = |name: &str, value: Option<u32>, default: u32, max: u32, problems: &mut Vec<Problem>| -> u32 {
            match value {
                None => default,
                Some(v) if (1..=max).contains(&v) => v,
                Some(v) => {
                    problems.push(Problem::target(
                        id.as_str(),
                        format!("`{name}` = {v} is out of range (1–{max})"),
                    ));
                    default
                }
            }
        };
        let max_rows = bounded("max_rows", t.max_rows, DEFAULT_MAX_ROWS, MAX_MAX_ROWS, &mut problems);
        let max_bytes = bounded(
            "max_bytes",
            t.max_bytes,
            DEFAULT_MAX_BYTES,
            MAX_MAX_BYTES,
            &mut problems,
        );
        let statement_timeout_ms = bounded(
            "statement_timeout_ms",
            t.statement_timeout_ms,
            DEFAULT_STATEMENT_TIMEOUT_MS,
            MAX_STATEMENT_TIMEOUT_MS,
            &mut problems,
        );
        let mut connection = connection;
        if let Some(c) = connection.as_object_mut() {
            let mut extensions = t.allow_extensions.clone();
            extensions.sort();
            extensions.dedup();
            c.insert("allow_extensions".into(), json!(extensions));
            c.insert("allow_grant_drift".into(), json!(t.allow_grant_drift));
            c.insert(
                "allow_prepared_transactions".into(),
                json!(t.allow_prepared_transactions),
            );
        }
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
            kind_version: KIND_VERSION,
            secret: Some(t.secret),
            exposure_at_approval: Some(exposure),
            writable: t.writable,
            connection,
            settings: json!({
                "description": t.description,
                "max_rows": max_rows,
                "max_bytes": max_bytes,
                "statement_timeout_ms": statement_timeout_ms,
            }),
        })
    }
}

/// A DNS hostname (which covers IPv4), or an IPv6 address, bare or in brackets. ASCII only, so a
/// look-alike host can't disguise itself in `allow`.
fn is_host(s: &str) -> bool {
    if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return true;
    }
    (1..=253).contains(&s.len())
        && s.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
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
        assert_eq!(local.exposure_at_approval, Some(Exposure::Exposed));
        assert_eq!(local.connection["port"], 5432);
        assert!(local.writable);
        let staging = &c.targets["staging-app"];
        assert_eq!(staging.exposure_at_approval, Some(Exposure::Protected));
        assert_eq!(staging.connection["socket"], "stage-core");
        let expected = ValetkeyRoot::at("/Users/dev/.valetkey")
            .socket_dir("stage-core")
            .join(SOCKET_FILE);
        assert_eq!(staging.connection["socket_path"], expected.display().to_string());
        assert!(!staging.writable);
    }

    /// Pins this kind's normalized form. A change here changes every approval's hash: bump
    /// `KIND_VERSION` when it's intentional.
    #[test]
    fn normalized_form_is_pinned() {
        let c = parse(LOCAL).unwrap();
        assert_eq!(
            serde_json::to_string(&c.targets["local-app"]).unwrap(),
            r#"{"kind":"postgres","kind_version":3,"secret":"env-file://.env#POSTGRES_PASSWORD","exposure_at_approval":"exposed","writable":true,"connection":{"allow_extensions":[],"allow_grant_drift":false,"allow_prepared_transactions":false,"database":"app","host":"localhost","port":5432,"user":"app"},"settings":{"description":null,"max_bytes":1048576,"max_rows":1000,"statement_timeout_ms":30000}}"#
        );
    }

    #[test]
    fn prepared_transactions_are_an_exposed_only_opt_in() {
        assert!(parse(&format!("{LOCAL}allow_prepared_transactions = true\n")).is_ok());
        let m = messages(&format!("{STAGING}allow_prepared_transactions = true\n"));
        assert!(m.iter().any(|m| m.contains("only for exposed targets")), "{m:?}");
    }

    #[test]
    fn tls_settings_fail_clearly_instead_of_falling_back() {
        for extra in ["tls = true\n", "sslmode = \"verify-full\"\n"] {
            let m = messages(&format!("{STAGING}{extra}"));
            assert!(m.iter().any(|m| m.contains("TLS arrives in M3")), "{extra}: {m:?}");
        }
    }

    #[test]
    fn limits_and_allow_lists_are_validated_and_read_back() {
        let text = format!(
            "{STAGING}max_rows = 50\nstatement_timeout_ms = 1000\nallow_extensions = [\"dblink\", \"dblink\"]\nallow_grant_drift = true\n"
        );
        let c = parse(&text).unwrap();
        let spec = TargetSpec::from_normalized(&c.targets["staging-app"]).unwrap();
        assert_eq!(spec.max_rows, 50);
        assert_eq!(spec.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(spec.statement_timeout_ms, 1000);
        assert_eq!(spec.allow_extensions, ["dblink"], "deduplicated");
        assert!(spec.allow_grant_drift);
        assert!(
            matches!(spec.endpoint().unwrap(), read::Endpoint::Socket(p) if p.ends_with("stage-core/.s.PGSQL.5432"))
        );

        assert!(
            messages(&format!("{STAGING}max_rows = 0\n"))
                .iter()
                .any(|m| m.contains("out of range"))
        );
        assert!(
            messages(&format!("{STAGING}max_rows = 99999\n"))
                .iter()
                .any(|m| m.contains("out of range"))
        );
        assert!(
            messages(&format!("{STAGING}allow_extensions = [\"x; drop\"]\n"))
                .iter()
                .any(|m| m.contains("invalid extension"))
        );
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
    fn hosts_must_be_plain_ascii_hostnames_or_ips() {
        for good in ["localhost", "db.internal", "10.0.0.5", "::1", "[fd00::1]"] {
            assert!(
                parse(&LOCAL.replace("\"localhost\"", &format!("'{good}'"))).is_ok(),
                "{good}"
            );
        }
        // TOML literal strings ('…') keep these characters as they are, so the host check is
        // what has to reject them.
        for bad in [
            "",
            "db host",
            "lo\u{202e}calhost",
            "d\u{0430}tabase",
            "h/x",
            "a\\b",
            "-",
            ":::",
            "db:5432",
            "a]b",
            "[db]",
            "a..b",
        ] {
            let text = LOCAL.replace("\"localhost\"", &format!("'{bad}'"));
            let problems = parse(&text).unwrap_err();
            assert!(
                problems.iter().any(|p| p.message.contains("invalid host")),
                "{bad:?}: {problems:?}"
            );
        }
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
