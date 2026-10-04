//! Secret references: `<scheme>://…` strings in `valetkey.toml` that say where the broker fetches
//! a secret at call time. A reference is never the secret itself (§2.3).
//!
//! Every reference has an [`Exposure`] (§6.0): whether the agent can already read the secret
//! inside the fence. Channel rules, unfenced mode and write approval all key off it.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::platform::Platform;

/// Where a secret lives.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretRef {
    /// `env-file://<path>#<KEY>`: a key in a dotenv file inside the project. Always exposed.
    EnvFile { path: String, key: String },
    /// `local://<id>`: valetkey's own store, `~/.valetkey/secrets/<id>`.
    Local { id: String },
    /// `keyring://<service>/<account>`: the OS keyring.
    Keyring { service: String, account: String },
    /// `gcp-sm://<project>/<name>`: GCP Secret Manager, latest version, through `gcloud`.
    GcpSm { project: String, name: String },
}

/// Whether the agent can already read a secret inside the fence (§6.0).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
    /// The agent can read it anyway; valetkey adds no protection.
    Exposed,
    /// The fence keeps it from the agent.
    Protected,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid secret reference `{input}`: {reason}")]
pub struct SecretRefError {
    input: String,
    reason: String,
}

impl SecretRef {
    /// The scheme, e.g. `gcp-sm`.
    pub fn scheme(&self) -> &'static str {
        match self {
            Self::EnvFile { .. } => "env-file",
            Self::Local { .. } => "local",
            Self::Keyring { .. } => "keyring",
            Self::GcpSm { .. } => "gcp-sm",
        }
    }

    /// The exposure of this reference on `platform`.
    ///
    /// M0 results: the macOS sandbox always allows the keychain's Mach service, so `keyring` is
    /// exposed there. On Linux the Secret Service is on D-Bus, which the sandbox blocks while unix
    /// sockets are fully denied; the fence profile (M4) downgrades it when they aren't. Native
    /// Windows has no sandbox at all.
    pub fn exposure(&self, platform: Platform) -> Exposure {
        match self {
            Self::EnvFile { .. } => Exposure::Exposed,
            Self::Local { .. } | Self::GcpSm { .. } => Exposure::Protected,
            Self::Keyring { .. } => match platform {
                Platform::Linux => Exposure::Protected,
                Platform::MacOs | Platform::Windows | Platform::Other => Exposure::Exposed,
            },
        }
    }
}

impl FromStr for SecretRef {
    type Err = SecretRefError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let err = |reason: &str| SecretRefError {
            input: input.to_owned(),
            reason: reason.to_owned(),
        };
        let (scheme, rest) = input.split_once("://").ok_or_else(|| err("expected `<scheme>://…`"))?;
        match scheme {
            "env-file" => {
                let (path, key) = rest
                    .rsplit_once('#')
                    .ok_or_else(|| err("expected `env-file://<path>#<KEY>`"))?;
                check_relative_path(path).map_err(|r| err(&r))?;
                if !is_env_key(key) {
                    return Err(err(
                        "the key must look like an environment variable name (`A-Z`, `0-9`, `_`)",
                    ));
                }
                Ok(Self::EnvFile {
                    path: path.to_owned(),
                    key: key.to_owned(),
                })
            }
            "local" => {
                if !is_slug(rest, 64) {
                    return Err(err(
                        "the id must be 1–64 characters of `a-z`, `0-9`, `.`, `_`, `-`, starting with a letter or digit",
                    ));
                }
                Ok(Self::Local { id: rest.to_owned() })
            }
            "keyring" => {
                let (service, account) = rest
                    .split_once('/')
                    .ok_or_else(|| err("expected `keyring://<service>/<account>`"))?;
                if service.is_empty() || account.is_empty() || account.contains('/') {
                    return Err(err("expected `keyring://<service>/<account>`"));
                }
                if has_control(service) || has_control(account) {
                    return Err(err("control characters aren't allowed"));
                }
                Ok(Self::Keyring {
                    service: service.to_owned(),
                    account: account.to_owned(),
                })
            }
            "gcp-sm" => {
                let (project, name) = rest
                    .split_once('/')
                    .ok_or_else(|| err("expected `gcp-sm://<project>/<name>`"))?;
                if !is_gcp_project_id(project) {
                    return Err(err(
                        "the project must be a GCP project id (6–30 characters of `a-z`, `0-9`, `-`)",
                    ));
                }
                if name.is_empty()
                    || name.len() > 255
                    || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    return Err(err(
                        "the secret name must be 1–255 characters of `A-Z`, `a-z`, `0-9`, `_`, `-`",
                    ));
                }
                Ok(Self::GcpSm {
                    project: project.to_owned(),
                    name: name.to_owned(),
                })
            }
            _ => Err(err("unknown scheme; supported: env-file, local, keyring, gcp-sm")),
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvFile { path, key } => write!(f, "env-file://{path}#{key}"),
            Self::Local { id } => write!(f, "local://{id}"),
            Self::Keyring { service, account } => write!(f, "keyring://{service}/{account}"),
            Self::GcpSm { project, name } => write!(f, "gcp-sm://{project}/{name}"),
        }
    }
}

impl Serialize for SecretRef {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for SecretRef {
    fn schema_name() -> Cow<'static, str> {
        "SecretRef".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "description": "Where the broker fetches the secret: env-file://<path>#<KEY>, local://<id>, keyring://<service>/<account> or gcp-sm://<project>/<name>. Never the secret itself.",
            "pattern": "^(env-file|local|keyring|gcp-sm)://.+$"
        })
    }
}

/// An env-file path must be relative to the project root and stay inside it (§6.2.1): no
/// absolute paths, no `..`, no `~`, no backslashes, no empty segments.
fn check_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("the path is empty".into());
    }
    if path.starts_with('/') || path.starts_with('~') || path.contains('\\') || path.contains(':') {
        return Err("the path must be relative to the project root (no `/`, `~`, `\\` or drive letters)".into());
    }
    if has_control(path) {
        return Err("control characters aren't allowed".into());
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err("the path can't contain empty, `.` or `..` segments".into());
        }
    }
    Ok(())
}

fn is_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `a-z0-9` first, then `a-z0-9._-`, at most `max` characters.
pub(crate) fn is_slug(s: &str, max: usize) -> bool {
    let mut chars = s.chars();
    !s.is_empty()
        && s.len() <= max
        && matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

fn is_gcp_project_id(s: &str) -> bool {
    (6..=30).contains(&s.len())
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && !s.ends_with('-')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<SecretRef, SecretRefError> {
        s.parse()
    }

    #[test]
    fn round_trips_every_scheme() {
        for s in [
            "env-file://.env#POSTGRES_PASSWORD",
            "env-file://apps/db/.env#DB_PASS",
            "local://crm-sandbox",
            "keyring://valetkey/staging-app",
            "gcp-sm://acme-stage/DB_PASSWORD",
        ] {
            assert_eq!(parse(s).unwrap().to_string(), s);
        }
    }

    #[test]
    fn env_file_paths_must_stay_inside_the_project() {
        for bad in [
            "env-file:///etc/passwd#X",
            "env-file://../other/.env#X",
            "env-file://a/../../.env#X",
            "env-file://~/.aws/credentials#X",
            "env-file://C:/x/.env#X",
            "env-file://a\\b#X",
            "env-file://a//b#X",
            "env-file://./.env#X",
        ] {
            assert!(parse(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn rejects_malformed_references() {
        for bad in [
            "",
            "plain-password",
            "vault://x",
            "env-file://.env",
            "env-file://.env#1BAD",
            "local://",
            "local://Upper",
            "local://../x",
            "keyring://only-service",
            "keyring://a/b/c",
            "gcp-sm://short/x",
            "gcp-sm://acme-stage/bad name",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn exposure_follows_the_source_and_platform() {
        let env = parse("env-file://.env#P").unwrap();
        let local = parse("local://x").unwrap();
        let keyring = parse("keyring://s/a").unwrap();
        let gcp = parse("gcp-sm://acme-stage/P").unwrap();
        for p in [Platform::MacOs, Platform::Linux, Platform::Windows] {
            assert_eq!(env.exposure(p), Exposure::Exposed);
            assert_eq!(local.exposure(p), Exposure::Protected);
            assert_eq!(gcp.exposure(p), Exposure::Protected);
        }
        assert_eq!(keyring.exposure(Platform::MacOs), Exposure::Exposed);
        assert_eq!(keyring.exposure(Platform::Linux), Exposure::Protected);
    }
}
