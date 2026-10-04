//! `valetkey.toml`: the project's committed, non-secret target and policy config (§2.3), and its
//! **canonical form**, which is what a human approves and what gets hashed (§6.1).
//!
//! Core doesn't know any target kind. Each adapter crate implements [`TargetKind`], and the
//! composition root registers it in a [`Registry`] (§6.11).

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::paths::ValetkeyRoot;
use crate::platform::Platform;
use crate::problem::Problem;
use crate::secret_ref::{Exposure, SecretRef, is_slug};

/// File name of the project config.
pub const CONFIG_FILE_NAME: &str = "valetkey.toml";

/// Version of the canonical form. Bump it when the canonical serialization changes, so old
/// snapshots read as changed instead of silently matching.
pub const CANONICAL_FORMAT: u32 = 1;

/// A target's name in `valetkey.toml`: 1–63 characters of `a-z`, `0-9`, `-`, `.`, `_`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TargetId(String);

impl TargetId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TargetId {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        if is_slug(&s, 63) {
            Ok(Self(s))
        } else {
            Err(format!(
                "invalid target id `{}`: use 1–63 characters of `a-z`, `0-9`, `.`, `_`, `-`, starting with a letter or digit",
                s.escape_debug()
            ))
        }
    }
}

impl From<TargetId> for String {
    fn from(id: TargetId) -> Self {
        id.0
    }
}

impl Borrow<str> for TargetId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TargetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a [`TargetKind`] may consult while normalizing a target.
#[derive(Debug)]
pub struct NormalizeCx<'a> {
    pub root: &'a ValetkeyRoot,
    pub platform: Platform,
}

/// One kind of target (`postgres`, later `http`, …), implemented by its adapter crate.
pub trait TargetKind: Send + Sync {
    /// The `kind = "…"` value this implementation handles.
    fn kind(&self) -> &'static str;

    /// Parses and validates a target's table (without its `kind` key) into its canonical form.
    /// Returns every problem found, not just the first.
    fn normalize(
        &self,
        id: &TargetId,
        fields: toml::Table,
        cx: &NormalizeCx<'_>,
    ) -> Result<NormalizedTarget, Vec<Problem>>;
}

/// A target in canonical form: what the broker serves and the human approves.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NormalizedTarget {
    pub kind: String,
    pub secret: Option<SecretRef>,
    pub exposure: Option<Exposure>,
    pub writable: bool,
    /// Where and as whom the broker connects: host, socket, database, user, TLS. Any change is
    /// high risk (§6.1).
    pub connection: serde_json::Value,
    /// Everything else (limits, descriptions). Changes are low risk.
    pub settings: serde_json::Value,
}

/// A whole `valetkey.toml` in canonical form.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub format: u32,
    pub min_version: Option<String>,
    pub require_fence: bool,
    pub targets: BTreeMap<TargetId, NormalizedTarget>,
}

/// The blake3 hash of a config's canonical form, hex-encoded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigHash(String);

impl ConfigHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ConfigHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl ProjectConfig {
    /// Deterministic bytes: JSON with every object's keys sorted, whatever serde_json features
    /// the build enables. Comments, whitespace and key order in the TOML don't affect it.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let value = serde_json::to_value(self).expect("a ProjectConfig always serializes");
        serde_json::to_vec(&sorted(value)).expect("a JSON value always serializes")
    }

    pub fn hash(&self) -> ConfigHash {
        ConfigHash(blake3::hash(&self.canonical_bytes()).to_hex().to_string())
    }
}

fn sorted(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().map(|(k, v)| (k, sorted(v))).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            serde_json::Value::Object(entries.into_iter().collect())
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// The target kinds this build supports.
#[derive(Default)]
pub struct Registry {
    kinds: BTreeMap<&'static str, Box<dyn TargetKind>>,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.kinds.keys()).finish()
    }
}

impl Registry {
    pub fn with(mut self, kind: impl TargetKind + 'static) -> Self {
        self.kinds.insert(kind.kind(), Box::new(kind));
        self
    }

    pub fn kinds(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.kinds.keys().copied()
    }

    /// Parses `valetkey.toml` text into its canonical form, collecting every problem.
    pub fn parse(&self, text: &str, cx: &NormalizeCx<'_>) -> Result<ProjectConfig, Vec<Problem>> {
        let raw: RawConfig =
            toml::from_str(text).map_err(|e| vec![Problem::global(e.to_string().trim_end().to_owned())])?;
        let mut problems = Vec::new();
        let mut targets = BTreeMap::new();

        for (id, mut fields) in raw.targets.unwrap_or_default() {
            let id = match TargetId::try_from(id) {
                Ok(id) => id,
                Err(e) => {
                    problems.push(Problem::global(e));
                    continue;
                }
            };
            let kind = match fields.remove("kind") {
                Some(toml::Value::String(kind)) => kind,
                Some(_) => {
                    problems.push(Problem::target(id.as_str(), "`kind` must be a string"));
                    continue;
                }
                None => {
                    problems.push(Problem::target(id.as_str(), "missing `kind`"));
                    continue;
                }
            };
            let Some(handler) = self.kinds.get(kind.as_str()) else {
                let supported: Vec<_> = self.kinds().collect();
                problems.push(Problem::target(
                    id.as_str(),
                    format!(
                        "unsupported kind `{}` (this build supports: {})",
                        kind.escape_debug(),
                        supported.join(", ")
                    ),
                ));
                continue;
            };
            match handler.normalize(&id, fields, cx) {
                Ok(target) => {
                    targets.insert(id, target);
                }
                Err(mut ps) => problems.append(&mut ps),
            }
        }

        if let Some(min) = &raw.min_version {
            match version_satisfies(env!("CARGO_PKG_VERSION"), min) {
                Some(true) => {}
                Some(false) => problems.push(Problem::global(format!(
                    "this project needs valetkey ≥ {min}; this is {}",
                    env!("CARGO_PKG_VERSION")
                ))),
                None => problems.push(Problem::global(format!(
                    "`min_version` must look like `0.1` or `0.1.2`, not `{}`",
                    min.escape_debug()
                ))),
            }
        }

        if problems.is_empty() {
            Ok(ProjectConfig {
                format: CANONICAL_FORMAT,
                min_version: raw.min_version,
                require_fence: raw.require_fence.unwrap_or(true),
                targets,
            })
        } else {
            Err(problems)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    min_version: Option<String>,
    require_fence: Option<bool>,
    targets: Option<BTreeMap<String, toml::Table>>,
}

/// Whether `version` (e.g. `0.1.0-dev`) is at least `min` (`0.1` or `0.1.2`). Pre-release
/// suffixes are ignored. `None` if `min` isn't a version.
fn version_satisfies(version: &str, min: &str) -> Option<bool> {
    let parse = |s: &str| -> Option<Vec<u64>> {
        let core = s.split(['-', '+']).next()?;
        let parts: Option<Vec<u64>> = core.split('.').map(|p| p.parse().ok()).collect();
        parts.filter(|p| (1..=3).contains(&p.len()))
    };
    let mut have = parse(version)?;
    let mut need = parse(min)?;
    have.resize(3, 0);
    need.resize(3, 0);
    Some(have >= need)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// A minimal target kind for tests: `host` is connection, `note` is a setting.
    pub(crate) struct FakeKind;

    impl TargetKind for FakeKind {
        fn kind(&self) -> &'static str {
            "fake"
        }

        fn normalize(
            &self,
            id: &TargetId,
            mut fields: toml::Table,
            cx: &NormalizeCx<'_>,
        ) -> Result<NormalizedTarget, Vec<Problem>> {
            let host = fields.remove("host").and_then(|v| v.as_str().map(str::to_owned));
            let note = fields.remove("note").and_then(|v| v.as_str().map(str::to_owned));
            let writable = fields.remove("writable").and_then(|v| v.as_bool()).unwrap_or(false);
            let secret: Option<SecretRef> = fields
                .remove("secret")
                .and_then(|v| v.as_str().and_then(|s| s.parse().ok()));
            if let Some(extra) = fields.keys().next() {
                return Err(vec![Problem::target(id.as_str(), format!("unknown field `{extra}`"))]);
            }
            Ok(NormalizedTarget {
                kind: "fake".into(),
                exposure: secret.as_ref().map(|s| s.exposure(cx.platform)),
                secret,
                writable,
                connection: json!({ "host": host }),
                settings: json!({ "note": note }),
            })
        }
    }

    pub(crate) fn parse(text: &str) -> Result<ProjectConfig, Vec<Problem>> {
        let root = ValetkeyRoot::at("/r");
        Registry::default().with(FakeKind).parse(
            text,
            &NormalizeCx {
                root: &root,
                platform: Platform::Linux,
            },
        )
    }

    #[test]
    fn canonical_hash_ignores_comments_whitespace_and_order() {
        let a =
            parse("[targets.b]\nkind = \"fake\"\nhost = \"h\"\n[targets.a]\nkind = \"fake\"\nnote = \"n\"\n").unwrap();
        let b = parse("# comment\n\n[targets.a]\nnote   = \"n\" # trailing\nkind = \"fake\"\n\n[targets.b]\nhost = \"h\"\nkind = \"fake\"\n").unwrap();
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn canonical_hash_changes_with_content() {
        let a = parse("[targets.a]\nkind = \"fake\"\nhost = \"h1\"\n").unwrap();
        let b = parse("[targets.a]\nkind = \"fake\"\nhost = \"h2\"\n").unwrap();
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn require_fence_defaults_to_true() {
        assert!(parse("").unwrap().require_fence);
        assert!(!parse("require_fence = false").unwrap().require_fence);
    }

    #[test]
    fn collects_every_problem() {
        let problems = parse("typo = 1\n").unwrap_err();
        assert_eq!(problems.len(), 1, "{problems:?}");

        let problems =
            parse("[targets.a]\nhost = \"h\"\n[targets.b]\nkind = \"mystery\"\n[targets.Bad]\nkind = \"fake\"\n")
                .unwrap_err();
        let text: Vec<String> = problems.iter().map(ToString::to_string).collect();
        assert_eq!(text.len(), 3, "{text:?}");
        assert!(text.iter().any(|t| t.contains("missing `kind`")));
        assert!(text.iter().any(|t| t.contains("unsupported kind `mystery`")));
        assert!(text.iter().any(|t| t.contains("invalid target id `Bad`")));
    }

    #[test]
    fn min_version_is_checked() {
        assert!(parse("min_version = \"0.1\"").is_ok());
        assert!(parse("min_version = \"99.0\"").is_err());
        assert!(parse("min_version = \"latest\"").is_err());
    }

    #[test]
    fn version_comparison() {
        assert_eq!(version_satisfies("0.1.0-dev", "0.1"), Some(true));
        assert_eq!(version_satisfies("0.1.0", "0.1.1"), Some(false));
        assert_eq!(version_satisfies("1.2.3", "1.2.3"), Some(true));
        assert_eq!(version_satisfies("1.2.3", "x"), None);
    }
}
