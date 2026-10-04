//! What changed between the approved config and the working one, with a risk label per change
//! (§6.1). Labels follow the change's **effect**, not the target's exposure.

use std::collections::BTreeSet;

use crate::config::{NormalizedTarget, ProjectConfig, TargetId};

/// How carefully a human should read a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    Low,
    High,
}

/// One change, described in plain words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The target, or `None` for a project-wide setting.
    pub target: Option<TargetId>,
    pub risk: Risk,
    pub description: String,
}

/// Every change from `old` (the approved snapshot, if any) to `new`.
pub fn diff(old: Option<&ProjectConfig>, new: &ProjectConfig) -> Vec<Change> {
    let mut changes = Vec::new();
    let global = |risk, description: String| Change {
        target: None,
        risk,
        description,
    };

    match old {
        None => changes.push(global(Risk::High, "first approval of this project".into())),
        Some(old) => {
            if old.require_fence && !new.require_fence {
                changes.push(global(
                    Risk::High,
                    "require_fence turned off: protected secrets would be served without a fence".into(),
                ));
            } else if !old.require_fence && new.require_fence {
                changes.push(global(Risk::Low, "require_fence turned on".into()));
            }
            if old.min_version != new.min_version {
                changes.push(global(
                    Risk::Low,
                    format!("min_version: {:?} → {:?}", old.min_version, new.min_version),
                ));
            }
        }
    }

    let empty = Default::default();
    let old_targets = old.map(|o| &o.targets).unwrap_or(&empty);
    let ids: BTreeSet<&TargetId> = old_targets.keys().chain(new.targets.keys()).collect();
    for id in ids {
        match (old_targets.get(id), new.targets.get(id)) {
            (None, Some(t)) => changes.push(Change {
                target: Some(id.clone()),
                risk: Risk::High,
                description: format!("new {} target{}", t.kind, if t.writable { " (writable)" } else { "" }),
            }),
            (Some(_), None) => changes.push(Change {
                target: Some(id.clone()),
                risk: Risk::Low,
                description: "removed".into(),
            }),
            (Some(a), Some(b)) => changes.extend(target_changes(id, a, b)),
            (None, None) => unreachable!("id came from one of the maps"),
        }
    }
    changes
}

fn target_changes(id: &TargetId, a: &NormalizedTarget, b: &NormalizedTarget) -> Vec<Change> {
    let mut out = Vec::new();
    let mut push = |risk, description: String| {
        out.push(Change {
            target: Some(id.clone()),
            risk,
            description,
        })
    };
    if a.kind != b.kind {
        push(Risk::High, format!("kind: {} → {}", a.kind, b.kind));
    }
    if a.secret != b.secret {
        let show = |s: &Option<crate::SecretRef>| s.as_ref().map_or_else(|| "none".to_owned(), ToString::to_string);
        push(Risk::High, format!("secret: {} → {}", show(&a.secret), show(&b.secret)));
    }
    if a.connection != b.connection {
        push(Risk::High, format!("connection: {} → {}", a.connection, b.connection));
    }
    if !a.writable && b.writable {
        push(Risk::High, "writable turned on".into());
    } else if a.writable && !b.writable {
        push(Risk::Low, "writable turned off".into());
    }
    if a.settings != b.settings {
        push(Risk::Low, format!("settings: {} → {}", a.settings, b.settings));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::parse;

    fn risks(old: &str, new: &str) -> Vec<(String, Risk)> {
        let old = parse(old).unwrap();
        let new = parse(new).unwrap();
        diff(Some(&old), &new)
            .into_iter()
            .map(|c| (c.description, c.risk))
            .collect()
    }

    #[test]
    fn first_approval_is_high_risk() {
        let new = parse("[targets.a]\nkind = \"fake\"\n").unwrap();
        assert!(diff(None, &new).iter().all(|c| c.risk == Risk::High));
    }

    #[test]
    fn labels_follow_the_effect() {
        let base = "[targets.a]\nkind = \"fake\"\nhost = \"h\"\nnote = \"n\"\n";
        assert_eq!(risks(base, base), vec![]);
        assert_eq!(risks(base, &base.replace("\"h\"", "\"evil\""))[0].1, Risk::High);
        assert_eq!(risks(base, &base.replace("\"n\"", "\"m\""))[0].1, Risk::Low);
        assert_eq!(risks(base, &format!("{base}writable = true\n"))[0].1, Risk::High);
        assert_eq!(risks(&format!("{base}writable = true\n"), base)[0].1, Risk::Low);
        assert_eq!(risks(base, &format!("{base}secret = \"local://x\"\n"))[0].1, Risk::High);
        assert_eq!(risks(base, "")[0], ("removed".into(), Risk::Low));
        assert_eq!(
            risks(base, &format!("{base}[targets.b]\nkind = \"fake\"\n"))[0].1,
            Risk::High
        );
        assert_eq!(risks(base, &format!("require_fence = false\n{base}"))[0].1, Risk::High);
    }
}
