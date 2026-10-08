//! Step 2 of every call: may this target be used now (§6.4, §6.7)? Runs before any secret is
//! fetched or any cache is consulted.

use valetkey_core::paths::check_private;
use valetkey_core::sanitize::for_display;
use valetkey_core::{Exposure, NormalizedTarget};
use valetkey_postgres::TargetSpec;

use crate::BrokerConfig;
use crate::session::Session;

/// A target that passed policy.
#[derive(Debug)]
pub struct Usable {
    pub id: String,
    pub target: NormalizedTarget,
    pub spec: TargetSpec,
    pub protected: bool,
    /// Set for protected targets used without a fence (`require_fence = false`).
    pub fence: Option<&'static str>,
}

/// The fence state reported when a protected target is used without one.
pub const UNFENCED: &str = "none: require_fence = false, so this protected secret is used without a sandbox fence";

/// Applies policy. `Err` is a message for the agent.
pub fn evaluate(config: &BrokerConfig, s: &Session, id: &str) -> Result<Usable, String> {
    if let Some(reason) = s.unusable_reason(config) {
        return Err(reason);
    }
    let snapshot = s.snapshot.as_ref().expect("approved sessions have a snapshot");
    let Some(target) = snapshot.config.targets.get(id) else {
        let ids: Vec<&str> = snapshot.config.targets.keys().map(|k| k.as_str()).collect();
        return Err(format!(
            "unknown target `{}`; approved targets: {}",
            for_display(id),
            ids.join(", ")
        ));
    };
    if target.kind != "postgres" {
        return Err(format!(
            "`{id}` is a {} target; these tools need a postgres target",
            target.kind
        ));
    }
    // Exposure is recomputed every call; the snapshot's copy is only what the human saw.
    let protected = target.secret.as_ref().map(|r| r.exposure(config.platform)) == Some(Exposure::Protected);
    let mut fence = None;
    if protected {
        if !s.dir_verified {
            return Err("refused: the project directory couldn't be verified against the client's MCP roots, so a protected secret won't be used".into());
        }
        if check_private(config.root.dir()).is_err() {
            return Err(format!(
                "refused: the valetkey root has loose permissions; run `{} doctor`",
                config.self_path.display()
            ));
        }
        if snapshot.config.require_fence {
            return Err("refused: this target's secret is protected, and fence detection arrives in M4; until then it's only used with require_fence = false".into());
        }
        fence = Some(UNFENCED);
    }
    let spec = TargetSpec::from_normalized(target)
        .map_err(|e| format!("internal error: the approved target is malformed ({e})"))?;
    Ok(Usable {
        id: id.to_owned(),
        target: target.clone(),
        spec,
        protected,
        fence,
    })
}
