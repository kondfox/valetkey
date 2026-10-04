//! `valetkey doctor`: check this machine and the current project, and say exactly what to fix
//! (§2.4). M1 covers the valetkey root, the project config and its approval. Fence checks
//! arrive in M4.

use std::path::Path;
use std::process::ExitCode;

use valetkey_core::paths::{check_private, os_home_dir};
use valetkey_core::safe_read::{MAX_CONFIG_LEN, read_untrusted};
use valetkey_core::sanitize::for_display;
use valetkey_core::snapshot::{self, ApprovalState};
use valetkey_core::user_config::UserConfig;
use valetkey_core::{Exposure, NormalizeCx, SecretRef, ValetkeyRoot, project};
use valetkey_postgres::SOCKET_FILE;
use valetkey_secrets::trust::{self, TrustPolicy};

use crate::output;

#[derive(Default)]
struct Outcome {
    failed: bool,
}

impl Outcome {
    fn fail(&mut self, text: impl AsRef<str>) {
        self.failed = true;
        output::fail(text);
    }
}

pub(crate) fn run() -> anyhow::Result<ExitCode> {
    let mut o = Outcome::default();
    let me = output::self_path();

    output::ok(format!("valetkey {}", env!("CARGO_PKG_VERSION")));
    if cfg!(debug_assertions) {
        output::warn(
            "this is a debug build: it honours VALETKEY_DEV_ROOT. Never register a debug build as your broker",
        );
    }

    let root = crate::resolve_root()?;
    check_root(&root, &mut o);

    let project = match project::discover(&std::env::current_dir()?) {
        Ok(p) => p,
        Err(e) => {
            o.fail(for_display(&e.to_string()));
            output::line(format!("  → create one with: {me} init"));
            return Ok(exit(&o));
        }
    };
    output::ok(format!("project: {}", for_display(&project.root.display().to_string())));

    let cx = NormalizeCx {
        root: &root,
        platform: crate::platform(),
    };
    let current = read_untrusted(&project.config_path, MAX_CONFIG_LEN)
        .map_err(|e| format!("\n  - {}", for_display(&e.to_string())))
        .and_then(|text| {
            crate::registry().parse(&text, &cx).map_err(|ps| {
                ps.iter()
                    .map(|p| format!("\n  - {}", for_display(&p.to_string())))
                    .collect::<String>()
            })
        });
    match &current {
        Ok(_) => output::ok("valetkey.toml is valid"),
        Err(problems) => o.fail(format!("valetkey.toml has problems:{problems}")),
    }

    let stored = match snapshot::load(&root, &project) {
        Ok(s) => s,
        Err(e) => {
            o.fail(format!("the stored approval can't be used: {e}"));
            None
        }
    };
    let state = ApprovalState::evaluate(stored, &project, current.as_ref().map_err(|_| ()));
    match &state {
        ApprovalState::Approved(_) => output::ok("approved on this machine"),
        ApprovalState::NotApproved => o.fail(format!(
            "not approved on this machine → run in a normal terminal: {me} allow"
        )),
        ApprovalState::Stale { .. } => o.fail(format!(
            "changed since it was approved; nothing is served → run in a normal terminal: {me} allow"
        )),
        ApprovalState::RootMismatch { .. } => {
            o.fail(format!("the stored approval belongs to another path → run: {me} allow"))
        }
    }

    let user = match UserConfig::load(&root) {
        Ok(u) => u,
        Err(e) => {
            o.fail(format!(
                "{} can't be used: {e} → re-run: {me} setup",
                root.user_config_file().display()
            ));
            UserConfig::default()
        }
    };
    if let Ok(config) = &current {
        for (id, t) in &config.targets {
            let exposure = match t.exposure_at_approval {
                Some(Exposure::Protected) => "protected",
                Some(Exposure::Exposed) => "exposed",
                None => "no secret",
            };
            output::line(format!(
                "  {} ({}, {exposure} secret{})",
                for_display(id.as_str()),
                t.kind,
                if t.writable { ", writable" } else { "" }
            ));
            check_secret_source(&root, &user, id.as_str(), t.secret.as_ref(), &mut o);
            if let Some(alias) = t.connection.get("socket").and_then(|v| v.as_str()) {
                let dir = root.socket_dir(alias);
                if dir.join(SOCKET_FILE).exists() {
                    output::ok(format!("  {}: proxy socket is there", for_display(id.as_str())));
                } else {
                    output::warn(format!(
                        "  {}: no proxy socket yet → start the proxy from a normal terminal, e.g.\n      cloud-sql-proxy '<project:region:instance>?unix-socket-path={}'",
                        for_display(id.as_str()),
                        dir.display()
                    ));
                }
            }
        }
    }

    output::warn(
        "fence checks (the agent's sandbox settings) arrive in M4; until then protected secrets are only used with require_fence = false",
    );
    Ok(exit(&o))
}

/// Whether a target's secret source is ready: `local://` secrets exist, `gcp-sm://` has a
/// configured gcloud that still passes `setup`'s checks.
fn check_secret_source(root: &ValetkeyRoot, user: &UserConfig, id: &str, secret: Option<&SecretRef>, o: &mut Outcome) {
    let me = output::self_path();
    let id = for_display(id);
    match secret {
        Some(SecretRef::Local { id: secret_id }) => {
            if !root.secrets_dir().join(secret_id).exists() {
                o.fail(format!(
                    "  {id}: local://{secret_id} isn't set → run in a normal terminal: {me} secret set {secret_id}"
                ));
            }
        }
        Some(SecretRef::GcpSm { .. }) => match user.tool("gcloud") {
            None => o.fail(format!(
                "  {id}: gcloud isn't configured → run in a normal terminal: {me} setup"
            )),
            Some(tool) => {
                let home = os_home_dir().unwrap_or_default();
                let policy = TrustPolicy::for_this_machine(home, None);
                let mut paths = vec![tool.path.clone()];
                paths.extend(tool.env.get("CLOUDSDK_PYTHON").map(Into::into));
                for path in paths {
                    if let Err(problem) = trust::check(&path, &policy) {
                        o.fail(format!("  {id}: {} → re-run: {me} setup", for_display(&problem)));
                    }
                }
                if let Some(config) = tool.env.get("CLOUDSDK_CONFIG")
                    && let Err(problem) = trust::check_gcloud_config(std::path::Path::new(config), &policy)
                {
                    o.fail(format!(
                        "  {id}: CLOUDSDK_CONFIG: {} → re-run: {me} setup",
                        for_display(&problem)
                    ));
                }
            }
        },
        _ => {}
    }
}

fn check_root(root: &ValetkeyRoot, o: &mut Outcome) {
    let dir = root.dir();
    output::ok(format!("valetkey root: {}", dir.display()));
    if !dir.exists() {
        output::warn("  it doesn't exist yet; `allow` creates it");
    }
    for d in [dir.to_owned(), dir.join("projects")] {
        if let Err(problem) = check_private(&d) {
            o.fail(problem);
        }
    }
    if let (Some(env_home), Ok(db_home)) = (std::env::var_os("HOME"), os_home_dir())
        && Path::new(&env_home) != db_home
        && std::env::var_os(valetkey_core::paths::DEV_ROOT_ENV).is_none()
    {
        output::warn(format!(
            "HOME is {}, but the user database says {}; valetkey uses the user database",
            Path::new(&env_home).display(),
            db_home.display()
        ));
    }
}

fn exit(o: &Outcome) -> ExitCode {
    if o.failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
