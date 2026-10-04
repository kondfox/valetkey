//! `valetkey doctor`: check this machine and the current project, and say exactly what to fix
//! (§2.4). M1 covers the valetkey root, the project config and its approval. Fence checks
//! arrive in M4.

use std::path::Path;
use std::process::ExitCode;

use valetkey_core::paths::os_home_dir;
use valetkey_core::sanitize::for_display;
use valetkey_core::snapshot::{self, ApprovalState};
use valetkey_core::{Exposure, NormalizeCx, ValetkeyRoot, project};
use valetkey_postgres::SOCKET_FILE;

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
    let current = std::fs::read_to_string(&project.config_path)
        .map_err(|e| e.to_string())
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

    let stored = snapshot::load(&root, &project)?;
    let state = ApprovalState::evaluate(stored, &project, current.as_ref().map_err(Clone::clone));
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

    if let Ok(config) = &current {
        for (id, t) in &config.targets {
            let exposure = match t.exposure {
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

    output::warn("fence checks (the agent's sandbox settings) arrive in M4; no tool uses a secret before then");
    Ok(exit(&o))
}

fn check_root(root: &ValetkeyRoot, o: &mut Outcome) {
    let dir = root.dir();
    output::ok(format!("valetkey root: {}", dir.display()));
    match std::fs::metadata(dir) {
        Ok(meta) => check_private(dir, &meta, o),
        Err(_) => output::warn("  it doesn't exist yet; `allow` creates it"),
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

#[cfg(unix)]
fn check_private(dir: &Path, meta: &std::fs::Metadata, o: &mut Outcome) {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        o.fail(format!(
            "{} is readable or writable by others (mode {mode:o}) → chmod 700 {}",
            dir.display(),
            dir.display()
        ));
    }
}

#[cfg(not(unix))]
fn check_private(_: &Path, _: &std::fs::Metadata, _: &mut Outcome) {}

fn exit(o: &Outcome) -> ExitCode {
    if o.failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
