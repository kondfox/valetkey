//! `valetkey allow`: show a human what `valetkey.toml` would let the agent use, and store the
//! approved snapshot (§6.1).
//!
//! The file is read **once**; what's stored is exactly what was shown. The command only runs in
//! an interactive terminal, and inside the agent's sandbox it can't write the snapshot anyway
//! (the valetkey root is write-denied).

use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;

use anyhow::Context;
use valetkey_core::diff::{self, Risk};
use valetkey_core::sanitize::{for_display, has_non_ascii};
use valetkey_core::snapshot::{self, Snapshot};
use valetkey_core::{NormalizeCx, ProjectConfig, project};

use crate::output;

pub(crate) fn run() -> anyhow::Result<ExitCode> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        output::fail(
            "valetkey allow needs an interactive terminal: a human runs it in a normal terminal, not through a pipe or the agent's session",
        );
        return Ok(ExitCode::FAILURE);
    }
    let root = crate::resolve_root()?;
    let project = project::discover(&std::env::current_dir()?)?;
    let text = std::fs::read_to_string(&project.config_path)
        .with_context(|| format!("can't read {}", project.config_path.display()))?;

    let cx = NormalizeCx {
        root: &root,
        platform: crate::platform(),
    };
    let config = match crate::registry().parse(&text, &cx) {
        Ok(c) => c,
        Err(problems) => {
            output::fail(format!(
                "{} has problems; nothing was approved:",
                for_display(&project.config_path.display().to_string())
            ));
            for p in problems {
                output::line(format!("  - {}", for_display(&p.to_string())));
            }
            return Ok(ExitCode::FAILURE);
        }
    };

    let previous = snapshot::load(&root, &project)?.filter(|s| s.project_root == project.root);
    if previous.as_ref().is_some_and(|s| s.config_hash == config.hash()) {
        output::ok("already approved; nothing changed");
        return Ok(ExitCode::SUCCESS);
    }

    output::line(format!(
        "Project:  {}",
        for_display(&project.root.display().to_string())
    ));
    output::line("");
    show_targets(&config);
    output::line("");
    output::line("Changes since the last approval:");
    for change in diff::diff(previous.as_ref().map(|s| &s.config), &config) {
        let label = match change.risk {
            Risk::High => "HIGH",
            Risk::Low => "low ",
        };
        let target = change
            .target
            .as_ref()
            .map(|t| format!("{}: ", for_display(t.as_str())))
            .unwrap_or_default();
        output::line(format!("  [{label}] {target}{}", for_display(&change.description)));
    }
    output::line("");

    if !confirm("Approve this configuration? Type `yes` to approve: ")? {
        output::fail("not approved; nothing changed");
        return Ok(ExitCode::FAILURE);
    }
    snapshot::store(&root, &project, &Snapshot::new(&project, config))?;
    output::ok("approved");
    Ok(ExitCode::SUCCESS)
}

fn show_targets(config: &ProjectConfig) {
    if config.targets.is_empty() {
        output::line("Targets:  none");
        return;
    }
    output::line("Targets:");
    for (id, t) in &config.targets {
        let flag = if has_non_ascii(id.as_str()) {
            "  ⚠ non-ASCII characters in the name"
        } else {
            ""
        };
        let exposure = match t.exposure {
            Some(valetkey_core::Exposure::Protected) => "protected secret",
            Some(valetkey_core::Exposure::Exposed) => "exposed secret",
            None => "no secret",
        };
        output::line(format!(
            "  {} ({}, {exposure}{}){flag}",
            for_display(id.as_str()),
            for_display(&t.kind),
            if t.writable { ", WRITABLE" } else { "" },
        ));
        output::line(format!("      connection: {}", for_display(&t.connection.to_string())));
        if let Some(secret) = &t.secret {
            output::line(format!("      secret:     {}", for_display(&secret.to_string())));
        }
    }
    if !config.require_fence {
        output::warn("require_fence = false: protected secrets will be used even without a fence");
    }
}

fn confirm(prompt: &str) -> anyhow::Result<bool> {
    let mut out = std::io::stdout().lock();
    write!(out, "{prompt}")?;
    out.flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(answer.trim() == "yes")
}
