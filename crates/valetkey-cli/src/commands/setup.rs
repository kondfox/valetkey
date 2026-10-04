//! `valetkey setup`: a human records which vendor CLIs the broker may run (§6.8, M2 decision D4).
//!
//! For each known tool it resolves the path through the human's `PATH`, checks the tool, its SDK
//! tree and its interpreter with [`valetkey_secrets::trust::check`], shows the result, and on
//! `yes` writes `~/.valetkey/config.toml`. The broker never resolves tools itself.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use valetkey_core::paths::os_home_dir;
use valetkey_core::sanitize::for_display;
use valetkey_core::user_config::{ToolConfig, UserConfig};
use valetkey_core::{ValetkeyRoot, project};
use valetkey_secrets::trust::{self, TrustPolicy};

use crate::output;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Saved,
    Unchanged,
    Declined,
    NothingToDo,
}

pub(crate) fn run() -> anyhow::Result<ExitCode> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        output::fail(
            "valetkey setup needs an interactive terminal: a human runs it in a normal terminal, not the agent's session",
        );
        return Ok(ExitCode::FAILURE);
    }
    let root = crate::resolve_root()?;
    let project = project::discover(&std::env::current_dir()?).ok().map(|p| p.root);
    let policy = TrustPolicy::for_this_machine(os_home_dir()?, project);
    let resolve = |name: &str| which::which(name).ok();
    let outcome = review(
        &root,
        &policy,
        &resolve,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )?;
    Ok(match outcome {
        Outcome::Declined => ExitCode::FAILURE,
        _ => ExitCode::SUCCESS,
    })
}

/// The whole flow with injected tool resolution and I/O.
pub(crate) fn review(
    root: &ValetkeyRoot,
    policy: &TrustPolicy,
    resolve: &dyn Fn(&str) -> Option<PathBuf>,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> anyhow::Result<Outcome> {
    let current = UserConfig::load(root)?;
    let mut proposed = current.clone();

    let Some(found) = resolve("gcloud") else {
        writeln!(
            out,
            "gcloud: not found on PATH; skipped (needed only for gcp-sm:// secrets)"
        )?;
        return Ok(Outcome::NothingToDo);
    };
    match plan_gcloud(&found, policy, resolve) {
        Ok((tool, warnings)) => {
            writeln!(out, "gcloud:  {}", for_display(&tool.path.display().to_string()))?;
            for (k, v) in &tool.env {
                writeln!(out, "  {k}={}", for_display(v))?;
            }
            for w in warnings {
                writeln!(out, "  ⚠ {}", for_display(&w))?;
            }
            proposed.tools.insert("gcloud".into(), tool);
        }
        Err(refusal) => {
            writeln!(
                out,
                "✘ gcloud at {} can't be used: {}",
                for_display(&found.display().to_string()),
                for_display(&refusal)
            )?;
            writeln!(
                out,
                "  Install the Google Cloud SDK somewhere outside any project and temp directory, then re-run setup."
            )?;
            return Ok(Outcome::NothingToDo);
        }
    }

    if proposed == current {
        writeln!(out, "✔ nothing changed")?;
        return Ok(Outcome::Unchanged);
    }
    write!(
        out,
        "The broker will run these tools outside the agent's sandbox. Type `yes` to save: "
    )?;
    out.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    if answer.trim() != "yes" {
        writeln!(out, "✘ not saved")?;
        return Ok(Outcome::Declined);
    }
    proposed.store(root)?;
    writeln!(out, "✔ saved {}", root.user_config_file().display())?;
    Ok(Outcome::Saved)
}

/// The gcloud config to store, after checking gcloud, its SDK tree and its Python.
fn plan_gcloud(
    found: &Path,
    policy: &TrustPolicy,
    resolve: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<(ToolConfig, Vec<String>), String> {
    let gcloud = std::fs::canonicalize(found).map_err(|e| e.to_string())?;
    let bin = gcloud.parent().ok_or("gcloud has no parent directory")?;
    let sdk_root = if bin.file_name().is_some_and(|n| n == "bin") {
        bin.parent().unwrap_or(bin)
    } else {
        bin
    };

    // gcloud runs Python from the SDK: check what it executes, not just the launcher. The tool
    // and its tree come first, so a refusal names the real problem.
    let mut to_check = vec![gcloud.clone(), sdk_root.to_owned(), bin.to_owned()];
    let lib = sdk_root.join("lib");
    if lib.is_dir() {
        to_check.push(lib);
    }
    let mut warnings = Vec::new();
    for path in &to_check {
        warnings.extend(trust::check(path, policy)?);
    }
    let bundled = sdk_root.join("platform/bundledpythonunix/bin/python3");
    let python = if bundled.exists() {
        std::fs::canonicalize(&bundled).map_err(|e| e.to_string())?
    } else {
        let p = resolve("python3").ok_or("no python3 on PATH, and the SDK has no bundled Python")?;
        std::fs::canonicalize(p).map_err(|e| e.to_string())?
    };
    warnings.extend(trust::check(&python, policy)?);
    if cfg!(target_os = "macos") && python == Path::new("/usr/bin/python3") {
        warnings.push("/usr/bin/python3 is Apple's stub; it can prompt to install developer tools. A Homebrew or python.org Python is more reliable".into());
    }

    let mut env = std::collections::BTreeMap::new();
    env.insert("CLOUDSDK_PYTHON".to_owned(), python.display().to_string());
    if let Some(config) = std::env::var_os("CLOUDSDK_CONFIG") {
        let config = std::fs::canonicalize(config).map_err(|e| format!("CLOUDSDK_CONFIG: {e}"))?;
        env.insert("CLOUDSDK_CONFIG".to_owned(), config.display().to_string());
    }
    Ok((ToolConfig { path: gcloud, env }, warnings))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Fx {
        _tmp: tempfile::TempDir,
        base: PathBuf,
        root: ValetkeyRoot,
        policy: TrustPolicy,
    }

    /// A fake SDK under `target/` (not /tmp, which is world-writable on Linux).
    fn fx() -> Fx {
        let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/setup-tests");
        std::fs::create_dir_all(&target).unwrap();
        let tmp = tempfile::tempdir_in(&target).unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        for dir in ["sdk/bin", "sdk/lib", "sdk/platform/bundledpythonunix/bin", "repo"] {
            std::fs::create_dir_all(base.join(dir)).unwrap();
        }
        std::fs::write(base.join("sdk/bin/gcloud"), "").unwrap();
        std::fs::write(base.join("sdk/platform/bundledpythonunix/bin/python3"), "").unwrap();
        let policy = TrustPolicy {
            home: base.clone(),
            project: Some(base.join("repo")),
            temp_dirs: vec![],
        };
        Fx {
            root: ValetkeyRoot::at(base.join("vk")),
            base,
            policy,
            _tmp: tmp,
        }
    }

    fn go(f: &Fx, gcloud: Option<PathBuf>, answer: &str) -> (Outcome, String) {
        let resolve = |name: &str| if name == "gcloud" { gcloud.clone() } else { None };
        let mut out = Vec::new();
        let o = review(
            &f.root,
            &f.policy,
            &resolve,
            &mut Cursor::new(answer.as_bytes().to_vec()),
            &mut out,
        )
        .unwrap();
        (o, String::from_utf8(out).unwrap())
    }

    #[test]
    fn records_gcloud_and_its_bundled_python_on_yes() {
        let f = fx();
        let (o, out) = go(&f, Some(f.base.join("sdk/bin/gcloud")), "yes\n");
        assert_eq!(o, Outcome::Saved, "{out}");
        let saved = UserConfig::load(&f.root).unwrap();
        let tool = saved.tool("gcloud").unwrap();
        assert_eq!(tool.path, f.base.join("sdk/bin/gcloud"));
        assert_eq!(
            tool.env["CLOUDSDK_PYTHON"],
            f.base
                .join("sdk/platform/bundledpythonunix/bin/python3")
                .display()
                .to_string()
        );

        let (o, _) = go(&f, Some(f.base.join("sdk/bin/gcloud")), "");
        assert_eq!(o, Outcome::Unchanged);
    }

    #[test]
    fn saves_nothing_without_yes() {
        let f = fx();
        let (o, _) = go(&f, Some(f.base.join("sdk/bin/gcloud")), "y\n");
        assert_eq!(o, Outcome::Declined);
        assert!(UserConfig::load(&f.root).unwrap().tools.is_empty());
    }

    #[test]
    fn refuses_a_gcloud_inside_the_project() {
        let f = fx();
        std::fs::create_dir_all(f.base.join("repo/bin")).unwrap();
        std::fs::write(f.base.join("repo/bin/gcloud"), "").unwrap();
        let (o, out) = go(&f, Some(f.base.join("repo/bin/gcloud")), "yes\n");
        assert_eq!(o, Outcome::NothingToDo);
        assert!(out.contains("current project"), "{out}");
        assert!(UserConfig::load(&f.root).unwrap().tools.is_empty());
    }

    #[test]
    fn missing_gcloud_is_skipped() {
        let f = fx();
        let (o, out) = go(&f, None, "");
        assert_eq!(o, Outcome::NothingToDo);
        assert!(out.contains("not found"), "{out}");
    }
}
