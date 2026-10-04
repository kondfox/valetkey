//! `valetkey allow`: show a human what `valetkey.toml` would let the agent use, and store the
//! approved snapshot (§6.1).
//!
//! The file is read **once**; what's stored is exactly what was shown. The command only runs in
//! an interactive terminal, and inside the agent's sandbox it can't write the snapshot anyway
//! (the valetkey root is write-denied).
//!
//! [`run`] is the terminal gate; [`review`] is the whole flow with injected input and output, so
//! tests can drive it.

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use valetkey_core::diff::{self, Risk};
use valetkey_core::safe_read::{MAX_CONFIG_LEN, read_untrusted};
use valetkey_core::sanitize::{for_display, has_non_ascii};
use valetkey_core::snapshot::{self, Snapshot};
use valetkey_core::{Exposure, NormalizeCx, Platform, ProjectConfig, Registry, ValetkeyRoot, project};

use crate::output;

/// The word a human must type to approve.
const CONFIRMATION: &str = "yes";

/// How a review ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Approved,
    AlreadyApproved,
    Declined,
    Invalid,
}

pub(crate) fn run() -> anyhow::Result<ExitCode> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        output::fail(
            "valetkey allow needs an interactive terminal: a human runs it in a normal terminal, not through a pipe or the agent's session",
        );
        return Ok(ExitCode::FAILURE);
    }
    let root = crate::resolve_root()?;
    let start = std::env::current_dir()?;
    let outcome = review(
        &root,
        &start,
        &crate::registry(),
        crate::platform(),
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )?;
    Ok(match outcome {
        Outcome::Approved | Outcome::AlreadyApproved => ExitCode::SUCCESS,
        Outcome::Declined | Outcome::Invalid => ExitCode::FAILURE,
    })
}

/// Reads the project's config once, shows it, asks for confirmation on `input`, and stores
/// exactly the config it showed.
pub(crate) fn review(
    root: &ValetkeyRoot,
    start: &Path,
    registry: &Registry,
    platform: Platform,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> anyhow::Result<Outcome> {
    let project = project::discover(start)?;
    let text = read_untrusted(&project.config_path, MAX_CONFIG_LEN)?;

    let cx = NormalizeCx { root, platform };
    let config = match registry.parse(&text, &cx) {
        Ok(c) => c,
        Err(problems) => {
            writeln!(
                out,
                "✘ {} has problems; nothing was approved:",
                for_display(&project.config_path.display().to_string())
            )?;
            for p in problems {
                writeln!(out, "  - {}", for_display(&p.to_string()))?;
            }
            return Ok(Outcome::Invalid);
        }
    };

    let previous = match snapshot::load(root, &project) {
        Ok(s) => s.filter(|s| s.project_root == project.root),
        Err(e) => {
            writeln!(out, "⚠ ignoring the previous approval: {}", for_display(&e.to_string()))?;
            None
        }
    };
    if previous.as_ref().is_some_and(|s| s.config_hash == config.hash()) {
        writeln!(out, "✔ already approved; nothing changed")?;
        return Ok(Outcome::AlreadyApproved);
    }

    writeln!(out, "Project:  {}", for_display(&project.root.display().to_string()))?;
    writeln!(out, "Config:   {}", config.hash())?;
    writeln!(out)?;
    show_targets(&config, out)?;
    writeln!(out)?;
    writeln!(out, "Changes since the last approval:")?;
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
        writeln!(out, "  [{label}] {target}{}", for_display(&change.description))?;
    }
    writeln!(out)?;

    write!(out, "Approve this configuration? Type `{CONFIRMATION}` to approve: ")?;
    out.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    if answer.trim() != CONFIRMATION {
        writeln!(out, "✘ not approved; nothing changed")?;
        return Ok(Outcome::Declined);
    }
    // `config` is the value parsed from the one read above; the file isn't read again.
    snapshot::store(root, &project, &Snapshot::new(&project, config))?;
    writeln!(out, "✔ approved")?;
    Ok(Outcome::Approved)
}

fn show_targets(config: &ProjectConfig, out: &mut dyn Write) -> std::io::Result<()> {
    if config.targets.is_empty() {
        return writeln!(out, "Targets:  none");
    }
    writeln!(out, "Targets:")?;
    for (id, t) in &config.targets {
        let flag = if has_non_ascii(id.as_str()) || has_non_ascii(&t.connection.to_string()) {
            "  ⚠ contains non-ASCII characters, which can disguise one name as another"
        } else {
            ""
        };
        let exposure = match t.exposure_at_approval {
            Some(Exposure::Protected) => "protected secret",
            Some(Exposure::Exposed) => "exposed secret",
            None => "no secret",
        };
        writeln!(
            out,
            "  {} ({}, {exposure}{}){flag}",
            for_display(id.as_str()),
            for_display(&t.kind),
            if t.writable { ", WRITABLE" } else { "" },
        )?;
        writeln!(out, "      connection: {}", for_display(&t.connection.to_string()))?;
        if let Some(secret) = &t.secret {
            writeln!(out, "      secret:     {}", for_display(&secret.to_string()))?;
        }
        let has_settings = t.settings.as_object().is_some_and(|m| m.values().any(|v| !v.is_null()));
        if has_settings {
            writeln!(out, "      settings:   {}", for_display(&t.settings.to_string()))?;
        }
    }
    if !config.require_fence {
        writeln!(
            out,
            "⚠ require_fence = false: protected secrets will be used even without a fence"
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::PathBuf;

    const CONFIG: &str = "[targets.local-app]\nkind = \"postgres\"\nhost = \"localhost\"\ndatabase = \"app\"\nuser = \"app\"\nsecret = \"env-file://.env#POSTGRES_PASSWORD\"\n";

    struct Fixture {
        _tmp: tempfile::TempDir,
        project: PathBuf,
        root: ValetkeyRoot,
    }

    fn fixture(config: &str) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let project = base.join("repo");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("valetkey.toml"), config).unwrap();
        Fixture {
            project,
            root: ValetkeyRoot::at(base.join("vk")),
            _tmp: tmp,
        }
    }

    fn review_with(f: &Fixture, input: &mut dyn BufRead) -> (Outcome, String) {
        let mut out = Vec::new();
        let outcome = review(
            &f.root,
            &f.project,
            &crate::registry(),
            Platform::Linux,
            input,
            &mut out,
        )
        .unwrap();
        (outcome, String::from_utf8(out).unwrap())
    }

    fn answer(s: &str) -> Cursor<Vec<u8>> {
        Cursor::new(s.as_bytes().to_vec())
    }

    fn stored(f: &Fixture) -> Option<Snapshot> {
        let p = project::discover(&f.project).unwrap();
        snapshot::load(&f.root, &p).unwrap()
    }

    #[test]
    fn yes_stores_exactly_the_config_that_was_shown() {
        let f = fixture(CONFIG);
        let (outcome, out) = review_with(&f, &mut answer("yes\n"));
        assert_eq!(outcome, Outcome::Approved);
        let snap = stored(&f).expect("a snapshot");
        assert!(out.contains(&format!("Config:   {}", snap.config_hash)), "{out}");
        assert!(out.contains("local-app (postgres, exposed secret)"), "{out}");
        assert!(out.contains("[HIGH] first approval"), "{out}");
    }

    #[test]
    fn anything_but_yes_stores_nothing() {
        for reply in ["y\n", "Y\n", "YES\n", "no\n", "\n", "", "yes please\n"] {
            let f = fixture(CONFIG);
            let (outcome, out) = review_with(&f, &mut answer(reply));
            assert_eq!(outcome, Outcome::Declined, "{reply:?}");
            assert!(stored(&f).is_none(), "{reply:?} must not approve");
            assert!(out.contains("not approved"), "{out}");
        }
    }

    /// Changes `valetkey.toml` while the prompt is waiting, like an agent racing the human.
    struct SwapOnRead {
        path: PathBuf,
        replacement: &'static str,
        inner: Cursor<Vec<u8>>,
    }

    impl std::io::Read for SwapOnRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl BufRead for SwapOnRead {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            std::fs::write(&self.path, self.replacement)?;
            self.inner.fill_buf()
        }
        fn consume(&mut self, n: usize) {
            self.inner.consume(n);
        }
    }

    #[test]
    fn a_file_swapped_during_the_prompt_is_not_what_gets_approved() {
        let f = fixture(CONFIG);
        let evil = CONFIG
            .replace("localhost", "attacker.example")
            .replace("env-file://.env#POSTGRES_PASSWORD", "env-file://.env#OTHER");
        let evil: &'static str = Box::leak(evil.into_boxed_str());
        let mut input = SwapOnRead {
            path: f.project.join("valetkey.toml"),
            replacement: evil,
            inner: answer("yes\n"),
        };
        let (outcome, _) = review_with(&f, &mut input);
        assert_eq!(outcome, Outcome::Approved);
        let on_disk = std::fs::read_to_string(f.project.join("valetkey.toml")).unwrap();
        assert_eq!(
            on_disk, evil,
            "the swap must have happened, or this test proves nothing"
        );

        let snap = stored(&f).unwrap();
        assert_eq!(
            snap.config.targets["local-app"].connection["host"], "localhost",
            "the shown config was stored"
        );
        // The swapped file doesn't match the approval, so the broker won't serve it.
        let cx = NormalizeCx {
            root: &f.root,
            platform: Platform::Linux,
        };
        let now = crate::registry().parse(evil, &cx).unwrap();
        assert_ne!(now.hash(), snap.config_hash);
    }

    #[test]
    fn invalid_config_is_shown_and_not_stored() {
        let f = fixture(&CONFIG.replace("env-file://.env#POSTGRES_PASSWORD", "local://app"));
        let (outcome, out) = review_with(&f, &mut answer("yes\n"));
        assert_eq!(outcome, Outcome::Invalid);
        assert!(stored(&f).is_none());
        assert!(out.contains("can't be sent over plain TCP"), "{out}");
    }

    #[test]
    fn unchanged_config_needs_no_prompt() {
        let f = fixture(CONFIG);
        review_with(&f, &mut answer("yes\n"));
        let (outcome, out) = review_with(&f, &mut answer(""));
        assert_eq!(outcome, Outcome::AlreadyApproved);
        assert!(!out.contains("Approve this configuration"), "{out}");
    }

    #[test]
    fn a_change_shows_its_risk() {
        let f = fixture(CONFIG);
        review_with(&f, &mut answer("yes\n"));
        std::fs::write(f.project.join("valetkey.toml"), format!("{CONFIG}writable = true\n")).unwrap();
        let (outcome, out) = review_with(&f, &mut answer("no\n"));
        assert_eq!(outcome, Outcome::Declined);
        assert!(out.contains("[HIGH] local-app: writable turned on"), "{out}");
    }

    #[test]
    fn displayed_strings_are_sanitized_and_flagged() {
        // A bidi override in the database name, an escape sequence in the description.
        let config = CONFIG.replace("database = \"app\"", "database = \"app\u{202e}lanif\"")
            + "description = \"\\u001b[2Jcleared\"\n"; // TOML escape → a real ESC in the value
        let f = fixture(&config);
        let (_, out) = review_with(&f, &mut answer("no\n"));
        assert!(!out.contains('\u{202e}'), "raw bidi override in: {out}");
        assert!(!out.contains('\u{1b}'), "raw escape in: {out}");
        assert!(out.contains("\\u{202e}"), "{out}");
        assert!(out.contains("settings:"), "{out}");
        assert!(out.contains("non-ASCII"), "{out}");
    }
}
