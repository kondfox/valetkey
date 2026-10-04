//! Human-facing terminal output. Everything that came from a config file goes through
//! [`valetkey_core::sanitize`] before it's printed.

use std::io::Write;

/// Prints a line to stdout. Commands that talk to humans use this; `mcp` never does.
#[allow(clippy::print_stdout)]
pub(crate) fn line(text: impl AsRef<str>) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", text.as_ref());
}

pub(crate) fn ok(text: impl AsRef<str>) {
    line(format!("✔ {}", text.as_ref()));
}

pub(crate) fn warn(text: impl AsRef<str>) {
    line(format!("⚠ {}", text.as_ref()));
}

pub(crate) fn fail(text: impl AsRef<str>) {
    line(format!("✘ {}", text.as_ref()));
}

/// The absolute path of the running binary, for hints (§6.3: hints use absolute paths).
pub(crate) fn self_path() -> String {
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "valetkey".into())
}
