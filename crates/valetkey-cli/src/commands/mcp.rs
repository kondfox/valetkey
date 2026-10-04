//! `valetkey mcp`: the broker. The agent client starts it; stdout belongs to MCP, so logs go to
//! `~/.valetkey/logs/mcp.log`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;

use tracing_subscriber::EnvFilter;
use valetkey_core::ValetkeyRoot;
use valetkey_core::paths::ensure_private_dir;
use valetkey_mcp::{Broker, BrokerConfig};

pub(crate) fn run() -> anyhow::Result<ExitCode> {
    let root = crate::resolve_root()?;
    init_logging(&root);
    // Untrusted: a settings `env` block can set it. The broker cross-checks it against the
    // client's MCP roots before relying on it (§6.1).
    let env_project_dir = std::env::var_os("CLAUDE_PROJECT_DIR").map(PathBuf::from);
    let config = BrokerConfig {
        root,
        registry: crate::registry(),
        platform: crate::platform(),
        env_project_dir,
        self_path: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("valetkey")),
        roots_timeout: valetkey_mcp::DEFAULT_ROOTS_TIMEOUT,
    };
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "broker starting");
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(Broker::new(config).serve_stdio())?;
    tracing::info!("broker stopped");
    Ok(ExitCode::SUCCESS)
}

/// Logs to a file under the valetkey root, or to stderr if that fails. Never to stdout.
fn init_logging(root: &ValetkeyRoot) {
    let filter = EnvFilter::new("info");
    let dir = root.logs_dir();
    let file = ensure_private_dir(&dir).and_then(|()| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("mcp.log"))
    });
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false);
    match file {
        Ok(file) => builder.with_writer(Mutex::new(file)).init(),
        Err(_) => builder.with_writer(std::io::stderr).init(),
    }
}
