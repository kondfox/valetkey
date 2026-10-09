//! valetkey's core: everything that doesn't touch a vendor library.
//!
//! - [`paths`]: the valetkey root, resolved from the OS user database.
//! - [`secret_ref`]: `<scheme>://…` secret references and their exposure.
//! - [`config`]: `valetkey.toml`, its target kinds, and its canonical form.
//! - [`project`]: finding the project root and its key.
//! - [`snapshot`]: approved config snapshots (`valetkey allow`).
//! - [`diff`]: what changed between two configs, and how risky it is.
//! - [`sanitize`]: making untrusted text safe to show a human.
//! - [`safe_read`]: reading agent-writable files without following links.
//! - [`secret_source`]: the interface every secret source implements.
//! - [`user_config`]: `~/.valetkey/config.toml`, the human-approved tool paths.
//! - [`write_request`]: a write a human approves out of band, its hash and its rendering.
//! - [`write_store`]: the pending-request and decision files behind `valetkey approve`.
//! - [`audit`]: the audit log.
//!
//! The spec is `docs/design.md` in the repository; section numbers in comments refer to it.

pub mod audit;
pub mod config;
pub mod diff;
pub mod paths;
pub mod platform;
pub mod problem;
pub mod project;
pub mod safe_read;
pub mod sanitize;
pub mod secret_ref;
pub mod secret_source;
pub mod snapshot;
pub mod user_config;
pub mod write_request;
pub mod write_store;

pub use config::{NormalizeCx, NormalizedTarget, ProjectConfig, Registry, TargetId, TargetKind};
pub use paths::ValetkeyRoot;
pub use platform::Platform;
pub use problem::Problem;
pub use project::{Project, ProjectKey};
pub use secret_ref::{Exposure, SecretRef};
