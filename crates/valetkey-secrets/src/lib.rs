//! Secret sources and the hardened process runner (§5, §6.8). The broker calls [`fetch`] only
//! after its policy checks pass; nothing here decides whether a secret *may* be used.

pub mod cache;
mod dotenv;
pub mod runner;
pub mod sources;
pub mod trust;

pub use sources::{all_sources, fetch};
