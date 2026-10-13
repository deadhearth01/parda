//! The parda daemon: one process that owns the engine (model, vault, cache),
//! the agent proxy, the clipboard service and the IPC endpoint the CLI and
//! TUI talk to.

pub mod ca_store;
pub mod cert_trust;
pub mod events;
pub mod logging;
pub mod paths;
mod run;
pub mod service;
pub mod sysproxy;

pub use paths::{Paths, load_config, load_rules, write_private};
pub use run::{Daemon, RunOptions, load_model, run, run_foreground};
