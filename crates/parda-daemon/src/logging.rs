//! Logging: a daily-rotated file in the log directory plus stderr. Log lines
//! carry kinds, counts and timings, never raw values.

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use crate::paths::Paths;

/// Install the global subscriber. Keep the guard alive for the process
/// lifetime so buffered lines are flushed. `PARDA_LOG` overrides the filter.
pub fn init(paths: &Paths, verbose: bool) -> anyhow::Result<WorkerGuard> {
    std::fs::create_dir_all(&paths.log_dir)?;
    let file = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("parda")
        .filename_suffix("log")
        .max_log_files(7)
        .build(&paths.log_dir)?;
    let (writer, guard) = tracing_appender::non_blocking(file);
    let default = if verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_env("PARDA_LOG")
        .unwrap_or_else(|_| EnvFilter::new(format!("{default},hyper=warn,reqwest=warn,ort=warn")));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_ansi(false),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init();
    Ok(guard)
}
