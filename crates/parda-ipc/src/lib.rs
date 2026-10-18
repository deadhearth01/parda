//! Local NDJSON protocol for the parda daemon and its CLI/TUI clients.
//!
//! The async server (`serve`) uses Tokio and `interprocess` local sockets: a
//! Unix domain socket at `<runtime_dir>/parda.sock` (directory mode 0700) or,
//! on Windows, the named pipe `parda-<user SID>-<hash>` whose DACL admits only
//! that user and SYSTEM; the Windows client also checks that the process
//! serving the pipe runs as the same user. The blocking [`Client`] uses
//! standard I/O. Each frame is UTF-8 JSON followed by LF, with a maximum of
//! 16 MiB before the LF; longer lines are answered with `Err{line_too_long}`
//! and the connection is closed.
//!
//! Handshake: `Client::connect` sends `Hello{version}`; a successful reply is
//! `{"kind":"Ok","version":1}`, a mismatch is `Err{version_mismatch}` followed
//! by close. Hello is recommended but optional for raw one-shot clients.
//! `Subscribe` sends `Event` lines without an Ok acknowledgement and consumes
//! the connection.
//!
//! A CLI that wants to fall back to in-process mode when no daemon runs checks
//! [`is_not_running`] (or [`IpcError::NotRunning`]) on the `Client::connect`
//! error.

pub mod proto;
pub mod transport;
#[cfg(windows)]
mod win;

pub use proto::{Event, PROTOCOL_VERSION, Request, Response};
pub use transport::{
    CONNECT_TIMEOUT, Client, Events, Handler, IpcError, MAX_LINE_BYTES, Result, is_not_running,
    serve, socket_name,
};
