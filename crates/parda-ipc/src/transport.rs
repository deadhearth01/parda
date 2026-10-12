//! A blocking client and an asynchronous, concurrent local socket server.

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    path::Path,
    sync::Arc,
    time::Duration,
};

use interprocess::{
    ConnectWaitMode,
    local_socket::{
        ConnectOptions, ListenerOptions, Name, Stream,
        prelude::*,
        tokio::Stream as AsyncStream,
        traits::tokio::{Listener as _, Stream as _},
    },
};
use serde::Serialize;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::broadcast,
    task::JoinSet,
};

use crate::{Event, PROTOCOL_VERSION, Request, Response};

/// Maximum encoded line length in bytes, excluding the terminating LF.
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// How long [`Client::connect`] waits to connect and complete the handshake.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// Nothing is listening: no socket or pipe, or a stale socket file.
    /// Callers such as the CLI use this to fall back to in-process mode.
    #[error("the parda daemon is not running")]
    NotRunning,
    /// The daemon accepted the connection but did not answer in time.
    #[error("timed out waiting for the parda daemon")]
    Timeout,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The daemon answered with `Err{code, message}`.
    #[error("{code}: {message}")]
    Remote { code: String, message: String },
    #[error("line exceeds 16 MiB")]
    LineTooLong,
    #[error("{0}")]
    Protocol(&'static str),
}

impl IpcError {
    /// True for [`IpcError::NotRunning`]: the daemon is absent, not misbehaving.
    pub fn is_not_running(&self) -> bool {
        matches!(self, Self::NotRunning)
    }
}

pub type Result<T> = std::result::Result<T, IpcError>;

/// True if `err`, or any error it wraps, is [`IpcError::NotRunning`].
pub fn is_not_running(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<IpcError>()
            .is_some_and(IpcError::is_not_running)
    })
}

/// Resolve `<runtime_dir>/parda.sock` on Unix or `parda-<USERNAME>` on Windows.
/// On Windows, `PARDA_PIPE_NAME` overrides the full namespaced pipe name.
///
/// # Panics
/// Panics if the OS cannot represent the name (for example an embedded NUL),
/// or if neither Windows naming environment variable is set. `Client::connect`
/// and `serve` return an error for these cases instead.
pub fn socket_name(runtime_dir: &Path) -> Name<'static> {
    checked_socket_name(runtime_dir).expect("invalid parda socket name")
}

#[cfg(unix)]
fn checked_socket_name(runtime_dir: &Path) -> io::Result<Name<'static>> {
    use interprocess::local_socket::GenericFilePath;
    runtime_dir
        .join("parda.sock")
        .to_fs_name::<GenericFilePath>()
}

#[cfg(windows)]
fn checked_socket_name(_runtime_dir: &Path) -> io::Result<Name<'static>> {
    use interprocess::local_socket::GenericNamespaced;
    let name = match std::env::var_os("PARDA_PIPE_NAME") {
        Some(name) => name,
        None => {
            let user = std::env::var_os("USERNAME")
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "USERNAME is not set"))?;
            let mut name = std::ffi::OsString::from("parda-");
            name.push(user);
            name
        }
    };
    name.to_ns_name::<GenericNamespaced>()
}

/// Application requests run on Tokio's blocking pool. `Hello` and `Subscribe`
/// are handled by the transport and never reach [`Handler::handle`].
pub trait Handler: Send + Sync {
    fn handle(&self, req: Request) -> Response;
    /// Called once per `Subscribe`; the receiver feeds that client's stream.
    fn subscribe(&self) -> broadcast::Receiver<Event>;
}

/// A synchronous client for CLI/TUI threads. Do not call it on an async worker.
///
/// After any transport or framing error the connection is unusable (the stream
/// position is unknown) and later calls fail without touching the socket.
/// Errors reported by the daemon (`IpcError::Remote`) do not poison it.
pub struct Client {
    stream: BufReader<Stream>,
    failed: bool,
}

impl Client {
    /// Connect and negotiate the protocol version, giving up after
    /// [`CONNECT_TIMEOUT`]. Returns [`IpcError::NotRunning`] if no daemon is
    /// listening; see [`is_not_running`].
    pub fn connect(runtime_dir: &Path) -> Result<Self> {
        Self::connect_with_timeout(runtime_dir, CONNECT_TIMEOUT)
    }

    /// Like [`Client::connect`] with a custom timeout. The timeout bounds the
    /// connect and the answer to the version handshake. Windows named pipes
    /// support neither read timeouts nor connect waits; there only the
    /// "not running" classification applies.
    pub fn connect_with_timeout(runtime_dir: &Path, timeout: Duration) -> Result<Self> {
        let stream = ConnectOptions::new()
            .name(checked_socket_name(runtime_dir)?)
            .wait_mode(ConnectWaitMode::Timeout(timeout))
            .connect_sync()
            .map_err(classify_connect_error)?;
        let bounded = stream.set_recv_timeout(Some(timeout)).is_ok();
        let mut client = Self {
            stream: BufReader::new(stream),
            failed: false,
        };
        match client.call(Request::Hello {
            version: PROTOCOL_VERSION,
        }) {
            Ok(_) => {}
            Err(IpcError::Io(e)) if is_timeout(&e) => return Err(IpcError::Timeout),
            Err(e) => return Err(e),
        }
        if bounded {
            client.stream.get_ref().set_recv_timeout(None)?;
        }
        Ok(client)
    }

    /// Send one request and wait for its response. Not for `Subscribe`: use
    /// [`Client::subscribe`].
    pub fn call(&mut self, req: Request) -> Result<serde_json::Value> {
        if matches!(req, Request::Subscribe) {
            return Err(IpcError::Protocol(
                "use Client::subscribe for event streams",
            ));
        }
        // An unsendable request leaves the connection untouched and usable.
        let frame = encode(&req)?;
        match self.exchange(&frame)? {
            Response::Ok(value) => Ok(value),
            Response::Err { code, message } => Err(IpcError::Remote { code, message }),
            Response::Event(_) => {
                self.failed = true;
                Err(IpcError::Protocol("unexpected event response"))
            }
        }
    }

    /// Send Subscribe and consume the connection as an event iterator.
    /// EOF or any error ends iteration; inspect [`Events::error`] for failures.
    pub fn subscribe(mut self) -> Events {
        let sent = encode(&Request::Subscribe).and_then(|frame| self.write_frame(&frame));
        let error = sent.err();
        Events {
            client: error.is_none().then_some(self),
            error,
        }
    }

    fn exchange(&mut self, frame: &[u8]) -> Result<Response> {
        if self.failed {
            return Err(IpcError::Protocol(
                "connection failed earlier; reconnect to continue",
            ));
        }
        let result = self.write_frame(frame).and_then(|()| {
            self.receive()?
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof).into())
        });
        self.failed = result.is_err();
        result
    }

    fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        let stream = self.stream.get_mut();
        stream.write_all(frame)?;
        stream.flush()?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<Response>> {
        let mut frame = Vec::new();
        // Take bounds allocation even for a peer that never sends a newline.
        Read::take(&mut self.stream, (MAX_LINE_BYTES + 1) as u64).read_until(b'\n', &mut frame)?;
        finish_frame(frame)?
            .map(|frame| serde_json::from_slice(&frame).map_err(IpcError::from))
            .transpose()
    }
}

fn classify_connect_error(error: io::Error) -> IpcError {
    use io::ErrorKind::{ConnectionRefused, NotADirectory, NotFound};
    match error.kind() {
        // Missing socket or pipe, a path that cannot hold one, or a stale
        // socket file that nobody listens on.
        NotFound | ConnectionRefused | NotADirectory => IpcError::NotRunning,
        _ if is_timeout(&error) => IpcError::Timeout,
        _ => IpcError::Io(error),
    }
}

fn is_timeout(error: &io::Error) -> bool {
    // SO_RCVTIMEO expiry surfaces as WouldBlock on Unix and TimedOut elsewhere.
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// A fused blocking iterator; no events are yielded after EOF or failure.
pub struct Events {
    client: Option<Client>,
    error: Option<IpcError>,
}

impl Events {
    /// Why iteration ended, or `None` if the daemon closed the stream cleanly
    /// (or iteration has not ended yet).
    pub fn error(&self) -> Option<&IpcError> {
        self.error.as_ref()
    }
}

impl Iterator for Events {
    type Item = Event;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.client.as_mut()?.receive();
        match result {
            Ok(Some(Response::Event(event))) => return Some(event),
            Ok(None) => {}
            Ok(Some(Response::Err { code, message })) => {
                self.error = Some(IpcError::Remote { code, message });
            }
            Ok(Some(Response::Ok(_))) => {
                self.error = Some(IpcError::Protocol("unexpected Ok in event stream"));
            }
            Err(error) => self.error = Some(error),
        }
        self.client = None;
        None
    }
}

impl std::iter::FusedIterator for Events {}

/// Serve until the future is dropped or a listener error occurs. Dropping the
/// future aborts connection tasks and reclaims the Unix socket name. Already
/// running blocking handlers finish normally. Shutdown is an application request;
/// the daemon owns cancellation of this future.
///
/// On Unix this creates `runtime_dir` (mode 0700) if missing, tightens an
/// existing one to 0700, and replaces a stale socket file. It refuses to touch
/// a live daemon's socket, a non-socket file, or a symlinked `runtime_dir`.
pub async fn serve(runtime_dir: &Path, handler: Arc<dyn Handler>) -> Result<()> {
    let name = checked_socket_name(runtime_dir)?;
    #[cfg(unix)]
    prepare_runtime(runtime_dir, &name).await?;
    let listener = ListenerOptions::new().name(name).create_tokio()?;
    tracing::debug!("ipc listening");
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            stream = listener.accept() => {
                let stream = stream?;
                let handler = handler.clone();
                connections.spawn(async move {
                    // Peer errors terminate only that connection. Never log
                    // frames or request data: they may contain raw PII.
                    if let Err(error) = connection(stream, handler).await {
                        tracing::debug!(%error, "ipc connection ended with an error");
                    }
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

#[cfg(unix)]
async fn prepare_runtime(runtime_dir: &Path, name: &Name<'_>) -> io::Result<()> {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt},
    };
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(runtime_dir)?;
    if !fs::symlink_metadata(runtime_dir)?.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime_dir must be a directory, not a symlink",
        ));
    }
    fs::set_permissions(runtime_dir, fs::Permissions::from_mode(0o700))?;
    let path = runtime_dir.join("parda.sock");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            // A stale socket refuses connections. Do not unlink a live daemon.
            match AsyncStream::connect(name.clone()).await {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "parda socket is in use",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    tracing::debug!("removing stale ipc socket");
                    fs::remove_file(path)?
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "parda.sock is not a socket",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn finish_frame(mut frame: Vec<u8>) -> Result<Option<Vec<u8>>> {
    if frame.is_empty() {
        return Ok(None);
    }
    if frame.last() == Some(&b'\n') {
        frame.pop();
        return Ok(Some(frame));
    }
    if frame.len() > MAX_LINE_BYTES {
        return Err(IpcError::LineTooLong);
    }
    Err(IpcError::Protocol("incomplete line: expected a newline"))
}

async fn read_frame(reader: &mut (impl AsyncBufRead + Unpin)) -> Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    AsyncReadExt::take(reader, (MAX_LINE_BYTES + 1) as u64)
        .read_until(b'\n', &mut frame)
        .await?;
    finish_frame(frame)
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut frame = serde_json::to_vec(value)?;
    if frame.len() > MAX_LINE_BYTES {
        return Err(IpcError::LineTooLong);
    }
    frame.push(b'\n');
    Ok(frame)
}

async fn write_response(writer: &mut (impl AsyncWrite + Unpin), response: Response) -> Result<()> {
    // Also validate directly constructed Ok variants, which bypass `Response::ok`.
    let (frame, oversized) = match encode(&response.normalized()) {
        Ok(frame) => (frame, false),
        Err(IpcError::LineTooLong) => (
            encode(&Response::err("line_too_long", "response exceeds 16 MiB"))?,
            true,
        ),
        Err(error) => return Err(error),
    };
    writer.write_all(&frame).await?;
    writer.flush().await?;
    if oversized {
        Err(IpcError::LineTooLong)
    } else {
        Ok(())
    }
}

async fn connection(stream: AsyncStream, handler: Arc<dyn Handler>) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let mut reader = tokio::io::BufReader::new(reader);
    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(error) => {
                let code = if matches!(error, IpcError::LineTooLong) {
                    "line_too_long"
                } else {
                    "invalid_request"
                };
                write_response(&mut writer, Response::err(code, "invalid NDJSON frame")).await?;
                return Ok(());
            }
        };
        let req = match serde_json::from_slice::<Request>(&frame) {
            Ok(req) => req,
            Err(_) => {
                write_response(
                    &mut writer,
                    Response::err("invalid_request", "invalid request JSON"),
                )
                .await?;
                return Ok(());
            }
        };
        drop(frame);
        match req {
            Request::Hello { version } => {
                if version != PROTOCOL_VERSION {
                    write_response(
                        &mut writer,
                        Response::err("version_mismatch", "expected protocol version 1"),
                    )
                    .await?;
                    return Ok(());
                }
                write_response(
                    &mut writer,
                    Response::ok(serde_json::json!({"version": PROTOCOL_VERSION})),
                )
                .await?;
            }
            Request::Subscribe => {
                let mut events =
                    match tokio::task::spawn_blocking(move || handler.subscribe()).await {
                        Ok(events) => events,
                        Err(_) => {
                            write_response(
                                &mut writer,
                                Response::err("handler_failed", "subscription handler failed"),
                            )
                            .await?;
                            return Ok(());
                        }
                    };
                loop {
                    tokio::select! {
                        // Subscribe is terminal: EOF or further input closes it.
                        // This releases idle subscriptions without needing an event.
                        _ = reader.read_u8() => return Ok(()),
                        event = events.recv() => {
                            let event = match event {
                                Ok(event) => event,
                                Err(broadcast::error::RecvError::Closed) => return Ok(()),
                                // A slow client loses the oldest events; tell it
                                // how many and keep the stream going.
                                Err(broadcast::error::RecvError::Lagged(missed)) => lag_warning(missed),
                            };
                            write_response(&mut writer, Response::Event(event)).await?;
                        }
                    }
                }
            }
            req => {
                let handler = handler.clone();
                let response = tokio::task::spawn_blocking(move || handler.handle(req))
                    .await
                    .unwrap_or_else(|_| Response::err("handler_failed", "request handler failed"));
                write_response(&mut writer, response).await?;
            }
        }
    }
}

fn lag_warning(missed: u64) -> Event {
    let mut event = Event::now(
        "ipc",
        format!("{missed} events dropped: subscriber too slow"),
    );
    event.level = "warn".into();
    event
        .counts
        .insert("dropped".into(), u32::try_from(missed).unwrap_or(u32::MAX));
    event
}
