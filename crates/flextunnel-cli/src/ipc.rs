//! Local control channel between a running `flextunnel client start` and
//! `flextunnel client control`.
//!
//! Transport: a Unix domain socket (`~/.config/flextunnel/client-<key>.sock`)
//! or a Windows named pipe (`\\.\pipe\flextunnel-client-<key>`), where `<key>`
//! is the server-id-prefix instance key (see `instance.rs`). Protocol:
//! JSON Lines, strict request → response over a long-lived connection. Both
//! ends are this one binary and the repo has a no-compatibility policy, so
//! there is no protocol version field.
//!
//! Unlike a read-only status socket, this channel *mutates* state (port
//! forwards), so the Unix socket is chmod'd 0600 (owner only). On Windows the
//! default pipe security descriptor already restricts other users.
//!
//! The socket is not the single-instance lock — see `lock.rs` for why. But
//! *because* the caller holds that lock, unconditionally removing a stale
//! socket file before bind is safe: no other live client of this instance can
//! own it.
//!
//! macOS caps `sun_path` around 104 bytes; with the socket under
//! `~/.config/flextunnel/` and the 16-char key, only a pathological home path
//! overflows — that surfaces as a clear bind error.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

// Windows derives everything from the pipe name; only the Unix socket path
// lives under the instance dir.
#[cfg(unix)]
use crate::instance;

/// Cap on one JSON line in either direction.
const MAX_LINE: usize = 1024 * 1024;
/// Client-side timeout for connect and for each request round trip.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    /// On-demand connection-path + custom-relay-health snapshot (mirrors the
    /// desktop modal / iOS sheet). Kept off the polled `Status` because the
    /// custom-relay `/healthz` probe does on-demand HTTP.
    ConnPath,
    AddForward { forward: WireForward },
    UpdateForward { forward: WireForward },
    DeleteForward { id: String },
    SetForwardEnabled { id: String, enabled: bool },
}

/// Every success — mutations included — answers with a fresh snapshot so the
/// TUI redraws immediately instead of waiting for its next poll tick.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "resp", rename_all = "snake_case")]
pub enum Response {
    Status(Box<StatusSnapshot>),
    ConnPath(WireConnSnapshot),
    Error { message: String },
}

/// [`flextunnel_core::forwards::PortForward`] with `enabled` made explicit
/// (the model marks it `#[serde(skip)]` so it is never *persisted*, but the
/// live wire must carry it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireForward {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Connecting => "connecting",
            Phase::Connected => "connected",
            Phase::Reconnecting => "reconnecting",
            Phase::Failed => "failed",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusSnapshot {
    /// The server-id-prefix instance key (see `instance.rs`).
    pub instance: String,
    /// Friendly profile name from the config ("aws", "home network"), if set.
    pub name: Option<String>,
    pub phase: Phase,
    /// Uptime of the current connection, if connected.
    pub connected_secs: Option<u64>,
    pub server_node_id: String,
    pub client_node_id: String,
    pub socks_addr: Option<SocketAddr>,
    pub http_addr: Option<SocketAddr>,
    /// Reserved host that is always tunneled to the server's status page.
    pub status_page_host: String,
    pub last_error: Option<String>,
    pub routes: WireRoutes,
    pub forwards: Vec<ForwardRow>,
}

/// On-demand connection snapshot served for [`Request::ConnPath`]: the live iroh
/// path(s) plus custom-relay `/healthz` health. Both are empty while the tunnel
/// link is down.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WireConnSnapshot {
    pub paths: Vec<WireConnPath>,
    pub custom_relays: Vec<WireCustomRelay>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WireCustomRelay {
    pub url: String,
    /// `Some(true)` = up (2xx), `Some(false)` = down, `None` = check not run.
    pub working: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WireRoutes {
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    /// alias → target, resolved server-side.
    pub host_aliases: Vec<(String, String)>,
    /// suffix → upstream servers.
    pub dns_forwards: Vec<(String, Vec<String>)>,
    pub bridges: Vec<WireBridge>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WireBridge {
    pub name: String,
    pub endpoint_id: String,
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WireConnPath {
    /// "direct" | "relay" | "other".
    pub kind: String,
    pub display: String,
    pub selected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardRowState {
    /// Disabled (the switch is off).
    Stopped,
    Starting,
    Listening,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ForwardRow {
    #[serde(flatten)]
    pub forward: WireForward,
    pub state: ForwardRowState,
    /// Bind-failure reason — including the retained reason of a forward that
    /// was auto-disabled after its listener failed to bind.
    pub error: Option<String>,
    /// Live relayed connections.
    pub active: usize,
    pub last_conn_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Session-side command plumbing
// ---------------------------------------------------------------------------

/// What a connection task asks of the client session loop.
pub enum IpcCmd {
    Status(oneshot::Sender<StatusSnapshot>),
    ConnPath(oneshot::Sender<WireConnSnapshot>),
    Mutate(Mutation, oneshot::Sender<Result<StatusSnapshot, String>>),
}

pub enum Mutation {
    Add(WireForward),
    Update(WireForward),
    Delete(String),
    SetEnabled(String, bool),
}

// ---------------------------------------------------------------------------
// Naming
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn socket_path(key: &str) -> Result<std::path::PathBuf> {
    Ok(instance::instance_dir()?.join(format!("client-{key}.sock")))
}

#[cfg(windows)]
fn pipe_name(key: &str) -> String {
    format!(r"\\.\pipe\flextunnel-client-{key}")
}

// ---------------------------------------------------------------------------
// Server side (runs inside the client session)
// ---------------------------------------------------------------------------

/// Owns the accept task; dropping it stops serving and (Unix) removes the
/// socket file.
pub struct IpcServerGuard {
    task: JoinHandle<()>,
    #[cfg(unix)]
    socket: std::path::PathBuf,
}

impl Drop for IpcServerGuard {
    fn drop(&mut self) {
        self.task.abort();
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Start serving the control channel for `instance`. The caller must already
/// hold the instance lock (that is what makes the stale-socket removal safe).
pub fn spawn_ipc_server(key: &str, tx: mpsc::Sender<IpcCmd>) -> Result<IpcServerGuard> {
    #[cfg(unix)]
    {
        spawn_unix(socket_path(key)?, tx)
    }
    #[cfg(windows)]
    {
        spawn_pipe(pipe_name(key), tx)
    }
}

#[cfg(unix)]
fn spawn_unix(socket: std::path::PathBuf, tx: mpsc::Sender<IpcCmd>) -> Result<IpcServerGuard> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;
    }
    // Safe unconditionally: the instance lock guarantees no live owner.
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket)
        .with_context(|| format!("Failed to bind control socket {}", socket.display()))?;
    // Owner-only: this channel accepts mutations.
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set permissions on {}", socket.display()))?;
    log::info!("Control socket listening on {}", socket.display());

    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let tx = tx.clone();
                    tokio::spawn(serve_connection(stream, tx));
                }
                Err(e) => {
                    log::warn!("Control socket accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
    Ok(IpcServerGuard { task, socket })
}

#[cfg(windows)]
fn spawn_pipe(name: String, tx: mpsc::Sender<IpcCmd>) -> Result<IpcServerGuard> {
    use tokio::net::windows::named_pipe::ServerOptions;

    // `first_pipe_instance` makes creation fail if another process already
    // owns the name — defense in depth on top of the instance lock.
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .with_context(|| format!("Failed to create control pipe {name}"))?;
    log::info!("Control pipe listening on {name}");

    let task = tokio::spawn(async move {
        loop {
            if let Err(e) = server.connect().await {
                log::warn!("Control pipe connect failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            // Create the next pipe instance *before* serving the connected one
            // so the name never briefly disappears for a concurrent attacher.
            // A transient creation failure must not disable IPC for the rest
            // of the session — retry until it succeeds (the guard aborts this
            // task on shutdown, which bounds the loop).
            let next = loop {
                match ServerOptions::new().create(&name) {
                    Ok(next) => break next,
                    Err(e) => {
                        log::warn!("Failed to re-create control pipe {name}: {e}; retrying");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            };
            let conn = std::mem::replace(&mut server, next);
            tokio::spawn(serve_connection(conn, tx.clone()));
        }
    });
    Ok(IpcServerGuard { task })
}

/// Serve one attached `client control`: read a JSON-line request, forward it to
/// the session loop, write the JSON-line response; repeat until EOF. A
/// malformed line gets `Response::Error` and the connection stays open; a
/// closed session channel ends the connection.
async fn serve_connection<S>(stream: S, tx: mpsc::Sender<IpcCmd>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufReader::new(stream);
    let mut line = Vec::new();
    loop {
        line.clear();
        match read_line_capped(&mut stream, &mut line).await {
            Ok(0) => return, // EOF: the TUI detached.
            Ok(_) => {}
            Err(e) => {
                log::debug!("Control connection read failed: {e}");
                return;
            }
        }

        let response = match serde_json::from_slice::<Request>(&line) {
            Ok(request) => match dispatch(request, &tx).await {
                Some(response) => response,
                None => return, // Session loop gone: client is shutting down.
            },
            Err(e) => Response::Error {
                message: format!("Bad request: {e}"),
            },
        };

        let mut buf = match serde_json::to_vec(&response) {
            Ok(buf) => buf,
            Err(e) => {
                log::warn!("Failed to encode control response: {e}");
                return;
            }
        };
        buf.push(b'\n');
        if let Err(e) = stream.get_mut().write_all(&buf).await {
            log::debug!("Control connection write failed: {e}");
            return;
        }
    }
}

async fn dispatch(request: Request, tx: &mpsc::Sender<IpcCmd>) -> Option<Response> {
    let (cmd, pending) = build_cmd(request);
    tx.send(cmd).await.ok()?;
    pending.into_response().await
}

/// Run one request against the session loop over the in-process command channel,
/// blocking the current thread for the reply. Used by the self-contained quick
/// panel (`client start --quick`), which drives its own session directly instead
/// of over a socket. Returns `None` once the session loop is gone (its receiver
/// dropped, or the reply sender dropped), which signals the panel to exit.
pub fn blocking_request(tx: &mpsc::Sender<IpcCmd>, request: Request) -> Option<Response> {
    let (cmd, pending) = build_cmd(request);
    tx.blocking_send(cmd).ok()?;
    pending.blocking_into_response()
}

/// The reply half of an [`IpcCmd`], kept separate from sending it so the command
/// can be awaited either async (the socket accept loop) or blocking (the
/// in-process quick panel) while the request → command mapping stays in one
/// place ([`build_cmd`]).
enum PendingReply {
    Status(oneshot::Receiver<StatusSnapshot>),
    ConnPath(oneshot::Receiver<WireConnSnapshot>),
    Mutate(oneshot::Receiver<Result<StatusSnapshot, String>>),
}

impl PendingReply {
    async fn into_response(self) -> Option<Response> {
        Some(match self {
            PendingReply::Status(rx) => Response::Status(Box::new(rx.await.ok()?)),
            PendingReply::ConnPath(rx) => Response::ConnPath(rx.await.ok()?),
            PendingReply::Mutate(rx) => reply_to_response(rx.await.ok()?),
        })
    }

    fn blocking_into_response(self) -> Option<Response> {
        Some(match self {
            PendingReply::Status(rx) => Response::Status(Box::new(rx.blocking_recv().ok()?)),
            PendingReply::ConnPath(rx) => Response::ConnPath(rx.blocking_recv().ok()?),
            PendingReply::Mutate(rx) => reply_to_response(rx.blocking_recv().ok()?),
        })
    }
}

fn reply_to_response(reply: Result<StatusSnapshot, String>) -> Response {
    match reply {
        Ok(snapshot) => Response::Status(Box::new(snapshot)),
        Err(message) => Response::Error { message },
    }
}

fn build_cmd(request: Request) -> (IpcCmd, PendingReply) {
    match request {
        Request::Status => {
            let (reply, rx) = oneshot::channel();
            (IpcCmd::Status(reply), PendingReply::Status(rx))
        }
        Request::ConnPath => {
            let (reply, rx) = oneshot::channel();
            (IpcCmd::ConnPath(reply), PendingReply::ConnPath(rx))
        }
        Request::AddForward { forward } => mutate_cmd(Mutation::Add(forward)),
        Request::UpdateForward { forward } => mutate_cmd(Mutation::Update(forward)),
        Request::DeleteForward { id } => mutate_cmd(Mutation::Delete(id)),
        Request::SetForwardEnabled { id, enabled } => mutate_cmd(Mutation::SetEnabled(id, enabled)),
    }
}

fn mutate_cmd(mutation: Mutation) -> (IpcCmd, PendingReply) {
    let (reply, rx) = oneshot::channel();
    (IpcCmd::Mutate(mutation, reply), PendingReply::Mutate(rx))
}

/// Read one `\n`-terminated line into `buf`, rejecting lines over [`MAX_LINE`]
/// (`read_line` alone would buffer without bound). Returns the number of bytes
/// read (0 on clean EOF); the trailing newline is stripped.
async fn read_line_capped<R>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<usize>
where
    R: AsyncBufRead + Unpin,
{
    let mut total = 0usize;
    loop {
        let read = (&mut *reader)
            .take((MAX_LINE + 1 - buf.len()) as u64)
            .read_until(b'\n', buf)
            .await?;
        total += read;
        if read == 0 || buf.last() == Some(&b'\n') {
            while matches!(buf.last(), Some(b'\n') | Some(b'\r')) {
                buf.pop();
            }
            return Ok(total);
        }
        if buf.len() > MAX_LINE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "control message exceeds the 1 MiB line cap",
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Client side (used by `flextunnel client control`)
// ---------------------------------------------------------------------------

#[cfg(unix)]
type ClientStream = tokio::net::UnixStream;
#[cfg(windows)]
type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

pub struct IpcClient {
    /// Kept so a request that had to discard its stream (see [`request`]) can
    /// reconnect on the next call.
    ///
    /// [`request`]: IpcClient::request
    key: String,
    /// `None` after a timed-out request left a half-consumed response on the
    /// wire; the next request reconnects before sending.
    stream: Option<BufReader<ClientStream>>,
}

impl IpcClient {
    /// Connect to the running client for the given instance key. `Ok(None)`
    /// means nothing is listening — the client is not running.
    pub async fn connect(key: &str) -> Result<Option<Self>> {
        match tokio::time::timeout(REQUEST_TIMEOUT, Self::open(key)).await {
            Ok(Ok(stream)) => Ok(Some(Self {
                key: key.to_string(),
                stream: Some(BufReader::new(stream)),
            })),
            Ok(Err(e)) if is_not_running(&e) => Ok(None),
            Ok(Err(e)) => Err(e).context("Failed to connect to the control socket"),
            Err(_) => anyhow::bail!("Timed out connecting to the control socket"),
        }
    }

    #[cfg(unix)]
    async fn open(key: &str) -> std::io::Result<ClientStream> {
        let path = socket_path(key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        tokio::net::UnixStream::connect(path).await
    }

    #[cfg(windows)]
    async fn open(key: &str) -> std::io::Result<ClientStream> {
        use tokio::net::windows::named_pipe::ClientOptions;

        const ERROR_PIPE_BUSY: i32 = 231;
        let name = pipe_name(key);
        // All pipe instances can be momentarily busy between one attacher
        // connecting and the server pre-creating the next instance; retry
        // briefly (the outer connect() timeout still bounds the wait).
        loop {
            match ClientOptions::new().open(&name) {
                Ok(stream) => return Ok(stream),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// One request → response round trip, bounded by [`REQUEST_TIMEOUT`].
    ///
    /// On timeout the stream is discarded rather than reused: a response may
    /// still be in flight, and pairing it with the *next* request would return
    /// a stale answer. The next call reconnects through [`Self::open`] first.
    pub async fn request(&mut self, request: &Request) -> Result<Response> {
        if self.stream.is_none() {
            self.reconnect().await?;
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, self.round_trip(request)).await {
            Ok(result) => result,
            Err(_) => {
                self.stream = None;
                Err(anyhow::anyhow!("Timed out waiting for the client's response"))
            }
        }
    }

    /// Re-establish the connection after a prior request discarded its stream.
    async fn reconnect(&mut self) -> Result<()> {
        match tokio::time::timeout(REQUEST_TIMEOUT, Self::open(&self.key)).await {
            Ok(Ok(stream)) => {
                self.stream = Some(BufReader::new(stream));
                Ok(())
            }
            Ok(Err(e)) => Err(e).context("Failed to reconnect to the control socket"),
            Err(_) => anyhow::bail!("Timed out reconnecting to the control socket"),
        }
    }

    async fn round_trip(&mut self, request: &Request) -> Result<Response> {
        let stream = self
            .stream
            .as_mut()
            .expect("stream reconnected before round_trip");
        let mut buf = serde_json::to_vec(request)?;
        buf.push(b'\n');
        stream.get_mut().write_all(&buf).await?;

        let mut line = Vec::new();
        let read = read_line_capped(stream, &mut line).await?;
        if read == 0 {
            anyhow::bail!("The client closed the control connection");
        }
        serde_json::from_slice(&line).context("Malformed control response")
    }
}

fn is_not_running(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_forward() -> WireForward {
        WireForward {
            id: "f1".into(),
            label: "db".into(),
            local_port: 5432,
            remote_host: "db.internal".into(),
            remote_port: 5432,
            enabled: true,
        }
    }

    fn snapshot() -> StatusSnapshot {
        StatusSnapshot {
            instance: "62e463a6d67fdeac".into(),
            name: Some("aws".into()),
            phase: Phase::Connected,
            connected_secs: Some(61),
            server_node_id: "server".into(),
            client_node_id: "client".into(),
            socks_addr: Some("127.0.0.1:1080".parse().unwrap()),
            http_addr: None,
            status_page_host: "flextunnel.internal".into(),
            last_error: None,
            routes: WireRoutes {
                domains: vec!["*.internal".into()],
                cidrs: vec![],
                host_aliases: vec![("nas.internal".into(), "10.0.0.7".into())],
                dns_forwards: vec![("test.example".into(), vec!["10.22.33.10".into()])],
                bridges: vec![WireBridge {
                    name: "kube1".into(),
                    endpoint_id: "abc".into(),
                    domains: vec!["*.svc".into()],
                    cidrs: vec![],
                }],
            },
            forwards: vec![ForwardRow {
                forward: wire_forward(),
                state: ForwardRowState::Listening,
                error: None,
                active: 2,
                last_conn_error: None,
            }],
        }
    }

    #[test]
    fn wire_types_roundtrip() {
        for request in [
            Request::Status,
            Request::ConnPath,
            Request::AddForward {
                forward: wire_forward(),
            },
            Request::UpdateForward {
                forward: wire_forward(),
            },
            Request::DeleteForward { id: "f1".into() },
            Request::SetForwardEnabled {
                id: "f1".into(),
                enabled: false,
            },
        ] {
            let json = serde_json::to_string(&request).unwrap();
            let _: Request = serde_json::from_str(&json).unwrap();
        }

        let json = serde_json::to_string(&Response::Status(Box::new(snapshot()))).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        match back {
            Response::Status(s) => {
                assert_eq!(s.phase, Phase::Connected);
                assert_eq!(s.forwards.len(), 1);
                // The wire carries `enabled` even though the model's serde skips it.
                assert!(s.forwards[0].forward.enabled);
                assert_eq!(s.forwards[0].state, ForwardRowState::Listening);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// Stub session loop: answers Status with a canned snapshot, accepts
    /// SetEnabled, rejects Delete.
    fn stub_session() -> mpsc::Sender<IpcCmd> {
        let (tx, mut rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    IpcCmd::Status(reply) => {
                        let _ = reply.send(snapshot());
                    }
                    IpcCmd::ConnPath(reply) => {
                        let _ = reply.send(WireConnSnapshot {
                            paths: vec![WireConnPath {
                                kind: "direct".into(),
                                display: "Direct 1.2.3.4:52186 (rtt 1ms)".into(),
                                selected: true,
                            }],
                            custom_relays: vec![WireCustomRelay {
                                url: "https://relay.example/".into(),
                                working: Some(true),
                                error: None,
                            }],
                        });
                    }
                    IpcCmd::Mutate(Mutation::Delete(id), reply) => {
                        let _ = reply.send(Err(format!("no forward with id {id:?}")));
                    }
                    IpcCmd::Mutate(_, reply) => {
                        let _ = reply.send(Ok(snapshot()));
                    }
                }
            }
        });
        tx
    }

    /// Spin up the real platform transport (UDS here, named pipe on Windows)
    /// against the stub session and drive it through the real `IpcClient`.
    #[tokio::test]
    async fn loopback_status_and_mutations() {
        // Unique per test run: instance names (and thus pipe names on
        // Windows) are global, and parallel `cargo test` runs must not collide.
        let instance = format!("test-ipc-{}", std::process::id());

        #[cfg(unix)]
        let (_dir, guard) = {
            // Keep the socket out of the real ~/.config: bind at a temp path
            // through the same internal entry point the public API uses.
            let dir = tempfile::tempdir().unwrap();
            let guard = spawn_unix(dir.path().join(format!("client-{instance}.sock")), stub_session())
                .unwrap();
            (dir, guard)
        };
        #[cfg(windows)]
        let guard = spawn_pipe(pipe_name(&instance), stub_session()).unwrap();

        #[cfg(unix)]
        let mut client = {
            let path = _dir.path().join(format!("client-{instance}.sock"));
            IpcClient {
                key: instance.clone(),
                stream: Some(BufReader::new(
                    tokio::net::UnixStream::connect(path).await.unwrap(),
                )),
            }
        };
        #[cfg(windows)]
        let mut client = IpcClient::connect(&instance).await.unwrap().expect("running");

        // Status.
        match client.request(&Request::Status).await.unwrap() {
            Response::Status(s) => {
                assert_eq!(s.instance, "62e463a6d67fdeac");
                assert_eq!(s.name.as_deref(), Some("aws"));
            }
            other => panic!("expected Status, got {other:?}"),
        }

        // A mutation that the session accepts returns a fresh snapshot...
        match client
            .request(&Request::SetForwardEnabled {
                id: "f1".into(),
                enabled: false,
            })
            .await
            .unwrap()
        {
            Response::Status(_) => {}
            other => panic!("expected Status, got {other:?}"),
        }

        // ...and one it rejects surfaces the message, keeping the connection open.
        match client
            .request(&Request::DeleteForward { id: "nope".into() })
            .await
            .unwrap()
        {
            Response::Error { message } => assert!(message.contains("nope"), "{message}"),
            other => panic!("expected Error, got {other:?}"),
        }
        match client.request(&Request::Status).await.unwrap() {
            Response::Status(_) => {}
            other => panic!("expected Status, got {other:?}"),
        }

        drop(guard);
    }

    #[tokio::test]
    async fn not_running_is_none() {
        // No client is serving this instance name.
        let missing = format!("test-missing-{}", std::process::id());
        assert!(IpcClient::connect(&missing).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_line_is_rejected() {
        let mut input = vec![b'a'; MAX_LINE + 10];
        input.push(b'\n');
        let mut reader = BufReader::new(std::io::Cursor::new(input));
        let mut buf = Vec::new();
        let err = read_line_capped(&mut reader, &mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn capped_reader_handles_lines_and_eof() {
        let mut reader = BufReader::new(std::io::Cursor::new(b"hello\nworld".to_vec()));
        let mut buf = Vec::new();
        assert_eq!(read_line_capped(&mut reader, &mut buf).await.unwrap(), 6);
        assert_eq!(buf, b"hello");
        buf.clear();
        // Final unterminated chunk, then clean EOF.
        assert_eq!(read_line_capped(&mut reader, &mut buf).await.unwrap(), 5);
        assert_eq!(buf, b"world");
        buf.clear();
        assert_eq!(read_line_capped(&mut reader, &mut buf).await.unwrap(), 0);
    }
}
