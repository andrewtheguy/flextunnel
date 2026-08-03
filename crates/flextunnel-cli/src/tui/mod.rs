//! The ratatui control panel — status (connection, routing, connection paths)
//! plus editable port forwards — reachable two ways over the same UI:
//!
//! - `flextunnel client control`: attaches to a *running* client over its
//!   control socket (see `ipc.rs`), as a separate process. Detaching (q) never
//!   affects the tunnel; the panel can re-attach any time, and several panels
//!   can attach at once. This is the [`IpcBackend`] path.
//! - `flextunnel client start --quick`: a *self-contained* session in this same
//!   process, driven over an in-process channel with no socket. Quitting (q)
//!   tears the session down — the tunnel disconnects. This is the
//!   [`InProcessBackend`] path (entry point [`run_quick_panel`]).
//!
//! Either way the panel runs a plain blocking event loop with per-request
//! round trips to a [`ControlBackend`]. This deliberately avoids crossterm's
//! `EventStream` so no separate crossterm dependency (with version-sync risk
//! against ratatui's re-export) is needed.

mod form;
mod view;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use flextunnel_core::config;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use tokio::sync::mpsc;

use crate::instance;
use crate::ipc::{IpcClient, IpcCmd, Request, Response, StatusSnapshot, WireConnSnapshot};
use form::{FIELD_ENABLED, FormState};

/// The panel's transport to a client session: one request → one response,
/// blocking the UI thread. Implemented over the control socket (a separate
/// `client control` process) and over an in-process channel (the self-contained
/// `client start --quick` session).
trait ControlBackend {
    fn request(&mut self, request: Request) -> Result<Response>;
}

/// Socket transport: a current-thread runtime driving the async [`IpcClient`]
/// (each round trip bounded by the 2 s request timeout).
struct IpcBackend {
    rt: tokio::runtime::Runtime,
    client: IpcClient,
}

impl ControlBackend for IpcBackend {
    fn request(&mut self, request: Request) -> Result<Response> {
        self.rt.block_on(self.client.request(&request))
    }
}

/// In-process transport for the self-contained quick panel: drives the client
/// session running in this process over its command channel. A closed channel
/// (the session ended) surfaces as an error, which ends the panel loop; dropping
/// this backend on quit drops the sender, which tears the session down.
struct InProcessBackend {
    tx: mpsc::Sender<IpcCmd>,
}

impl ControlBackend for InProcessBackend {
    fn request(&mut self, request: Request) -> Result<Response> {
        crate::ipc::blocking_request(&self.tx, request).context("the tunnel session ended")
    }
}

/// How often the panel polls the client for a fresh snapshot.
const REFRESH: Duration = Duration::from_secs(1);

enum Mode {
    Normal,
    Form(FormState),
    ConfirmDelete { id: String, name: String },
    /// On-demand connection-path overlay: a point-in-time snapshot (paths +
    /// custom-relay health) captured when opened, refreshable, not polled —
    /// mirrors the desktop modal.
    ConnPath(WireConnSnapshot),
}

struct App {
    snapshot: StatusSnapshot,
    /// Selected row in the forwards table.
    selected: usize,
    routing_scroll: u16,
    mode: Mode,
    /// Transient error line (e.g. a rejected toggle), cleared on next input.
    notice: Option<String>,
}

pub fn run(config_path: Option<PathBuf>, server_node_id: Option<String>) -> Result<()> {
    // The running client is identified by the profile's server node id
    // (-n wins over the config file; bare `client control` reads the default
    // config), from which the same instance key as the client's is derived.
    // With -n and no -c, identify purely by server id (skip the config load).
    let file = if server_node_id.is_some() && config_path.is_none() {
        None
    } else {
        config::load_client_config(config_path.as_deref())
            .context("client control needs a profile: -c <file>, the default config, or -n <server id>")?
    };
    let cli = config::ClientConfig {
        server_node_id,
        ..Default::default()
    };
    let r = config::resolve_client(cli, file);
    let server_id = r.server_node_id.context(
        "The profile has no server node id (set server_node_id in the config or pass -n).",
    )?;
    let key = instance::instance_key(&server_id)?;
    let profile = r.name.unwrap_or_else(|| format!("server {key}…"));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let Some(client) = rt.block_on(IpcClient::connect(&key))? else {
        eprintln!("The flextunnel client for {profile} is not running.");
        std::process::exit(1);
    };
    let mut backend = IpcBackend { rt, client };
    // First snapshot before touching terminal modes, so early failures print
    // as ordinary errors.
    let snapshot = request_snapshot(&mut backend, Request::Status)?;

    let app = App::new(snapshot);
    run_panel(app, &mut backend).context("Lost the connection to the client (did it stop?)")
}

/// Run the self-contained control panel for `client start --quick`: the same UI
/// as `client control`, but driving the session in this process over `tx`
/// instead of a socket. Quitting (q/Esc/Ctrl-C) returns, dropping `tx` — which
/// tears the session down, so the tunnel disconnects rather than detaching.
pub fn run_quick_panel(tx: mpsc::Sender<IpcCmd>, initial: StatusSnapshot) -> Result<()> {
    let mut backend = InProcessBackend { tx };
    run_panel(App::new(initial), &mut backend)
}

/// Drive the panel's event loop against `backend`, bracketing it with terminal
/// setup/teardown. `ratatui::init` installs a panic hook that restores the
/// terminal first — required under the workspace's `panic = "abort"` release
/// profile, where no unwinding drop guard would run.
fn run_panel(mut app: App, backend: &mut dyn ControlBackend) -> Result<()> {
    let mut terminal = ratatui::init();
    let res = app.run(&mut terminal, backend);
    ratatui::restore();
    res
}

fn request_snapshot(backend: &mut dyn ControlBackend, request: Request) -> Result<StatusSnapshot> {
    match backend.request(request)? {
        Response::Status(snapshot) => Ok(*snapshot),
        Response::Error { message } => anyhow::bail!("{message}"),
        Response::ConnPath(_) => anyhow::bail!("unexpected conn-path response to a status request"),
    }
}

impl App {
    fn new(snapshot: StatusSnapshot) -> Self {
        App {
            snapshot,
            selected: 0,
            routing_scroll: 0,
            mode: Mode::Normal,
            notice: None,
        }
    }

    fn run(
        &mut self,
        terminal: &mut ratatui::DefaultTerminal,
        backend: &mut dyn ControlBackend,
    ) -> Result<()> {
        let mut last_refresh = Instant::now();
        loop {
            terminal.draw(|frame| view::draw(frame, self))?;

            let timeout = REFRESH
                .saturating_sub(last_refresh.elapsed())
                .min(Duration::from_millis(250));
            if event::poll(timeout)?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                self.notice = None;
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('c')
                {
                    return Ok(());
                }
                let quit = match &mut self.mode {
                    Mode::Normal => self.handle_normal_key(key.code, backend)?,
                    Mode::Form(_) => {
                        self.handle_form_key(key.code, backend)?;
                        false
                    }
                    Mode::ConfirmDelete { .. } => {
                        self.handle_confirm_key(key.code, backend)?;
                        false
                    }
                    Mode::ConnPath(_) => {
                        self.handle_conn_path_key(key.code, backend)?;
                        false
                    }
                };
                if quit {
                    return Ok(());
                }
            }

            if last_refresh.elapsed() >= REFRESH {
                // Poll-based refresh, like the desktop's ticker. Mutations
                // also refresh inline via the returned snapshot.
                self.set_snapshot(request_snapshot(backend, Request::Status)?);
                last_refresh = Instant::now();
            }
        }
    }

    fn set_snapshot(&mut self, snapshot: StatusSnapshot) {
        // Follow the selected forward by its stable id across the refresh: a
        // row added or removed above it shifts the index, so clamping alone
        // would silently move the selection to a different forward.
        let selected_id = self
            .selected_forward()
            .map(|row| row.forward.id.clone());
        self.snapshot = snapshot;
        self.selected = selected_id
            .and_then(|id| self.snapshot.forwards.iter().position(|r| r.forward.id == id))
            .unwrap_or_else(|| self.selected.min(self.snapshot.forwards.len().saturating_sub(1)));
    }

    /// Send a mutation; a fresh snapshot means success, an error message is
    /// returned for the caller to surface (form line or footer notice).
    fn mutate(
        &mut self,
        backend: &mut dyn ControlBackend,
        request: Request,
    ) -> Result<Option<String>> {
        match backend.request(request)? {
            Response::Status(snapshot) => {
                self.set_snapshot(*snapshot);
                Ok(None)
            }
            Response::Error { message } => Ok(Some(message)),
            Response::ConnPath(_) => Ok(Some("unexpected conn-path response".to_string())),
        }
    }

    fn selected_forward(&self) -> Option<&crate::ipc::ForwardRow> {
        self.snapshot.forwards.get(self.selected)
    }

    fn handle_normal_key(
        &mut self,
        code: KeyCode,
        backend: &mut dyn ControlBackend,
    ) -> Result<bool> {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = (self.selected + 1)
                    .min(self.snapshot.forwards.len().saturating_sub(1));
            }
            KeyCode::Char('[') | KeyCode::PageUp => {
                self.routing_scroll = self.routing_scroll.saturating_sub(3);
            }
            KeyCode::Char(']') | KeyCode::PageDown => {
                // Clamped against the content height at render time.
                self.routing_scroll = self.routing_scroll.saturating_add(3);
            }
            KeyCode::Char('a') => self.mode = Mode::Form(FormState::add()),
            KeyCode::Char('e') | KeyCode::Enter => {
                if let Some(row) = self.selected_forward() {
                    self.mode = Mode::Form(FormState::edit(&row.forward));
                }
            }
            KeyCode::Char('d') => {
                if let Some(row) = self.selected_forward() {
                    self.mode = Mode::ConfirmDelete {
                        id: row.forward.id.clone(),
                        name: form::display_name(&row.forward),
                    };
                }
            }
            KeyCode::Char(' ') => {
                if let Some(row) = self.selected_forward() {
                    let request = Request::SetForwardEnabled {
                        id: row.forward.id.clone(),
                        enabled: !row.forward.enabled,
                    };
                    self.notice = self.mutate(backend, request)?;
                }
            }
            // On-demand connection-path + custom-relay-health overlay (not polled).
            KeyCode::Char('p') => match self.request_conn_path(backend)? {
                Ok(snapshot) => self.mode = Mode::ConnPath(snapshot),
                Err(message) => self.notice = Some(message),
            },
            _ => {}
        }
        Ok(false)
    }

    /// Fetch an on-demand connection snapshot. The outer `Result` is a transport
    /// failure (ends the loop); the inner is a session-reported error to surface
    /// as a footer notice.
    fn request_conn_path(
        &mut self,
        backend: &mut dyn ControlBackend,
    ) -> Result<std::result::Result<WireConnSnapshot, String>> {
        Ok(match backend.request(Request::ConnPath)? {
            Response::ConnPath(snapshot) => Ok(snapshot),
            Response::Error { message } => Err(message),
            Response::Status(_) => Err("unexpected status response".to_string()),
        })
    }

    fn handle_conn_path_key(
        &mut self,
        code: KeyCode,
        backend: &mut dyn ControlBackend,
    ) -> Result<()> {
        match code {
            // Re-probe in place (paths + relay /healthz).
            KeyCode::Char('r') => match self.request_conn_path(backend)? {
                Ok(snapshot) => self.mode = Mode::ConnPath(snapshot),
                Err(message) => {
                    self.notice = Some(message);
                    self.mode = Mode::Normal;
                }
            },
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => self.mode = Mode::Normal,
            _ => {}
        }
        Ok(())
    }

    fn handle_form_key(
        &mut self,
        code: KeyCode,
        backend: &mut dyn ControlBackend,
    ) -> Result<()> {
        let Mode::Form(form) = &mut self.mode else {
            return Ok(());
        };
        match code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Tab | KeyCode::Down => form.focus_next(),
            KeyCode::BackTab | KeyCode::Up => form.focus_prev(),
            KeyCode::Enter => {
                match form.validate(&self.snapshot.forwards) {
                    Err(message) => form.error = Some(message),
                    Ok(forward) => {
                        let request = if form.is_edit() {
                            Request::UpdateForward { forward }
                        } else {
                            Request::AddForward { forward }
                        };
                        match self.mutate(backend, request)? {
                            // The running client rejected it (it re-validates
                            // authoritatively): keep the form open.
                            Some(message) => {
                                if let Mode::Form(form) = &mut self.mode {
                                    form.error = Some(message);
                                }
                            }
                            None => self.mode = Mode::Normal,
                        }
                    }
                }
            }
            KeyCode::Char(' ') if form.focus == FIELD_ENABLED => form.enabled = !form.enabled,
            KeyCode::Char(c) => {
                if let Some(text) = form.focused_text() {
                    text.push(c);
                }
            }
            KeyCode::Backspace => {
                if let Some(text) = form.focused_text() {
                    text.pop();
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_confirm_key(
        &mut self,
        code: KeyCode,
        backend: &mut dyn ControlBackend,
    ) -> Result<()> {
        let Mode::ConfirmDelete { id, .. } = &self.mode else {
            return Ok(());
        };
        match code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let request = Request::DeleteForward { id: id.clone() };
                self.mode = Mode::Normal;
                self.notice = self.mutate(backend, request)?;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => self.mode = Mode::Normal,
            _ => {}
        }
        Ok(())
    }
}
