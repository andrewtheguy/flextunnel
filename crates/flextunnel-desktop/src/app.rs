//! The iced daemon state machine: a sidebar of connection profiles plus a
//! detail pane, driven alongside the system tray. Each profile can run its own
//! tunnel session concurrently (its optional proxy ports and direct forwards).
//! The daemon
//! owns all state, so closing the window (which destroys it) loses nothing —
//! the tray re-opens it on demand. Tray/menu events are forwarded from
//! tray-icon's handlers into a channel drained by a [`Subscription`], so a
//! tray click wakes the runtime even while no window exists; a 500 ms tick
//! keeps the snapshots and the tray state fresh the rest of the time.

use crate::config::{self, Profile, DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT};
use flextunnel_core::forwards::{
    PortForward, disable_failed_forwards, parse_port, validate_label, validate_remote_host,
};
use crate::icon;
use crate::logging;
use crate::tray::{self, Tray};
use crate::tunnel::{Controller, Phase, ProfileId, Snapshot};
use crate::view;
use flextunnel_core::transport::paths::ConnectionSnapshot;
use iced::futures::Stream;
use iced::{window, Element, Size, Subscription, Task};
use std::collections::HashMap;
use std::time::Duration;
use tray_icon::menu::MenuEvent;
use tray_icon::TrayIconEvent;

/// What the detail pane shows (the sidebar's selected row).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Selection {
    Profile(ProfileId),
    Logs,
}

#[derive(Debug, Clone)]
pub enum Message {
    Tick,
    SetupTray,
    TrayMenu(String),
    TrayIcon(TrayIconEvent),
    WindowOpened,
    WindowClosed(window::Id),
    Select(Selection),
    CopyText(String),
    /// Fetch the current iroh connection path (relay/direct) once and open the
    /// modal showing it.
    ShowConnPath,
    /// Close the connection-path modal.
    DismissConnPath,
    // Profiles
    AddProfile,
    EditProfile(ProfileId),
    DeleteProfile(ProfileId),
    Connect(ProfileId),
    Disconnect(ProfileId),
    ExportProfiles,
    ImportProfiles,
    ExportPicked(Option<std::path::PathBuf>),
    ImportPicked(Option<std::path::PathBuf>),
    // Profile form
    ProfileNameChanged(String),
    ServerNodeIdChanged(String),
    AuthKeyChanged(String),
    /// Fill the form's auth-key field with a freshly generated keypair.
    GenerateAuthKey,
    SocksEnabledToggled(bool),
    SocksPortChanged(String),
    HttpEnabledToggled(bool),
    HttpPortChanged(String),
    RelayUrlsChanged(String),
    RelayAuthTokenChanged(String),
    ProfileFormSave,
    ProfileFormCancel,
    // Forwards
    AddForward(ProfileId),
    EditForward(ProfileId, String),
    DeleteForward(ProfileId, String),
    ToggleForward(ProfileId, String, bool),
    FormLabelChanged(String),
    FormLocalPortChanged(String),
    FormRemoteHostChanged(String),
    FormRemotePortChanged(String),
    FormEnabledToggled(bool),
    FormSave,
    FormCancel,
    // Logs
    LogFilterChanged(String),
    OpenLogFolder,
    CopyLogs,
}

/// Sentinel option shown in the Logs pane's profile filter.
pub const LOG_FILTER_ALL: &str = "All profiles";

/// Human description of what already occupies a local port, across every
/// profile — profiles can run concurrently, so all local ports share one
/// namespace. `exclude_profile` skips that profile's proxy ports (its own
/// form edits them); `exclude_forward` skips the forward being edited.
fn port_owner(
    profiles: &[Profile],
    port: u16,
    exclude_profile: Option<&str>,
    exclude_forward: Option<&str>,
) -> Option<String> {
    for profile in profiles {
        if Some(profile.id.as_str()) != exclude_profile {
            if profile.socks_port == Some(port) {
                return Some(format!("the SOCKS5 port of profile \"{}\"", profile.name));
            }
            if profile.http_port == Some(port) {
                return Some(format!("the HTTP port of profile \"{}\"", profile.name));
            }
        }
        for forward in &profile.forwards {
            if Some(forward.id.as_str()) == exclude_forward {
                continue;
            }
            if forward.local_port == port {
                return Some(format!(
                    "forward \"{}\" in profile \"{}\"",
                    forward.display_name(),
                    profile.name
                ));
            }
        }
    }
    None
}

/// `desired` if no other profile (than `own_id`) uses it, else the first free
/// "desired - 2", "desired - 3", … The base is shortened if a suffix would
/// push past the 64-character name limit.
fn unique_name(profiles: &[Profile], desired: String, own_id: Option<&str>) -> String {
    let taken = |name: &str| {
        profiles
            .iter()
            .any(|p| p.name == name && Some(p.id.as_str()) != own_id)
    };
    if !taken(&desired) {
        return desired;
    }
    (2..)
        .map(|n| {
            let suffix = format!(" - {n}");
            let mut base = desired.clone();
            while base.len() + suffix.len() > 64 {
                base.pop();
            }
            format!("{}{suffix}", base.trim_end())
        })
        .find(|candidate| !taken(candidate))
        .expect("some numbered name is free")
}

/// Merge an imported (already structurally validated) profile list into the
/// current one. A matching server node id replaces that profile's settings
/// and forwards but keeps its id and both secrets (auth key and relay auth
/// token); anything else is added as a new profile with a fresh id and no
/// secrets — imports never carry them. Colliding names get a " - N" suffix,
/// and imported forwards get fresh ids so they stay globally unique. Returns
/// `(added, replaced-profile ids)`.
fn merge_imported(
    profiles: &mut Vec<Profile>,
    imported: Vec<Profile>,
) -> (usize, Vec<ProfileId>) {
    let mut added = 0;
    let mut replaced = Vec::new();
    for mut incoming in imported {
        for forward in &mut incoming.forwards {
            forward.id = PortForward::new_id();
        }
        match profiles
            .iter()
            .position(|p| p.server_node_id == incoming.server_node_id)
        {
            Some(pos) => {
                incoming.id = profiles[pos].id.clone();
                incoming.auth_key = profiles[pos].auth_key.clone();
                incoming.relay_auth_token = profiles[pos].relay_auth_token.clone();
                incoming.name = unique_name(profiles, incoming.name, Some(&incoming.id));
                profiles[pos] = incoming;
                replaced.push(profiles[pos].id.clone());
            }
            None => {
                incoming.id = Profile::new_id();
                incoming.auth_key = String::new();
                incoming.relay_auth_token = None;
                incoming.name = unique_name(profiles, incoming.name, None);
                profiles.push(incoming);
                added += 1;
            }
        }
    }
    (added, replaced)
}

/// First port from the default upward not used by any profile or forward, as
/// the suggested SOCKS5 port for a new profile.
fn next_free_port(profiles: &[Profile]) -> u16 {
    let mut port = DEFAULT_SOCKS_PORT;
    while port_owner(profiles, port, None, None).is_some() && port < u16::MAX {
        port += 1;
    }
    port
}

/// Editable profile buffers (the add/edit form). `editing_id` is `None` when
/// adding.
#[derive(Default)]
pub struct ProfileForm {
    editing_id: Option<ProfileId>,
    pub name: String,
    pub server_node_id: String,
    pub auth_key: String,
    pub socks_enabled: bool,
    pub socks_port: String,
    pub http_enabled: bool,
    pub http_port: String,
    pub relay_urls: String,
    pub relay_auth_token: String,
}

impl ProfileForm {
    pub fn is_edit(&self) -> bool {
        self.editing_id.is_some()
    }

    /// The public key derived from the form's auth key, when it parses. The
    /// public half is never a secret — the UI shows it unmasked so it can be
    /// copied onto the server's authorized-keys file.
    pub fn public_key(&self) -> Option<String> {
        flextunnel_core::auth::ClientKey::from_secret_str(self.auth_key.trim())
            .ok()
            .map(|key| key.public_str())
    }

    fn add(profiles: &[Profile]) -> Self {
        Self {
            socks_enabled: true,
            socks_port: next_free_port(profiles).to_string(),
            http_port: DEFAULT_HTTP_PORT.to_string(),
            ..Self::default()
        }
    }

    fn edit(profile: &Profile) -> Self {
        Self {
            editing_id: Some(profile.id.clone()),
            name: profile.name.clone(),
            server_node_id: profile.server_node_id.clone(),
            auth_key: profile.auth_key.clone(),
            socks_enabled: profile.socks_port.is_some(),
            socks_port: profile
                .socks_port
                .map(|port| port.to_string())
                .unwrap_or_else(|| DEFAULT_SOCKS_PORT.to_string()),
            http_enabled: profile.http_port.is_some(),
            http_port: profile
                .http_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| DEFAULT_HTTP_PORT.to_string()),
            relay_urls: profile.relay_urls.join(", "),
            relay_auth_token: profile.relay_auth_token.clone().unwrap_or_default(),
        }
    }

    pub fn validate(&self, profiles: &[Profile]) -> Result<Profile, String> {
        // Normalize into the stored shape (see `Profile::is_valid_name`):
        // words separated by single spaces, nothing leading or trailing.
        let name = self.name.split_whitespace().collect::<Vec<_>>().join(" ");
        if name.is_empty() {
            return Err("Profile name is required".into());
        }
        if name.len() > 64 {
            return Err("Profile name must be 64 characters or fewer".into());
        }
        // Unique names keep the tray submenus and the per-profile log
        // attribution (thread names) unambiguous.
        if profiles
            .iter()
            .any(|p| p.name == name && Some(p.id.as_str()) != self.editing_id.as_deref())
        {
            return Err(format!("Another profile is already named \"{name}\""));
        }
        let server_node_id = self.server_node_id.trim();
        if server_node_id.is_empty() {
            return Err("Server node id is required".into());
        }
        // One profile per server: a second profile against the same server is
        // an accidental duplicate, not a use case.
        if let Some(other) = profiles.iter().find(|p| {
            p.server_node_id == server_node_id
                && Some(p.id.as_str()) != self.editing_id.as_deref()
        }) {
            return Err(format!(
                "Profile \"{}\" already connects to this server",
                other.name
            ));
        }
        let auth_key = self.auth_key.trim();
        if auth_key.is_empty() {
            return Err("Auth key is required (generate one, or paste a flextunnelsecretv1: key)".into());
        }
        flextunnel_core::auth::ClientKey::from_secret_str(auth_key)
            .map_err(|e| format!("Invalid auth key: {e}"))?;
        let editing = self.editing_id.as_deref();
        let socks_port = if self.socks_enabled {
            let port = parse_port(&self.socks_port, "SOCKS5 port")?;
            if let Some(owner) = port_owner(profiles, port, editing, None) {
                return Err(format!("SOCKS5 port {port} is already used by {owner}"));
            }
            Some(port)
        } else {
            None
        };
        let http_port = if self.http_enabled {
            let port = parse_port(&self.http_port, "HTTP port")?;
            if socks_port == Some(port) {
                return Err("HTTP port must differ from the SOCKS5 port".into());
            }
            if let Some(owner) = port_owner(profiles, port, editing, None) {
                return Err(format!("HTTP port {port} is already used by {owner}"));
            }
            Some(port)
        } else {
            None
        };
        let relay_urls: Vec<String> = self
            .relay_urls
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        let relay_auth_token = {
            let token = self.relay_auth_token.trim();
            (!token.is_empty()).then(|| token.to_string())
        };
        // A relay token only applies to custom relays, so reject it with none set
        // (mirrors the core `RelayConfig` guard and ezvpn-apple's form check).
        if relay_auth_token.is_some() && relay_urls.is_empty() {
            return Err("A relay auth token requires at least one relay URL".into());
        }
        // Editing keeps the profile's forwards; the form doesn't touch them.
        let forwards = editing
            .and_then(|id| profiles.iter().find(|p| p.id == id))
            .map(|p| p.forwards.clone())
            .unwrap_or_default();
        Ok(Profile {
            id: self.editing_id.clone().unwrap_or_else(Profile::new_id),
            name,
            server_node_id: server_node_id.into(),
            auth_key: auth_key.into(),
            socks_port,
            http_port,
            relay_urls,
            relay_auth_token,
            forwards,
        })
    }
}

/// Editable add/edit buffers for one port forward, mirroring the iOS sheet.
/// `editing_id` is `None` when adding.
pub struct ForwardForm {
    editing_id: Option<String>,
    pub label: String,
    pub local_port: String,
    pub remote_host: String,
    pub remote_port: String,
    pub enabled: bool,
}

impl ForwardForm {
    pub fn is_edit(&self) -> bool {
        self.editing_id.is_some()
    }

    fn add() -> Self {
        Self {
            editing_id: None,
            label: String::new(),
            local_port: String::new(),
            remote_host: String::new(),
            remote_port: String::new(),
            enabled: true,
        }
    }

    fn edit(forward: &PortForward) -> Self {
        Self {
            editing_id: Some(forward.id.clone()),
            label: forward.label.clone(),
            local_port: forward.local_port.to_string(),
            remote_host: forward.remote_host.clone(),
            remote_port: forward.remote_port.to_string(),
            enabled: forward.enabled,
        }
    }

    /// Validate against every profile: local ports share one namespace since
    /// any set of profiles can run concurrently.
    pub fn validate(&self, profiles: &[Profile]) -> Result<PortForward, String> {
        let label = validate_label(&self.label)?;
        let local_port = parse_port(&self.local_port, "Local port")?;
        let remote_host = validate_remote_host(&self.remote_host)?;
        let remote_port = parse_port(&self.remote_port, "Remote port")?;
        if let Some(owner) =
            port_owner(profiles, local_port, None, self.editing_id.as_deref())
        {
            return Err(format!("Local port {local_port} is already used by {owner}"));
        }
        Ok(PortForward {
            id: self
                .editing_id
                .clone()
                .unwrap_or_else(PortForward::new_id),
            label,
            local_port,
            remote_host,
            remote_port,
            enabled: self.enabled,
        })
    }
}

pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

fn open_log_folder() {
    let Some(dir) = logging::log_dir() else {
        return;
    };
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(&dir).spawn();
    #[cfg(windows)]
    let result = std::process::Command::new("explorer").arg(&dir).spawn();
    #[cfg(not(any(target_os = "macos", windows)))]
    let result = std::process::Command::new("xdg-open").arg(&dir).spawn();
    if let Err(e) = result {
        log::error!("Failed to open the log folder {}: {e}", dir.display());
    }
}

/// Menu-bar app with a Dock presence only while the window is open: Regular
/// (Dock icon, app switcher) when it exists, Accessory when it closes. winit
/// applies Regular during launch anyway (overriding the bundle's LSUIElement),
/// so this only has to run on the open/close transitions afterwards. No-op off
/// macOS.
fn set_activation_policy(regular: bool) {
    #[cfg(target_os = "macos")]
    {
        use objc2::MainThreadMarker;
        use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};
        match MainThreadMarker::new() {
            Some(mtm) => {
                let app = NSApplication::sharedApplication(mtm);
                app.setActivationPolicy(if regular {
                    NSApplicationActivationPolicy::Regular
                } else {
                    NSApplicationActivationPolicy::Accessory
                });
                if regular {
                    // Switching Accessory → Regular does not bring the app
                    // forward on its own.
                    #[allow(deprecated)]
                    app.activateIgnoringOtherApps(true);
                }
            }
            None => log::warn!("Not on the main thread; leaving the activation policy alone"),
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = regular;
}

fn window_settings() -> window::Settings {
    let (rgba, width, height) = icon::window_icon_rgba(256);
    window::Settings {
        size: Size::new(860.0, 640.0),
        min_size: Some(Size::new(680.0, 500.0)),
        icon: window::icon::from_rgba(rgba, width, height).ok(),
        ..window::Settings::default()
    }
}

pub struct App {
    controller: Controller,
    tray: Option<Tray>,
    window: Option<window::Id>,
    /// Ordered source of truth; persisted via `config::save_profiles`.
    pub profiles: Vec<Profile>,
    pub selection: Selection,
    pub profile_form: Option<ProfileForm>,
    /// The open forward form and the profile it belongs to.
    pub forward_form: Option<(ProfileId, ForwardForm)>,
    /// Two-click delete guard: the profile whose Delete was clicked once.
    pub confirm_delete: Option<ProfileId>,
    /// Transient status line in the detail pane (save results/failures).
    pub notice: Option<String>,
    /// Open connection-path modal: a point-in-time path snapshot (`ezvpn
    /// status`-style), overlaid until dismissed. `None` when closed.
    pub conn_path_modal: Option<ConnectionSnapshot>,
    /// Transient export/import result shown in the sidebar.
    pub io_notice: Option<String>,
    /// Setup-failure reason per forward id, retained after the failed forward
    /// is auto-stopped (see [`disable_failed_forwards`]) so the row can keep
    /// showing why; cleared when the forward is started again or removed.
    /// Forward ids are globally unique, so one map covers every profile.
    pub forward_errors: HashMap<String, String>,
    /// Advisory-badge caches per profile: each `RoutedSet` rebuilt only when
    /// that profile's pushed domains/CIDRs change.
    pub routed_caches: HashMap<ProfileId, view::RoutedCache>,
    log_revision: u64,
    /// Logs-pane profile filter: only lines from that profile's session
    /// threads (`[tunnel-<name>]`); `None` shows everything.
    pub log_filter: Option<String>,
    /// The in-memory log ring, filtered and joined for the Logs pane;
    /// rebuilt on revision or filter change only.
    pub log_text: String,
    clipboard: Option<arboard::Clipboard>,
    /// Refreshed by [`App::refresh`] on every tick, rendered by `view`.
    pub snapshots: HashMap<ProfileId, Snapshot>,
}

impl App {
    pub fn boot() -> (Self, Task<Message>) {
        let controller = Controller::start();

        let profiles = match config::load_profiles() {
            Ok(profiles) => profiles,
            Err(e) => {
                log::error!("{e:#}");
                Vec::new()
            }
        };
        let selection = profiles
            .first()
            .map(|p| Selection::Profile(p.id.clone()))
            .unwrap_or(Selection::Logs);
        // First run: go straight to creating a profile.
        let profile_form = profiles.is_empty().then(|| ProfileForm::add(&[]));

        let mut app = Self {
            controller,
            tray: None,
            window: None,
            profiles,
            selection,
            profile_form,
            forward_form: None,
            confirm_delete: None,
            notice: None,
            conn_path_modal: None,
            io_notice: None,
            forward_errors: HashMap::new(),
            routed_caches: HashMap::new(),
            // MAX so the first refresh always builds the log text.
            log_revision: u64::MAX,
            log_filter: None,
            log_text: String::new(),
            clipboard: None,
            snapshots: HashMap::new(),
        };
        let open = app.open_window();
        // The tray is created via a task so it lands on the main thread with
        // the event loop already running (a macOS requirement).
        (app, Task::batch([Task::done(Message::SetupTray), open]))
    }

    pub fn title(&self, _window: window::Id) -> String {
        "flextunnel".into()
    }

    pub fn style(&self, theme: &iced::Theme) -> iced::theme::Style {
        crate::style::app(theme)
    }

    pub fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            // Steady heartbeat so the snapshots and tray state stay fresh even
            // while no window exists; tray events wake the runtime instantly.
            iced::time::every(Duration::from_millis(500)).map(|_| Message::Tick),
            window::close_events().map(Message::WindowClosed),
            Subscription::run(tray_events),
        ])
    }

    pub fn view(&self, _window: window::Id) -> Element<'_, Message> {
        view::root(self)
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => {
                self.refresh();
                Task::none()
            }
            Message::SetupTray => {
                set_activation_policy(self.window.is_some());
                match Tray::new() {
                    Ok(tray) => self.tray = Some(tray),
                    Err(e) => log::error!("Failed to create the tray icon: {e:#}"),
                }
                self.refresh();
                Task::none()
            }
            Message::TrayMenu(id) => self.handle_menu_event(&id),
            Message::TrayIcon(event) => {
                // Windows convention: left click on the tray icon toggles the
                // window. On macOS the left click opens the menu natively.
                #[cfg(not(target_os = "macos"))]
                if let TrayIconEvent::Click {
                    button: tray_icon::MouseButton::Left,
                    button_state: tray_icon::MouseButtonState::Up,
                    ..
                } = event
                {
                    return match self.window.take() {
                        Some(id) => window::close(id),
                        None => self.open_window(),
                    };
                }
                let _ = event;
                Task::none()
            }
            Message::WindowOpened => Task::none(),
            Message::WindowClosed(id) => {
                // Closing the window destroys it; the app lives on in the
                // tray (and off the Dock). Quit comes from the tray menu.
                if self.window == Some(id) {
                    self.window = None;
                    set_activation_policy(false);
                }
                Task::none()
            }
            Message::Select(selection) => {
                self.selection = selection;
                self.profile_form = None;
                self.forward_form = None;
                self.confirm_delete = None;
                self.notice = None;
                self.conn_path_modal = None;
                Task::none()
            }
            Message::CopyText(text) => {
                self.copy_text(text);
                Task::none()
            }
            Message::ShowConnPath => {
                // A one-shot readout shown in a dismissable modal overlay — a
                // point-in-time snapshot that sits above the layout (not in it)
                // so it can't be mistaken for a live field and leaves the pane
                // untouched.
                if let Selection::Profile(id) = &self.selection {
                    let snapshot = self.controller.query_conn_path(&id.clone());
                    self.conn_path_modal = Some(snapshot);
                }
                Task::none()
            }
            Message::DismissConnPath => {
                self.conn_path_modal = None;
                Task::none()
            }
            Message::AddProfile => {
                self.profile_form = Some(ProfileForm::add(&self.profiles));
                self.forward_form = None;
                self.confirm_delete = None;
                self.notice = None;
                Task::none()
            }
            Message::EditProfile(id) => {
                if let Some(profile) = self.profiles.iter().find(|p| p.id == id) {
                    self.profile_form = Some(ProfileForm::edit(profile));
                    self.forward_form = None;
                    self.notice = None;
                }
                Task::none()
            }
            Message::DeleteProfile(id) => {
                self.delete_profile(id);
                Task::none()
            }
            Message::Connect(id) => self.connect_profile(&id),
            Message::Disconnect(id) => {
                self.controller.disconnect(&id);
                Task::none()
            }
            Message::ExportProfiles => Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .add_filter("JSON", &["json"])
                        .set_file_name("flextunnel-profiles.json")
                        .save_file()
                        .await
                        .map(|file| file.path().to_path_buf())
                },
                Message::ExportPicked,
            ),
            Message::ImportProfiles => Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .add_filter("JSON", &["json"])
                        .pick_file()
                        .await
                        .map(|file| file.path().to_path_buf())
                },
                Message::ImportPicked,
            ),
            Message::ExportPicked(path) => {
                if let Some(path) = path {
                    self.io_notice = Some(match config::export_profiles(&path, &self.profiles) {
                        Ok(()) => format!("Exported {} profile(s).", self.profiles.len()),
                        Err(e) => {
                            log::error!("{e:#}");
                            format!("Export failed: {e:#}")
                        }
                    });
                }
                Task::none()
            }
            Message::ImportPicked(path) => {
                if let Some(path) = path {
                    self.import_profiles(&path);
                }
                Task::none()
            }
            Message::ProfileNameChanged(value) => {
                if let Some(form) = &mut self.profile_form {
                    form.name = value;
                }
                Task::none()
            }
            Message::ServerNodeIdChanged(value) => {
                if let Some(form) = &mut self.profile_form {
                    form.server_node_id = value;
                }
                Task::none()
            }
            Message::AuthKeyChanged(value) => {
                if let Some(form) = &mut self.profile_form {
                    form.auth_key = value;
                }
                Task::none()
            }
            Message::GenerateAuthKey => {
                if let Some(form) = &mut self.profile_form {
                    form.auth_key = flextunnel_core::auth::ClientKey::generate().secret_str();
                }
                Task::none()
            }
            Message::SocksEnabledToggled(enabled) => {
                if let Some(form) = &mut self.profile_form {
                    form.socks_enabled = enabled;
                }
                Task::none()
            }
            Message::SocksPortChanged(value) => {
                if let Some(form) = &mut self.profile_form {
                    form.socks_port = value;
                }
                Task::none()
            }
            Message::HttpEnabledToggled(enabled) => {
                if let Some(form) = &mut self.profile_form {
                    form.http_enabled = enabled;
                }
                Task::none()
            }
            Message::HttpPortChanged(value) => {
                if let Some(form) = &mut self.profile_form {
                    form.http_port = value;
                }
                Task::none()
            }
            Message::RelayUrlsChanged(value) => {
                if let Some(form) = &mut self.profile_form {
                    form.relay_urls = value;
                }
                Task::none()
            }
            Message::RelayAuthTokenChanged(value) => {
                if let Some(form) = &mut self.profile_form {
                    form.relay_auth_token = value;
                }
                Task::none()
            }
            Message::ProfileFormSave => {
                self.save_profile_form();
                Task::none()
            }
            Message::ProfileFormCancel => {
                self.profile_form = None;
                Task::none()
            }
            Message::AddForward(profile_id) => {
                self.forward_form = Some((profile_id, ForwardForm::add()));
                Task::none()
            }
            Message::EditForward(profile_id, forward_id) => {
                if let Some(forward) = self
                    .profiles
                    .iter()
                    .find(|p| p.id == profile_id)
                    .and_then(|p| p.forwards.iter().find(|f| f.id == forward_id))
                {
                    self.forward_form = Some((profile_id, ForwardForm::edit(forward)));
                }
                Task::none()
            }
            Message::DeleteForward(profile_id, forward_id) => {
                if let Some(profile) = self.profiles.iter_mut().find(|p| p.id == profile_id) {
                    let before = profile.forwards.len();
                    profile.forwards.retain(|f| f.id != forward_id);
                    if profile.forwards.len() != before {
                        self.forward_errors.remove(&forward_id);
                        self.commit_forwards(&profile_id);
                    }
                }
                Task::none()
            }
            Message::ToggleForward(profile_id, forward_id, enabled) => {
                if let Some(forward) = self
                    .profiles
                    .iter_mut()
                    .find(|p| p.id == profile_id)
                    .and_then(|p| p.forwards.iter_mut().find(|f| f.id == forward_id))
                {
                    // Desired state, but not a plain checkbox: enabling
                    // attempts the setup now, and a setup failure snaps the
                    // switch back off (see disable_failed_forwards).
                    forward.enabled = enabled;
                    if enabled {
                        // A fresh start attempt supersedes the old failure.
                        self.forward_errors.remove(&forward_id);
                    }
                    self.commit_forwards(&profile_id);
                }
                Task::none()
            }
            Message::FormLabelChanged(value) => {
                if let Some((_, form)) = &mut self.forward_form {
                    form.label = value;
                }
                Task::none()
            }
            Message::FormLocalPortChanged(value) => {
                if let Some((_, form)) = &mut self.forward_form {
                    form.local_port = value;
                }
                Task::none()
            }
            Message::FormRemoteHostChanged(value) => {
                if let Some((_, form)) = &mut self.forward_form {
                    form.remote_host = value;
                }
                Task::none()
            }
            Message::FormRemotePortChanged(value) => {
                if let Some((_, form)) = &mut self.forward_form {
                    form.remote_port = value;
                }
                Task::none()
            }
            Message::FormEnabledToggled(enabled) => {
                if let Some((_, form)) = &mut self.forward_form {
                    form.enabled = enabled;
                }
                Task::none()
            }
            Message::FormSave => {
                self.save_forward_form();
                Task::none()
            }
            Message::FormCancel => {
                self.forward_form = None;
                Task::none()
            }
            Message::LogFilterChanged(value) => {
                self.log_filter = (value != LOG_FILTER_ALL).then_some(value);
                self.rebuild_log_text();
                Task::none()
            }
            Message::OpenLogFolder => {
                open_log_folder();
                Task::none()
            }
            Message::CopyLogs => {
                let text = self.log_text.clone();
                self.copy_text(text);
                Task::none()
            }
        }
    }

    pub fn profile(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// The profile's latest snapshot, or the shared idle one before its first
    /// session.
    pub fn snapshot_for(&self, id: &str) -> &Snapshot {
        match self.snapshots.get(id) {
            Some(snapshot) => snapshot,
            None => Snapshot::empty(),
        }
    }

    fn open_window(&mut self) -> Task<Message> {
        let (id, open) = window::open(window_settings());
        self.window = Some(id);
        set_activation_policy(true);
        open.map(|_| Message::WindowOpened)
    }

    fn show_window(&mut self) -> Task<Message> {
        match self.window {
            Some(id) => window::gain_focus(id),
            None => self.open_window(),
        }
    }

    fn connect_profile(&mut self, id: &str) -> Task<Message> {
        let Some(profile) = self.profile(id).cloned() else {
            return Task::none();
        };
        if profile.is_ready() {
            self.controller.connect(profile);
            Task::none()
        } else {
            // The token's keychain entry was lost — re-enter it.
            self.selection = Selection::Profile(profile.id.clone());
            self.profile_form = Some(ProfileForm::edit(&profile));
            self.notice = Some("Enter the auth key to connect.".into());
            self.show_window()
        }
    }

    fn delete_profile(&mut self, id: ProfileId) {
        if self.confirm_delete.as_deref() != Some(id.as_str()) {
            self.confirm_delete = Some(id);
            return;
        }
        self.confirm_delete = None;
        let Some(pos) = self.profiles.iter().position(|p| p.id == id) else {
            return;
        };
        self.controller.remove_profile(&id);
        config::delete_profile_secret(&id);
        let removed = self.profiles.remove(pos);
        for forward in &removed.forwards {
            self.forward_errors.remove(&forward.id);
        }
        self.routed_caches.remove(&id);
        self.snapshots.remove(&id);
        self.forward_form = None;
        if self.log_filter.as_deref() == Some(removed.name.as_str()) {
            self.log_filter = None;
            self.rebuild_log_text();
        }
        self.persist_profiles();
        if self.selection == Selection::Profile(id) {
            self.selection = self
                .profiles
                .get(pos.min(self.profiles.len().saturating_sub(1)))
                .map(|p| Selection::Profile(p.id.clone()))
                .unwrap_or(Selection::Logs);
        }
        if self.profiles.is_empty() {
            self.profile_form = Some(ProfileForm::add(&[]));
        }
    }

    fn handle_menu_event(&mut self, id: &str) -> Task<Message> {
        match id {
            tray::MENU_OPEN => self.show_window(),
            tray::MENU_QUIT => {
                self.controller.shutdown();
                iced::exit()
            }
            _ => {
                if let Some(profile_id) = id.strip_prefix(tray::MENU_CONNECT_PREFIX) {
                    let profile_id = profile_id.to_string();
                    return self.connect_profile(&profile_id);
                }
                if let Some(profile_id) = id.strip_prefix(tray::MENU_DISCONNECT_PREFIX) {
                    self.controller.disconnect(profile_id);
                } else if let Some(profile_id) = id.strip_prefix(tray::MENU_COPY_SOCKS_PREFIX)
                    && let Some(addr) = self.snapshots.get(profile_id).and_then(|s| s.socks_addr)
                {
                    self.copy_text(format!("socks5://{addr}"));
                }
                Task::none()
            }
        }
    }

    /// Poll the tunnel snapshots and derived state; runs on every tick and
    /// after the tray is created.
    fn refresh(&mut self) {
        self.snapshots = self.controller.snapshots();

        // Runs every tick so a forward whose setup failed snaps back to
        // stopped promptly, per profile.
        let mut failed_in: Vec<ProfileId> = Vec::new();
        for profile in &mut self.profiles {
            let Some(snapshot) = self.snapshots.get(&profile.id) else {
                continue;
            };
            let failed = disable_failed_forwards(&mut profile.forwards, &snapshot.forwards);
            if !failed.is_empty() {
                self.forward_errors.extend(failed);
                failed_in.push(profile.id.clone());
            }
            view::refresh_routed_cache(
                self.routed_caches.entry(profile.id.clone()).or_default(),
                &snapshot.routes,
            );
        }
        for id in &failed_in {
            if let Some(profile) = self.profile(id) {
                self.controller.set_forwards(id, profile.forwards.clone());
            }
        }
        if !failed_in.is_empty() {
            self.persist_profiles();
        }

        let revision = logging::revision();
        if revision != self.log_revision {
            self.log_revision = revision;
            self.rebuild_log_text();
        }

        if let Some(tray) = &mut self.tray {
            tray.sync(&self.profiles, &self.snapshots);
        }
    }

    fn save_profile_form(&mut self) {
        let Some(form) = &self.profile_form else {
            return;
        };
        let Ok(profile) = form.validate(&self.profiles) else {
            return;
        };
        if let Err(e) = config::save_profile_secret(&profile.id, &profile.auth_key) {
            log::error!("{e:#}");
            self.notice = Some(format!("{e:#}"));
            return;
        }
        let id = profile.id.clone();
        let running = self.snapshots.get(&id).is_some_and(|s| {
            matches!(s.phase, Phase::Connecting | Phase::Connected | Phase::Reconnecting)
        });
        match self.profiles.iter().position(|p| p.id == id) {
            Some(pos) => {
                // Follow a rename with the log filter (new lines carry the
                // new thread name; old lines keep matching by text only).
                let filter_renamed = self.log_filter.as_deref()
                    == Some(self.profiles[pos].name.as_str())
                    && self.profiles[pos].name != profile.name;
                if filter_renamed {
                    self.log_filter = Some(profile.name.clone());
                    self.rebuild_log_text();
                }
                self.profiles[pos] = profile;
            }
            None => self.profiles.push(profile),
        }
        self.persist_profiles();
        if self.notice.is_none() {
            self.notice = Some(if running {
                "Saved — reconnect to apply.".into()
            } else {
                "Saved.".into()
            });
        }
        self.selection = Selection::Profile(id);
        self.profile_form = None;
    }

    fn save_forward_form(&mut self) {
        let Some((profile_id, form)) = &self.forward_form else {
            return;
        };
        let profile_id = profile_id.clone();
        let Ok(saved) = form.validate(&self.profiles) else {
            return;
        };
        let Some(profile) = self.profiles.iter_mut().find(|p| p.id == profile_id) else {
            return;
        };
        if saved.enabled {
            // The edit may fix what failed (e.g. a new local port); the fresh
            // start attempt supersedes the old failure.
            self.forward_errors.remove(&saved.id);
        }
        match profile.forwards.iter_mut().find(|f| f.id == saved.id) {
            Some(slot) => *slot = saved,
            None => profile.forwards.push(saved),
        }
        self.commit_forwards(&profile_id);
        self.forward_form = None;
    }

    /// Persist all profiles and push one profile's forwards to its session
    /// (live apply).
    fn commit_forwards(&mut self, profile_id: &str) {
        self.persist_profiles();
        if let Some(profile) = self.profile(profile_id) {
            self.controller
                .set_forwards(profile_id, profile.forwards.clone());
        }
    }

    fn import_profiles(&mut self, path: &std::path::Path) {
        let imported = match config::import_profiles(path) {
            Ok(imported) => imported,
            Err(e) => {
                log::error!("{e:#}");
                self.io_notice = Some(format!("Import failed: {e:#}"));
                return;
            }
        };
        let (added, replaced) = merge_imported(&mut self.profiles, imported);
        // A replaced profile's session (if live) reconciles to the imported
        // forward list — which loads all-disabled, like any fresh load.
        for id in &replaced {
            if let Some(profile) = self.profile(id) {
                self.controller.set_forwards(id, profile.forwards.clone());
            }
        }
        self.persist_profiles();
        self.io_notice = Some(format!(
            "Imported: {added} added, {} replaced.",
            replaced.len()
        ));
        // Land somewhere sensible if nothing (or a since-removed profile) was
        // selected; added profiles still need their tokens entered.
        if !matches!(&self.selection, Selection::Profile(id) if self.profile(id).is_some())
            && let Some(profile) = self.profiles.first()
        {
            self.selection = Selection::Profile(profile.id.clone());
        }
        self.profile_form = None;
    }

    /// Re-join the log ring for the Logs pane, keeping only the filtered
    /// profile's session-thread lines (`[tunnel-<name>]`) when a filter is on.
    fn rebuild_log_text(&mut self) {
        let lines = logging::recent_lines();
        self.log_text = match &self.log_filter {
            Some(name) => {
                let tag = format!("[tunnel-{name}]");
                lines
                    .iter()
                    .filter(|line| line.contains(&tag))
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            None => lines.join("\n"),
        };
    }

    fn persist_profiles(&mut self) {
        if let Err(e) = config::save_profiles(&self.profiles) {
            log::error!("Failed to save profiles: {e:#}");
            self.notice = Some(format!("Failed to save profiles: {e:#}"));
        }
    }

    fn copy_text(&mut self, text: String) {
        if self.clipboard.is_none() {
            match arboard::Clipboard::new() {
                Ok(clipboard) => self.clipboard = Some(clipboard),
                Err(e) => {
                    log::error!("Clipboard unavailable: {e}");
                    return;
                }
            }
        }
        if let Some(clipboard) = &mut self.clipboard
            && let Err(e) = clipboard.set_text(text)
        {
            log::error!("Failed to copy to the clipboard: {e}");
        }
    }
}

/// Forward tray/menu events into the runtime. The handlers replace tray-icon's
/// default channel delivery; sending through the subscription channel wakes
/// the event loop even while no window exists. Runs (and installs the
/// handlers) once for the daemon's lifetime.
fn tray_events() -> impl Stream<Item = Message> {
    iced::stream::channel(32, async move |mut output| {
        use iced::futures::channel::mpsc;
        use iced::futures::{SinkExt, StreamExt};

        let (tx, mut rx) = mpsc::unbounded();
        let menu_tx = tx.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            let _ = menu_tx.unbounded_send(Message::TrayMenu(event.id().as_ref().to_owned()));
        }));
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            let _ = tx.unbounded_send(Message::TrayIcon(event));
        }));
        while let Some(message) = rx.next().await {
            if output.send(message).await.is_err() {
                return;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_form() -> ProfileForm {
        ProfileForm {
            editing_id: None,
            name: " prod ".into(),
            server_node_id: " node-id ".into(),
            auth_key: flextunnel_core::auth::ClientKey::generate().secret_str(),
            socks_enabled: true,
            socks_port: "1080".into(),
            http_enabled: false,
            http_port: "8080".into(),
            relay_urls: " https://a.example ,, https://b.example ".into(),
            relay_auth_token: String::new(),
        }
    }

    fn valid_forward_form() -> ForwardForm {
        ForwardForm {
            editing_id: None,
            label: "  db  ".into(),
            local_port: "5432".into(),
            remote_host: " db.internal ".into(),
            remote_port: "5432".into(),
            enabled: true,
        }
    }

    fn existing_forward(id: &str, local_port: u16) -> PortForward {
        PortForward {
            id: id.into(),
            label: String::new(),
            local_port,
            remote_host: "other.internal".into(),
            remote_port: 80,
            enabled: true,
        }
    }

    fn existing_profile(id: &str, socks_port: u16, forwards: Vec<PortForward>) -> Profile {
        Profile {
            id: id.into(),
            name: format!("profile-{id}"),
            server_node_id: "node".into(),
            auth_key: "token".into(),
            socks_port: Some(socks_port),
            http_port: None,
            relay_urls: Vec::new(),
            relay_auth_token: None,
            forwards,
        }
    }

    #[test]
    fn forward_form_trims_and_builds() {
        let profiles = [existing_profile("p1", 1080, vec![])];
        let forward = valid_forward_form().validate(&profiles).expect("valid");
        assert_eq!(forward.label, "db");
        assert_eq!(forward.local_port, 5432);
        assert_eq!(forward.remote_host, "db.internal");
        assert_eq!(forward.remote_port, 5432);
        assert!(forward.enabled);
        assert!(!forward.id.is_empty());
    }

    #[test]
    fn forward_form_rejects_bad_input() {
        let base = [existing_profile("p1", 1080, vec![])];

        let mut form = valid_forward_form();
        form.local_port = "0".into();
        assert!(form.validate(&base).is_err());

        let mut form = valid_forward_form();
        form.remote_host = "  ".into();
        assert!(form.validate(&base).is_err());

        let mut form = valid_forward_form();
        form.remote_host = "networking..internal".into();
        assert!(form.validate(&base).is_err());

        let mut form = valid_forward_form();
        form.label = "x".repeat(65);
        assert!(form.validate(&base).is_err());

        let mut form = valid_forward_form();
        form.remote_port = "70000".into();
        assert!(form.validate(&base).is_err());

        // Collisions with any profile's proxy ports.
        let form = valid_forward_form();
        assert!(form.validate(&[existing_profile("p1", 5432, vec![])]).is_err());
        let mut http_profile = existing_profile("p1", 1080, vec![]);
        http_profile.http_port = Some(5432);
        assert!(form.validate(std::slice::from_ref(&http_profile)).is_err());

        // Duplicate local port among any profile's forwards…
        let taken = [existing_profile("p2", 1081, vec![existing_forward("aaaa", 5432)])];
        assert!(form.validate(&taken).is_err());

        // …unless it is the forward being edited (id reused).
        let mut form = valid_forward_form();
        form.editing_id = Some("aaaa".into());
        let edited = form.validate(&taken).expect("editing the same forward");
        assert_eq!(edited.id, "aaaa");
    }

    #[test]
    fn import_merges_by_server_id_and_uniquifies_names() {
        // "profile-p1" on server "node" (with a token), "profile-p2" on
        // "node-2".
        let mut current = vec![
            existing_profile("p1", 1080, vec![existing_forward("f1", 5000)]),
            existing_profile("p2", 1081, vec![]),
        ];
        current[1].server_node_id = "node-2".into();
        current[0].auth_key = "secret".into();
        current[0].relay_auth_token = Some("relay-psk".into());

        // Same server as p1: replaces settings/forwards, keeps id + secrets.
        // A relay token on an incoming entry is never trusted (imports strip
        // it); pretend a hand-edited one slipped through to prove that.
        let mut same_server = existing_profile("x", 2080, vec![existing_forward("f2", 6000)]);
        same_server.name = "renamed".into();
        same_server.relay_auth_token = Some("imported-psk".into());
        // New server, but colliding with p2's name: gets " - 2".
        let mut name_clash = existing_profile("y", 3080, vec![]);
        name_clash.name = "profile-p2".into();
        name_clash.server_node_id = "node-3".into();
        name_clash.relay_auth_token = Some("imported-psk".into());

        let (added, replaced) = merge_imported(&mut current, vec![same_server, name_clash]);
        assert_eq!(added, 1);
        assert_eq!(replaced, vec!["p1".to_string()]);

        let p1 = &current[0];
        assert_eq!(p1.id, "p1", "id kept");
        assert_eq!(p1.auth_key, "secret", "token kept");
        assert_eq!(
            p1.relay_auth_token.as_deref(),
            Some("relay-psk"),
            "existing relay token kept, not overwritten by the import"
        );
        assert_eq!(p1.name, "renamed");
        assert_eq!(p1.socks_port, Some(2080));
        assert_eq!(p1.forwards.len(), 1);
        assert_ne!(p1.forwards[0].id, "f2", "imported forward ids are fresh");

        let new = &current[2];
        assert_eq!(new.name, "profile-p2 - 2");
        assert!(new.auth_key.is_empty(), "no secret in imports");
        assert_eq!(new.relay_auth_token, None, "no relay secret in imports");
        assert_ne!(new.id, "y", "imported profile ids are fresh");

        // A second import of the same name-clashing profile bumps to " - 3"
        // only if its server is also new; same server replaces in place.
        let mut again = existing_profile("z", 4080, vec![]);
        again.name = "profile-p2".into();
        again.server_node_id = "node-4".into();
        let (added, replaced) = merge_imported(&mut current, vec![again]);
        assert_eq!((added, replaced.len()), (1, 0));
        assert_eq!(current[3].name, "profile-p2 - 3");
    }

    #[test]
    fn unique_name_respects_length_limit() {
        let taken = existing_profile("p1", 1080, vec![]);
        let mut long = existing_profile("p2", 1081, vec![]);
        long.name = "a".repeat(64);
        let profiles = [taken, long.clone()];

        assert_eq!(
            unique_name(&profiles, "fresh".into(), None),
            "fresh",
            "free names pass through"
        );
        let bumped = unique_name(&profiles, long.name.clone(), None);
        assert_eq!(bumped, format!("{} - 2", "a".repeat(60)));
        assert!(bumped.len() <= 64);
        assert!(bumped.ends_with(" - 2"));
        assert!(Profile::is_valid_name(&bumped));
    }

    #[test]
    fn name_whitespace_is_normalized() {
        let mut form = valid_form();
        form.name = "  staging   aws \t kube  ".into();
        let profile = form.validate(&[]).expect("valid");
        assert_eq!(profile.name, "staging aws kube");
        assert!(Profile::is_valid_name(&profile.name));
    }

    #[test]
    fn validate_trims_and_parses() {
        let profile = valid_form().validate(&[]).expect("valid");
        assert_eq!(profile.name, "prod");
        assert_eq!(profile.server_node_id, "node-id");
        assert_eq!(profile.socks_port, Some(1080));
        assert_eq!(profile.http_port, None);
        assert_eq!(
            profile.relay_urls,
            vec!["https://a.example".to_string(), "https://b.example".to_string()]
        );
        assert!(!profile.id.is_empty());
        assert!(profile.forwards.is_empty());
    }

    #[test]
    fn validate_rejects_bad_input() {
        let mut form = valid_form();
        form.name = "  ".into();
        assert!(form.validate(&[]).is_err());

        let mut form = valid_form();
        form.auth_key = "not-a-token".into();
        assert!(form.validate(&[]).is_err());

        let mut form = valid_form();
        form.socks_port = "0".into();
        assert!(form.validate(&[]).is_err());

        let mut form = valid_form();
        form.http_enabled = true;
        form.http_port = form.socks_port.clone();
        assert!(form.validate(&[]).is_err());

        let mut form = valid_form();
        form.server_node_id = "  ".into();
        assert!(form.validate(&[]).is_err());

        // Duplicate profile name (they key tray submenus and log threads)…
        let existing = [existing_profile("p1", 2080, vec![])];
        let mut form = valid_form();
        form.name = " profile-p1 ".into();
        assert!(form.validate(&existing).is_err());
        // …unless it is the profile being edited.
        form.editing_id = Some("p1".into());
        assert!(form.validate(&existing).is_ok());

        // Duplicate server node id…
        let mut form = valid_form();
        form.server_node_id = "node".into();
        assert!(form.validate(&existing).is_err());
        // …unless it is the profile being edited.
        form.editing_id = Some("p1".into());
        assert!(form.validate(&existing).is_ok());
    }

    #[test]
    fn profile_ports_share_one_namespace() {
        let existing = [existing_profile("p1", 1080, vec![existing_forward("f1", 5000)])];

        // Another profile's SOCKS port.
        let form = valid_form();
        assert!(form.validate(&existing).is_err());

        // Another profile's forward local port (as SOCKS or HTTP).
        let mut form = valid_form();
        form.socks_port = "5000".into();
        assert!(form.validate(&existing).is_err());
        let mut form = valid_form();
        form.socks_port = "1090".into();
        form.http_enabled = true;
        form.http_port = "5000".into();
        assert!(form.validate(&existing).is_err());

        // A free port is fine.
        let mut form = valid_form();
        form.socks_port = "1081".into();
        assert!(form.validate(&existing).is_ok());

        // Editing a profile skips its own proxy ports but keeps its forwards.
        let mut form = valid_form();
        form.editing_id = Some("p1".into());
        form.socks_port = "1080".into();
        let edited = form.validate(&existing).expect("own port is not a clash");
        assert_eq!(edited.id, "p1");
        assert_eq!(edited.forwards, existing[0].forwards);

        // A forward in another profile can't take a port a new profile's own
        // forward holds — and vice versa (covered by forward_form tests).
        assert_eq!(next_free_port(&existing), 1081);
    }
}
