//! The iced daemon state machine: a sidebar of connection profiles plus a
//! detail pane, driven alongside the system tray. Each profile can run its own
//! tunnel session concurrently (its optional proxy ports and direct forwards).
//! The daemon
//! owns all state, so closing the window (which destroys it) loses nothing —
//! the tray re-opens it on demand. Tray/menu events are forwarded from
//! tray-icon's handlers into a channel drained by a [`Subscription`], so a
//! tray click wakes the runtime even while no window exists; a 500 ms tick
//! keeps the snapshots and the tray state fresh the rest of the time.

use crate::config::{self, AuthKey, Profile, DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT};
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
    Keys,
    Logs,
}

/// One entry of the profile form's auth-key picker. Keys are picked by name
/// (names are unique — see `drop_invalid_keys`); the id travels along so the
/// selection maps back to the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyChoice {
    pub id: String,
    pub name: String,
}

impl std::fmt::Display for KeyChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
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
    /// Pick a shared auth key for the profile being edited.
    AuthKeyPicked(KeyChoice),
    /// Open the profile form's "New key" prompt (a name field next to the
    /// picker).
    NewKeyPrompt,
    NewKeyNameChanged(String),
    /// Generate a keypair under the prompted name, add it to the shared list,
    /// and select it in the profile form.
    NewKeyCreate,
    NewKeyCancel,
    // Auth keys (the Keys pane)
    AddKey,
    EditKey(String),
    DeleteKey(String),
    /// Copy the key's secret to the clipboard (two-click, like delete) so it
    /// can be imported on another device.
    ExportKey(String),
    KeyNameChanged(String),
    KeySecretChanged(String),
    /// Fill the key form's secret field with a freshly generated keypair.
    KeyGenerateSecret,
    KeyFormSave,
    KeyFormCancel,
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

/// `desired` if `taken` reports it free, else the first free "desired - 2",
/// "desired - 3", … The base is shortened if a suffix would push past the
/// 64-character name limit.
fn unique_name(desired: String, taken: impl Fn(&str) -> bool) -> String {
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
/// and forwards but keeps its id, auth-key reference, and relay auth token;
/// anything else is added as a new profile with a fresh id, no key picked,
/// and no relay token — imports never carry them. Colliding names get a
/// " - N" suffix, and imported forwards get fresh ids so they stay globally
/// unique. Returns `(added, replaced-profile ids)`.
fn merge_imported(
    profiles: &mut Vec<Profile>,
    imported: Vec<Profile>,
) -> (usize, Vec<ProfileId>) {
    let mut added = 0;
    let mut replaced = Vec::new();
    let profile_name_taken = |profiles: &[Profile], name: &str, own_id: Option<&str>| {
        profiles
            .iter()
            .any(|p| p.name == name && Some(p.id.as_str()) != own_id)
    };
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
                incoming.auth_key_id = profiles[pos].auth_key_id.clone();
                incoming.relay_auth_token = profiles[pos].relay_auth_token.clone();
                incoming.name = unique_name(incoming.name.clone(), |name| {
                    profile_name_taken(profiles, name, Some(&incoming.id))
                });
                profiles[pos] = incoming;
                replaced.push(profiles[pos].id.clone());
            }
            None => {
                incoming.id = Profile::new_id();
                incoming.auth_key_id = String::new();
                incoming.relay_auth_token = None;
                incoming.name = unique_name(incoming.name.clone(), |name| {
                    profile_name_taken(profiles, name, None)
                });
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
    /// The picked shared key ([`AuthKey::id`]); empty while none is picked.
    pub auth_key_id: String,
    /// The "New key" prompt's name buffer; `None` while the prompt is closed.
    pub new_key_name: Option<String>,
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
            auth_key_id: profile.auth_key_id.clone(),
            new_key_name: None,
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

    pub fn validate(&self, profiles: &[Profile], keys: &[AuthKey]) -> Result<Profile, String> {
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
        if config::find_key(keys, &self.auth_key_id).is_none() {
            return Err("Pick an auth key (or create one with New key)".into());
        }
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
            auth_key_id: self.auth_key_id.clone(),
            socks_port,
            http_port,
            relay_urls,
            relay_auth_token,
            forwards,
        })
    }
}

/// Editable buffers for one shared auth key (the Keys pane's add/edit form).
/// `editing_id` is `None` when adding.
#[derive(Default)]
pub struct KeyForm {
    editing_id: Option<String>,
    pub name: String,
    pub secret: String,
}

impl KeyForm {
    pub fn is_edit(&self) -> bool {
        self.editing_id.is_some()
    }

    /// The id of the key being edited (`None` when adding), so the Keys pane
    /// can hide that key's card while its form is open.
    pub fn editing_id(&self) -> Option<&str> {
        self.editing_id.as_deref()
    }

    fn edit(key: &AuthKey) -> Self {
        Self {
            editing_id: Some(key.id.clone()),
            name: key.name.clone(),
            secret: key.secret.clone(),
        }
    }

    /// The public key derived from the form's secret, when it parses. The
    /// public half is never a secret — the UI shows it unmasked so it can be
    /// copied onto the server's authorized-keys file.
    pub fn public_key(&self) -> Option<String> {
        flextunnel_core::auth::ClientKey::from_secret_str(self.secret.trim())
            .ok()
            .map(|key| key.public_str())
    }

    pub fn validate(&self, keys: &[AuthKey]) -> Result<AuthKey, String> {
        let name = validate_key_name(&self.name, keys, self.editing_id.as_deref())?;
        let secret = self.secret.trim();
        if secret.is_empty() {
            return Err(
                "Secret key is required (generate one, or paste a flxtsecretv1: key)".into(),
            );
        }
        let client_key = flextunnel_core::auth::ClientKey::from_secret_str(secret)
            .map_err(|e| format!("Invalid secret key: {e}"))?;
        let public_key = client_key.public_str();
        // The same keypair twice under two names is an accidental re-add, not
        // a use case — profiles share one entry instead.
        if let Some(other) = keys
            .iter()
            .find(|k| k.public_key == public_key && Some(k.id.as_str()) != self.editing_id.as_deref())
        {
            return Err(format!("Key \"{}\" already holds this secret", other.name));
        }
        Ok(AuthKey {
            id: self.editing_id.clone().unwrap_or_else(AuthKey::new_id),
            name,
            public_key,
            secret: secret.into(),
        })
    }
}

/// Normalize and validate a key name (same shape as profile names — see
/// `config::is_valid_name`), rejecting duplicates of any key other than
/// `own_id`. Shared by the Keys form and the profile form's New key prompt;
/// unique names keep the profile form's picker unambiguous.
pub fn validate_key_name(
    name: &str,
    keys: &[AuthKey],
    own_id: Option<&str>,
) -> Result<String, String> {
    let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.is_empty() {
        return Err("Key name is required".into());
    }
    if name.chars().count() > 64 {
        return Err("Key name must be 64 characters or fewer".into());
    }
    if keys
        .iter()
        .any(|k| k.name == name && Some(k.id.as_str()) != own_id)
    {
        return Err(format!("Another key is already named \"{name}\""));
    }
    Ok(name)
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
    /// Ordered source of truth; persisted via `config::save_store`.
    pub profiles: Vec<Profile>,
    /// The shared auth keys profiles reference into; persisted alongside.
    pub keys: Vec<AuthKey>,
    pub selection: Selection,
    pub profile_form: Option<ProfileForm>,
    /// The Keys pane's open add/edit form.
    pub key_form: Option<KeyForm>,
    /// The open forward form and the profile it belongs to.
    pub forward_form: Option<(ProfileId, ForwardForm)>,
    /// Two-click delete guard: the profile whose Delete was clicked once.
    pub confirm_delete: Option<ProfileId>,
    /// Two-click delete guard for the Keys pane.
    pub confirm_delete_key: Option<String>,
    /// Two-click export guard for the Keys pane: the key whose Export was
    /// clicked once; the second click copies its secret to the clipboard.
    pub confirm_export_key: Option<String>,
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

        let store = match config::load_store() {
            Ok(store) => store,
            Err(e) => {
                log::error!("{e:#}");
                config::Store::default()
            }
        };
        let selection = store
            .profiles
            .first()
            .map(|p| Selection::Profile(p.id.clone()))
            .unwrap_or(Selection::Logs);
        // First run: go straight to creating a profile.
        let profile_form = store.profiles.is_empty().then(|| ProfileForm::add(&[]));

        let mut app = Self {
            controller,
            tray: None,
            window: None,
            profiles: store.profiles,
            keys: store.keys,
            selection,
            profile_form,
            key_form: None,
            forward_form: None,
            confirm_delete: None,
            confirm_delete_key: None,
            confirm_export_key: None,
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
                self.key_form = None;
                self.forward_form = None;
                self.confirm_delete = None;
                self.confirm_delete_key = None;
                self.confirm_export_key = None;
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
                self.key_form = None;
                self.forward_form = None;
                self.confirm_delete = None;
                self.notice = None;
                Task::none()
            }
            Message::EditProfile(id) => {
                if let Some(profile) = self.profiles.iter().find(|p| p.id == id) {
                    self.profile_form = Some(ProfileForm::edit(profile));
                    self.key_form = None;
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
            Message::AuthKeyPicked(choice) => {
                if let Some(form) = &mut self.profile_form {
                    form.auth_key_id = choice.id;
                }
                Task::none()
            }
            Message::NewKeyPrompt => {
                if let Some(form) = &mut self.profile_form
                    && form.new_key_name.is_none()
                {
                    form.new_key_name = Some(String::new());
                }
                Task::none()
            }
            Message::NewKeyNameChanged(value) => {
                if let Some(form) = &mut self.profile_form
                    && let Some(buffer) = &mut form.new_key_name
                {
                    *buffer = value;
                }
                Task::none()
            }
            Message::NewKeyCreate => {
                self.create_key_for_profile_form();
                Task::none()
            }
            Message::NewKeyCancel => {
                if let Some(form) = &mut self.profile_form {
                    form.new_key_name = None;
                }
                Task::none()
            }
            Message::AddKey => {
                self.key_form = Some(KeyForm::default());
                self.confirm_delete_key = None;
                self.confirm_export_key = None;
                self.notice = None;
                Task::none()
            }
            Message::EditKey(id) => {
                if let Some(key) = config::find_key(&self.keys, &id) {
                    self.key_form = Some(KeyForm::edit(key));
                    self.confirm_delete_key = None;
                    self.confirm_export_key = None;
                    self.notice = None;
                }
                Task::none()
            }
            Message::DeleteKey(id) => {
                self.delete_key(id);
                Task::none()
            }
            Message::ExportKey(id) => {
                self.export_key(id);
                Task::none()
            }
            Message::KeyNameChanged(value) => {
                if let Some(form) = &mut self.key_form {
                    form.name = value;
                }
                Task::none()
            }
            Message::KeySecretChanged(value) => {
                if let Some(form) = &mut self.key_form {
                    form.secret = value;
                }
                Task::none()
            }
            Message::KeyGenerateSecret => {
                if let Some(form) = &mut self.key_form {
                    form.secret = flextunnel_core::auth::ClientKey::generate().secret_str();
                }
                Task::none()
            }
            Message::KeyFormSave => {
                self.save_key_form();
                Task::none()
            }
            Message::KeyFormCancel => {
                self.key_form = None;
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
        match config::find_key(&self.keys, &profile.auth_key_id) {
            Some(key) if !key.secret.is_empty() && !profile.server_node_id.is_empty() => {
                let secret = key.secret.clone();
                self.controller.connect(profile, secret);
                Task::none()
            }
            Some(key) if key.secret.is_empty() => {
                // The key's keychain entry was lost — re-enter its secret.
                let (key_name, key_form) = (key.name.clone(), KeyForm::edit(key));
                self.selection = Selection::Keys;
                self.profile_form = None;
                self.key_form = Some(key_form);
                self.notice = Some(format!(
                    "Re-enter the secret of key \"{key_name}\" to connect."
                ));
                self.show_window()
            }
            key => {
                // `Some` here means the key is usable (the empty-secret case
                // was caught above) and the server node id is empty (only a
                // hand-edited file gets there); `None` is no key picked (fresh
                // import) or a dangling reference.
                let notice = if key.is_some() {
                    "Enter the server node id to connect."
                } else {
                    "Pick an auth key to connect."
                };
                self.selection = Selection::Profile(profile.id.clone());
                self.profile_form = Some(ProfileForm::edit(&profile));
                self.notice = Some(notice.into());
                self.show_window()
            }
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
        // The referenced auth key stays — it's shared, managed in the Keys pane.
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
        self.persist_store();
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
            self.persist_store();
        }

        let revision = logging::revision();
        if revision != self.log_revision {
            self.log_revision = revision;
            self.rebuild_log_text();
        }

        if let Some(tray) = &mut self.tray {
            tray.sync(&self.profiles, &self.keys, &self.snapshots);
        }
    }

    fn save_profile_form(&mut self) {
        let Some(form) = &self.profile_form else {
            return;
        };
        let Ok(profile) = form.validate(&self.profiles, &self.keys) else {
            return;
        };
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
        self.persist_store();
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

    /// The profile form's "New key" prompt: generate a keypair under the
    /// entered name, add it to the shared list, and select it in the form.
    /// (Cancelling the profile form afterwards keeps the key — it's in the
    /// list, deletable from the Keys pane.)
    fn create_key_for_profile_form(&mut self) {
        let Some(name) = self.profile_form.as_ref().and_then(|f| f.new_key_name.clone()) else {
            return;
        };
        // The view disables Create on an invalid name; this is the backstop.
        let Ok(name) = validate_key_name(&name, &self.keys, None) else {
            return;
        };
        let client_key = flextunnel_core::auth::ClientKey::generate();
        let key = AuthKey {
            id: AuthKey::new_id(),
            name,
            public_key: client_key.public_str(),
            secret: client_key.secret_str(),
        };
        let id = key.id.clone();
        self.keys.push(key);
        self.persist_store();
        if let Some(form) = &mut self.profile_form {
            form.auth_key_id = id;
            form.new_key_name = None;
        }
    }

    fn save_key_form(&mut self) {
        let Some(form) = &self.key_form else {
            return;
        };
        let Ok(key) = form.validate(&self.keys) else {
            return;
        };
        match self.keys.iter_mut().find(|k| k.id == key.id) {
            Some(slot) => *slot = key,
            None => self.keys.push(key),
        }
        self.persist_store();
        if self.notice.is_none() {
            // An edited secret reaches running sessions on their next connect.
            self.notice = Some("Saved — profiles using this key apply it on reconnect.".into());
        }
        self.key_form = None;
    }

    fn delete_key(&mut self, id: String) {
        self.confirm_export_key = None;
        // Shared keys never delete out from under a profile; repoint or
        // delete the profiles first.
        if let Some(user) = self.profiles.iter().find(|p| p.auth_key_id == id) {
            self.notice = Some(format!(
                "This key is used by profile \"{}\" — repoint or delete that profile first.",
                user.name
            ));
            self.confirm_delete_key = None;
            return;
        }
        if self.confirm_delete_key.as_deref() != Some(id.as_str()) {
            self.confirm_delete_key = Some(id);
            return;
        }
        self.confirm_delete_key = None;
        self.keys.retain(|k| k.id != id);
        self.key_form = None;
        // The sealed blob is rebuilt from the retained keys, so this also
        // erases the deleted key's secret.
        self.persist_store();
    }

    /// Two-click export: the second click puts the key's secret on the
    /// clipboard, ready to paste into another install's key form (or the iOS
    /// app's key import). The clipboard is the export channel on purpose —
    /// no secret ever lands in a file.
    fn export_key(&mut self, id: String) {
        self.confirm_delete_key = None;
        if self.confirm_export_key.as_deref() != Some(id.as_str()) {
            self.confirm_export_key = Some(id);
            return;
        }
        self.confirm_export_key = None;
        // The view never offers export for a secretless key, but the list can
        // change between the two clicks.
        let Some(key) = config::find_key(&self.keys, &id).filter(|k| !k.secret.is_empty()) else {
            return;
        };
        let (name, secret) = (key.name.clone(), key.secret.clone());
        self.copy_text(secret);
        self.notice = Some(format!(
            "Secret key of \"{name}\" copied — paste it into the key form of another install."
        ));
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
        self.persist_store();
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
        self.persist_store();
        self.io_notice = Some(format!(
            "Imported: {added} added, {} replaced.",
            replaced.len()
        ));
        // Land somewhere sensible if nothing (or a since-removed profile) was
        // selected; added profiles still need an auth key picked.
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

    fn persist_store(&mut self) {
        if let Err(e) = config::save_store(&self.keys, &self.profiles) {
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

    fn test_keys() -> Vec<AuthKey> {
        vec![AuthKey {
            id: "k1".into(),
            name: "work laptop".into(),
            public_key: "flxtpubv1:abc".into(),
            secret: "flxtsecretv1:xyz".into(),
        }]
    }

    fn valid_form() -> ProfileForm {
        ProfileForm {
            editing_id: None,
            name: " prod ".into(),
            server_node_id: " node-id ".into(),
            auth_key_id: "k1".into(),
            new_key_name: None,
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
            auth_key_id: "k1".into(),
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
        current[0].auth_key_id = "key-ref".into();
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
        assert_eq!(p1.auth_key_id, "key-ref", "key reference kept");
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
        assert!(new.auth_key_id.is_empty(), "no key reference in imports");
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
        let is_taken = |name: &str| profiles.iter().any(|p| p.name == name);

        assert_eq!(
            unique_name("fresh".into(), is_taken),
            "fresh",
            "free names pass through"
        );
        let bumped = unique_name(long.name.clone(), is_taken);
        assert_eq!(bumped, format!("{} - 2", "a".repeat(60)));
        assert!(bumped.len() <= 64);
        assert!(bumped.ends_with(" - 2"));
        assert!(config::is_valid_name(&bumped));
    }

    #[test]
    fn name_whitespace_is_normalized() {
        let mut form = valid_form();
        form.name = "  staging   aws \t kube  ".into();
        let profile = form.validate(&[], &test_keys()).expect("valid");
        assert_eq!(profile.name, "staging aws kube");
        assert!(config::is_valid_name(&profile.name));
    }

    #[test]
    fn validate_trims_and_parses() {
        let profile = valid_form().validate(&[], &test_keys()).expect("valid");
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
        let keys = test_keys();
        let mut form = valid_form();
        form.name = "  ".into();
        assert!(form.validate(&[], &keys).is_err());

        // No key picked, and a reference to a key that doesn't exist.
        let mut form = valid_form();
        form.auth_key_id = String::new();
        assert!(form.validate(&[], &keys).is_err());
        form.auth_key_id = "missing".into();
        assert!(form.validate(&[], &keys).is_err());

        let mut form = valid_form();
        form.socks_port = "0".into();
        assert!(form.validate(&[], &keys).is_err());

        let mut form = valid_form();
        form.http_enabled = true;
        form.http_port = form.socks_port.clone();
        assert!(form.validate(&[], &keys).is_err());

        let mut form = valid_form();
        form.server_node_id = "  ".into();
        assert!(form.validate(&[], &keys).is_err());

        // Duplicate profile name (they key tray submenus and log threads)…
        let existing = [existing_profile("p1", 2080, vec![])];
        let mut form = valid_form();
        form.name = " profile-p1 ".into();
        assert!(form.validate(&existing, &keys).is_err());
        // …unless it is the profile being edited.
        form.editing_id = Some("p1".into());
        assert!(form.validate(&existing, &keys).is_ok());

        // Duplicate server node id…
        let mut form = valid_form();
        form.server_node_id = "node".into();
        assert!(form.validate(&existing, &keys).is_err());
        // …unless it is the profile being edited.
        form.editing_id = Some("p1".into());
        assert!(form.validate(&existing, &keys).is_ok());
    }

    #[test]
    fn key_form_validates() {
        let keys = test_keys();
        let secret = flextunnel_core::auth::ClientKey::generate().secret_str();

        let form = KeyForm {
            editing_id: None,
            name: "  home   nas ".into(),
            secret: format!(" {secret} "),
        };
        let key = form.validate(&keys).expect("valid");
        assert_eq!(key.name, "home nas");
        assert_eq!(key.secret, secret);
        assert!(!key.id.is_empty());
        assert_eq!(
            Some(key.public_key.clone()),
            form.public_key(),
            "stored public key matches the derived one"
        );

        // Empty name, empty secret, unparsable secret.
        let mut bad = KeyForm {
            editing_id: None,
            name: String::new(),
            secret: secret.clone(),
        };
        assert!(bad.validate(&keys).is_err());
        bad.name = "ok".into();
        bad.secret = String::new();
        assert!(bad.validate(&keys).is_err());
        bad.secret = "not-a-key".into();
        assert!(bad.validate(&keys).is_err());

        // Duplicate name…
        let mut dup = KeyForm {
            editing_id: None,
            name: "work laptop".into(),
            secret: secret.clone(),
        };
        assert!(dup.validate(&keys).is_err());
        // …unless it is the key being edited.
        dup.editing_id = Some("k1".into());
        let edited = dup.validate(&keys).expect("editing the same key");
        assert_eq!(edited.id, "k1");

        // The same keypair under a second name is an accidental re-add.
        let mut existing_pair = keys.clone();
        existing_pair.push(KeyForm {
            editing_id: None,
            name: "first".into(),
            secret: secret.clone(),
        }
        .validate(&keys)
        .unwrap());
        let readd = KeyForm {
            editing_id: None,
            name: "second".into(),
            secret,
        };
        assert!(readd.validate(&existing_pair).is_err());
    }

    #[test]
    fn profile_ports_share_one_namespace() {
        let keys = test_keys();
        let existing = [existing_profile("p1", 1080, vec![existing_forward("f1", 5000)])];

        // Another profile's SOCKS port.
        let form = valid_form();
        assert!(form.validate(&existing, &keys).is_err());

        // Another profile's forward local port (as SOCKS or HTTP).
        let mut form = valid_form();
        form.socks_port = "5000".into();
        assert!(form.validate(&existing, &keys).is_err());
        let mut form = valid_form();
        form.socks_port = "1090".into();
        form.http_enabled = true;
        form.http_port = "5000".into();
        assert!(form.validate(&existing, &keys).is_err());

        // A free port is fine.
        let mut form = valid_form();
        form.socks_port = "1081".into();
        assert!(form.validate(&existing, &keys).is_ok());

        // Editing a profile skips its own proxy ports but keeps its forwards.
        let mut form = valid_form();
        form.editing_id = Some("p1".into());
        form.socks_port = "1080".into();
        let edited = form
            .validate(&existing, &keys)
            .expect("own port is not a clash");
        assert_eq!(edited.id, "p1");
        assert_eq!(edited.forwards, existing[0].forwards);

        // A forward in another profile can't take a port a new profile's own
        // forward holds — and vice versa (covered by forward_form tests).
        assert_eq!(next_free_port(&existing), 1081);
    }
}
