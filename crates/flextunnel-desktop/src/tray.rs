//! System tray icon + menu: an aggregate status line plus one submenu per
//! profile (status, Connect, Disconnect, Copy SOCKS5 Address). Created and
//! mutated only on the main thread (from the iced update loop); the tray-icon
//! event handlers installed by the tray subscription merely forward events and
//! wake the runtime, since they may fire off the main thread.
//!
//! Per-profile menu item ids carry the profile id after a prefix
//! (`connect:<id>`), parsed by `App::handle_menu_event`.

use crate::config::{AuthKey, Profile};
use crate::icon::{self, TrayState};
use crate::tunnel::{Phase, Snapshot};
use anyhow::Result;
use std::collections::HashMap;
use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{TrayIcon, TrayIconBuilder};

pub const MENU_OPEN: &str = "open";
pub const MENU_QUIT: &str = "quit";
pub const MENU_CONNECT_PREFIX: &str = "connect:";
pub const MENU_DISCONNECT_PREFIX: &str = "disconnect:";
pub const MENU_COPY_SOCKS_PREFIX: &str = "copy-socks:";

pub fn status_line(phase: Phase) -> &'static str {
    match phase {
        Phase::Idle => "Disconnected",
        Phase::Connecting => "Connecting…",
        Phase::Connected => "Connected",
        Phase::Reconnecting => "Reconnecting…",
        Phase::Failed => "Connection failed",
    }
}

fn profile_phase(snapshots: &HashMap<String, Snapshot>, id: &str) -> Phase {
    snapshots.get(id).map(|s| s.phase).unwrap_or(Phase::Idle)
}

/// The icon reflects the worst/most-notable state across profiles: a failure
/// beats connected beats in-progress beats idle. When at least one profile is
/// connected, the icon distinguishes "everything settled" ([`TrayState::AllConnected`],
/// checkmark) from "still working" ([`TrayState::Connected`], dot): the checkmark
/// shows only once no profile is still connecting or reconnecting.
fn aggregate_state(phases: &[Phase]) -> TrayState {
    if phases.contains(&Phase::Failed) {
        TrayState::Failed
    } else if phases.contains(&Phase::Connected) {
        let in_progress = phases
            .iter()
            .any(|p| matches!(p, Phase::Connecting | Phase::Reconnecting));
        if in_progress {
            TrayState::Connected
        } else {
            TrayState::AllConnected
        }
    } else if phases.contains(&Phase::Reconnecting) {
        TrayState::Reconnecting
    } else if phases.contains(&Phase::Connecting) {
        TrayState::Connecting
    } else {
        TrayState::Idle
    }
}

fn aggregate_line(phases: &[Phase]) -> String {
    let connected = phases.iter().filter(|p| **p == Phase::Connected).count();
    if phases.is_empty() {
        "No profiles".into()
    } else if connected > 0 {
        format!("{connected} of {} connected", phases.len())
    } else if phases.contains(&Phase::Failed) {
        "Connection failed".into()
    } else if phases
        .iter()
        .any(|p| matches!(p, Phase::Connecting | Phase::Reconnecting))
    {
        "Connecting…".into()
    } else {
        "Disconnected".into()
    }
}

/// Retained handles into one profile's submenu, mutated in place on phase
/// changes so the whole menu is only rebuilt when the profile set changes.
struct ProfileItems {
    status: MenuItem,
    connect: MenuItem,
    disconnect: MenuItem,
    copy_socks: MenuItem,
}

/// Everything `sync` reacts to; native calls only happen when it changes.
type SyncKey = (TrayState, String, Vec<(String, String, Phase, bool, bool)>);

pub struct Tray {
    tray: TrayIcon,
    status: MenuItem,
    items: HashMap<String, ProfileItems>,
    /// The `(id, name)` list the current menu was built from; a change (added,
    /// removed, renamed or reordered profile) rebuilds the menu.
    menu_profiles: Vec<(String, String)>,
    synced: Option<SyncKey>,
}

fn make_icon(state: TrayState) -> Result<tray_icon::Icon> {
    let (rgba, w, h) = icon::tray_rgba(state);
    Ok(tray_icon::Icon::from_rgba(rgba, w, h)?)
}

impl Tray {
    pub fn new() -> Result<Self> {
        let status = MenuItem::with_id("status", "Disconnected", false, None);
        let tray = TrayIconBuilder::new()
            .with_icon(make_icon(TrayState::Idle)?)
            .with_icon_as_template(icon::is_template())
            .with_menu(Box::new(Menu::new()))
            .with_tooltip("flextunnel — disconnected")
            // Windows convention: left click toggles the window (handled via
            // TrayIconEvent), right click opens the menu. macOS keeps the
            // native left-click menu.
            .with_menu_on_left_click(cfg!(target_os = "macos"))
            .build()?;

        let mut this = Self {
            tray,
            status,
            items: HashMap::new(),
            menu_profiles: Vec::new(),
            synced: None,
        };
        this.rebuild_menu(&[])?;
        Ok(this)
    }

    fn rebuild_menu(&mut self, profiles: &[Profile]) -> Result<()> {
        let menu = Menu::new();
        menu.append(&MenuItem::with_id(MENU_OPEN, "Open flextunnel…", true, None))?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&self.status)?;
        menu.append(&PredefinedMenuItem::separator())?;

        self.items.clear();
        for profile in profiles {
            let status =
                MenuItem::with_id(format!("profile-status:{}", profile.id), "…", false, None);
            let connect = MenuItem::with_id(
                format!("{MENU_CONNECT_PREFIX}{}", profile.id),
                "Connect",
                false,
                None,
            );
            let disconnect = MenuItem::with_id(
                format!("{MENU_DISCONNECT_PREFIX}{}", profile.id),
                "Disconnect",
                false,
                None,
            );
            let copy_socks = MenuItem::with_id(
                format!("{MENU_COPY_SOCKS_PREFIX}{}", profile.id),
                "Copy SOCKS5 Address",
                false,
                None,
            );
            let submenu = Submenu::with_items(
                &profile.name,
                true,
                &[&status, &connect, &disconnect, &copy_socks],
            )?;
            menu.append(&submenu)?;
            self.items.insert(
                profile.id.clone(),
                ProfileItems {
                    status,
                    connect,
                    disconnect,
                    copy_socks,
                },
            );
        }
        if !profiles.is_empty() {
            menu.append(&PredefinedMenuItem::separator())?;
        }

        menu.append(&MenuItem::with_id(
            "version",
            concat!("flextunnel v", env!("CARGO_PKG_VERSION")),
            false,
            None,
        ))?;
        menu.append(&MenuItem::with_id(MENU_QUIT, "Quit flextunnel", true, None))?;
        self.tray.set_menu(Some(Box::new(menu)));
        self.menu_profiles = profiles
            .iter()
            .map(|p| (p.id.clone(), p.name.clone()))
            .collect();
        Ok(())
    }

    /// Reflect the tunnel states in the icon/menu. Native calls only happen on
    /// a change; called every UI frame.
    pub fn sync(
        &mut self,
        profiles: &[Profile],
        keys: &[AuthKey],
        snapshots: &HashMap<String, Snapshot>,
    ) {
        let phases: Vec<Phase> = profiles
            .iter()
            .map(|p| profile_phase(snapshots, &p.id))
            .collect();
        let state = aggregate_state(&phases);
        let line = aggregate_line(&phases);
        let key: SyncKey = (
            state,
            line.clone(),
            profiles
                .iter()
                .zip(&phases)
                .map(|(p, phase)| {
                    let copyable = snapshots
                        .get(&p.id)
                        .is_some_and(|s| s.socks_addr.is_some());
                    (p.id.clone(), p.name.clone(), *phase, p.is_ready(keys), copyable)
                })
                .collect(),
        );
        if self.synced.as_ref() == Some(&key) {
            return;
        }
        let icon_changed = self.synced.as_ref().map(|(s, ..)| *s) != Some(state);
        self.synced = Some(key);

        let names: Vec<(String, String)> = profiles
            .iter()
            .map(|p| (p.id.clone(), p.name.clone()))
            .collect();
        if names != self.menu_profiles
            && let Err(e) = self.rebuild_menu(profiles)
        {
            log::error!("Failed to rebuild the tray menu: {e:#}");
            return;
        }

        self.status.set_text(&line);
        for profile in profiles {
            let Some(items) = self.items.get(&profile.id) else {
                continue;
            };
            let phase = profile_phase(snapshots, &profile.id);
            items.status.set_text(status_line(phase));
            items.connect.set_enabled(
                matches!(phase, Phase::Idle | Phase::Failed) && profile.is_ready(keys),
            );
            items.disconnect.set_enabled(matches!(
                phase,
                Phase::Connecting | Phase::Connected | Phase::Reconnecting
            ));
            items.copy_socks.set_enabled(
                phase == Phase::Connected
                    && snapshots
                        .get(&profile.id)
                        .is_some_and(|s| s.socks_addr.is_some()),
            );
        }

        if icon_changed
            && let Ok(icon) = make_icon(state)
        {
            // `set_icon` alone re-sets the macOS image as non-template
            // (rendering it solid black instead of adapting to the menu
            // bar), so pass the template flag through explicitly.
            let _ = self
                .tray
                .set_icon_with_as_template(Some(icon), icon::is_template());
        }
        let _ = self.tray.set_tooltip(Some(format!("flextunnel — {line}")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_connected_only_without_in_progress_profiles() {
        // No profiles / none connected: never the connected states.
        assert_eq!(aggregate_state(&[]), TrayState::Idle);
        assert_eq!(aggregate_state(&[Phase::Connecting]), TrayState::Connecting);

        // Every connecting profile has connected → checkmark. Idle profiles
        // aren't "connecting", so they don't hold back the checkmark.
        assert_eq!(aggregate_state(&[Phase::Connected]), TrayState::AllConnected);
        assert_eq!(
            aggregate_state(&[Phase::Connected, Phase::Connected]),
            TrayState::AllConnected
        );
        assert_eq!(
            aggregate_state(&[Phase::Connected, Phase::Idle]),
            TrayState::AllConnected
        );

        // A profile still in progress keeps the plain dot.
        assert_eq!(
            aggregate_state(&[Phase::Connected, Phase::Connecting]),
            TrayState::Connected
        );
        assert_eq!(
            aggregate_state(&[Phase::Connected, Phase::Reconnecting]),
            TrayState::Connected
        );

        // A failure still dominates over connected profiles.
        assert_eq!(
            aggregate_state(&[Phase::Connected, Phase::Failed]),
            TrayState::Failed
        );
    }
}
