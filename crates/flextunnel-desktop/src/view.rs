//! Widget tree for the profile-sidebar + detail-pane window, rendered from
//! [`App`] state — all pure functions of `&App`, every mutation flows back
//! through a [`Message`]. The look (cards, pills, ghost buttons, sidebar rows)
//! comes from the design system in [`crate::style`].

use crate::app::{
    format_duration, App, ForwardForm, KeyChoice, KeyForm, Message, ProfileForm, Selection,
    LOG_FILTER_ALL,
};
use crate::config::{self, AuthKey, Profile};
use flextunnel_core::forwards::{ForwardState, ForwardStatus, PortForward};
use crate::style::{self, AMBER, GRAY, GREEN, RED};
use crate::tunnel::{Phase, Snapshot};
use flextunnel_core::proxy::signaling::Target;
use flextunnel_core::proxy::{reserved, RoutedSet, TunnelRoutes};
use flextunnel_core::transport::paths::{ConnPathKind, ConnectionSnapshot, CustomRelayStatus};
use iced::widget::{
    button, center, checkbox, column, container, mouse_area, opaque, pick_list, row, scrollable,
    space, stack, text, text_input, toggler,
};
use iced::{Center, Color, Element, Fill, Font};
use std::net::SocketAddr;

/// Advisory-badge cache: the `RoutedSet` rebuilt only when the pushed
/// domains/CIDRs change (`None` inside means the set failed to parse).
pub type RoutedCache = Option<(Vec<String>, Vec<String>, Option<RoutedSet>)>;

/// Rebuild the advisory-badge `RoutedSet` only when the pushed routes change.
pub fn refresh_routed_cache(cache: &mut RoutedCache, routes: &TunnelRoutes) {
    let fresh = matches!(cache,
        Some((domains, cidrs, _)) if *domains == routes.domains && *cidrs == routes.cidrs);
    if !fresh {
        let set = RoutedSet::new(&routes.domains, &routes.cidrs)
            .inspect_err(|e| log::debug!("Routed set unusable for the badge: {e:#}"))
            .ok();
        *cache = Some((routes.domains.clone(), routes.cidrs.clone(), set));
    }
}

/// Everything is tunneled when the server pushes no routed set at all, a
/// wildcard domain, or an all-covering CIDR (mirrors the iOS derivation).
fn is_full_tunnel(routes: &TunnelRoutes) -> bool {
    (routes.domains.is_empty() && routes.cidrs.is_empty())
        || routes.domains.iter().any(|d| d == "*")
        || routes.cidrs.iter().any(|c| c == "0.0.0.0/0" || c == "::/0")
}

/// Advisory tunneled/direct badge for a forward (`None` = hidden). Mirrors the
/// core's routing decision — reserved hosts always tunnel, everything else per
/// the routed set — but never gates traffic; the core decides for real per
/// connection (like the iOS badge).
fn forward_badge(
    phase: Phase,
    routes: &TunnelRoutes,
    routed_set: Option<&RoutedSet>,
    forward: &PortForward,
) -> Option<bool> {
    if phase != Phase::Connected {
        return None;
    }
    if is_full_tunnel(routes) || reserved::is_reserved_host(&forward.remote_host) {
        return Some(true);
    }
    let set = routed_set?;
    Some(set.allows(&Target::Domain(
        forward.remote_host.clone(),
        forward.remote_port,
    )))
}

/// Live state pill for a forward row: gray "stopped", amber "starting…",
/// green "listening (· N)", red "failed" (the reason shows under the route).
fn forward_pill(
    forward: &PortForward,
    status: Option<&ForwardStatus>,
    phase: Phase,
) -> (String, Color) {
    if !forward.enabled {
        return ("stopped".into(), GRAY);
    }
    match status {
        Some(status) => match &status.state {
            ForwardState::Starting => ("starting…".into(), AMBER),
            ForwardState::Listening if status.active > 0 => {
                (format!("listening · {}", status.active), GREEN)
            }
            ForwardState::Listening => ("listening".into(), GREEN),
            ForwardState::Failed(_) => ("failed".into(), RED),
        },
        // No status = no running session for this forward. The profile's
        // connection banner explains the disconnected case in one place.
        None => match phase {
            Phase::Idle | Phase::Failed => ("stopped".into(), GRAY),
            _ => ("starting…".into(), AMBER),
        },
    }
}

fn phase_color(phase: Phase) -> Color {
    match phase {
        Phase::Idle => GRAY,
        Phase::Connecting | Phase::Reconnecting => AMBER,
        Phase::Connected => GREEN,
        Phase::Failed => RED,
    }
}

fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Idle => "disconnected",
        Phase::Connecting => "connecting…",
        Phase::Connected => "connected",
        Phase::Reconnecting => "reconnecting…",
        Phase::Failed => "failed",
    }
}

pub fn root(app: &App) -> Element<'_, Message> {
    let base = row![sidebar(app), detail_pane(app)];
    match &app.conn_path_modal {
        Some(snapshot) => modal(base, conn_path_modal(snapshot)),
        None => base.into(),
    }
}

/// Overlay `content`, centered on a dimmed backdrop, as a stack layer above
/// `base` — so it never touches `base`'s layout. Clicking the backdrop
/// dismisses; the content card swallows its own clicks.
fn modal<'a>(
    base: impl Into<Element<'a, Message>>,
    content: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    stack![
        base.into(),
        opaque(
            mouse_area(center(opaque(content)).style(|_theme| container::Style {
                background: Some(Color { a: 0.7, ..Color::BLACK }.into()),
                ..container::Style::default()
            }))
            .on_press(Message::DismissConnPath),
        ),
    ]
    .into()
}

/// The connection-path modal card: a point-in-time snapshot of how the profile
/// reaches the server, each path dotted by transport (direct/relay) with the
/// active one pilled — mirrors `ezvpn client status`.
fn conn_path_modal(snapshot: &ConnectionSnapshot) -> Element<'_, Message> {
    let mut card = column![
        row![
            text("Connection path").size(15).font(semibold()),
            space().width(Fill),
            button(text("Close").size(12))
                .padding([3, 10])
                .style(style::ghost)
                .on_press(Message::DismissConnPath),
        ]
        .align_y(Center),
        text("Snapshot taken just now — how this profile reaches the server.")
            .size(11)
            .style(style::dim_text),
    ]
    .spacing(10);

    if snapshot.paths.is_empty() {
        card = card.push(
            text("No path available — close this and try again in a moment.")
                .size(12)
                .style(style::dim_text),
        );
    } else {
        for path in &snapshot.paths {
            let color = match path.kind {
                ConnPathKind::Direct => GREEN,
                ConnPathKind::Relay => AMBER,
                ConnPathKind::Other => GRAY,
            };
            let mut r = row![dot(color, 7.0), mono(path.display.clone())]
                .spacing(8)
                .align_y(Center);
            if path.selected {
                r = r.push(pill("active".to_string(), GREEN));
            }
            card = card.push(r);
        }
    }

    // Custom-relay health, from an on-demand /healthz probe. Empty with the
    // default iroh relays. /healthz is unauthenticated — it confirms the relay
    // is up, not that a relay auth token is accepted.
    if !snapshot.custom_relays.is_empty() {
        card = card.push(
            text("Custom relays")
                .size(12)
                .font(semibold())
                .style(style::dim_text),
        );
        for relay in &snapshot.custom_relays {
            card = card.push(custom_relay_row(relay));
        }
    }

    container(card)
        .padding([16, 18])
        .max_width(480)
        .style(style::card)
        .into()
}

/// One custom relay's health row: its URL plus a colored status derived from the
/// on-demand `/healthz` probe — `working` is `Some(true)` (up), `Some(false)`
/// (down, with the error), or `None` (the check could not run).
fn custom_relay_row(relay: &CustomRelayStatus) -> Element<'_, Message> {
    let (color, status) = match relay.working {
        Some(true) => (GREEN, "Reachable".to_string()),
        Some(false) => (
            RED,
            relay
                .error
                .clone()
                .map(|e| format!("Unreachable — {e}"))
                .unwrap_or_else(|| "Unreachable".to_string()),
        ),
        None => (GRAY, "Status unavailable".to_string()),
    };
    column![
        row![dot(color, 7.0), mono(relay.url.clone())]
            .spacing(8)
            .align_y(Center),
        text(status).size(11).color(color),
    ]
    .spacing(3)
    .into()
}

// ---------------------------------------------------------------------------
// Sidebar

fn sidebar(app: &App) -> Element<'_, Message> {
    let header = row![
        section_label("PROFILES"),
        space().width(Fill),
        button(text("+").size(14).font(semibold()))
            .padding([1, 9])
            .style(style::tinted)
            .on_press(Message::AddProfile),
    ]
    .align_y(Center);

    let mut list = column![].spacing(2);
    for profile in &app.profiles {
        list = list.push(sidebar_profile_row(app, profile));
    }

    let keys_selected = app.selection == Selection::Keys && app.profile_form.is_none();
    let keys_row = button(text("Keys").size(13))
        .padding([6, 10])
        .width(Fill)
        .style(style::sidebar_row(keys_selected))
        .on_press(Message::Select(Selection::Keys));

    let logs_selected = app.selection == Selection::Logs && app.profile_form.is_none();
    let logs_row = button(text("Logs").size(13))
        .padding([6, 10])
        .width(Fill)
        .style(style::sidebar_row(logs_selected))
        .on_press(Message::Select(Selection::Logs));

    let io_row = row![
        button(text("Export").size(11))
            .padding([3, 10])
            .style(style::ghost)
            .on_press_maybe((!app.profiles.is_empty()).then_some(Message::ExportProfiles)),
        button(text("Import").size(11))
            .padding([3, 10])
            .style(style::ghost)
            .on_press(Message::ImportProfiles),
    ]
    .spacing(4);

    let mut footer = column![keys_row, logs_row, io_row].spacing(6);
    if let Some(notice) = &app.io_notice {
        footer = footer.push(text(notice.as_str()).size(10).style(style::dim_text));
    }
    footer = footer.push(
        text(concat!("v", env!("CARGO_PKG_VERSION")))
            .size(10)
            .style(style::faint_text),
    );

    container(
        column![header, scrollable(list).height(Fill).spacing(4), footer].spacing(10),
    )
    .padding([14, 12])
    .width(210)
    .height(Fill)
    .style(style::sidebar)
    .into()
}

fn sidebar_profile_row<'a>(app: &'a App, profile: &'a Profile) -> Element<'a, Message> {
    let snapshot = app.snapshot_for(&profile.id);
    let selected = app.selection == Selection::Profile(profile.id.clone())
        && app.profile_form.is_none();

    let title = row![
        dot(phase_color(snapshot.phase), 8.0),
        text(profile.name.as_str()).size(13).font(semibold()),
    ]
    .spacing(7)
    .align_y(Center);

    let running = profile
        .forwards
        .iter()
        .filter(|f| {
            f.enabled
                && snapshot
                    .forwards
                    .iter()
                    .any(|s| s.id == f.id && s.state == ForwardState::Listening)
        })
        .count();
    let mut counts = format!(
        "{} forward{}",
        profile.forwards.len(),
        if profile.forwards.len() == 1 { "" } else { "s" }
    );
    if running > 0 {
        counts.push_str(&format!(" · {running} running"));
    }

    let mut content = column![title].spacing(3);
    content = content.push(
        row![
            space().width(15),
            text(counts).size(11).style(if running > 0 {
                |_: &iced::Theme| iced::widget::text::Style { color: Some(GREEN) }
            } else {
                style::faint_text
            }),
        ]
        .align_y(Center),
    );
    for forward in &profile.forwards {
        let status = snapshot.forwards.iter().find(|s| s.id == forward.id);
        let (_, color) = forward_pill(forward, status, snapshot.phase);
        content = content.push(
            row![
                space().width(15),
                dot(color, 5.0),
                text(forward.display_name()).size(11).style(style::dim_text),
            ]
            .spacing(6)
            .align_y(Center),
        );
    }

    button(content)
        .padding([7, 10])
        .width(Fill)
        .style(style::sidebar_row(selected))
        .on_press(Message::Select(Selection::Profile(profile.id.clone())))
        .into()
}

// ---------------------------------------------------------------------------
// Detail pane

fn detail_pane(app: &App) -> Element<'_, Message> {
    let content: Element<'_, Message> = if let Some(form) = &app.profile_form {
        profile_form_view(app, form)
    } else {
        match &app.selection {
            Selection::Keys => keys_pane(app),
            Selection::Logs => logs_pane(app),
            Selection::Profile(id) => match app.profile(id) {
                Some(profile) => profile_detail(app, profile),
                None => empty_state(),
            },
        }
    };
    container(content).padding(16).width(Fill).height(Fill).into()
}

fn empty_state() -> Element<'static, Message> {
    container(
        column![
            text("No profiles yet.").size(14).style(style::dim_text),
            button(text("+ Add profile").size(13).font(semibold()))
                .padding([6, 14])
                .style(style::tinted)
                .on_press(Message::AddProfile),
        ]
        .spacing(12)
        .align_x(Center),
    )
    .width(Fill)
    .height(Fill)
    .align_x(Center)
    .align_y(Center)
    .into()
}

fn profile_detail<'a>(app: &'a App, profile: &'a Profile) -> Element<'a, Message> {
    let snapshot = app.snapshot_for(&profile.id);
    let ready = profile.is_ready(&app.keys);

    let mut hero = row![
        dot(phase_color(snapshot.phase), 12.0),
        text(profile.name.as_str()).size(20).font(semibold()),
        pill(phase_label(snapshot.phase).to_string(), phase_color(snapshot.phase)),
    ]
    .spacing(10)
    .align_y(Center);
    if let Some(since) = snapshot.connected_since {
        hero = hero.push(
            text(format!("for {}", format_duration(since.elapsed())))
                .size(13)
                .style(style::dim_text),
        );
    }
    hero = hero.push(space().width(Fill));
    hero = hero.push(match snapshot.phase {
        Phase::Idle | Phase::Failed => button(text("Connect").size(13).font(semibold()))
            .padding([7, 16])
            .style(style::primary)
            .on_press_maybe(ready.then(|| Message::Connect(profile.id.clone()))),
        _ => button(text("Disconnect").size(13))
            .padding([7, 16])
            .style(style::outlined)
            .on_press(Message::Disconnect(profile.id.clone())),
    });

    let mut col = column![hero].spacing(12);

    if let Some(notice) = &app.notice {
        col = col.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    if let Some(error) = &snapshot.last_error {
        col = col.push(text(error.as_str()).size(12).color(RED));
    }
    if !ready {
        let fix = match config::find_key(&app.keys, &profile.auth_key_id) {
            // The key exists but its secret was lost from the keychain.
            Some(key) => format!(
                "The secret of key \"{}\" is missing — re-enter it in the Keys pane.",
                key.name
            ),
            None => "No auth key picked — edit the profile to pick one.".into(),
        };
        col = col.push(text(fix).size(12).color(AMBER));
    }

    // CONNECTION card
    let node_id = profile.server_node_id.clone();
    let socks = snapshot
        .socks_addr
        .or_else(|| profile.socks_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p))))
        .map(|addr| addr.to_string());
    let http = snapshot
        .http_addr
        .or_else(|| profile.http_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p))))
        .map(|a| a.to_string());

    let copy_node = (!node_id.is_empty()).then(|| node_id.clone());
    let mut info = column![
        // The full id never fits (and iced has no ellipsis overflow); both
        // ends stay visible for eyeballing, Copy carries the whole thing.
        info_row("Server node id", truncate_middle(&node_id, 22), copy_node),
    ]
    .spacing(8);
    // The key's public half is not a secret — always shown unmasked so it can
    // be copied onto the server's authorized-keys file. (The secret never
    // appears anywhere in the UI.)
    if let Some(key) = config::find_key(&app.keys, &profile.auth_key_id) {
        info = info.push(info_row(
            "Auth key",
            format!("{} ({})", key.name, truncate_middle(&key.public_key, 14)),
            Some(key.public_key.clone()),
        ));
    }
    if let Some(socks) = socks {
        let copy = Some(format!("socks5://{socks}"));
        info = info.push(info_row("SOCKS5 proxy", socks, copy));
    }
    if let Some(http) = http {
        let copy = Some(format!("http://{http}"));
        info = info.push(info_row("HTTP proxy", http, copy));
    }
    let mut header = row![section_label("CONNECTION"), space().width(Fill)].align_y(Center);
    if snapshot.phase == Phase::Connected {
        // A one-shot readout of the live iroh path, shown in a dismissable
        // modal overlay (see `App::conn_path_modal`) — a point-in-time check
        // rather than a live field.
        header = header.push(
            button(text("Connection path").size(12))
                .padding([3, 10])
                .style(style::ghost)
                .on_press(Message::ShowConnPath),
        );
    }
    header = header.push(
        button(text("Edit").size(12))
            .padding([3, 10])
            .style(style::ghost)
            .on_press(Message::EditProfile(profile.id.clone())),
    );
    col = col.push(header);
    col = col.push(container(info).padding([12, 14]).width(Fill).style(style::card));

    if snapshot.phase == Phase::Connected {
        col = col.push(section_label("ROUTING"));
        col = col.push(
            container(routes_section(snapshot))
                .padding([12, 14])
                .width(Fill)
                .style(style::card),
        );
    }

    // FORWARDINGS
    if let Some(banner) = connection_banner(profile, ready, snapshot) {
        col = col.push(banner);
    }
    col = col.push(
        row![
            section_label(if profile.forwards.is_empty() {
                "PORT FORWARDS".to_string()
            } else {
                format!("PORT FORWARDS · {}", profile.forwards.len())
            }),
            space().width(Fill),
            button(text("+ Add").size(12).font(semibold()))
                .padding([4, 12])
                .style(style::tinted)
                .on_press(Message::AddForward(profile.id.clone())),
        ]
        .align_y(Center),
    );

    // Inline add/edit form — one at a time; an inline card fits the window
    // better than a separate one.
    if let Some((form_profile, form)) = &app.forward_form
        && *form_profile == profile.id
    {
        col = col.push(forward_form_view(app, form));
    }

    if profile.forwards.is_empty() {
        col = col.push(
            container(
                text("No port forwards yet. Add one to expose a remote service on localhost.")
                    .size(12)
                    .style(style::dim_text),
            )
            .padding(24)
            .width(Fill)
            .align_x(Center)
            .style(style::card),
        );
    } else {
        let routed_set = app
            .routed_caches
            .get(&profile.id)
            .and_then(|c| c.as_ref())
            .and_then(|(_, _, set)| set.as_ref());
        for forward in &profile.forwards {
            col = col.push(forward_card(app, profile, forward, snapshot, routed_set));
        }
        col = col.push(
            text(
                "Forwards listen on localhost only (127.0.0.1 and ::1) and open \
                 server-direct tunnel streams. The server rejects targets outside its tunnel set.",
            )
            .size(11)
            .style(style::faint_text),
        );
    }

    // Delete, tucked at the very bottom behind a two-click confirm.
    let confirming = app.confirm_delete.as_deref() == Some(profile.id.as_str());
    col = col.push(space().height(8));
    col = col.push(
        row![button(
            text(if confirming {
                "Click again to delete this profile"
            } else {
                "Delete profile…"
            })
            .size(12)
        )
        .padding([4, 12])
        .style(style::ghost_danger)
        .on_press(Message::DeleteProfile(profile.id.clone()))]
        .align_y(Center),
    );

    scrollable(col.padding([0, 4])).height(Fill).spacing(4).into()
}

/// One tinted banner explaining why forwards aren't live, with an inline
/// Connect button where that's the fix — instead of every row repeating it.
fn connection_banner<'a>(
    profile: &'a Profile,
    ready: bool,
    snapshot: &'a Snapshot,
) -> Option<Element<'a, Message>> {
    let (color, message, show_connect) = match snapshot.phase {
        Phase::Connected => return None,
        Phase::Idle => (
            AMBER,
            "Not connected — forwards are inactive until you connect.",
            true,
        ),
        Phase::Failed => (
            RED,
            "Connection failed — forwards are inactive until you reconnect.",
            true,
        ),
        Phase::Connecting => (AMBER, "Connecting — forwards start automatically.", false),
        Phase::Reconnecting => (AMBER, "Reconnecting — forwards resume automatically.", false),
    };
    let mut r = row![dot(color, 8.0), text(message).size(12)]
        .spacing(8)
        .align_y(Center);
    if show_connect {
        r = r.push(space().width(Fill));
        r = r.push(
            button(text("Connect").size(11).font(semibold()))
                .padding([3, 10])
                .style(style::tinted)
                .on_press_maybe(ready.then(|| Message::Connect(profile.id.clone()))),
        );
    }
    Some(
        container(r)
            .padding([9, 12])
            .width(Fill)
            .style(style::banner(color))
            .into(),
    )
}

fn forward_form_view<'a>(app: &'a App, form: &'a ForwardForm) -> Element<'a, Message> {
    let validated = form.validate(&app.profiles);

    let mut col = column![
        text(if form.is_edit() {
            "Edit forward"
        } else {
            "Add forward"
        })
        .size(13)
        .font(semibold()),
        form_row(
            "Label",
            input("optional", &form.label, Message::FormLabelChanged),
        ),
        form_row(
            "Local port",
            input("", &form.local_port, Message::FormLocalPortChanged).width(90),
        ),
        form_row(
            "Remote host",
            input(
                "host or IP — resolved server-side",
                &form.remote_host,
                Message::FormRemoteHostChanged,
            ),
        ),
        form_row(
            "Remote port",
            input("", &form.remote_port, Message::FormRemotePortChanged).width(90),
        ),
        form_row(
            "Enabled",
            checkbox(form.enabled)
                .on_toggle(Message::FormEnabledToggled)
                .style(style::check),
        ),
    ]
    .spacing(10);

    if let Err(message) = &validated {
        col = col.push(text(message.clone()).size(12).color(AMBER));
    }
    col = col.push(
        row![
            button(text("Save").size(13).font(semibold()))
                .padding([6, 16])
                .style(style::primary)
                .on_press_maybe(validated.is_ok().then_some(Message::FormSave)),
            button(text("Cancel").size(13))
                .padding([6, 16])
                .style(style::outlined)
                .on_press(Message::FormCancel),
        ]
        .spacing(8),
    );

    container(col)
        .padding([12, 14])
        .width(Fill)
        .style(style::card)
        .into()
}

fn forward_card<'a>(
    app: &'a App,
    profile: &'a Profile,
    forward: &'a PortForward,
    snapshot: &'a Snapshot,
    routed_set: Option<&RoutedSet>,
) -> Element<'a, Message> {
    let status = snapshot.forwards.iter().find(|s| s.id == forward.id);
    let (pill_text, pill_color) = forward_pill(forward, status, snapshot.phase);

    // The name stays prominent even while stopped — the pill and the switch
    // carry the state.
    let name = text(forward.display_name()).size(14).font(semibold());

    let mut title = row![name, pill(pill_text, pill_color)]
        .spacing(8)
        .align_y(Center);
    if let Some(tunneled) = forward_badge(snapshot.phase, &snapshot.routes, routed_set, forward) {
        let (badge, color) = if tunneled {
            ("server-direct", GREEN)
        } else {
            ("not routed", AMBER)
        };
        title = title.push(pill(badge.to_string(), color));
    }

    let route = arrow_copy_row(forward.local_endpoint(), forward.remote_endpoint(), true);

    let mut info = column![title, route].spacing(5).width(Fill);
    // A live bind failure (before the switch snaps back off), then the
    // retained reason after the auto-disable, then per-connection errors.
    if let Some(ForwardState::Failed(reason)) = status.map(|s| &s.state) {
        info = info.push(text(reason.clone()).size(11).color(RED));
    }
    if let Some(reason) = app.forward_errors.get(&forward.id) {
        info = info.push(text(reason.as_str()).size(11).color(RED));
    }
    if forward.enabled
        && let Some(error) = status.and_then(|s| s.last_conn_error.as_deref())
    {
        info = info.push(text(error).size(11).color(AMBER));
    }

    let profile_id = profile.id.clone();
    let forward_id = forward.id.clone();
    let controls = row![
        button(text("Edit").size(12))
            .padding([4, 10])
            .style(style::ghost)
            .on_press(Message::EditForward(profile.id.clone(), forward.id.clone())),
        button(text("Delete").size(12))
            .padding([4, 10])
            .style(style::ghost_danger)
            .on_press(Message::DeleteForward(profile.id.clone(), forward.id.clone())),
        // Desired state, but not a plain checkbox: enabling attempts the
        // setup now, and a setup failure snaps the switch back off (see
        // disable_failed_forwards).
        toggler(forward.enabled)
            .on_toggle(move |enabled| {
                Message::ToggleForward(profile_id.clone(), forward_id.clone(), enabled)
            })
            .size(20)
            .style(style::switch),
    ]
    .spacing(4)
    .align_y(Center);

    container(row![info, controls].spacing(12).align_y(Center))
        .padding([12, 14])
        .width(Fill)
        .style(style::card)
        .into()
}

fn routes_section(snapshot: &Snapshot) -> Element<'_, Message> {
    let routes = &snapshot.routes;
    let mut col = column![].spacing(3);
    if is_full_tunnel(routes) {
        col = col.push(text("Everything through the tunnel").size(12));
    } else {
        col = col.push(
            text(format!(
                "Split tunnel — {} domain(s), {} CIDR(s) routed through the server:",
                routes.domains.len(),
                routes.cidrs.len()
            ))
            .size(12),
        );
        for domain in &routes.domains {
            col = col.push(route_row(domain.clone(), None));
        }
        for cidr in &routes.cidrs {
            col = col.push(route_row(cidr.clone(), None));
        }
    }
    if !routes.host_aliases.is_empty() {
        col = col.push(space().height(8));
        col = col.push(
            text(format!(
                "Host aliases — {} resolved server-side:",
                routes.host_aliases.len()
            ))
            .size(12),
        );
        for (alias, target) in &routes.host_aliases {
            col = col.push(arrow_copy_row(alias.clone(), target.clone(), false));
        }
    }
    if !routes.dns_forwards.is_empty() {
        col = col.push(space().height(8));
        col = col.push(
            text(format!(
                "DNS forwards — {} resolved via upstream server(s):",
                routes.dns_forwards.len()
            ))
            .size(12),
        );
        for (suffix, servers) in &routes.dns_forwards {
            col = col.push(arrow_copy_row(
                format!("{suffix} (+ subdomains)"),
                servers.join(", "),
                false,
            ));
        }
    }
    if !routes.bridges.is_empty() {
        col = col.push(space().height(8));
        col = col.push(
            text(format!(
                "Bridge routes — {} forwarded via another server:",
                routes.bridges.len()
            ))
            .size(12),
        );
        for bridge in &routes.bridges {
            col = col.push(space().height(4));
            col = col.push(mono(format!("{}:", bridge.name)));
            col = col.push(
                row![
                    space().width(16),
                    text("endpoint id:").size(12).style(style::dim_text),
                    mono(bridge.endpoint_id.clone()),
                    copy_button(bridge.endpoint_id.clone()),
                ]
                .spacing(6)
                .align_y(Center),
            );
            if !bridge.domains.is_empty() {
                col = col.push(indented_label("routed domains:"));
                for d in &bridge.domains {
                    col = col.push(indented_item(d));
                }
            }
            if !bridge.cidrs.is_empty() {
                col = col.push(indented_label("routed CIDRs:"));
                for c in &bridge.cidrs {
                    col = col.push(indented_item(c));
                }
            }
        }
    }
    // The reserved status host is always tunneled to the server, regardless of
    // the routed set — surface it so it's discoverable (and copyable).
    col = col.push(space().height(8));
    col = col.push(text("Server status page — always tunneled:").size(12));
    col = col.push(route_row(reserved::STATUS_HOST.to_string(), None));
    col.into()
}

// ---------------------------------------------------------------------------
// Profile form

fn profile_form_view<'a>(app: &'a App, form: &'a ProfileForm) -> Element<'a, Message> {
    let mut socks = row![checkbox(form.socks_enabled)
        .label("enable")
        .text_size(13)
        .on_toggle(Message::SocksEnabledToggled)
        .style(style::check)]
    .spacing(10)
    .align_y(Center);
    if form.socks_enabled {
        socks = socks.push(text("port").size(12).style(style::dim_text));
        socks = socks.push(input("", &form.socks_port, Message::SocksPortChanged).width(90));
    }
    let mut http = row![checkbox(form.http_enabled)
        .label("enable")
        .text_size(13)
        .on_toggle(Message::HttpEnabledToggled)
        .style(style::check)]
    .spacing(10)
    .align_y(Center);
    if form.http_enabled {
        http = http.push(text("port").size(12).style(style::dim_text));
        http = http.push(input("", &form.http_port, Message::HttpPortChanged).width(90));
    }

    let validated = form.validate(&app.profiles, &app.keys);

    let mut card = column![
        form_row("Name", input("e.g. prod", &form.name, Message::ProfileNameChanged)),
        form_row(
            "Server node id",
            input("", &form.server_node_id, Message::ServerNodeIdChanged),
        ),
    ]
    .spacing(10);
    if let Some(new_name) = &form.new_key_name {
        // The "New key" prompt replaces the picker and public-key rows while
        // open, so the form shows exactly one key flow at a time: name the
        // key, then Create generates the keypair, adds it to the shared list,
        // and selects it; Cancel returns to the picker.
        let name_check = crate::app::validate_key_name(new_name, &app.keys, None);
        card = card.push(form_row(
            "New key name",
            row![
                input("e.g. work laptop", new_name, Message::NewKeyNameChanged).width(240),
                button(text("Create").size(12).font(semibold()))
                    .padding([4, 10])
                    .style(style::primary)
                    .on_press_maybe(name_check.is_ok().then_some(Message::NewKeyCreate)),
                button(text("Cancel").size(12))
                    .padding([4, 10])
                    .style(style::outlined)
                    .on_press(Message::NewKeyCancel),
            ]
            .spacing(8)
            .align_y(Center),
        ));
        // Only nag once something was typed — an empty prompt just opened.
        if let Err(message) = &name_check
            && !new_name.is_empty()
        {
            card = card.push(text(message.clone()).size(12).color(AMBER));
        }
    } else {
        // Keys are shared across profiles: pick one from the list (managed in
        // the Keys pane), or mint a fresh one right here with "New key…".
        let choices: Vec<KeyChoice> = app
            .keys
            .iter()
            .map(|k| KeyChoice {
                id: k.id.clone(),
                name: k.name.clone(),
            })
            .collect();
        let selected = choices.iter().find(|c| c.id == form.auth_key_id).cloned();
        card = card.push(form_row(
            "Auth key",
            row![
                pick_list(choices, selected, Message::AuthKeyPicked)
                    .placeholder(if app.keys.is_empty() {
                        "no keys yet"
                    } else {
                        "pick a key"
                    })
                    .text_size(13)
                    .width(240),
                button(text("New key…").size(12))
                    .padding([4, 10])
                    .style(style::outlined)
                    .on_press(Message::NewKeyPrompt),
            ]
            .spacing(8)
            .align_y(Center),
        ));
        if let Some(key) = config::find_key(&app.keys, &form.auth_key_id) {
            card = card.push(form_row(
                "Public key",
                row![
                    text(truncate_middle(&key.public_key, 30)).size(12).font(Font::MONOSPACE),
                    copy_button(key.public_key.clone()),
                ]
                .spacing(8)
                .align_y(Center),
            ));
        }
    }
    card = card.extend([
        form_row("SOCKS5 proxy", socks),
        form_row("HTTP proxy", http),
        form_row(
            "Relay URLs",
            input(
                "comma-separated, optional",
                &form.relay_urls,
                Message::RelayUrlsChanged,
            ),
        ),
        form_row(
            "Relay auth token",
            input(
                "optional, custom relays only",
                &form.relay_auth_token,
                Message::RelayAuthTokenChanged,
            )
            .secure(true)
            .width(240),
        ),
    ]);

    if let Err(message) = &validated {
        card = card.push(text(message.clone()).size(12).color(AMBER));
    }
    let mut buttons = row![
        button(text("Save").size(13).font(semibold()))
            .padding([6, 16])
            .style(style::primary)
            .on_press_maybe(validated.is_ok().then_some(Message::ProfileFormSave)),
        button(text("Cancel").size(13))
            .padding([6, 16])
            .style(style::outlined)
            .on_press(Message::ProfileFormCancel),
    ]
    .spacing(8)
    .align_y(Center);
    if let Some(notice) = &app.notice {
        buttons = buttons.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    card = card.push(buttons);

    column![
        section_label(if form.is_edit() {
            "EDIT PROFILE"
        } else {
            "NEW PROFILE"
        }),
        container(card).padding([12, 14]).width(Fill).style(style::card),
        text("Auth keys are shared — any number of profiles can pick the same one (manage them \
              in the Keys pane). Give the public key to the server operator \
              (authorized_keys_file).")
            .size(11)
            .style(style::faint_text),
    ]
    .spacing(10)
    .into()
}

// ---------------------------------------------------------------------------
// Keys pane

fn keys_pane(app: &App) -> Element<'_, Message> {
    let header = row![
        section_label(if app.keys.is_empty() {
            "AUTH KEYS".to_string()
        } else {
            format!("AUTH KEYS · {}", app.keys.len())
        }),
        space().width(Fill),
        button(text("+ Add key").size(12).font(semibold()))
            .padding([4, 12])
            .style(style::tinted)
            .on_press(Message::AddKey),
    ]
    .align_y(Center);

    let mut col = column![header].spacing(12);
    if let Some(notice) = &app.notice {
        col = col.push(text(notice.as_str()).size(12).style(style::dim_text));
    }
    if let Some(form) = &app.key_form {
        col = col.push(key_form_view(app, form));
    }

    if app.keys.is_empty() {
        col = col.push(
            container(
                text("No auth keys yet. Add one to authenticate profiles with — any number \
                      of profiles can share the same key.")
                    .size(12)
                    .style(style::dim_text),
            )
            .padding(24)
            .width(Fill)
            .align_x(Center)
            .style(style::card),
        );
    }
    for key in &app.keys {
        col = col.push(key_card(app, key));
    }
    col = col.push(
        text("Secret halves live in the system keychain; names and public keys in a local \
              file. Put a key's public half on each server's authorized_keys_file.")
            .size(11)
            .style(style::faint_text),
    );

    scrollable(col.padding([0, 4])).height(Fill).spacing(4).into()
}

fn key_card<'a>(app: &'a App, key: &'a AuthKey) -> Element<'a, Message> {
    let users: Vec<&str> = app
        .profiles
        .iter()
        .filter(|p| p.auth_key_id == key.id)
        .map(|p| p.name.as_str())
        .collect();
    let confirming = app.confirm_delete_key.as_deref() == Some(key.id.as_str());

    let header = row![
        text(key.name.as_str()).size(14).font(semibold()),
        space().width(Fill),
        button(text("Edit").size(12))
            .padding([3, 10])
            .style(style::ghost)
            .on_press(Message::EditKey(key.id.clone())),
        button(
            text(if confirming { "Click again to delete" } else { "Delete…" }).size(12)
        )
        .padding([3, 10])
        .style(style::ghost_danger)
        .on_press(Message::DeleteKey(key.id.clone())),
    ]
    .spacing(6)
    .align_y(Center);

    let mut card = column![
        header,
        info_row(
            "Public key",
            truncate_middle(&key.public_key, 30),
            Some(key.public_key.clone()),
        ),
    ]
    .spacing(8);
    if key.secret.is_empty() {
        card = card.push(
            text("Secret missing from the keychain — edit this key to re-enter it.")
                .size(12)
                .color(AMBER),
        );
    }
    card = card.push(
        text(if users.is_empty() {
            "Not used by any profile.".to_string()
        } else {
            format!("Used by: {}", users.join(", "))
        })
        .size(11)
        .style(style::faint_text),
    );

    container(card).padding([12, 14]).width(Fill).style(style::card).into()
}

fn key_form_view<'a>(app: &'a App, form: &'a KeyForm) -> Element<'a, Message> {
    let validated = form.validate(&app.keys);

    // The secret stays masked; the derived public key below is not a secret
    // and is always shown unmasked (it's what goes on the server's
    // authorized-keys file).
    let secret = row![
        input("flextunnelsecretv1:…", &form.secret, Message::KeySecretChanged)
            .secure(true)
            .width(240),
        button(text("Generate").size(12))
            .padding([4, 10])
            .style(style::outlined)
            .on_press(Message::KeyGenerateSecret),
    ]
    .spacing(8)
    .align_y(Center);

    let mut col = column![
        text(if form.is_edit() { "Edit key" } else { "Add key" })
            .size(13)
            .font(semibold()),
        form_row("Name", input("e.g. work laptop", &form.name, Message::KeyNameChanged)),
        form_row("Secret key", secret),
    ]
    .spacing(10);
    if let Some(public_key) = form.public_key() {
        col = col.push(form_row(
            "Public key",
            row![
                text(truncate_middle(&public_key, 30)).size(12).font(Font::MONOSPACE),
                copy_button(public_key),
            ]
            .spacing(8)
            .align_y(Center),
        ));
    }

    if let Err(message) = &validated {
        col = col.push(text(message.clone()).size(12).color(AMBER));
    }
    col = col.push(
        row![
            button(text("Save").size(13).font(semibold()))
                .padding([6, 16])
                .style(style::primary)
                .on_press_maybe(validated.is_ok().then_some(Message::KeyFormSave)),
            button(text("Cancel").size(13))
                .padding([6, 16])
                .style(style::outlined)
                .on_press(Message::KeyFormCancel),
        ]
        .spacing(8)
        .align_y(Center),
    );

    container(col).padding([12, 14]).width(Fill).style(style::card).into()
}

// ---------------------------------------------------------------------------
// Logs

fn logs_pane(app: &App) -> Element<'_, Message> {
    let mut filter_options: Vec<String> = vec![LOG_FILTER_ALL.into()];
    filter_options.extend(app.profiles.iter().map(|p| p.name.clone()));
    let selected = app
        .log_filter
        .clone()
        .unwrap_or_else(|| LOG_FILTER_ALL.into());

    let header = row![
        section_label("LOGS".to_string()),
        space().width(Fill),
        pick_list(filter_options, Some(selected), Message::LogFilterChanged)
            .text_size(12)
            .padding([3, 8])
            .style(style::picker)
            .menu_style(style::picker_menu),
        button(text("Open folder").size(12))
            .padding([4, 10])
            .style(style::ghost)
            .on_press(Message::OpenLogFolder),
        button(text("Copy all").size(12))
            .padding([4, 10])
            .style(style::ghost)
            .on_press(Message::CopyLogs),
    ]
    .spacing(4)
    .align_y(Center);

    let log = scrollable(
        text(app.log_text.as_str())
            .size(11)
            .font(Font::MONOSPACE)
            .width(Fill),
    )
    .direction(scrollable::Direction::Vertical(
        scrollable::Scrollbar::new().spacing(4),
    ))
    .anchor_bottom()
    .width(Fill)
    .height(Fill);

    column![
        header,
        container(log)
            .padding([8, 10])
            .width(Fill)
            .height(Fill)
            .style(style::card),
    ]
    .spacing(10)
    .into()
}

// ---------------------------------------------------------------------------
// Shared bits

fn info_row(label: &'static str, value: String, copy: Option<String>) -> Element<'static, Message> {
    let display = if value.is_empty() { "—".into() } else { value };
    let mut r = row![
        text(label).size(12).style(style::dim_text).width(110),
        text(display).size(12).font(Font::MONOSPACE),
    ]
    .spacing(10)
    .align_y(Center);
    if let Some(copy) = copy {
        r = r.push(space().width(Fill));
        r = r.push(copy_button(copy));
    }
    r.into()
}

/// Small quiet "Copy" button feeding `Message::CopyText` — iced `text` isn't
/// selectable, so this is the only way to lift a value out of the UI.
fn copy_button(value: String) -> Element<'static, Message> {
    button(text("Copy").size(11))
        .padding([2, 8])
        .style(style::ghost)
        .on_press(Message::CopyText(value))
        .into()
}

/// A `left → right` entry with its own Copy button on each side — used for host
/// aliases (alias / server-resolved target) and port forwards (local / remote
/// endpoint), where either side may be the value you want. `dim` renders the
/// values in the secondary text color (the forward route under its bold name).
fn arrow_copy_row<'a>(left: String, right: String, dim: bool) -> Element<'a, Message> {
    let cell = |value: String| -> Element<'static, Message> {
        let t = text(value).size(12).font(Font::MONOSPACE);
        if dim { t.style(style::dim_text).into() } else { t.into() }
    };
    row![
        cell(left.clone()),
        copy_button(left),
        cell("→".into()),
        cell(right.clone()),
        copy_button(right),
    ]
    .spacing(8)
    .align_y(Center)
    .into()
}

/// A dimmed sub-label indented under a route entry (e.g. "routed domains:").
fn indented_label<'a>(label: &'static str) -> Element<'a, Message> {
    row![space().width(16), text(label).size(12).style(style::dim_text)]
        .spacing(6)
        .align_y(Center)
        .into()
}

/// A monospace list item indented under a sub-label (rendered as "- value").
fn indented_item<'a>(value: &str) -> Element<'a, Message> {
    row![space().width(32), mono(format!("- {value}"))]
        .spacing(6)
        .align_y(Center)
        .into()
}

/// A monospace routing entry with a right-aligned Copy button. `trailing` is an
/// optional badge shown before the button.
fn route_row<'a>(value: String, trailing: Option<Element<'a, Message>>) -> Element<'a, Message> {
    let mut r = row![mono(value.clone())].spacing(8).align_y(Center);
    if let Some(trailing) = trailing {
        r = r.push(trailing);
    }
    r = r.push(space().width(Fill));
    r = r.push(copy_button(value));
    r.into()
}

fn form_row<'a>(
    label: &'static str,
    input: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    row![
        text(label).size(12).style(style::dim_text).width(100),
        input.into(),
    ]
    .spacing(10)
    .align_y(Center)
    .into()
}

fn input<'a>(
    placeholder: &'a str,
    value: &'a str,
    on_input: fn(String) -> Message,
) -> iced::widget::TextInput<'a, Message> {
    text_input(placeholder, value)
        .on_input(on_input)
        .size(13)
        .padding([6, 10])
        .style(style::input)
}

/// Shorten to `max` characters by replacing the middle with an ellipsis.
/// ASCII-safe inputs only (node ids, addresses).
fn truncate_middle(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.into();
    }
    let keep = (max - 1) / 2;
    format!("{}…{}", &s[..keep], &s[s.len() - keep..])
}

fn section_label(label: impl Into<String>) -> Element<'static, Message> {
    text(label.into())
        .size(11)
        .font(semibold())
        .style(style::dim_text)
        .into()
}

fn mono<'a>(fragment: impl text::IntoFragment<'a>) -> Element<'a, Message> {
    text(fragment).size(12).font(Font::MONOSPACE).into()
}

/// Small tinted pill badge (forward state, phase).
fn pill(label: impl Into<String>, color: Color) -> Element<'static, Message> {
    container(text(label.into()).size(11).font(semibold()).color(color))
        .padding([2, 8])
        .style(style::pill(color))
        .into()
}

/// Small filled status dot, vertically centered against the row text.
fn dot(color: Color, size: f32) -> Element<'static, Message> {
    container(space())
        .width(size)
        .height(size)
        .style(style::dot(color))
        .into()
}

fn semibold() -> Font {
    Font {
        weight: iced::font::Weight::Semibold,
        ..Font::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn middle_truncation() {
        assert_eq!(truncate_middle("short", 22), "short");
        let id = "feedfacefeedfacefeedfacefeedface";
        let shown = truncate_middle(id, 22);
        assert_eq!(shown, "feedfacefe…cefeedface");
        assert!(shown.chars().count() <= 22);
    }

    #[test]
    fn full_tunnel_derivation() {
        let mut routes = TunnelRoutes::default();
        assert!(is_full_tunnel(&routes));
        routes.domains = vec!["example.com".into()];
        assert!(!is_full_tunnel(&routes));
        routes.domains.push("*".into());
        assert!(is_full_tunnel(&routes));
        routes.domains = vec!["example.com".into()];
        routes.cidrs = vec!["0.0.0.0/0".into()];
        assert!(is_full_tunnel(&routes));
    }
}
