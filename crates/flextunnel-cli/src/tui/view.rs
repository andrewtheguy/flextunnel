//! Rendering for the control panel, mirroring the desktop status page:
//! connection header, connection paths, routing breakdown, and the editable
//! port-forwards table.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::ipc::{ForwardRow, ForwardRowState, Phase, StatusSnapshot, WireConnSnapshot, WireRoutes};

use super::form::{
    FIELD_ENABLED, FIELD_LABEL, FIELD_LOCAL_PORT, FIELD_REMOTE_HOST, FIELD_REMOTE_PORT, FormState,
};
use super::{App, Mode};

const DIM: Style = Style::new().fg(Color::DarkGray);

pub fn draw(frame: &mut Frame, app: &App) {
    let s = &app.snapshot;

    let header_lines = header_lines(s);
    let forwards_height = (s.forwards.len().max(1) + 2).min(12) as u16;
    let [header_area, routing_area, forwards_area, footer_area] = Layout::vertical([
        Constraint::Length(header_lines.len() as u16 + 2),
        Constraint::Min(3),
        Constraint::Length(forwards_height),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(
        Paragraph::new(header_lines).block(titled_block("Connection")),
        header_area,
    );

    let routing = routing_lines(&s.routes, &s.status_page_host);
    let max_scroll = (routing.len() as u16).saturating_sub(routing_area.height.saturating_sub(2));
    frame.render_widget(
        Paragraph::new(routing)
            .scroll((app.routing_scroll.min(max_scroll), 0))
            .block(titled_block("Routing  ([/] to scroll)")),
        routing_area,
    );

    // Keep the selected row visible when the list is taller than the table:
    // scroll just enough that the selection sits at the bottom edge.
    let visible_forwards = forwards_area.height.saturating_sub(2) as usize;
    let forwards_scroll = (app.selected + 1).saturating_sub(visible_forwards.max(1)) as u16;
    frame.render_widget(
        Paragraph::new(forward_lines(&s.forwards, app.selected, matches!(app.mode, Mode::Normal)))
            .scroll((forwards_scroll, 0))
            .block(titled_block(&format!("Port forwards · {}", s.forwards.len()))),
        forwards_area,
    );

    frame.render_widget(Paragraph::new(footer_line(app)), footer_area);

    match &app.mode {
        Mode::Normal => {}
        Mode::Form(form) => draw_form(frame, form),
        Mode::ConfirmDelete { name, .. } => draw_confirm(frame, name),
        Mode::ConnPath(snapshot) => draw_conn_path(frame, snapshot),
    }
}

fn titled_block(title: &str) -> Block<'_> {
    Block::new()
        .borders(Borders::ALL)
        .border_style(DIM)
        .title(Span::styled(
            format!(" {title} "),
            Style::new().add_modifier(Modifier::BOLD),
        ))
}

fn phase_style(phase: Phase) -> Style {
    match phase {
        Phase::Connected => Style::new().fg(Color::Green),
        Phase::Connecting | Phase::Reconnecting => Style::new().fg(Color::Yellow),
        Phase::Failed => Style::new().fg(Color::Red),
    }
}

fn format_uptime(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

fn header_lines(s: &StatusSnapshot) -> Vec<Line<'static>> {
    // Friendly profile name when the config sets one; the server-id prefix
    // otherwise.
    let title = s
        .name
        .clone()
        .unwrap_or_else(|| format!("server {}…", s.instance));
    let mut first = vec![
        Span::styled(title, Style::new().add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(format!("● {}", s.phase.label()), phase_style(s.phase)),
    ];
    if let Some(secs) = s.connected_secs {
        first.push(Span::styled(format!("  for {}", format_uptime(secs)), DIM));
    }

    let proxy = |name: &str, addr: Option<std::net::SocketAddr>| match addr {
        Some(addr) => Span::raw(format!("{name} {addr}")),
        None => Span::styled(format!("{name} off"), DIM),
    };

    let mut lines = vec![
        Line::from(first),
        Line::from(vec![
            Span::styled("server node id  ", DIM),
            Span::raw(s.server_node_id.clone()),
        ]),
        Line::from(vec![
            Span::styled("client node id  ", DIM),
            Span::raw(s.client_node_id.clone()),
        ]),
        Line::from(vec![
            proxy("socks5", s.socks_addr),
            Span::raw("   "),
            proxy("http", s.http_addr),
            Span::raw("   "),
            Span::styled(format!("status page http://{}/", s.status_page_host), DIM),
        ]),
    ];
    if let Some(err) = &s.last_error {
        lines.push(Line::from(Span::styled(
            format!("error: {err}"),
            Style::new().fg(Color::Red),
        )));
    }
    lines
}

/// Lines for the on-demand connection-path overlay: the iroh path(s) and, when
/// custom relays are configured, their `/healthz` health.
fn conn_path_lines(snapshot: &WireConnSnapshot) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if snapshot.paths.is_empty() {
        lines.push(Line::from(Span::styled(
            "No path yet — the tunnel link is down or still establishing.",
            DIM,
        )));
    } else {
        for p in &snapshot.paths {
            let style = match p.kind.as_str() {
                "direct" => Style::new().fg(Color::Green),
                "relay" => Style::new().fg(Color::Yellow),
                _ => DIM,
            };
            let mut spans = vec![Span::styled(p.display.clone(), style)];
            if p.selected {
                spans.push(Span::styled(
                    "  ● active",
                    Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
                ));
            }
            lines.push(Line::from(spans));
        }
    }

    // Custom-relay health (empty with the default relays). /healthz is
    // unauthenticated — it confirms the relay is up, not that a token is accepted.
    if !snapshot.custom_relays.is_empty() {
        lines.push(Line::default());
        lines.push(section("Custom relays:".to_string()));
        for relay in &snapshot.custom_relays {
            let (style, status) = match relay.working {
                Some(true) => (Style::new().fg(Color::Green), "reachable".to_string()),
                Some(false) => (
                    Style::new().fg(Color::Red),
                    match &relay.error {
                        Some(e) => format!("unreachable — {e}"),
                        None => "unreachable".to_string(),
                    },
                ),
                None => (DIM, "status unavailable".to_string()),
            };
            lines.push(Line::from(vec![
                Span::raw(format!("  {}  ", relay.url)),
                Span::styled(format!("[{status}]"), style),
            ]));
        }
    }
    lines
}

/// The on-demand connection-path overlay (r refresh · Esc close), captured when
/// opened — mirrors the desktop connection-path modal.
fn draw_conn_path(frame: &mut Frame, snapshot: &WireConnSnapshot) {
    let lines = conn_path_lines(snapshot);
    let height = (lines.len() as u16 + 2).clamp(3, frame.area().height.max(3));
    let area = centered(frame.area(), 74, height);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).block(titled_block("Connection path  (r refresh · Esc close)")),
        area,
    );
}

fn section(title: String) -> Line<'static> {
    Line::from(Span::styled(title, Style::new().add_modifier(Modifier::BOLD)))
}

fn item(text: String) -> Line<'static> {
    Line::from(format!("  {text}"))
}

fn routing_lines(r: &WireRoutes, status_host: &str) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    lines.push(section(format!(
        "Split tunnel — {} domain(s), {} CIDR(s) routed through the server:",
        r.domains.len(),
        r.cidrs.len()
    )));
    if r.domains.is_empty() && r.cidrs.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (none — the server routes everything through the tunnel)",
            DIM,
        )));
    }
    for d in &r.domains {
        lines.push(item(d.clone()));
    }
    for c in &r.cidrs {
        lines.push(item(c.clone()));
    }

    if !r.host_aliases.is_empty() {
        lines.push(Line::default());
        lines.push(section(format!(
            "Host aliases — {} resolved server-side:",
            r.host_aliases.len()
        )));
        for (alias, target) in &r.host_aliases {
            lines.push(item(format!("{alias} → {target}")));
        }
    }

    if !r.dns_forwards.is_empty() {
        lines.push(Line::default());
        lines.push(section(format!(
            "DNS forwards — {} resolved via upstream server(s):",
            r.dns_forwards.len()
        )));
        for (suffix, servers) in &r.dns_forwards {
            lines.push(item(format!(
                "{suffix} (+ subdomains) → {}",
                servers.join(", ")
            )));
        }
    }

    if !r.bridges.is_empty() {
        lines.push(Line::default());
        lines.push(section(format!(
            "Bridge routes — {} forwarded via another server:",
            r.bridges.len()
        )));
        for b in &r.bridges {
            lines.push(item(format!("{}:", b.name)));
            lines.push(item(format!("  endpoint id: {}", b.endpoint_id)));
            for d in &b.domains {
                lines.push(item(format!("  – {d}")));
            }
            for c in &b.cidrs {
                lines.push(item(format!("  – {c}")));
            }
        }
    }

    if !r.agent_routes.is_empty() {
        lines.push(Line::default());
        lines.push(section(format!(
            "Agent routes — {} via agents:",
            r.agent_routes.len()
        )));
        for (name, state) in &r.agent_routes {
            let style = match state.as_str() {
                "connected" => Style::new().fg(Color::Green),
                "disconnected" => Style::new().fg(Color::Red),
                _ => DIM,
            };
            lines.push(Line::from(vec![
                Span::raw(format!("  {name}  ")),
                Span::styled(format!("[{state}]"), style),
            ]));
        }
    }

    lines.push(Line::default());
    lines.push(section("Server status page — always tunneled:".to_string()));
    lines.push(item(status_host.to_string()));

    lines
}

fn forward_state_span(row: &ForwardRow) -> Span<'static> {
    match row.state {
        ForwardRowState::Stopped => Span::styled("stopped", DIM),
        ForwardRowState::Starting => Span::styled("starting", Style::new().fg(Color::Yellow)),
        ForwardRowState::Listening => Span::styled(
            format!("listening ({} active)", row.active),
            Style::new().fg(Color::Green),
        ),
        ForwardRowState::Failed => Span::styled("failed", Style::new().fg(Color::Red)),
    }
}

fn forward_lines(forwards: &[ForwardRow], selected: usize, show_cursor: bool) -> Vec<Line<'static>> {
    if forwards.is_empty() {
        return vec![Line::from(Span::styled(
            "no port forwards — press a to add one",
            DIM,
        ))];
    }
    forwards
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let f = &row.forward;
            let mut spans = vec![
                Span::raw(if show_cursor && i == selected { "❯ " } else { "  " }),
                Span::styled(
                    if f.enabled { "[on]  " } else { "[off] " },
                    if f.enabled {
                        Style::new().fg(Color::Green)
                    } else {
                        DIM
                    },
                ),
                Span::styled(
                    format!("{:<20}", super::form::display_name(f)),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    " localhost:{} → {}  ",
                    f.local_port,
                    flextunnel_core::forwards::format_host_port(&f.remote_host, f.remote_port)
                )),
                forward_state_span(row),
            ];
            if let Some(err) = &row.error {
                spans.push(Span::styled(
                    format!("  {err}"),
                    Style::new().fg(Color::Red),
                ));
            } else if let Some(err) = &row.last_conn_error {
                spans.push(Span::styled(format!("  last error: {err}"), DIM));
            }
            let line = Line::from(spans);
            if show_cursor && i == selected {
                line.style(Style::new().bg(Color::Rgb(40, 40, 40)))
            } else {
                line
            }
        })
        .collect()
}

fn footer_line(app: &App) -> Line<'static> {
    if let Some(notice) = &app.notice {
        return Line::from(Span::styled(
            notice.clone(),
            Style::new().fg(Color::Red),
        ));
    }
    let hints = match app.mode {
        Mode::Normal => {
            "q quit · ↑/↓ select · space on/off · a add · e edit · d delete · p path · [/] scroll"
        }
        Mode::Form(_) => "Tab/Shift-Tab field · space toggle enabled · Enter save · Esc cancel",
        Mode::ConfirmDelete { .. } => "y delete · n cancel",
        Mode::ConnPath(_) => "r refresh · Esc close",
    };
    Line::from(Span::styled(hints, DIM))
}

/// A centered `width` x `height` rect clamped to `area`.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

fn draw_form(frame: &mut Frame, form: &FormState) {
    let area = centered(frame.area(), 56, 10);
    frame.render_widget(Clear, area);

    let field = |idx: usize, name: &str, value: String| {
        let focused = form.focus == idx;
        Line::from(vec![
            Span::styled(
                format!("{}{name:<12}", if focused { "❯ " } else { "  " }),
                if focused {
                    Style::new().add_modifier(Modifier::BOLD)
                } else {
                    DIM
                },
            ),
            Span::styled(
                if focused { format!("{value}█") } else { value },
                Style::new(),
            ),
        ])
    };

    let mut lines = vec![
        field(FIELD_LABEL, "Label", form.label.clone()),
        field(FIELD_LOCAL_PORT, "Local port", form.local_port.clone()),
        field(FIELD_REMOTE_HOST, "Remote host", form.remote_host.clone()),
        field(FIELD_REMOTE_PORT, "Remote port", form.remote_port.clone()),
        field(
            FIELD_ENABLED,
            "Enabled",
            (if form.enabled { "[x]" } else { "[ ]" }).to_string(),
        ),
    ];
    if let Some(err) = &form.error {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            err.clone(),
            Style::new().fg(Color::Red),
        )));
    }

    frame.render_widget(
        Paragraph::new(lines).block(titled_block(if form.is_edit() {
            "Edit port forward"
        } else {
            "Add port forward"
        })),
        area,
    );
}

fn draw_confirm(frame: &mut Frame, name: &str) {
    let area = centered(frame.area(), 44, 3);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(Line::from(format!("Delete forward \"{name}\"?  y/n")))
            .block(titled_block("Confirm")),
        area,
    );
}
