//! Observe tab — device table + transport status + log tail.

use std::time::Instant;

use bacnet_client::discovery::DiscoveredDevice;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
    TableState, Wrap,
};

use crate::config::GatewayConfig;
use crate::state::GatewayState;
use crate::tui::logger::LogBuffer;
use crate::tui::theme;

/// Per-tab state for Observe.
pub struct ObserveState {
    pub devices: Vec<DiscoveredDevice>,
    pub last_refresh: Option<Instant>,
    pub table: TableState,
    pub scrollbar: ScrollbarState,
    pub log_scroll_offset: usize,
    pub log_min_level: tracing::Level,
}

impl ObserveState {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            last_refresh: None,
            table: TableState::default(),
            scrollbar: ScrollbarState::default(),
            log_scroll_offset: 0,
            log_min_level: tracing::Level::INFO,
        }
    }

    pub fn select_next(&mut self) {
        if self.devices.is_empty() {
            return;
        }
        let next = self
            .table
            .selected()
            .map_or(0, |i| (i + 1) % self.devices.len());
        self.table.select(Some(next));
        self.scrollbar = self.scrollbar.position(next);
    }

    pub fn select_prev(&mut self) {
        if self.devices.is_empty() {
            return;
        }
        let prev = match self.table.selected() {
            Some(0) => self.devices.len() - 1,
            Some(i) => i - 1,
            None => 0,
        };
        self.table.select(Some(prev));
        self.scrollbar = self.scrollbar.position(prev);
    }

    pub fn log_page_back(&mut self) {
        self.log_scroll_offset = self.log_scroll_offset.saturating_add(20);
    }

    pub fn log_page_forward(&mut self) {
        self.log_scroll_offset = self.log_scroll_offset.saturating_sub(20);
    }

    pub fn log_level_up(&mut self) {
        self.log_min_level = match self.log_min_level {
            tracing::Level::TRACE => tracing::Level::DEBUG,
            tracing::Level::DEBUG => tracing::Level::INFO,
            tracing::Level::INFO => tracing::Level::WARN,
            tracing::Level::WARN | tracing::Level::ERROR => tracing::Level::ERROR,
        };
    }

    pub fn log_level_down(&mut self) {
        self.log_min_level = match self.log_min_level {
            tracing::Level::ERROR => tracing::Level::WARN,
            tracing::Level::WARN => tracing::Level::INFO,
            tracing::Level::INFO => tracing::Level::DEBUG,
            tracing::Level::DEBUG | tracing::Level::TRACE => tracing::Level::TRACE,
        };
    }
}

impl Default for ObserveState {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn render(
    frame: &mut Frame,
    area: Rect,
    state: &mut ObserveState,
    gateway: &GatewayState,
    config: &GatewayConfig,
    log_buffer: &LogBuffer,
    http_listening: bool,
    focused: bool,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(chunks[0]);

    render_devices(frame, top[0], state, focused);
    render_status(frame, top[1], gateway, config, http_listening);
    render_logs(frame, chunks[1], state, log_buffer);
}

fn render_devices(frame: &mut Frame, area: Rect, state: &mut ObserveState, focused: bool) {
    let header_cells = ["Instance", "Vendor", "Net", "MAC", "Max APDU", "Seg"]
        .iter()
        .map(|h| Cell::from(*h).style(theme::TABLE_HEADER));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = state
        .devices
        .iter()
        .map(|d| {
            let mac = d
                .mac_address
                .as_slice()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            let net = d
                .source_network
                .map(|n| n.to_string())
                .unwrap_or_else(|| "—".into());
            Row::new(vec![
                Cell::from(d.object_identifier.instance_number().to_string()),
                Cell::from(d.vendor_id.to_string()),
                Cell::from(net),
                Cell::from(mac),
                Cell::from(d.max_apdu_length.to_string()),
                Cell::from(format!("{:?}", d.segmentation_supported)),
            ])
        })
        .collect();

    let title_text = match state.last_refresh {
        Some(t) => format!(
            " Devices ({} known, last poll {}s ago) ",
            state.devices.len(),
            t.elapsed().as_secs()
        ),
        None => " Devices (no poll yet) ".into(),
    };

    let widths = [
        Constraint::Length(10),
        Constraint::Length(7),
        Constraint::Length(5),
        Constraint::Length(20),
        Constraint::Length(10),
        Constraint::Min(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(theme::TABLE_ROW_SELECTED.add_modifier(Modifier::BOLD))
        .highlight_symbol("▸ ")
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if focused {
                    theme::BORDER_FOCUSED
                } else {
                    theme::BORDER
                })
                .title(Span::styled(
                    title_text,
                    if focused {
                        theme::TITLE_FOCUSED
                    } else {
                        theme::TITLE_UNFOCUSED
                    },
                )),
        );
    frame.render_stateful_widget(table, area, &mut state.table);

    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None);
    state.scrollbar = state.scrollbar.content_length(state.devices.len());
    frame.render_stateful_widget(
        scrollbar,
        area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut state.scrollbar,
    );
}

fn render_status(
    frame: &mut Frame,
    area: Rect,
    gateway: &GatewayState,
    config: &GatewayConfig,
    http_listening: bool,
) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("Device ", theme::HEADER_TITLE),
        Span::raw(format!(
            "{} (instance {})",
            config.device.name, config.device.instance
        )),
    ]));
    // Read-only state comes from the live RuntimeFlags atomic, not the frozen
    // config — TUI hot-reload of mcp.read_only updates the atomic and this
    // panel reflects the change on the next render.
    lines.push(Line::from(vec![
        Span::styled("Mode ", theme::HEADER_TITLE),
        if gateway.is_read_only() {
            Span::styled("read-only", theme::WARN)
        } else {
            Span::styled("writable", theme::OK)
        },
    ]));

    lines.push(Line::raw(""));

    lines.push(Line::from(Span::styled("Transports", theme::HEADER_TITLE)));
    if let Some(bip) = &config.transports.bip {
        let badge = if gateway.client().is_some() {
            Span::styled(" UP ", theme::OK)
        } else {
            Span::styled(" DOWN ", theme::ERR)
        };
        lines.push(Line::from(vec![
            Span::raw("  BIP "),
            badge,
            Span::raw(format!(
                "  {}:{} net {}",
                bip.interface, bip.port, bip.network_number
            )),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "  BIP — not configured",
            theme::DIM,
        )));
    }
    if let Some(sc) = &config.transports.sc {
        let role = match (sc.listen.as_deref(), sc.hub_uri.as_deref()) {
            (Some(addr), _) => format!("Hub @ {addr}"),
            (_, Some(uri)) => format!("Node → {uri}"),
            _ => "(unconfigured)".into(),
        };
        lines.push(Line::from(vec![
            Span::raw("  SC  "),
            Span::styled(" PEND ", theme::WARN),
            Span::raw(format!("  {role} net {}", sc.network_number)),
        ]));
        lines.push(Line::from(Span::styled(
            "       (wiring lands in Phase 4)",
            theme::DIM,
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  SC  — not configured",
            theme::DIM,
        )));
    }

    lines.push(Line::raw(""));

    lines.push(Line::from(Span::styled("MCP", theme::HEADER_TITLE)));
    lines.push(Line::from(vec![
        Span::raw("  stdio "),
        Span::styled(" OFF ", theme::DIM),
        Span::styled(" (TUI owns stdout)", theme::DIM),
    ]));
    // Render based on actual listener state, not config presence: --no-http
    // disables the listener even when [mcp.http] is set in the file.
    match (http_listening, &config.mcp.http) {
        (true, Some(http)) => {
            lines.push(Line::from(vec![
                Span::raw("  http  "),
                Span::styled(" UP ", theme::OK),
                Span::raw(format!(" {}/mcp", http.bind)),
            ]));
            let auth_label = if config.mcp.api_key.is_some() {
                Span::styled("bearer auth required", theme::OK)
            } else {
                Span::styled("no auth (open)", theme::WARN)
            };
            lines.push(Line::from(vec![Span::raw("        "), auth_label]));
        }
        (true, None) => {
            // Defensive — main.rs reconciles this, but render gracefully if not.
            lines.push(Line::from(vec![
                Span::raw("  http  "),
                Span::styled(" UP ", theme::OK),
                Span::styled(" (bind unknown)", theme::WARN),
            ]));
        }
        (false, Some(http)) => {
            lines.push(Line::from(vec![
                Span::raw("  http  "),
                Span::styled(" DOWN ", theme::ERR),
                Span::styled(
                    format!(" (--no-http; would bind {})", http.bind),
                    theme::DIM,
                ),
            ]));
        }
        (false, None) => {
            lines.push(Line::from(Span::styled(
                "  http  — disabled (--no-http)",
                theme::DIM,
            )));
        }
    }

    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::BORDER)
                .title(" Status "),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn render_logs(frame: &mut Frame, area: Rect, state: &ObserveState, log_buffer: &LogBuffer) {
    // Pull a generous snapshot then filter locally so the user can switch
    // levels without losing recent context.
    let entries = log_buffer.snapshot(2000);
    let filtered: Vec<_> = entries
        .into_iter()
        .filter(|e| level_at_least(e.level, state.log_min_level))
        .collect();

    let visible_height = area.height.saturating_sub(2) as usize;
    let total = filtered.len();
    let end = total.saturating_sub(state.log_scroll_offset);
    let start = end.saturating_sub(visible_height);
    let lines: Vec<Line> = filtered[start..end]
        .iter()
        .map(|e| {
            let elapsed = format!("{:>5}s ", e.at.elapsed().as_secs());
            Line::from(vec![
                Span::styled(elapsed, theme::DIM),
                Span::styled(format!("{} ", e.level_label()), e.level_style()),
                Span::styled(
                    format!("{:<28}", truncate(&e.target, 28)),
                    Style::default().fg(ratatui::style::Color::Magenta),
                ),
                Span::raw(" "),
                Span::raw(e.message.clone()),
            ])
        })
        .collect();

    let title = format!(
        " Logs ({} of {} ≥ {} · {} back) ",
        filtered.len(),
        log_buffer.len(),
        state.log_min_level,
        state.log_scroll_offset,
    );
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::BORDER)
                .title(title),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("…{}", &s[s.len() - (max - 1)..])
    }
}

fn level_at_least(actual: tracing::Level, min: tracing::Level) -> bool {
    // tracing::Level orders: ERROR < WARN < INFO < DEBUG < TRACE? No — actually
    // Level implements Ord such that ERROR < WARN < INFO etc. But "min" here
    // means "show this level and more important" — so we want events whose
    // level is at most as verbose as `min`. That's `actual <= min` in Ord.
    actual <= min
}
