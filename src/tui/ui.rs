//! Top-level render — chrome (header / tabs / status bar) plus tab dispatch
//! plus modal overlays (help popup, toasts).

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Tabs, Wrap};

use crate::tui::app::App;
use crate::tui::event::StatusKind;
use crate::tui::tabs::{Tab, configure, observe, operate};
use crate::tui::theme;

pub fn render(frame: &mut Frame, app: &mut App) {
    app.cull_toast();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Length(1), // tabs
            Constraint::Min(0),    // body
            Constraint::Length(1), // status bar
        ])
        .split(frame.area());

    render_header(frame, chunks[0], app);
    render_tabs(frame, chunks[1], app.tab);
    render_body(frame, chunks[2], app);
    render_status_bar(frame, chunks[3], app);

    if app.help_visible {
        render_help_popup(frame);
    }
    render_toast(frame, app);
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let device = format!(
        " bacnet-mcp · {} (instance {}) ",
        app.config.device.name, app.config.device.instance
    );
    let mode = if app.config.mcp.read_only {
        Span::styled(" READ-ONLY ", theme::WARN.add_modifier(Modifier::REVERSED))
    } else {
        Span::styled(
            " WRITES ENABLED ",
            theme::ERR.add_modifier(Modifier::REVERSED),
        )
    };
    let line = Line::from(vec![
        Span::styled(device, theme::HEADER_TITLE),
        Span::raw(" · "),
        mode,
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_tabs(frame: &mut Frame, area: Rect, current: Tab) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| {
            let style = if *t == current {
                theme::TAB_ACTIVE
            } else {
                theme::TAB_INACTIVE
            };
            Line::from(Span::styled(format!(" {} ", t.title()), style))
        })
        .collect();
    let tabs = Tabs::new(titles)
        .select(current.index())
        .divider(Span::styled("│", theme::TAB_DIVIDER))
        .padding("", "");
    frame.render_widget(tabs, area);
}

fn render_body(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.tab {
        Tab::Configure => configure::render(frame, area, &mut app.configure, true),
        Tab::Observe => observe::render(
            frame,
            area,
            &mut app.observe,
            &app.gateway,
            &app.config,
            &app.log_buffer,
            true,
        ),
        Tab::Operate => operate::render(frame, area, &app.operate, true),
    }
}

fn render_status_bar(frame: &mut Frame, area: Rect, app: &App) {
    let kvs: Vec<(&'static str, &'static str)> = {
        let mut v: Vec<(&'static str, &'static str)> = vec![("Tab", "switch view")];
        match app.tab {
            Tab::Configure => {
                v.push(("F5", "validate"));
                v.push(("F9", "save+reload"));
            }
            Tab::Observe => {
                v.push(("j/k", "select"));
                v.push(("+/-", "log level"));
                v.push(("h/l", "log page"));
            }
            Tab::Operate => {
                v.push(("1/2/3", "form"));
                v.push(("↑↓", "field"));
                v.push(("Enter", "run"));
            }
        }
        v.push(("F1", "help"));
        v.push(("Ctrl-M", "mouse"));
        v.push(("q", "quit"));
        v
    };

    let mut spans: Vec<Span<'static>> = vec![Span::styled("  ", theme::STATUS_BAR)];
    for (key, desc) in kvs {
        spans.push(Span::styled(key, theme::STATUS_KEY));
        spans.push(Span::styled(format!(" {desc}  "), theme::STATUS_DESC));
    }

    let line = Line::from(spans);
    let para = Paragraph::new(line).style(theme::STATUS_BAR);
    frame.render_widget(para, area);
}

fn render_help_popup(frame: &mut Frame) {
    let lines = vec![
        Line::from(Span::styled(
            "BACnet MCP — Operator Console",
            theme::HEADER_TITLE.add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(Span::styled("Global", theme::HEADER_TITLE)),
        Line::raw("  Tab / Shift-Tab    cycle tabs"),
        Line::raw("  q / Ctrl-C         quit"),
        Line::raw("  F1                 toggle this help"),
        Line::raw("  Ctrl-M             toggle mouse capture"),
        Line::raw(""),
        Line::from(Span::styled("Configure", theme::HEADER_TITLE)),
        Line::raw("  F5                 validate buffer"),
        Line::raw("  F9                 save & reload"),
        Line::raw("  Esc                cancel selection"),
        Line::raw(""),
        Line::from(Span::styled("Observe", theme::HEADER_TITLE)),
        Line::raw("  j/k or ↑/↓         move device cursor"),
        Line::raw("  g/G                first/last device"),
        Line::raw("  h/l                page logs back/forward"),
        Line::raw("  +/-                log verbosity"),
        Line::raw(""),
        Line::from(Span::styled("Operate", theme::HEADER_TITLE)),
        Line::raw("  1/2/3              switch form (WhoIs / Read / Write)"),
        Line::raw("  ↑/↓                field navigation"),
        Line::raw("  Enter              run the form"),
    ];
    // Centered popup: 60% wide × 75% tall, capped to a sensible max.
    let area = frame.area();
    let popup_area = centered_rect(
        60.min((area.width as u32).saturating_sub(4) as u16),
        22,
        area,
    );
    frame.render_widget(Clear, popup_area);
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::POPUP_BORDER)
                .title(Span::styled(" Help ", theme::POPUP_BORDER)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(para, popup_area);
}

/// Produce a Rect of the given content height/width, centered in `area`.
/// width/height are absolute character counts, not percentages.
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}

fn render_toast(frame: &mut Frame, app: &App) {
    let Some((_, kind, msg)) = &app.toast else {
        return;
    };
    let style = match kind {
        StatusKind::Info => theme::HEADER_TITLE,
        StatusKind::Ok => theme::OK,
        StatusKind::Warn => theme::WARN,
        StatusKind::Err => theme::ERR,
    };
    let area = frame.area();
    if area.width < 30 || area.height < 5 {
        return;
    }
    // Right-aligned floating toast above the status bar.
    let width = (msg.len() as u16 + 4).min(area.width.saturating_sub(2));
    let toast_area = Rect {
        x: area.x + area.width.saturating_sub(width + 1),
        y: area.y + area.height.saturating_sub(3),
        width,
        height: 3,
    };
    frame.render_widget(Clear, toast_area);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(msg.clone(), style))).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(style)
                .title(" Status "),
        ),
        toast_area,
    );
}
