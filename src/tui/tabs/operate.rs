//! Operate tab — manual BACnet operations: WhoIs, Read Property, Write Property.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::tui::theme;

/// Which sub-form is in focus inside the Operate tab.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OpForm {
    WhoIs,
    Read,
    Write,
}

impl OpForm {
    pub fn title(self) -> &'static str {
        match self {
            OpForm::WhoIs => "WhoIs",
            OpForm::Read => "Read Property",
            OpForm::Write => "Write Property",
        }
    }
}

/// One field in a form. Fields hold a label, a buffer, and a hint.
#[derive(Debug, Clone)]
pub struct Field {
    pub label: &'static str,
    pub value: String,
    pub hint: &'static str,
}

impl Field {
    pub fn new(label: &'static str, hint: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            hint,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Form {
    pub fields: Vec<Field>,
    pub focused: usize,
}

impl Form {
    pub fn focus_next(&mut self) {
        if !self.fields.is_empty() {
            self.focused = (self.focused + 1) % self.fields.len();
        }
    }
    pub fn focus_prev(&mut self) {
        if !self.fields.is_empty() {
            self.focused = (self.focused + self.fields.len() - 1) % self.fields.len();
        }
    }
    pub fn current(&mut self) -> &mut Field {
        &mut self.fields[self.focused]
    }
}

/// One row in the recent-actions log.
#[derive(Debug, Clone)]
pub struct ActionRecord {
    pub at: Instant,
    pub kind: &'static str,
    pub summary: String,
    pub success: bool,
}

pub struct OperateState {
    pub form: OpForm,
    pub whois: Form,
    pub read: Form,
    pub write: Form,
    pub last_result: Option<Result<String, String>>,
    pub recent: Vec<ActionRecord>,
}

impl OperateState {
    pub fn new() -> Self {
        Self {
            form: OpForm::WhoIs,
            whois: Form {
                fields: vec![
                    Field::new("Low instance", "0–4194302, blank for any"),
                    Field::new("High instance", "0–4194302, blank for any"),
                    Field::new("Timeout (s)", "default 3, max 30"),
                ],
                focused: 0,
            },
            read: Form {
                fields: vec![
                    Field::new("Device instance", "must be in device table"),
                    Field::new("Object type", "e.g. analog-input"),
                    Field::new("Object instance", "u32"),
                    Field::new("Property", "e.g. present-value"),
                ],
                focused: 0,
            },
            write: Form {
                fields: vec![
                    Field::new("Device instance", "must be in device table"),
                    Field::new("Object type", "e.g. analog-output"),
                    Field::new("Object instance", "u32"),
                    Field::new("Property", "e.g. present-value"),
                    Field::new("Value", "JSON literal: 72.5, true, \"text\", null"),
                    Field::new("Priority", "1–16, blank for default"),
                ],
                focused: 0,
            },
            last_result: None,
            recent: Vec::new(),
        }
    }

    pub fn current_form_mut(&mut self) -> &mut Form {
        match self.form {
            OpForm::WhoIs => &mut self.whois,
            OpForm::Read => &mut self.read,
            OpForm::Write => &mut self.write,
        }
    }

    pub fn record(&mut self, kind: &'static str, summary: String, success: bool) {
        self.recent.insert(
            0,
            ActionRecord {
                at: Instant::now(),
                kind,
                summary,
                success,
            },
        );
        if self.recent.len() > 50 {
            self.recent.truncate(50);
        }
    }
}

impl Default for OperateState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn render(frame: &mut Frame, area: Rect, state: &OperateState, focused: bool) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // form selector
            Constraint::Min(8),    // form fields
            Constraint::Length(8), // result panel
        ])
        .split(cols[0]);

    render_form_selector(frame, left[0], state.form);
    render_form_fields(frame, left[1], state, focused);
    render_result(frame, left[2], state.last_result.as_ref());
    render_recent(frame, cols[1], &state.recent);
}

fn render_form_selector(frame: &mut Frame, area: Rect, current: OpForm) {
    let make = |form: OpForm, key: char| {
        let style = if form == current {
            theme::TAB_ACTIVE
        } else {
            theme::TAB_INACTIVE
        };
        Span::styled(format!(" [{}] {} ", key, form.title()), style)
    };
    let line = Line::from(vec![
        make(OpForm::WhoIs, '1'),
        Span::raw(" "),
        make(OpForm::Read, '2'),
        Span::raw(" "),
        make(OpForm::Write, '3'),
    ]);
    let para = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::BORDER)
            .title(" Form (1/2/3 to switch) "),
    );
    frame.render_widget(para, area);
}

fn render_form_fields(frame: &mut Frame, area: Rect, state: &OperateState, focused: bool) {
    let form = match state.form {
        OpForm::WhoIs => &state.whois,
        OpForm::Read => &state.read,
        OpForm::Write => &state.write,
    };

    let lines: Vec<Line> = form
        .fields
        .iter()
        .enumerate()
        .flat_map(|(i, f)| {
            let is_active = i == form.focused;
            let label_style = if is_active {
                theme::TITLE_FOCUSED.add_modifier(Modifier::BOLD)
            } else {
                theme::DIM
            };
            let value_style = if is_active {
                theme::HEADER_VALUE.add_modifier(Modifier::REVERSED)
            } else {
                theme::HEADER_VALUE
            };
            let cursor = if is_active { "▸ " } else { "  " };
            let value_display = if f.value.is_empty() {
                format!("({})", f.hint)
            } else {
                f.value.clone()
            };
            vec![Line::from(vec![
                Span::raw(cursor),
                Span::styled(format!("{:<18}", f.label), label_style),
                Span::styled(value_display, value_style),
            ])]
        })
        .collect();

    let title = format!(" {} (Enter run · Tab next field) ", state.form.title());
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if focused {
                    theme::BORDER_FOCUSED
                } else {
                    theme::BORDER
                })
                .title(Span::styled(
                    title,
                    if focused {
                        theme::TITLE_FOCUSED
                    } else {
                        theme::TITLE_UNFOCUSED
                    },
                )),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn render_result(frame: &mut Frame, area: Rect, result: Option<&Result<String, String>>) {
    let lines: Vec<Line> = match result {
        None => vec![Line::from(Span::styled(
            "No action yet. Press Enter inside a form to run.",
            theme::DIM,
        ))],
        Some(Ok(msg)) => msg
            .lines()
            .map(|l| Line::from(Span::styled(l.to_string(), theme::OK)))
            .collect(),
        Some(Err(msg)) => msg
            .lines()
            .map(|l| Line::from(Span::styled(l.to_string(), theme::ERR)))
            .collect(),
    };
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::BORDER)
                .title(" Result "),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn render_recent(frame: &mut Frame, area: Rect, recent: &[ActionRecord]) {
    let items: Vec<ListItem> = recent
        .iter()
        .map(|r| {
            let badge = if r.success {
                Span::styled(" OK  ", theme::OK)
            } else {
                Span::styled(" ERR ", theme::ERR)
            };
            ListItem::new(Line::from(vec![
                badge,
                Span::raw(format!(" {:>4}s ago  ", r.at.elapsed().as_secs())),
                Span::styled(r.kind, theme::HEADER_TITLE),
                Span::raw(" "),
                Span::raw(r.summary.clone()),
            ]))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::BORDER)
            .title(" Recent actions "),
    );
    frame.render_widget(list, area);
}
