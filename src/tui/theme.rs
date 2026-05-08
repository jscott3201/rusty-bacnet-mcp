//! Color theme for the TUI. Centralized so a future light-mode variant can
//! swap a single struct.

use ratatui::style::{Color, Modifier, Style};

pub const HEADER_TITLE: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);

pub const HEADER_VALUE: Style = Style::new().fg(Color::Gray);

pub const TAB_INACTIVE: Style = Style::new().fg(Color::DarkGray);

pub const TAB_ACTIVE: Style = Style::new()
    .fg(Color::Black)
    .bg(Color::Yellow)
    .add_modifier(Modifier::BOLD);

pub const TAB_DIVIDER: Style = Style::new().fg(Color::DarkGray);

pub const STATUS_BAR: Style = Style::new().fg(Color::White).bg(Color::DarkGray);

pub const STATUS_KEY: Style = Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD);

pub const STATUS_DESC: Style = Style::new().fg(Color::Gray);

pub const BORDER: Style = Style::new().fg(Color::DarkGray);

pub const BORDER_FOCUSED: Style = Style::new().fg(Color::Cyan);

pub const TITLE_FOCUSED: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);

pub const TITLE_UNFOCUSED: Style = Style::new().fg(Color::Gray);

pub const TABLE_HEADER: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);

pub const TABLE_ROW_SELECTED: Style = Style::new().bg(Color::Rgb(40, 40, 40));

pub const OK: Style = Style::new().fg(Color::Green);
pub const WARN: Style = Style::new().fg(Color::Yellow);
pub const ERR: Style = Style::new().fg(Color::Red);
pub const DIM: Style = Style::new().fg(Color::DarkGray);

pub const POPUP_BORDER: Style = Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD);
