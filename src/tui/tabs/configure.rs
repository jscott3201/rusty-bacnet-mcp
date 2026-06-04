//! Configure tab — JSON config editor with validation and reload.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use tui_textarea::TextArea;

use crate::config::GatewayConfig;
use crate::tui::theme;

/// State for the Configure tab.
pub struct ConfigureState {
    /// The text editor buffer (live JSON).
    pub editor: TextArea<'static>,
    /// Last loaded JSON text (for dirty comparison).
    pub disk_text: String,
    /// Last validation result. None = unvalidated; Some(Ok) = clean; Some(Err) = error.
    pub last_validation: Option<Result<(), String>>,
    /// Status line beneath the editor.
    pub status_line: String,
}

impl ConfigureState {
    pub fn new(initial_text: String) -> Self {
        let mut editor = TextArea::from(initial_text.lines().collect::<Vec<_>>());
        style_editor(&mut editor);
        Self {
            editor,
            disk_text: initial_text,
            last_validation: None,
            status_line: "F5 validate · F9 save & reload · Ctrl-Z undo".into(),
        }
    }

    pub fn is_dirty(&self) -> bool {
        // tui-textarea drops the trailing newline that POSIX-style files end
        // with, so a freshly-loaded file would show as modified immediately
        // unless we normalize. Strip trailing newlines on both sides.
        let editor_text = self.editor.lines().join("\n");
        editor_text.trim_end_matches('\n') != self.disk_text.trim_end_matches('\n')
    }

    /// Run JSON parse + GatewayConfig validate against the buffer contents.
    pub fn validate(&mut self) -> Result<GatewayConfig, String> {
        let text = self.editor.lines().join("\n");
        let parsed = GatewayConfig::from_json(&text).map_err(|e| format!("JSON parse: {e}"))?;
        parsed.validate().map_err(|e| e.to_string())?;
        self.last_validation = Some(Ok(()));
        self.status_line = "Validation OK".into();
        Ok(parsed)
    }

    /// Mark the buffer as just-saved.
    pub fn mark_saved(&mut self) {
        self.disk_text = self.editor.lines().join("\n");
        self.status_line = "Saved & reloaded".into();
    }

    pub fn record_error(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        self.last_validation = Some(Err(msg.clone()));
        self.status_line = msg;
    }
}

fn style_editor(editor: &mut TextArea<'_>) {
    editor.set_line_number_style(Style::default().fg(ratatui::style::Color::DarkGray));
    editor.set_cursor_line_style(Style::default().add_modifier(Modifier::REVERSED));
    editor.set_cursor_style(
        Style::default()
            .bg(ratatui::style::Color::Yellow)
            .fg(ratatui::style::Color::Black),
    );
}

pub fn render(frame: &mut Frame, area: Rect, state: &mut ConfigureState, focused: bool) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // editor
            Constraint::Length(3), // validation panel
        ])
        .split(area);

    let title = if state.is_dirty() {
        " Config (modified) "
    } else {
        " Config "
    };
    let block = Block::default()
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
        ));
    state.editor.set_block(block);
    frame.render_widget(&state.editor, chunks[0]);

    // Validation panel
    let lines = match &state.last_validation {
        None => vec![Line::from(Span::styled(
            "Press F5 to validate. F9 saves and reloads.",
            theme::DIM,
        ))],
        Some(Ok(())) => vec![Line::from(vec![
            Span::styled("✔ ", theme::OK),
            Span::styled("Configuration is valid.", theme::OK),
        ])],
        Some(Err(msg)) => vec![
            Line::from(vec![
                Span::styled("✘ ", theme::ERR),
                Span::styled(msg.clone(), theme::ERR),
            ]),
            Line::from(Span::styled(state.status_line.clone(), theme::DIM)),
        ],
    };
    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::BORDER)
                .title(" Validation "),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(panel, chunks[1]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_check_normalizes_trailing_newline() {
        let state = ConfigureState::new(valid_config_text_with_newline());
        assert!(!state.is_dirty());
    }

    #[test]
    fn validate_accepts_valid_config_and_updates_status() {
        let mut state = ConfigureState::new(valid_config_text());

        let parsed = state.validate().unwrap();

        assert_eq!(parsed.device.instance, 1234);
        assert_eq!(state.status_line, "Validation OK");
        assert!(matches!(state.last_validation, Some(Ok(()))));
    }

    #[test]
    fn validate_rejects_config_errors() {
        let mut state = ConfigureState::new(invalid_config_text());

        let err = state.validate().unwrap_err();

        assert!(err.contains("device instance"), "got: {err}");
        assert!(state.last_validation.is_none());
    }

    #[test]
    fn mark_saved_updates_disk_snapshot_and_clears_dirty_state() {
        let mut state = ConfigureState::new(valid_config_text_with_newline());
        state.editor = TextArea::from(valid_config_text().lines().collect::<Vec<_>>());

        state.mark_saved();

        assert_eq!(state.status_line, "Saved & reloaded");
        assert!(!state.is_dirty());
    }

    #[test]
    fn record_error_sets_validation_error_and_status_line() {
        let mut state = ConfigureState::new(valid_config_text());

        state.record_error("bad config");

        assert_eq!(state.status_line, "bad config");
        assert!(matches!(
            state.last_validation,
            Some(Err(ref msg)) if msg == "bad config"
        ));
    }

    fn valid_config_text() -> String {
        r#"{
  "mcp": {
    "read_only": true
  },
  "device": {
    "instance": 1234,
    "name": "TUI Test Gateway",
    "vendor_id": 999,
    "description": "test"
  },
  "transports": {
    "bip": {
      "interface": "127.0.0.1",
      "port": 47808,
      "broadcast": "127.255.255.255",
      "network_number": 1
    }
  }
}"#
        .into()
    }

    fn valid_config_text_with_newline() -> String {
        format!("{}\n", valid_config_text())
    }

    fn invalid_config_text() -> String {
        valid_config_text().replace("\"instance\": 1234", "\"instance\": 4194303")
    }
}
