//! Top-level App state and the input handler that translates events into
//! state transitions. The render code lives in `ui` and the per-tab `tabs/*`
//! modules — App holds the data, those modules paint it.

use std::time::{Duration, Instant};

use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use tokio_util::sync::CancellationToken;
use tui_textarea::{Input, Key};

#[allow(unused_imports)]
use ratatui::crossterm::event::KeyEventKind;

use crate::config::GatewayConfig;
use crate::state::GatewayState;
use crate::tui::event::{Event, StatusKind};
use crate::tui::logger::LogBuffer;
use crate::tui::tabs::{
    Tab,
    configure::ConfigureState,
    observe::ObserveState,
    operate::{OpForm, OperateState},
};

/// What `handle_event` asks the run loop to do next.
#[derive(Debug, Clone)]
pub enum Action {
    /// No-op (most events).
    None,
    /// Quit the TUI cleanly.
    Quit,
    /// Detach the TUI to headless mode (F12). The render loop tears down and
    /// the terminal is restored, but the BACnet stack and HTTP MCP server keep
    /// running in the same process. Once detached, no reconnect — operator
    /// must restart the daemon to get the TUI back.
    DetachToHeadless,
    /// Validate and reload config from the editor buffer (F9).
    SaveAndReload,
    /// Run the active operate form (Enter inside operate tab).
    RunOperate,
    /// Toggle mouse capture (Ctrl-M) — mouse off lets the terminal handle native selection.
    ToggleMouse,
    /// Show or hide the help popup.
    ToggleHelp,
}

pub struct App {
    pub gateway: GatewayState,
    pub config: GatewayConfig,
    pub config_path: String,
    pub shutdown: CancellationToken,
    pub log_buffer: LogBuffer,
    /// True when the HTTP MCP listener was started for this session.
    /// Renders as the UP/DOWN badge — independent of whether `config.mcp.http`
    /// is populated, so `--no-http` shows DOWN even with an http block in the
    /// config file.
    pub http_listening: bool,

    pub tab: Tab,
    pub mouse_capture: bool,
    pub help_visible: bool,
    pub should_quit: bool,
    /// Set by F12. When true the run loop breaks like `should_quit` but the
    /// caller skips `shutdown.cancel()` so the BACnet stack + HTTP MCP server
    /// keep running after the TUI tears down.
    pub should_detach: bool,

    pub configure: ConfigureState,
    pub observe: ObserveState,
    pub operate: OperateState,

    pub toast: Option<(Instant, StatusKind, String)>,
}

impl App {
    pub fn new(
        gateway: GatewayState,
        config: GatewayConfig,
        config_path: String,
        shutdown: CancellationToken,
        initial_config_text: String,
        log_buffer: LogBuffer,
        http_listening: bool,
    ) -> Self {
        Self {
            gateway,
            config,
            config_path,
            shutdown,
            log_buffer,
            http_listening,
            tab: Tab::Observe,
            mouse_capture: true,
            help_visible: false,
            should_quit: false,
            should_detach: false,
            configure: ConfigureState::new(initial_config_text),
            observe: ObserveState::new(),
            operate: OperateState::new(),
            toast: None,
        }
    }

    /// Translate a raw event into an Action. The caller (`run_loop`) executes
    /// async work the action implies (config reload, BACnet calls).
    pub fn handle_event(&mut self, ev: Event) -> Action {
        match ev {
            Event::Tick => Action::None,
            Event::Render => Action::None,
            Event::Resize(_, _) => Action::None,
            Event::Status(kind, msg) => {
                self.toast = Some((Instant::now(), kind, msg));
                Action::None
            }
            Event::Key(k) => self.handle_key(k),
            Event::Mouse(m) => self.handle_mouse(m),
        }
    }

    fn handle_key(&mut self, k: KeyEvent) -> Action {
        // Global keys first — these win over tab-specific bindings.
        if k.modifiers.contains(KeyModifiers::CONTROL) && matches!(k.code, KeyCode::Char('c')) {
            self.should_quit = true;
            return Action::Quit;
        }
        if self.help_visible {
            // Any key dismisses the help popup.
            self.help_visible = false;
            return Action::None;
        }
        if matches!(k.code, KeyCode::F(1)) {
            return Action::ToggleHelp;
        }
        if matches!(k.code, KeyCode::F(12)) {
            return self.request_detach();
        }
        if k.modifiers.contains(KeyModifiers::CONTROL) && matches!(k.code, KeyCode::Char('m')) {
            return Action::ToggleMouse;
        }

        // Tab cycling (works on any tab as long as we're not editing text).
        let editing_text = self.tab == Tab::Configure
            || (self.tab == Tab::Operate && !self.operate.current_form_mut().fields.is_empty());

        if !editing_text || matches!(k.code, KeyCode::Tab | KeyCode::BackTab) {
            match k.code {
                KeyCode::Tab => {
                    self.tab = self.tab.next();
                    return Action::None;
                }
                KeyCode::BackTab => {
                    self.tab = self.tab.prev();
                    return Action::None;
                }
                _ => {}
            }
        }

        match self.tab {
            Tab::Configure => self.handle_key_configure(k),
            Tab::Observe => self.handle_key_observe(k),
            Tab::Operate => self.handle_key_operate(k),
        }
    }

    fn handle_key_configure(&mut self, k: KeyEvent) -> Action {
        match k.code {
            KeyCode::F(5) => {
                match self.configure.validate() {
                    Ok(_) => {
                        self.toast = Some((Instant::now(), StatusKind::Ok, "Validation OK".into()));
                    }
                    Err(msg) => {
                        self.configure.record_error(msg.clone());
                        self.toast = Some((Instant::now(), StatusKind::Err, msg));
                    }
                }
                Action::None
            }
            KeyCode::F(9) => Action::SaveAndReload,
            KeyCode::Esc => {
                // Esc in configure = cancel any selection. Keep the tab.
                self.configure.editor.cancel_selection();
                Action::None
            }
            _ => {
                let input: Input = k.into();
                // Filter out raw newline → Enter is fine for tui-textarea, just
                // pass through.
                self.configure.editor.input(input);
                Action::None
            }
        }
    }

    fn handle_key_observe(&mut self, k: KeyEvent) -> Action {
        match k.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
                Action::Quit
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.observe.select_next();
                Action::None
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.observe.select_prev();
                Action::None
            }
            KeyCode::Char('g') => {
                if !self.observe.devices.is_empty() {
                    self.observe.table.select(Some(0));
                }
                Action::None
            }
            KeyCode::Char('G') => {
                if !self.observe.devices.is_empty() {
                    self.observe
                        .table
                        .select(Some(self.observe.devices.len() - 1));
                }
                Action::None
            }
            // Log pane keybinds — paging and verbosity filtering.
            KeyCode::Char('l') => {
                self.observe.log_page_forward();
                Action::None
            }
            KeyCode::Char('h') => {
                self.observe.log_page_back();
                Action::None
            }
            KeyCode::Char('-') => {
                self.observe.log_level_up();
                Action::None
            }
            KeyCode::Char('+') | KeyCode::Char('=') => {
                self.observe.log_level_down();
                Action::None
            }
            _ => Action::None,
        }
    }

    fn handle_key_operate(&mut self, k: KeyEvent) -> Action {
        match k.code {
            KeyCode::Char('1') => {
                self.operate.form = OpForm::WhoIs;
                Action::None
            }
            KeyCode::Char('2') => {
                self.operate.form = OpForm::Read;
                Action::None
            }
            KeyCode::Char('3') => {
                self.operate.form = OpForm::Write;
                Action::None
            }
            KeyCode::Char('q') => {
                self.should_quit = true;
                Action::Quit
            }
            KeyCode::Up => {
                self.operate.current_form_mut().focus_prev();
                Action::None
            }
            KeyCode::Down => {
                self.operate.current_form_mut().focus_next();
                Action::None
            }
            KeyCode::Backspace => {
                self.operate.current_form_mut().current().value.pop();
                Action::None
            }
            KeyCode::Enter => Action::RunOperate,
            KeyCode::Char(c) => {
                self.operate.current_form_mut().current().value.push(c);
                Action::None
            }
            _ => Action::None,
        }
    }

    fn handle_mouse(&mut self, m: MouseEvent) -> Action {
        if !self.mouse_capture {
            return Action::None;
        }
        match m.kind {
            // Scroll the log pane / table when on Observe tab.
            MouseEventKind::ScrollDown if self.tab == Tab::Observe => {
                self.observe.select_next();
                Action::None
            }
            MouseEventKind::ScrollUp if self.tab == Tab::Observe => {
                self.observe.select_prev();
                Action::None
            }
            MouseEventKind::Down(MouseButton::Left) => Action::None,
            _ => Action::None,
        }
    }

    /// F12 handler. Refuses if the HTTP MCP server isn't listening — without
    /// HTTP the daemon has no outside surface, so detaching would leave a
    /// process running that nothing can reach. Operator should `q` instead.
    fn request_detach(&mut self) -> Action {
        if !self.http_listening {
            self.toast = Some((
                Instant::now(),
                StatusKind::Warn,
                "Detach refused: no HTTP MCP transport — the daemon would be unreachable. Press q to quit instead.".into(),
            ));
            return Action::None;
        }
        Action::DetachToHeadless
    }

    /// Drop expired toasts (older than 4 seconds).
    pub fn cull_toast(&mut self) {
        if let Some((at, _, _)) = self.toast
            && at.elapsed() > Duration::from_secs(4)
        {
            self.toast = None;
        }
    }
}

/// tui-textarea provides `From<KeyEvent>` for `Input` via its crossterm feature.
/// This explicit conversion exists in case future code paths need to construct
/// an Input without a real crossterm event (e.g. macro-driven actions).
#[allow(dead_code)]
fn key_to_input(k: KeyEvent) -> Input {
    let key = match k.code {
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Enter => Key::Enter,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Tab => Key::Tab,
        KeyCode::Delete => Key::Delete,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Esc => Key::Esc,
        _ => Key::Null,
    };
    Input {
        key,
        ctrl: k.modifiers.contains(KeyModifiers::CONTROL),
        alt: k.modifiers.contains(KeyModifiers::ALT),
        shift: k.modifiers.contains(KeyModifiers::SHIFT),
    }
}

#[cfg(test)]
mod detach_tests {
    use super::*;
    use crate::config::{BipConfig, DeviceConfig, McpConfig, TransportsConfig};
    use bacnet_objects::database::ObjectDatabase;
    use ratatui::crossterm::event::{KeyEvent, KeyEventKind};

    fn baseline_config() -> GatewayConfig {
        GatewayConfig {
            mcp: McpConfig {
                api_key: None,
                read_only: true,
                http: None,
                safety: None,
                audit: None,
            },
            device: DeviceConfig {
                instance: 389001,
                name: "Test".into(),
                vendor_id: 999,
                description: "test".into(),
            },
            transports: TransportsConfig {
                bip: Some(BipConfig {
                    interface: "0.0.0.0".into(),
                    port: 47808,
                    broadcast: "192.168.1.255".into(),
                    network_number: 1,
                }),
                sc: None,
            },
            bbmd: None,
            foreign_device: None,
            routes: vec![],
            objects: vec![],
        }
    }

    fn make_app(http_listening: bool) -> App {
        let config = baseline_config();
        let state = GatewayState::new(ObjectDatabase::new(), config.clone());
        App::new(
            state,
            config,
            "/tmp/test.json".into(),
            CancellationToken::new(),
            "{}".into(),
            LogBuffer::default(),
            http_listening,
        )
    }

    fn f12() -> KeyEvent {
        KeyEvent {
            code: KeyCode::F(12),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: ratatui::crossterm::event::KeyEventState::NONE,
        }
    }

    #[test]
    fn f12_returns_detach_action_when_http_listening() {
        let mut app = make_app(true);
        let action = app.handle_event(Event::Key(f12()));
        assert!(matches!(action, Action::DetachToHeadless));
        // App state itself isn't flipped here — the run loop sets should_detach
        // when it executes the action. Flag stays false until execute_action.
        assert!(!app.should_detach);
        assert!(!app.should_quit);
    }

    #[test]
    fn f12_refused_when_http_not_listening() {
        let mut app = make_app(false);
        let action = app.handle_event(Event::Key(f12()));
        assert!(matches!(action, Action::None));
        // Operator gets a toast explaining why nothing happened — silence
        // would feel like a broken keybind.
        let toast = app.toast.expect("expected refusal toast");
        assert!(matches!(toast.1, StatusKind::Warn));
        assert!(toast.2.contains("no HTTP MCP transport"));
    }

    #[test]
    fn f12_works_from_configure_tab_text_editor() {
        // The Configure tab swallows most keys to feed the textarea editor.
        // F12 must NOT be one of them — it's a global keybind.
        let mut app = make_app(true);
        app.tab = Tab::Configure;
        let action = app.handle_event(Event::Key(f12()));
        assert!(matches!(action, Action::DetachToHeadless));
    }
}
