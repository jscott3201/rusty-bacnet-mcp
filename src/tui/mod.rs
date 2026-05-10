//! Operator console — ratatui-based TUI for the bacnet-mcp daemon.
//!
//! Three tabs: **Configure** (JSON editor + validate + reload), **Observe**
//! (device table + log tail + transport status), **Operate** (manual WhoIs /
//! ReadProperty / WriteProperty with confirmation). Uses the same
//! `GatewayState` that the MCP transports use, so any action taken in the
//! TUI is reflected to outside MCP clients and vice versa.

pub mod app;
pub mod event;
pub mod logger;
pub mod reload;
pub mod tabs;
pub mod theme;
pub mod ui;

pub use reload::{ReloadOutcome, reload_safety_check};

pub use logger::{LogBuffer, LogLayer};

use std::io;
use std::time::Duration;

use bacnet_types::primitives::ObjectIdentifier;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use tokio_util::sync::CancellationToken;

use crate::config::GatewayConfig;
use crate::parse::{
    decode_raw_property_to_json_with_context, json_to_property_value, object_type_name,
    parse_object_type, parse_property_name, property_name,
};
use crate::state::GatewayState;
use crate::tui::app::{Action, App};
use crate::tui::event::{AppSender, Event, StatusKind};
use crate::tui::tabs::Tab;
use crate::tui::tabs::operate::OpForm;

type Tui = Terminal<CrosstermBackend<io::Stdout>>;

/// How the TUI exited. Drives whether the caller (`main.rs::run_tui`) tears
/// the daemon down or keeps it running headless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiExit {
    /// Operator quit (q / Ctrl-C / external shutdown). Daemon should stop.
    Quit,
    /// Operator detached (F12). Daemon should keep serving MCP — the caller
    /// must wait on its own shutdown signal (SIGINT/SIGTERM) to stop.
    Detached,
}

/// Public entry point. Sets up the terminal, runs the loop, restores the
/// terminal on exit (or panic). `shutdown` propagates Ctrl-C / SIGTERM from
/// outside; on a Quit exit the TUI cancels it so the rest of the daemon
/// tears down. On a Detached exit the token is left untouched so the BACnet
/// stack and HTTP MCP server keep running. `log_buffer` is the shared ring
/// buffer that the tracing Layer (installed by `main.rs`) writes into and the
/// Observe tab reads from. `http_listening` reflects whether the streamable-
/// HTTP MCP transport was actually started for this session — the Observe
/// tab uses this for the UP/DOWN badge instead of inferring from config
/// presence, and the F12 detach handler refuses when it's false.
pub async fn run(
    state: GatewayState,
    config: GatewayConfig,
    config_path: String,
    log_buffer: LogBuffer,
    http_listening: bool,
    shutdown: CancellationToken,
) -> Result<TuiExit, Box<dyn std::error::Error + Send + Sync>> {
    // Read the on-disk config text so the editor starts mirroring the file.
    let config_text =
        std::fs::read_to_string(&config_path).map_err(|e| format!("read {config_path}: {e}"))?;

    install_panic_hook();
    let mut terminal = setup_terminal()?;

    let result = main_loop(
        &mut terminal,
        state,
        config,
        config_path,
        config_text,
        log_buffer,
        http_listening,
        shutdown.clone(),
    )
    .await;

    restore_terminal(&mut terminal)?;
    match result {
        Ok(TuiExit::Quit) => {
            shutdown.cancel();
            Ok(TuiExit::Quit)
        }
        Ok(TuiExit::Detached) => {
            // Leave `shutdown` alive — HTTP MCP server and BACnet stack
            // keep going. Caller will await its own signal handler.
            Ok(TuiExit::Detached)
        }
        Err(e) => {
            // Any TUI-internal failure tears the daemon down too — we have
            // no way to surface it once headless.
            shutdown.cancel();
            Err(e.into())
        }
    }
}

fn setup_terminal() -> io::Result<Tui> {
    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(out);
    Terminal::new(backend)
}

fn restore_terminal(terminal: &mut Tui) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Best-effort terminal restore so the user's shell isn't left in raw mode.
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        original(info);
    }));
}

#[allow(clippy::too_many_arguments)]
async fn main_loop(
    terminal: &mut Tui,
    state: GatewayState,
    config: GatewayConfig,
    config_path: String,
    config_text: String,
    log_buffer: LogBuffer,
    http_listening: bool,
    shutdown: CancellationToken,
) -> Result<TuiExit, String> {
    let mut app = App::new(
        state.clone(),
        config,
        config_path.clone(),
        shutdown.clone(),
        config_text,
        log_buffer,
        http_listening,
    );

    // Event fan-in (crossterm + ticks + render) and a sender we can hand to
    // background tasks (device poller, action runners).
    let (mut events, sender, event_handle) = event::spawn(shutdown.clone());

    // Spawn the device-table poller — every 2s, snapshot the BACnet client's
    // discovered_devices into an event the UI consumes.
    let poll_handle = spawn_device_poller(state.clone(), sender.clone(), shutdown.clone());

    while let Some(ev) = events.recv().await {
        if app.should_quit || app.should_detach || shutdown.is_cancelled() {
            break;
        }

        // Some events go straight to render path or per-tab side-channels:
        match &ev {
            // BACnet client doesn't push, we pull on tick — refresh from cache here too.
            Event::Tick => {
                refresh_observe_cache(&mut app, &state).await;
            }
            Event::Render => {
                terminal
                    .draw(|f| ui::render(f, &mut app))
                    .map_err(|e| format!("draw: {e}"))?;
                continue;
            }
            _ => {}
        }

        let action = app.handle_event(ev);
        execute_action(&mut app, action, &state, &sender).await;
    }

    poll_handle.abort();
    let _ = event_handle.await;
    // Detach wins over quit if both happen to be set (shouldn't, but be safe):
    // detach implies the user explicitly chose to keep the daemon alive.
    if app.should_detach {
        Ok(TuiExit::Detached)
    } else {
        Ok(TuiExit::Quit)
    }
}

async fn refresh_observe_cache(app: &mut App, state: &GatewayState) {
    if app.tab != Tab::Observe {
        return;
    }
    if let Some(client) = state.client() {
        let devices = client.discovered_devices().await;
        app.observe.devices = devices;
        app.observe.last_refresh = Some(std::time::Instant::now());
    }
}

fn spawn_device_poller(
    state: GatewayState,
    sender: AppSender,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tick.tick() => {
                    if let Some(_client) = state.client() {
                        // Push a Tick — the main loop pulls discovered_devices()
                        // from the client cache directly. We just nudge it.
                        let _ = sender.send(Event::Tick);
                    }
                }
            }
        }
    })
}

async fn execute_action(app: &mut App, action: Action, state: &GatewayState, _sender: &AppSender) {
    match action {
        Action::None => {}
        Action::Quit => {
            app.should_quit = true;
        }
        Action::DetachToHeadless => {
            // Logged at info — this transition is operationally significant
            // (operator just left the daemon running unattended).
            tracing::info!(
                "TUI detach requested (F12) — tearing down render loop, leaving \
                 BACnet stack and HTTP MCP server running"
            );
            app.should_detach = true;
        }
        Action::ToggleHelp => {
            app.help_visible = !app.help_visible;
        }
        Action::ToggleMouse => {
            app.mouse_capture = !app.mouse_capture;
            // Best-effort terminal flag toggle — failure here is non-fatal.
            if app.mouse_capture {
                let _ = execute!(io::stdout(), EnableMouseCapture);
                app.toast = Some((
                    std::time::Instant::now(),
                    StatusKind::Ok,
                    "Mouse capture: ON".into(),
                ));
            } else {
                let _ = execute!(io::stdout(), DisableMouseCapture);
                app.toast = Some((
                    std::time::Instant::now(),
                    StatusKind::Ok,
                    "Mouse capture: OFF (terminal selection works)".into(),
                ));
            }
        }
        Action::SaveAndReload => {
            reload::do_save_and_reload(app).await;
        }
        Action::RunOperate => {
            run_operate(app, state).await;
        }
    }
}

async fn run_operate(app: &mut App, state: &GatewayState) {
    let result = match app.operate.form {
        OpForm::WhoIs => run_whois(app, state).await,
        OpForm::Read => run_read(app, state).await,
        OpForm::Write => run_write(app, state).await,
    };
    let summary = match &result {
        Ok(s) => s.lines().next().unwrap_or("").to_string(),
        Err(e) => e.lines().next().unwrap_or("").to_string(),
    };
    app.operate.record(
        match app.operate.form {
            OpForm::WhoIs => "whois",
            OpForm::Read => "read",
            OpForm::Write => "write",
        },
        summary,
        result.is_ok(),
    );
    app.operate.last_result = Some(result);
}

async fn run_whois(app: &mut App, state: &GatewayState) -> Result<String, String> {
    let client = state.require_client()?;
    let lo = parse_opt_u32(&app.operate.whois.fields[0].value)?;
    let hi = parse_opt_u32(&app.operate.whois.fields[1].value)?;
    let timeout = parse_opt_u64(&app.operate.whois.fields[2].value)?
        .unwrap_or(3)
        .min(30);

    client
        .who_is(lo, hi)
        .await
        .map_err(|e| format!("WhoIs send: {e}"))?;
    tokio::time::sleep(Duration::from_secs(timeout)).await;
    let devices = client.discovered_devices().await;
    Ok(format!(
        "WhoIs complete. Device table: {} entries.",
        devices.len()
    ))
}

async fn run_read(app: &mut App, state: &GatewayState) -> Result<String, String> {
    let client = state.require_client()?;
    let device_instance = parse_required_u32(&app.operate.read.fields[0].value, "device instance")?;
    let obj_type = parse_object_type(app.operate.read.fields[1].value.trim())?;
    let obj_instance = parse_required_u32(&app.operate.read.fields[2].value, "object instance")?;
    let property = parse_property_name(app.operate.read.fields[3].value.trim())?;

    let oid = ObjectIdentifier::new(obj_type, obj_instance).map_err(|e| format!("{e}"))?;
    let entry = state.resolve_device(device_instance).await?;
    let ack = client
        .read_property(&entry.mac_address, oid, property, None)
        .await
        .map_err(|e| format!("ReadProperty: {e}"))?;
    let val = decode_raw_property_to_json_with_context(&ack.property_value, property);
    let display = val
        .get("value")
        .map(|v| format!("{v}"))
        .unwrap_or_else(|| format!("{val}"));
    Ok(format!(
        "{}:{} {} = {}",
        object_type_name(obj_type),
        obj_instance,
        property_name(property),
        display
    ))
}

async fn run_write(app: &mut App, state: &GatewayState) -> Result<String, String> {
    state.require_writable()?;
    let client = state.require_client()?;
    let device_instance =
        parse_required_u32(&app.operate.write.fields[0].value, "device instance")?;
    let obj_type = parse_object_type(app.operate.write.fields[1].value.trim())?;
    let obj_instance = parse_required_u32(&app.operate.write.fields[2].value, "object instance")?;
    let property = parse_property_name(app.operate.write.fields[3].value.trim())?;
    let raw_value = app.operate.write.fields[4].value.trim();
    if raw_value.is_empty() {
        return Err("value is required".into());
    }
    let value_json: serde_json::Value =
        serde_json::from_str(raw_value).map_err(|e| format!("value JSON parse: {e}"))?;
    let priority = parse_opt_u8(&app.operate.write.fields[5].value)?;

    let oid = ObjectIdentifier::new(obj_type, obj_instance).map_err(|e| format!("{e}"))?;
    let entry = state.resolve_device(device_instance).await?;
    let value = json_to_property_value(&value_json).map_err(|e| format!("encode: {e}"))?;

    let mut buf = bytes::BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(&mut buf, &value)
        .map_err(|e| format!("encode: {e}"))?;

    client
        .write_property(
            &entry.mac_address,
            oid,
            property,
            None,
            buf.to_vec(),
            priority,
        )
        .await
        .map_err(|e| format!("WriteProperty: {e}"))?;
    Ok(format!(
        "Wrote {} to {}:{} {}",
        raw_value,
        object_type_name(obj_type),
        obj_instance,
        property_name(property),
    ))
}

fn parse_opt_u32(s: &str) -> Result<Option<u32>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse::<u32>()
        .map(Some)
        .map_err(|e| format!("u32 parse: {e}"))
}

fn parse_opt_u64(s: &str) -> Result<Option<u64>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse::<u64>()
        .map(Some)
        .map_err(|e| format!("u64 parse: {e}"))
}

fn parse_opt_u8(s: &str) -> Result<Option<u8>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse::<u8>()
        .map(Some)
        .map_err(|e| format!("u8 parse: {e}"))
}

fn parse_required_u32(s: &str, label: &str) -> Result<u32, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err(format!("{label} is required"));
    }
    s.parse::<u32>().map_err(|e| format!("{label}: {e}"))
}
