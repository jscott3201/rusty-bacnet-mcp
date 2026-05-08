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
pub mod tabs;
pub mod theme;
pub mod ui;

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

/// Public entry point. Sets up the terminal, runs the loop, restores the
/// terminal on exit (or panic). `shutdown` propagates Ctrl-C / SIGTERM from
/// outside; the TUI also cancels it on its own quit. `log_buffer` is the
/// shared ring buffer that the tracing Layer (installed by `main.rs`) writes
/// into and the Observe tab reads from. `http_listening` reflects whether the
/// streamable-HTTP MCP transport was actually started for this session — the
/// Observe tab uses this for the UP/DOWN badge instead of inferring from
/// config presence.
pub async fn run(
    state: GatewayState,
    config: GatewayConfig,
    config_path: String,
    log_buffer: LogBuffer,
    http_listening: bool,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    shutdown.cancel();
    result.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })
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
) -> Result<(), String> {
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
        if app.should_quit || shutdown.is_cancelled() {
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
    Ok(())
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
            do_save_and_reload(app).await;
        }
        Action::RunOperate => {
            run_operate(app, state).await;
        }
    }
}

/// Classification of a config change as it relates to hot-reload.
///
/// - `Applied`: every changed field is hot-swap safe; live state has been updated.
/// - `PartialApplied`: some fields applied immediately, others need a daemon restart.
/// - `Refused`: at least one change would corrupt running state — nothing was touched.
#[derive(Debug, Clone)]
pub enum ReloadOutcome {
    Applied {
        changed: Vec<&'static str>,
    },
    PartialApplied {
        applied: Vec<&'static str>,
        stale: Vec<&'static str>,
    },
    Refused {
        reason: String,
    },
}

/// Classify a proposed config change.
///
/// **Bucketing rationale:**
/// - `Applied` — fields that `RuntimeFlags::apply()` knows how to swap atomically.
///   Today: `mcp.read_only`. Phase 2 will add the safety control plane fields.
/// - `Refused` — changes that would corrupt the BACnet wire protocol or running peers.
///   Today: `device.instance` (already-discovered peers cache I-Am responses; a
///   mid-flight change creates two devices claiming the same instance number).
/// - `Stale` (still allowed) — restart-required but harmless to write to disk.
///   The operator gets a precise list of what won't take effect until restart.
pub fn reload_safety_check(old: &GatewayConfig, new: &GatewayConfig) -> ReloadOutcome {
    // ── Refused ──────────────────────────────────────────────────────────
    if old.device.instance != new.device.instance {
        return ReloadOutcome::Refused {
            reason: format!(
                "device.instance change ({} → {}) requires daemon restart — \
                 already-discovered peers cached the old I-Am and a live swap \
                 would create conflicting identities on the BACnet network",
                old.device.instance, new.device.instance,
            ),
        };
    }

    let mut applied: Vec<&'static str> = Vec::new();
    let mut stale: Vec<&'static str> = Vec::new();

    // ── Hot-swap safe (covered by RuntimeFlags::apply) ──────────────────
    if old.mcp.read_only != new.mcp.read_only {
        applied.push("mcp.read_only");
    }
    if old.mcp.safety != new.mcp.safety {
        // Whole `safety` block is hot-swappable via ArcSwap. Tracking
        // sub-fields individually doesn't add value — the block deserializes
        // to a single `WritePolicy` that gets atomically replaced.
        applied.push("mcp.safety");
    }

    // ── Stale until restart ─────────────────────────────────────────────
    if old.mcp.api_key != new.mcp.api_key {
        stale.push("mcp.api_key (HTTP auth middleware bound at startup)");
    }
    if old.mcp.http != new.mcp.http {
        stale.push("mcp.http (TCP listener already bound)");
    }
    if old.device.name != new.device.name {
        stale.push("device.name (Device object held in DB)");
    }
    if old.device.vendor_id != new.device.vendor_id {
        stale.push("device.vendor_id (Device object held in DB)");
    }
    if old.device.description != new.device.description {
        stale.push("device.description (Device object held in DB)");
    }
    if old.transports.bip != new.transports.bip {
        stale.push("transports.bip (UDP socket already bound)");
    }
    if old.transports.sc != new.transports.sc {
        stale.push("transports.sc (transport already established)");
    }
    if old.bbmd != new.bbmd {
        stale.push("bbmd (BDT registered with peers)");
    }
    if old.foreign_device != new.foreign_device {
        stale.push("foreign_device (BBMD registration TTL active)");
    }
    if old.routes != new.routes {
        stale.push("routes (NPDU routing table built at boot)");
    }
    if old.objects != new.objects {
        stale.push("objects (local DB pre-populated at boot)");
    }
    if old.mcp.audit != new.mcp.audit {
        // Audit log is a per-startup file handle. Path / capacity changes
        // require a restart to take effect — the in-memory ring buffer would
        // otherwise have to be drained-and-reopened mid-flight, which loses
        // entries.
        stale.push("mcp.audit (audit log file/capacity bound at startup)");
    }

    if stale.is_empty() {
        ReloadOutcome::Applied { changed: applied }
    } else {
        ReloadOutcome::PartialApplied { applied, stale }
    }
}

async fn do_save_and_reload(app: &mut App) {
    // 1. Parse + validate the editor buffer.
    let parsed = match app.configure.validate() {
        Ok(p) => p,
        Err(msg) => {
            app.configure.record_error(msg.clone());
            app.toast = Some((std::time::Instant::now(), StatusKind::Err, msg));
            return;
        }
    };

    // 2. Classify the change. Refused changes never touch disk or live state.
    let outcome = reload_safety_check(&app.config, &parsed);
    if let ReloadOutcome::Refused { reason } = &outcome {
        app.configure.record_error(reason.clone());
        app.toast = Some((
            std::time::Instant::now(),
            StatusKind::Err,
            format!("Refused: {}", first_line(reason)),
        ));
        tracing::warn!("Reload refused: {reason}");
        return;
    }

    // 3. Write to disk. We persist the new config even when fields are stale
    //    so the next daemon restart picks them up. Write with a trailing
    //    newline (POSIX convention); the dirty-check normalizes both sides.
    let mut text = app.configure.editor.lines().join("\n");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    if let Err(e) = std::fs::write(&app.config_path, &text) {
        let msg = format!("write {}: {}", app.config_path, e);
        app.configure.record_error(msg.clone());
        app.toast = Some((std::time::Instant::now(), StatusKind::Err, msg));
        return;
    }
    app.configure.disk_text = text;

    // 4. Apply hot-safe live changes. The atomic swap happens here; in-flight
    //    MCP tool calls see the new value on their next read. If the safety
    //    block is malformed, surface the error and skip the apply — the file
    //    has already been written so the next restart picks it up, but live
    //    state stays on the previous policy.
    if let Err(e) = app.gateway.flags.apply(&parsed) {
        let msg = format!("safety policy invalid (live state unchanged): {e}");
        app.configure.record_error(msg.clone());
        app.toast = Some((std::time::Instant::now(), StatusKind::Err, msg));
        return;
    }

    // 5. Update the TUI's runtime view so it reflects what's actually live.
    //
    //    On `Applied`, every change is hot-safe → mirror the whole parsed
    //    config so future reload-checks compare against the new baseline.
    //
    //    On `PartialApplied`, restart-required fields are NOT live yet — the
    //    Observe tab and `bacnet://state/config` resource must keep showing
    //    the old (still-effective) values. We only mirror the fields that
    //    actually applied; the new file lives on disk and takes effect at
    //    next daemon start.
    match &outcome {
        ReloadOutcome::Applied { .. } => {
            app.config = parsed;
        }
        ReloadOutcome::PartialApplied { .. } => {
            crate::state::RuntimeFlags::mirror_applied_fields(&parsed, &mut app.config);
        }
        ReloadOutcome::Refused { .. } => unreachable!("handled at step 2"),
    }
    app.configure.mark_saved();

    // 6. Toast the operator about what actually applied vs. what's stale.
    let (kind, msg) = format_reload_toast(&outcome);
    tracing::info!(
        "Config reload: {} (file: {})",
        format_reload_log(&outcome),
        app.config_path,
    );
    app.toast = Some((std::time::Instant::now(), kind, msg));
}

fn format_reload_toast(outcome: &ReloadOutcome) -> (StatusKind, String) {
    match outcome {
        ReloadOutcome::Applied { changed } if changed.is_empty() => (
            StatusKind::Info,
            "Saved (no live-config changes detected)".into(),
        ),
        ReloadOutcome::Applied { changed } => {
            (StatusKind::Ok, format!("Applied: {}", changed.join(", ")))
        }
        ReloadOutcome::PartialApplied { applied, stale } => {
            let prefix = if applied.is_empty() {
                String::new()
            } else {
                format!("Applied: {}.  ", applied.join(", "))
            };
            (
                StatusKind::Warn,
                format!(
                    "{prefix}Restart required for {} field(s) — see logs.",
                    stale.len()
                ),
            )
        }
        ReloadOutcome::Refused { reason } => (StatusKind::Err, format!("Refused: {reason}")),
    }
}

fn format_reload_log(outcome: &ReloadOutcome) -> String {
    match outcome {
        ReloadOutcome::Applied { changed } if changed.is_empty() => "no-op".into(),
        ReloadOutcome::Applied { changed } => format!("applied [{}]", changed.join(", ")),
        ReloadOutcome::PartialApplied { applied, stale } => format!(
            "applied [{}], stale [{}]",
            applied.join(", "),
            stale.join(", "),
        ),
        ReloadOutcome::Refused { reason } => format!("refused: {reason}"),
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
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

#[cfg(test)]
mod reload_tests {
    use super::*;
    use crate::config::{BipConfig, DeviceConfig, McpConfig, McpHttpConfig, TransportsConfig};

    fn baseline() -> GatewayConfig {
        GatewayConfig {
            mcp: McpConfig {
                api_key: Some("token-A".into()),
                read_only: true,
                http: Some(McpHttpConfig {
                    bind: "127.0.0.1:3000".into(),
                }),
                safety: None,
                audit: None,
            },
            device: DeviceConfig {
                instance: 389001,
                name: "Test Gateway".into(),
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

    #[test]
    fn no_change_is_noop_applied() {
        let outcome = reload_safety_check(&baseline(), &baseline());
        match outcome {
            ReloadOutcome::Applied { changed } => assert!(changed.is_empty()),
            other => panic!("expected Applied{{}} no-op, got {other:?}"),
        }
    }

    #[test]
    fn read_only_toggle_is_hot_applied() {
        let old = baseline();
        let mut new = baseline();
        new.mcp.read_only = false;
        match reload_safety_check(&old, &new) {
            ReloadOutcome::Applied { changed } => assert_eq!(changed, vec!["mcp.read_only"]),
            other => panic!("expected Applied with mcp.read_only, got {other:?}"),
        }
    }

    #[test]
    fn device_instance_change_is_refused() {
        let old = baseline();
        let mut new = baseline();
        new.device.instance = 999_999;
        match reload_safety_check(&old, &new) {
            ReloadOutcome::Refused { reason } => {
                assert!(reason.contains("device.instance"), "reason: {reason}");
                assert!(reason.contains("389001"), "reason: {reason}");
                assert!(reason.contains("999999"), "reason: {reason}");
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn api_key_rotation_is_stale_until_restart() {
        let old = baseline();
        let mut new = baseline();
        new.mcp.api_key = Some("token-B".into());
        match reload_safety_check(&old, &new) {
            ReloadOutcome::PartialApplied { applied, stale } => {
                assert!(applied.is_empty());
                assert!(stale.iter().any(|s| s.contains("mcp.api_key")));
            }
            other => panic!("expected PartialApplied, got {other:?}"),
        }
    }

    #[test]
    fn read_only_plus_api_key_is_partial_applied() {
        let old = baseline();
        let mut new = baseline();
        new.mcp.read_only = false;
        new.mcp.api_key = Some("token-B".into());
        match reload_safety_check(&old, &new) {
            ReloadOutcome::PartialApplied { applied, stale } => {
                assert_eq!(applied, vec!["mcp.read_only"]);
                assert!(stale.iter().any(|s| s.contains("mcp.api_key")));
            }
            other => panic!("expected PartialApplied with mixed bucket, got {other:?}"),
        }
    }

    #[test]
    fn http_bind_change_is_stale() {
        let old = baseline();
        let mut new = baseline();
        new.mcp.http = Some(McpHttpConfig {
            bind: "0.0.0.0:8080".into(),
        });
        match reload_safety_check(&old, &new) {
            ReloadOutcome::PartialApplied { applied, stale } => {
                assert!(applied.is_empty());
                assert!(stale.iter().any(|s| s.contains("mcp.http")));
            }
            other => panic!("expected PartialApplied for mcp.http change, got {other:?}"),
        }
    }

    #[test]
    fn transport_change_is_stale() {
        let old = baseline();
        let mut new = baseline();
        if let Some(bip) = &mut new.transports.bip {
            bip.broadcast = "10.0.0.255".into();
        }
        match reload_safety_check(&old, &new) {
            ReloadOutcome::PartialApplied { applied, stale } => {
                assert!(applied.is_empty());
                assert!(stale.iter().any(|s| s.contains("transports.bip")));
            }
            other => panic!("expected PartialApplied for transport change, got {other:?}"),
        }
    }

    #[test]
    fn refused_takes_precedence_over_other_changes() {
        // Even if we'd apply read_only, the device.instance change should
        // still refuse — the operator gets a clear "no" instead of partial work.
        let old = baseline();
        let mut new = baseline();
        new.mcp.read_only = false;
        new.device.instance = 999_999;
        match reload_safety_check(&old, &new) {
            ReloadOutcome::Refused { .. } => {}
            other => {
                panic!("expected Refused even with hot-safe edits also present, got {other:?}")
            }
        }
    }

    #[test]
    fn runtime_flags_apply_swaps_atomically() {
        // Sanity check that RuntimeFlags::apply actually mirrors what the
        // classifier promised. If the bucketing diverges from apply's behavior,
        // this test catches it.
        let config = baseline();
        let flags = crate::state::RuntimeFlags::from_config(&config).unwrap();
        assert!(flags.is_read_only());

        let mut next = baseline();
        next.mcp.read_only = false;
        flags.apply(&next).unwrap();
        assert!(!flags.is_read_only());
    }

    #[test]
    fn mirror_applied_fields_only_updates_hot_safe_bits() {
        // The TUI calls mirror_applied_fields on PartialApplied so the runtime
        // view shows new values for applied fields while keeping old values for
        // restart-required fields. This test pins that contract: after mirror,
        // mcp.read_only matches the new config but mcp.api_key (stale) does not.
        let mut runtime_view = baseline();
        let mut new_file = baseline();
        new_file.mcp.read_only = false;
        new_file.mcp.api_key = Some("rotated-token".into());
        new_file.mcp.http = Some(crate::config::McpHttpConfig {
            bind: "0.0.0.0:9999".into(),
        });

        crate::state::RuntimeFlags::mirror_applied_fields(&new_file, &mut runtime_view);

        // Applied → mirrored.
        assert!(!runtime_view.mcp.read_only);
        // Stale → unchanged from baseline.
        assert_eq!(runtime_view.mcp.api_key.as_deref(), Some("token-A"));
        assert_eq!(
            runtime_view.mcp.http.as_ref().map(|h| h.bind.as_str()),
            Some("127.0.0.1:3000")
        );
    }
}
