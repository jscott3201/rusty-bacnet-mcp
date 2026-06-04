//! Shell tab — command REPL for quick read-oriented BACnet operations.

use std::time::{Duration, Instant};

use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::ObjectIdentifier;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::config::{GatewayConfig, describe_sc_runtime};
use crate::parse::{
    decode_raw_property_to_json_with_context, object_type_name, parse_object_type,
    parse_property_name, property_name,
};
use crate::state::GatewayState;
use crate::tui::theme;

const MAX_OUTPUT_RECORDS: usize = 100;
const MAX_COMMAND_HISTORY: usize = 100;

/// Parsed shell commands. This is intentionally read-oriented for the first
/// shell slice; the Operate tab remains the explicit write surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellCommand {
    Help,
    Status,
    Devices,
    WhoIs {
        low: Option<u32>,
        high: Option<u32>,
        timeout_secs: u64,
    },
    Read {
        device_instance: u32,
        object_type: ObjectType,
        object_instance: u32,
        property: PropertyIdentifier,
    },
}

/// One completed command row.
#[derive(Debug, Clone)]
pub struct ShellRecord {
    pub at: Instant,
    pub command: String,
    pub result: Result<String, String>,
}

pub struct ShellState {
    pub input: String,
    pub records: Vec<ShellRecord>,
    command_history: Vec<String>,
    recall_index: Option<usize>,
}

impl ShellState {
    pub fn new() -> Self {
        Self {
            input: String::new(),
            records: Vec::new(),
            command_history: Vec::new(),
            recall_index: None,
        }
    }

    pub fn push_char(&mut self, c: char) {
        self.input.push(c);
        self.recall_index = None;
    }

    pub fn backspace(&mut self) {
        self.input.pop();
        self.recall_index = None;
    }

    pub fn clear_input(&mut self) {
        self.input.clear();
        self.recall_index = None;
    }

    pub fn take_command(&mut self) -> Option<String> {
        let command = self.input.trim().to_string();
        self.input.clear();
        self.recall_index = None;
        if command.is_empty() {
            None
        } else {
            Some(command)
        }
    }

    pub fn record_result(&mut self, command: String, result: Result<String, String>) {
        if self.command_history.first() != Some(&command) {
            self.command_history.insert(0, command.clone());
            if self.command_history.len() > MAX_COMMAND_HISTORY {
                self.command_history.truncate(MAX_COMMAND_HISTORY);
            }
        }
        self.records.insert(
            0,
            ShellRecord {
                at: Instant::now(),
                command,
                result,
            },
        );
        if self.records.len() > MAX_OUTPUT_RECORDS {
            self.records.truncate(MAX_OUTPUT_RECORDS);
        }
    }

    pub fn recall_previous(&mut self) {
        if self.command_history.is_empty() {
            return;
        }
        let next = match self.recall_index {
            Some(i) => (i + 1).min(self.command_history.len() - 1),
            None => 0,
        };
        self.recall_index = Some(next);
        self.input = self.command_history[next].clone();
    }

    pub fn recall_next(&mut self) {
        let Some(i) = self.recall_index else {
            return;
        };
        if i == 0 {
            self.recall_index = None;
            self.input.clear();
        } else {
            let next = i - 1;
            self.recall_index = Some(next);
            self.input = self.command_history[next].clone();
        }
    }
}

impl Default for ShellState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_shell_command(input: &str) -> Result<Option<ShellCommand>, String> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    let Some((command, args)) = parts.split_first() else {
        return Ok(None);
    };

    match command.to_ascii_lowercase().as_str() {
        "help" | "?" => {
            require_arg_count(args, 0, "help")?;
            Ok(Some(ShellCommand::Help))
        }
        "status" => {
            require_arg_count(args, 0, "status")?;
            Ok(Some(ShellCommand::Status))
        }
        "devices" => {
            require_arg_count(args, 0, "devices")?;
            Ok(Some(ShellCommand::Devices))
        }
        "whois" | "who-is" => parse_whois(args).map(Some),
        "read" | "rp" => parse_read(args).map(Some),
        other => Err(format!("unknown shell command '{other}'")),
    }
}

pub async fn execute_shell_command(
    command: ShellCommand,
    state: &GatewayState,
    config: &GatewayConfig,
    http_listening: bool,
) -> Result<String, String> {
    match command {
        ShellCommand::Help => Ok(help_text().to_string()),
        ShellCommand::Status => Ok(status_text(state, config, http_listening)),
        ShellCommand::Devices => list_devices(state).await,
        ShellCommand::WhoIs {
            low,
            high,
            timeout_secs,
        } => run_whois(state, low, high, timeout_secs).await,
        ShellCommand::Read {
            device_instance,
            object_type,
            object_instance,
            property,
        } => {
            read_property(
                state,
                device_instance,
                object_type,
                object_instance,
                property,
            )
            .await
        }
    }
}

pub fn render(frame: &mut Frame, area: Rect, state: &ShellState, focused: bool) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),    // output
            Constraint::Length(3), // prompt
        ])
        .split(area);

    render_output(frame, chunks[0], state);
    render_prompt(frame, chunks[1], state, focused);
}

fn render_output(frame: &mut Frame, area: Rect, state: &ShellState) {
    let visible_height = area.height.saturating_sub(2) as usize;
    let mut lines: Vec<Line> = Vec::new();

    if state.records.is_empty() {
        lines.push(Line::from(Span::styled(
            "Type `help` for commands. This shell runs read-oriented BACnet operations.",
            theme::DIM,
        )));
    } else {
        for record in state.records.iter().take(visible_height).rev() {
            let age = format!("{:>4}s", record.at.elapsed().as_secs());
            let prompt = Line::from(vec![
                Span::styled(age, theme::DIM),
                Span::raw("  "),
                Span::styled("> ", theme::STATUS_KEY),
                Span::styled(record.command.clone(), theme::HEADER_TITLE),
            ]);
            lines.push(prompt);
            match &record.result {
                Ok(msg) => {
                    for line in msg.lines().take(6) {
                        lines.push(Line::from(vec![
                            Span::raw("      "),
                            Span::styled(line.to_string(), theme::OK),
                        ]));
                    }
                }
                Err(msg) => {
                    for line in msg.lines().take(6) {
                        lines.push(Line::from(vec![
                            Span::raw("      "),
                            Span::styled(line.to_string(), theme::ERR),
                        ]));
                    }
                }
            }
        }
    }

    let output = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::BORDER)
                .title(" Shell output "),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(output, area);
}

fn render_prompt(frame: &mut Frame, area: Rect, state: &ShellState, focused: bool) {
    let line = Line::from(vec![
        Span::styled("> ", theme::STATUS_KEY.add_modifier(Modifier::BOLD)),
        Span::styled(state.input.clone(), theme::HEADER_VALUE),
        Span::styled("█", theme::TITLE_FOCUSED),
    ]);
    let prompt = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(if focused {
                theme::BORDER_FOCUSED
            } else {
                theme::BORDER
            })
            .title(Span::styled(
                " Shell (Enter run · ↑/↓ history · Esc clear) ",
                if focused {
                    theme::TITLE_FOCUSED
                } else {
                    theme::TITLE_UNFOCUSED
                },
            )),
    );
    frame.render_widget(prompt, area);
}

fn parse_whois(args: &[&str]) -> Result<ShellCommand, String> {
    if args.len() > 3 {
        return Err("whois usage: whois [low] [high] [timeout_seconds]".into());
    }
    let low = parse_optional_u32(args.first().copied(), "low instance")?;
    let high = parse_optional_u32(args.get(1).copied(), "high instance")?;
    let timeout_secs = parse_optional_u64(args.get(2).copied(), "timeout seconds")?
        .unwrap_or(3)
        .min(30);
    Ok(ShellCommand::WhoIs {
        low,
        high,
        timeout_secs,
    })
}

fn parse_read(args: &[&str]) -> Result<ShellCommand, String> {
    if args.len() != 4 {
        return Err("read usage: read <device> <object-type> <object-instance> <property>".into());
    }
    let device_instance = parse_required_u32(args[0], "device instance")?;
    let object_type = parse_object_type(args[1])?;
    let object_instance = parse_required_u32(args[2], "object instance")?;
    let property = parse_property_name(args[3])?;
    Ok(ShellCommand::Read {
        device_instance,
        object_type,
        object_instance,
        property,
    })
}

fn require_arg_count(args: &[&str], count: usize, command: &str) -> Result<(), String> {
    if args.len() == count {
        Ok(())
    } else {
        Err(format!("{command} takes no arguments"))
    }
}

fn parse_optional_u32(value: Option<&str>, label: &str) -> Result<Option<u32>, String> {
    match value {
        Some(s) if !s.trim().is_empty() => s
            .parse::<u32>()
            .map(Some)
            .map_err(|e| format!("{label}: {e}")),
        _ => Ok(None),
    }
}

fn parse_optional_u64(value: Option<&str>, label: &str) -> Result<Option<u64>, String> {
    match value {
        Some(s) if !s.trim().is_empty() => s
            .parse::<u64>()
            .map(Some)
            .map_err(|e| format!("{label}: {e}")),
        _ => Ok(None),
    }
}

fn parse_required_u32(value: &str, label: &str) -> Result<u32, String> {
    value.parse::<u32>().map_err(|e| format!("{label}: {e}"))
}

fn help_text() -> &'static str {
    "commands:
  help
  status
  devices
  whois [low] [high] [timeout_seconds]
  read <device> <object-type> <object-instance> <property>"
}

fn status_text(state: &GatewayState, config: &GatewayConfig, http_listening: bool) -> String {
    let mode = if state.is_read_only() {
        "read-only"
    } else {
        "writable"
    };
    let bip = config
        .transports
        .bip
        .as_ref()
        .map(|b| format!("B/IP {}:{} net {}", b.interface, b.port, b.network_number))
        .unwrap_or_else(|| "B/IP not configured".to_string());
    let sc = config
        .transports
        .sc
        .as_ref()
        .map(|s| format!("SC {} net {}", describe_sc_runtime(s), s.network_number))
        .unwrap_or_else(|| "SC not configured".to_string());
    let http = match (http_listening, &config.mcp.http) {
        (true, Some(h)) => format!("HTTP up at {}/mcp", h.bind),
        (true, None) => "HTTP up".to_string(),
        (false, Some(h)) => format!("HTTP down (--no-http; config {})", h.bind),
        (false, None) => "HTTP disabled".to_string(),
    };
    let client = if state.client().is_some() {
        "BACnet client up"
    } else {
        "BACnet client down"
    };

    format!("{mode}\n{client}\n{http}\n{bip}\n{sc}")
}

async fn list_devices(state: &GatewayState) -> Result<String, String> {
    let client = state.require_client()?;
    let devices = client.discovered_devices().await;
    if devices.is_empty() {
        return Ok("No discovered devices. Try `whois` first.".into());
    }
    let mut lines = Vec::with_capacity(devices.len() + 1);
    lines.push(format!("{} discovered device(s):", devices.len()));
    for device in devices.iter().take(25) {
        lines.push(format!(
            "  {} vendor {} net {} mac {}",
            device.object_identifier.instance_number(),
            device.vendor_id,
            device
                .source_network
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".to_string()),
            format_mac(device.mac_address.as_slice()),
        ));
    }
    if devices.len() > 25 {
        lines.push(format!("  ... {} more", devices.len() - 25));
    }
    Ok(lines.join("\n"))
}

async fn run_whois(
    state: &GatewayState,
    low: Option<u32>,
    high: Option<u32>,
    timeout_secs: u64,
) -> Result<String, String> {
    let client = state.require_client()?;
    client
        .who_is(low, high)
        .await
        .map_err(|e| format!("WhoIs send: {e}"))?;
    tokio::time::sleep(Duration::from_secs(timeout_secs)).await;
    let devices = client.discovered_devices().await;
    Ok(format!(
        "WhoIs complete. Device table: {} entries.",
        devices.len()
    ))
}

async fn read_property(
    state: &GatewayState,
    device_instance: u32,
    object_type: ObjectType,
    object_instance: u32,
    property: PropertyIdentifier,
) -> Result<String, String> {
    let client = state.require_client()?;
    let oid = ObjectIdentifier::new(object_type, object_instance).map_err(|e| format!("{e}"))?;
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
        object_type_name(object_type),
        object_instance,
        property_name(property),
        display
    ))
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BipConfig, DeviceConfig, McpConfig, TransportsConfig};
    use bacnet_objects::database::ObjectDatabase;

    fn config() -> GatewayConfig {
        GatewayConfig {
            mcp: McpConfig {
                api_key: None,
                read_only: true,
                http: Some(crate::config::McpHttpConfig {
                    bind: "127.0.0.1:3000".into(),
                }),
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

    #[test]
    fn parse_shell_command_accepts_read_aliases_and_names() {
        let parsed = parse_shell_command("rp 389001 analog-input 4 present-value")
            .unwrap()
            .unwrap();
        assert!(matches!(
            parsed,
            ShellCommand::Read {
                device_instance: 389001,
                object_instance: 4,
                ..
            }
        ));
    }

    #[test]
    fn parse_shell_command_accepts_empty_and_help_alias() {
        assert!(parse_shell_command("   ").unwrap().is_none());
        assert_eq!(
            parse_shell_command("?").unwrap().unwrap(),
            ShellCommand::Help
        );
    }

    #[test]
    fn parse_shell_command_defaults_whois_timeout_and_caps_max() {
        let parsed = parse_shell_command("whois 1 100 999").unwrap().unwrap();
        assert_eq!(
            parsed,
            ShellCommand::WhoIs {
                low: Some(1),
                high: Some(100),
                timeout_secs: 30,
            }
        );
        let defaulted = parse_shell_command("who-is").unwrap().unwrap();
        assert_eq!(
            defaulted,
            ShellCommand::WhoIs {
                low: None,
                high: None,
                timeout_secs: 3,
            }
        );
    }

    #[test]
    fn parse_shell_command_rejects_bad_shapes() {
        assert!(parse_shell_command("read 1 analog-input").is_err());
        assert!(parse_shell_command("read 1 analog-input 1 not-a-property").is_err());
        assert!(parse_shell_command("status extra").is_err());
        assert!(parse_shell_command("wat").is_err());
    }

    #[test]
    fn shell_state_records_and_recalls_commands() {
        let mut state = ShellState::new();
        state.input = "status".into();
        let command = state.take_command().unwrap();
        state.record_result(command, Ok("read-only".into()));
        state.input = "devices".into();
        let command = state.take_command().unwrap();
        state.record_result(command, Err("BACnet client not started".into()));

        state.recall_previous();
        assert_eq!(state.input, "devices");
        state.recall_previous();
        assert_eq!(state.input, "status");
        state.recall_next();
        assert_eq!(state.input, "devices");
        state.recall_next();
        assert_eq!(state.input, "");
    }

    #[test]
    fn shell_state_caps_output_and_command_history() {
        let mut state = ShellState::new();
        for i in 0..150 {
            state.record_result(format!("status {i}"), Ok("ok".into()));
        }
        assert_eq!(state.records.len(), MAX_OUTPUT_RECORDS);
        assert_eq!(state.command_history.len(), MAX_COMMAND_HISTORY);
        assert_eq!(state.records[0].command, "status 149");
    }

    #[tokio::test]
    async fn status_command_runs_without_bacnet_client() {
        let config = config();
        let state = GatewayState::new(ObjectDatabase::new(), config.clone());
        let text = execute_shell_command(ShellCommand::Status, &state, &config, true)
            .await
            .unwrap();
        assert!(text.contains("read-only"));
        assert!(text.contains("BACnet client down"));
        assert!(text.contains("HTTP up"));
        assert!(text.contains("B/IP 0.0.0.0:47808 net 1"));
    }

    #[tokio::test]
    async fn devices_command_requires_bacnet_client() {
        let config = config();
        let state = GatewayState::new(ObjectDatabase::new(), config.clone());
        let err = execute_shell_command(ShellCommand::Devices, &state, &config, true)
            .await
            .unwrap_err();
        assert_eq!(err, "BACnet client not started");
    }
}
