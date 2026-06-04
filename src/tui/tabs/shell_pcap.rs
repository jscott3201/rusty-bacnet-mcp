//! Pcap command support for the TUI shell.

use crate::state::GatewayState;

#[cfg(feature = "mcp")]
use crate::mcp::{pcap_live, pcap_tools};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapShellCommand {
    Interfaces {
        limit: Option<u32>,
        include_addresses: Option<bool>,
    },
    File {
        path: String,
        max_packets: Option<u32>,
        max_rows: Option<u32>,
        include_errors: Option<bool>,
    },
    Start {
        interface: String,
        filter: Option<String>,
        snaplen: Option<u32>,
        max_packets: Option<u32>,
        ring_size: Option<u32>,
        timeout_ms: Option<u32>,
        promisc: Option<bool>,
    },
    Stop {
        session_id: String,
    },
    List {
        include_finished: Option<bool>,
        max_rows: Option<u32>,
    },
    Read {
        session_id: String,
        max_rows: Option<u32>,
        include_errors: Option<bool>,
    },
}

pub fn parse_pcap_command(input: &str) -> Result<PcapShellCommand, String> {
    let words = shell_words(input)?;
    let Some((command, args)) = words.split_first() else {
        return Err(pcap_usage());
    };
    if !command.eq_ignore_ascii_case("pcap") {
        return Err(pcap_usage());
    }
    let Some((subcommand, args)) = args.split_first() else {
        return Err(pcap_usage());
    };

    match normalize_key(subcommand).as_str() {
        "interfaces" | "ifaces" => parse_interfaces(args),
        "file" | "analyze" => parse_file(args),
        "start" => parse_start(args),
        "stop" => parse_stop(args),
        "list" => parse_list(args),
        "read" => parse_read(args),
        other => Err(format!("unknown pcap shell command '{other}'")),
    }
}

pub async fn execute_pcap_shell_command(
    command: PcapShellCommand,
    state: &GatewayState,
) -> Result<String, String> {
    #[cfg(feature = "mcp")]
    {
        execute_pcap_shell_command_mcp(command, state).await
    }
    #[cfg(not(feature = "mcp"))]
    {
        let _ = (command, state);
        Err("pcap shell commands require the `mcp` feature".to_string())
    }
}

#[cfg(feature = "mcp")]
async fn execute_pcap_shell_command_mcp(
    command: PcapShellCommand,
    state: &GatewayState,
) -> Result<String, String> {
    match command {
        PcapShellCommand::Interfaces {
            limit,
            include_addresses,
        } => pcap_tools::list_pcap_interfaces_impl(pcap_tools::ListPcapInterfacesParams {
            limit,
            include_addresses,
        }),
        PcapShellCommand::File {
            path,
            max_packets,
            max_rows,
            include_errors,
        } => {
            let params = pcap_tools::AnalyzePcapFileParams {
                path,
                max_packets,
                max_rows,
                include_errors,
            };
            #[cfg(feature = "pcap")]
            {
                tokio::task::spawn_blocking(move || pcap_tools::analyze_pcap_file_impl(params))
                    .await
                    .map_err(|e| format!("pcap shell file analysis task failed: {e}"))?
            }
            #[cfg(not(feature = "pcap"))]
            {
                pcap_tools::analyze_pcap_file_impl(params)
            }
        }
        PcapShellCommand::Start {
            interface,
            filter,
            snaplen,
            max_packets,
            ring_size,
            timeout_ms,
            promisc,
        } => {
            let params = pcap_live::StartPcapCaptureParams {
                interface,
                filter,
                snaplen,
                max_packets,
                ring_size,
                timeout_ms,
                promisc,
            };
            #[cfg(feature = "pcap")]
            {
                let state = state.clone();
                tokio::task::spawn_blocking(move || {
                    pcap_live::start_pcap_capture_impl(&state, params)
                })
                .await
                .map_err(|e| format!("pcap shell capture start task failed: {e}"))?
            }
            #[cfg(not(feature = "pcap"))]
            {
                pcap_live::start_pcap_capture_impl(state, params)
            }
        }
        PcapShellCommand::Stop { session_id } => pcap_live::stop_pcap_capture_impl(
            state,
            pcap_live::StopPcapCaptureParams { session_id },
        ),
        PcapShellCommand::List {
            include_finished,
            max_rows,
        } => pcap_live::list_pcap_captures_impl(
            state,
            pcap_live::ListPcapCapturesParams {
                include_finished,
                max_rows,
            },
        ),
        PcapShellCommand::Read {
            session_id,
            max_rows,
            include_errors,
        } => pcap_live::read_pcap_capture_impl(
            state,
            pcap_live::ReadPcapCaptureParams {
                session_id,
                max_rows,
                include_errors,
            },
        ),
    }
}

fn parse_interfaces(args: &[String]) -> Result<PcapShellCommand, String> {
    let mut limit = None;
    let mut include_addresses = None;
    for arg in args {
        if let Some((key, value)) = split_option(arg) {
            match key.as_str() {
                "limit" | "max" => limit = Some(parse_u32(value, "limit")?),
                "addresses" | "addrs" | "include_addresses" => {
                    include_addresses = Some(parse_bool(value, "include_addresses")?)
                }
                _ => return Err(format!("unknown pcap interfaces option '{key}'")),
            }
        } else if is_digits(arg) {
            limit = Some(parse_u32(arg, "limit")?);
        } else {
            match normalize_key(arg).as_str() {
                "addresses" | "addrs" => include_addresses = Some(true),
                "no_addresses" | "no_addrs" => include_addresses = Some(false),
                _ => {
                    return Err(
                        "pcap interfaces usage: pcap interfaces [limit=N] [addresses=false]".into(),
                    );
                }
            }
        }
    }
    Ok(PcapShellCommand::Interfaces {
        limit,
        include_addresses,
    })
}

fn parse_file(args: &[String]) -> Result<PcapShellCommand, String> {
    let Some((path, args)) = args.split_first() else {
        return Err("pcap file usage: pcap file <path> [max=N] [rows=N] [errors=false]".into());
    };
    let mut max_packets = None;
    let mut max_rows = None;
    let mut include_errors = None;
    for arg in args {
        let Some((key, value)) = split_option(arg) else {
            return Err("pcap file options must be key=value pairs".into());
        };
        match key.as_str() {
            "max" | "max_packets" => max_packets = Some(parse_u32(value, "max_packets")?),
            "rows" | "max_rows" => max_rows = Some(parse_u32(value, "max_rows")?),
            "errors" | "include_errors" => {
                include_errors = Some(parse_bool(value, "include_errors")?)
            }
            _ => return Err(format!("unknown pcap file option '{key}'")),
        }
    }
    Ok(PcapShellCommand::File {
        path: path.clone(),
        max_packets,
        max_rows,
        include_errors,
    })
}

fn parse_start(args: &[String]) -> Result<PcapShellCommand, String> {
    let Some((interface, args)) = args.split_first() else {
        return Err("pcap start usage: pcap start <interface> [filter=\"udp port 47808\"] [max=N] [ring=N] [timeout_ms=N] [promisc=true]".into());
    };
    let mut filter = None;
    let mut snaplen = None;
    let mut max_packets = None;
    let mut ring_size = None;
    let mut timeout_ms = None;
    let mut promisc = None;
    for arg in args {
        if let Some((key, value)) = split_option(arg) {
            match key.as_str() {
                "filter" | "bpf" => filter = Some(value.to_string()),
                "snaplen" => snaplen = Some(parse_u32(value, "snaplen")?),
                "max" | "max_packets" => max_packets = Some(parse_u32(value, "max_packets")?),
                "ring" | "ring_size" => ring_size = Some(parse_u32(value, "ring_size")?),
                "timeout" | "timeout_ms" => timeout_ms = Some(parse_u32(value, "timeout_ms")?),
                "promisc" => promisc = Some(parse_bool(value, "promisc")?),
                _ => return Err(format!("unknown pcap start option '{key}'")),
            }
        } else {
            match normalize_key(arg).as_str() {
                "promisc" => promisc = Some(true),
                "no_promisc" => promisc = Some(false),
                _ => return Err("pcap start options must be key=value pairs".into()),
            }
        }
    }
    Ok(PcapShellCommand::Start {
        interface: interface.clone(),
        filter,
        snaplen,
        max_packets,
        ring_size,
        timeout_ms,
        promisc,
    })
}

fn parse_stop(args: &[String]) -> Result<PcapShellCommand, String> {
    if args.len() != 1 {
        return Err("pcap stop usage: pcap stop <session_id>".into());
    }
    Ok(PcapShellCommand::Stop {
        session_id: args[0].clone(),
    })
}

fn parse_list(args: &[String]) -> Result<PcapShellCommand, String> {
    let mut include_finished = None;
    let mut max_rows = None;
    for arg in args {
        if let Some((key, value)) = split_option(arg) {
            match key.as_str() {
                "rows" | "max_rows" => max_rows = Some(parse_u32(value, "max_rows")?),
                "finished" | "include_finished" => {
                    include_finished = Some(parse_bool(value, "include_finished")?)
                }
                _ => return Err(format!("unknown pcap list option '{key}'")),
            }
        } else {
            match normalize_key(arg).as_str() {
                "active" => include_finished = Some(false),
                "all" | "finished" => include_finished = Some(true),
                _ => return Err("pcap list usage: pcap list [active|all] [rows=N]".into()),
            }
        }
    }
    Ok(PcapShellCommand::List {
        include_finished,
        max_rows,
    })
}

fn parse_read(args: &[String]) -> Result<PcapShellCommand, String> {
    let Some((session_id, args)) = args.split_first() else {
        return Err("pcap read usage: pcap read <session_id> [rows=N] [errors=false]".into());
    };
    let mut max_rows = None;
    let mut include_errors = None;
    for arg in args {
        let Some((key, value)) = split_option(arg) else {
            return Err("pcap read options must be key=value pairs".into());
        };
        match key.as_str() {
            "rows" | "max_rows" => max_rows = Some(parse_u32(value, "max_rows")?),
            "errors" | "include_errors" => {
                include_errors = Some(parse_bool(value, "include_errors")?)
            }
            _ => return Err(format!("unknown pcap read option '{key}'")),
        }
    }
    Ok(PcapShellCommand::Read {
        session_id: session_id.clone(),
        max_rows,
        include_errors,
    })
}

fn shell_words(input: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escape = false;

    for c in input.chars() {
        if escape {
            current.push(c);
            escape = false;
            continue;
        }
        if c == '\\' {
            escape = true;
            continue;
        }
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => current.push(c),
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            None => current.push(c),
        }
    }
    if escape {
        return Err("dangling escape in pcap shell command".into());
    }
    if quote.is_some() {
        return Err("unterminated quote in pcap shell command".into());
    }
    if !current.is_empty() {
        words.push(current);
    }
    Ok(words)
}

fn split_option(arg: &str) -> Option<(String, &str)> {
    let (key, value) = arg.split_once('=')?;
    Some((normalize_key(key), value))
}

fn normalize_key(value: &str) -> String {
    value
        .trim_start_matches('-')
        .replace('-', "_")
        .to_ascii_lowercase()
}

fn parse_u32(value: &str, label: &str) -> Result<u32, String> {
    value.parse::<u32>().map_err(|e| format!("{label}: {e}"))
}

fn parse_bool(value: &str, label: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "y" | "on" => Ok(true),
        "false" | "0" | "no" | "n" | "off" => Ok(false),
        _ => Err(format!("{label}: expected true/false")),
    }
}

fn is_digits(value: &str) -> bool {
    value.chars().all(|c| c.is_ascii_digit())
}

fn pcap_usage() -> String {
    "pcap usage: pcap <interfaces|file|start|stop|list|read> ...".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
    use bacnet_objects::database::ObjectDatabase;

    fn config() -> GatewayConfig {
        GatewayConfig {
            mcp: McpConfig::default(),
            device: DeviceConfig {
                instance: 389001,
                name: "Test".into(),
                vendor_id: 999,
                description: "test".into(),
            },
            transports: TransportsConfig::default(),
            bbmd: None,
            foreign_device: None,
            routes: vec![],
            objects: vec![],
        }
    }

    #[test]
    fn parse_pcap_start_accepts_quoted_filter_and_options() {
        let parsed = parse_pcap_command(
            r#"pcap start en0 filter="udp port 47808" max=50 ring=10 timeout-ms=250 promisc"#,
        )
        .unwrap();

        assert_eq!(
            parsed,
            PcapShellCommand::Start {
                interface: "en0".to_string(),
                filter: Some("udp port 47808".to_string()),
                snaplen: None,
                max_packets: Some(50),
                ring_size: Some(10),
                timeout_ms: Some(250),
                promisc: Some(true),
            }
        );
    }

    #[test]
    fn parse_pcap_file_and_session_commands() {
        assert_eq!(
            parse_pcap_command(r#"pcap file "/tmp/capture test.pcap" max=100 rows=3 errors=false"#)
                .unwrap(),
            PcapShellCommand::File {
                path: "/tmp/capture test.pcap".to_string(),
                max_packets: Some(100),
                max_rows: Some(3),
                include_errors: Some(false),
            }
        );
        assert_eq!(
            parse_pcap_command("pcap list active rows=5").unwrap(),
            PcapShellCommand::List {
                include_finished: Some(false),
                max_rows: Some(5),
            }
        );
        assert_eq!(
            parse_pcap_command("pcap read pcap-1 errors=off").unwrap(),
            PcapShellCommand::Read {
                session_id: "pcap-1".to_string(),
                max_rows: None,
                include_errors: Some(false),
            }
        );
        assert_eq!(
            parse_pcap_command("pcap stop pcap-1").unwrap(),
            PcapShellCommand::Stop {
                session_id: "pcap-1".to_string(),
            }
        );
    }

    #[test]
    fn parse_pcap_interfaces_accepts_limit_and_address_flags() {
        assert_eq!(
            parse_pcap_command("pcap ifaces 25 no-addrs").unwrap(),
            PcapShellCommand::Interfaces {
                limit: Some(25),
                include_addresses: Some(false),
            }
        );
    }

    #[test]
    fn parse_pcap_rejects_bad_shapes() {
        assert!(parse_pcap_command(r#"pcap start en0 filter="udp"#).is_err());
        assert!(parse_pcap_command("pcap file").is_err());
        assert!(parse_pcap_command("pcap list rows=nope").is_err());
        assert!(parse_pcap_command("pcap wat").is_err());
    }

    #[cfg(not(feature = "pcap"))]
    #[tokio::test]
    async fn pcap_shell_reports_disabled_feature_without_pcap() {
        let state = GatewayState::new(ObjectDatabase::new(), config());
        let err = execute_pcap_shell_command(
            PcapShellCommand::Interfaces {
                limit: None,
                include_addresses: None,
            },
            &state,
        )
        .await
        .unwrap_err();

        assert!(err.contains("rebuild with feature `pcap`"));
    }

    #[cfg(feature = "pcap")]
    #[tokio::test]
    async fn pcap_shell_session_list_and_unknown_read_need_no_capture_privileges() {
        let state = GatewayState::new(ObjectDatabase::new(), config());
        let out = execute_pcap_shell_command(
            PcapShellCommand::List {
                include_finished: None,
                max_rows: None,
            },
            &state,
        )
        .await
        .unwrap();
        assert!(out.contains("pcap capture sessions"));

        let err = execute_pcap_shell_command(
            PcapShellCommand::Read {
                session_id: "pcap-404".to_string(),
                max_rows: None,
                include_errors: None,
            },
            &state,
        )
        .await
        .unwrap_err();
        assert!(err.contains("unknown pcap capture session"));
    }
}
