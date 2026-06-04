//! Live pcap capture MCP tools for BACnet/IP diagnostics.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::state::GatewayState;

#[cfg(feature = "pcap")]
use crate::mcp::pcap_tools::{datalink_label, wire_input_for_datalink};
#[cfg(feature = "pcap")]
use crate::mcp::wire::{self, WireInputKind};
#[cfg(feature = "pcap")]
use crate::pcap_state::{
    CaptureSessionMeta, DecodedPacketObservation, MAX_ACTIVE_CAPTURE_SESSIONS,
};

#[cfg(any(feature = "pcap", test))]
const DEFAULT_FILTER: &str = "udp port 47808";
#[cfg(any(feature = "pcap", test))]
const MAX_FILTER_CHARS: usize = 512;
#[cfg(any(feature = "pcap", test))]
const MAX_INTERFACE_CHARS: usize = 128;
#[cfg(any(feature = "pcap", test))]
const DEFAULT_SNAPLEN: usize = 65_535;
#[cfg(any(feature = "pcap", test))]
const MAX_SNAPLEN: usize = 262_144;
#[cfg(any(feature = "pcap", test))]
const DEFAULT_MAX_PACKETS: usize = 10_000;
#[cfg(any(feature = "pcap", test))]
const MAX_MAX_PACKETS: usize = 1_000_000;
#[cfg(any(feature = "pcap", test))]
const DEFAULT_RING_SIZE: usize = 100;
#[cfg(any(feature = "pcap", test))]
const MAX_RING_SIZE: usize = 1_000;
#[cfg(any(feature = "pcap", test))]
const DEFAULT_TIMEOUT_MS: usize = 250;
#[cfg(any(feature = "pcap", test))]
const MIN_TIMEOUT_MS: usize = 10;
#[cfg(any(feature = "pcap", test))]
const MAX_TIMEOUT_MS: usize = 5_000;
#[cfg(any(feature = "pcap", test))]
const DEFAULT_ROW_LIMIT: usize = 25;
#[cfg(any(feature = "pcap", test))]
const MAX_ROW_LIMIT: usize = 200;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StartPcapCaptureParams {
    #[schemars(description = "Capture interface name, for example en0 or any")]
    pub interface: String,
    #[schemars(description = "BPF filter (default udp port 47808)")]
    pub filter: Option<String>,
    #[schemars(description = "Capture snaplen bytes (default 65535, max 262144)")]
    pub snaplen: Option<u32>,
    #[schemars(description = "Max packets before auto-stop (default 10000, max 1000000)")]
    pub max_packets: Option<u32>,
    #[schemars(description = "Recent packet summary ring size (default 100, max 1000)")]
    pub ring_size: Option<u32>,
    #[schemars(description = "Live read timeout ms (default 250, range 10..5000)")]
    pub timeout_ms: Option<u32>,
    #[schemars(description = "Enable promiscuous capture (default false)")]
    pub promisc: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StopPcapCaptureParams {
    #[schemars(description = "Capture session id returned by start_pcap_capture")]
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListPcapCapturesParams {
    #[schemars(description = "Include finished sessions (default true)")]
    pub include_finished: Option<bool>,
    #[schemars(description = "Max sessions to list (default 25, max 200)")]
    pub max_rows: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadPcapCaptureParams {
    #[schemars(description = "Capture session id")]
    pub session_id: String,
    #[schemars(description = "Max rows per section (default 25, max 200)")]
    pub max_rows: Option<u32>,
    #[schemars(description = "Include decode error summaries (default true)")]
    pub include_errors: Option<bool>,
}

#[cfg(feature = "pcap")]
pub fn start_pcap_capture_impl(
    state: &GatewayState,
    params: StartPcapCaptureParams,
) -> Result<String, String> {
    let cfg = LiveCaptureConfig::from_params(params)?;
    if state.pcap_captures.active_count() >= MAX_ACTIVE_CAPTURE_SESSIONS {
        return Err(format!(
            "too many active pcap captures; max is {MAX_ACTIVE_CAPTURE_SESSIONS}"
        ));
    }

    let inactive = pcap::Capture::from_device(cfg.interface.as_str())
        .map_err(|e| format!("cannot create pcap capture on '{}': {e}", cfg.interface))?
        .timeout(cfg.timeout_ms as i32)
        .snaplen(cfg.snaplen as i32)
        .promisc(cfg.promisc);
    let mut capture = inactive
        .open()
        .map_err(|e| format!("cannot open pcap capture on '{}': {e}", cfg.interface))?;
    capture
        .filter(&cfg.filter, true)
        .map_err(|e| format!("cannot apply BPF filter '{}': {e}", cfg.filter))?;

    let datalink = capture.get_datalink();
    let input = wire_input_for_datalink(datalink)?;
    let input_label = input.label().to_string();
    let datalink = datalink_label(datalink);
    let id = state.pcap_captures.next_session_id();
    let meta = CaptureSessionMeta {
        id: id.clone(),
        interface: cfg.interface.clone(),
        filter: cfg.filter.clone(),
        datalink: datalink.clone(),
        input: input_label.clone(),
        snaplen: cfg.snaplen,
        promisc: cfg.promisc,
        max_packets: cfg.max_packets,
        ring_size: cfg.ring_size,
        started_ms: crate::pcap_state::now_ms(),
    };
    let session = state.pcap_captures.insert_running(meta)?;
    let worker_session = session.clone();
    std::thread::Builder::new()
        .name(format!("bacnet-pcap-{id}"))
        .spawn(move || capture_loop(worker_session, capture, input, cfg.max_packets))
        .map_err(|e| {
            session.finish(format!("capture thread spawn failed: {e}"));
            format!("cannot spawn pcap capture thread: {e}")
        })?;

    Ok(format!(
        "pcap capture {id} started: iface={} datalink={} input={} filter=\"{}\" max_packets={} ring_size={}",
        cfg.interface, datalink, input_label, cfg.filter, cfg.max_packets, cfg.ring_size
    ))
}

#[cfg(not(feature = "pcap"))]
pub fn start_pcap_capture_impl(
    state: &GatewayState,
    params: StartPcapCaptureParams,
) -> Result<String, String> {
    let _ = (state, params);
    Err(pcap_feature_error())
}

pub fn stop_pcap_capture_impl(
    state: &GatewayState,
    params: StopPcapCaptureParams,
) -> Result<String, String> {
    #[cfg(feature = "pcap")]
    {
        state.pcap_captures.request_stop(&params.session_id)
    }
    #[cfg(not(feature = "pcap"))]
    {
        let _ = (state, params);
        Err(pcap_feature_error())
    }
}

pub fn list_pcap_captures_impl(
    state: &GatewayState,
    params: ListPcapCapturesParams,
) -> Result<String, String> {
    #[cfg(feature = "pcap")]
    {
        let max_rows = row_limit(params.max_rows)?;
        Ok(state
            .pcap_captures
            .format_list(params.include_finished.unwrap_or(true), max_rows))
    }
    #[cfg(not(feature = "pcap"))]
    {
        let _ = (state, params);
        Err(pcap_feature_error())
    }
}

pub fn read_pcap_capture_impl(
    state: &GatewayState,
    params: ReadPcapCaptureParams,
) -> Result<String, String> {
    #[cfg(feature = "pcap")]
    {
        let max_rows = row_limit(params.max_rows)?;
        let include_errors = params.include_errors.unwrap_or(true);
        Ok(state
            .pcap_captures
            .get(&params.session_id)?
            .format_summary(max_rows, include_errors))
    }
    #[cfg(not(feature = "pcap"))]
    {
        let _ = (state, params);
        Err(pcap_feature_error())
    }
}

#[cfg(feature = "pcap")]
fn capture_loop(
    session: std::sync::Arc<crate::pcap_state::CaptureSession>,
    mut capture: pcap::Capture<pcap::Active>,
    input: WireInputKind,
    max_packets: usize,
) {
    loop {
        if session.should_stop() {
            session.finish("stopped by request");
            return;
        }
        if session.packet_count() >= max_packets {
            session.finish(format!("max_packets {max_packets} reached"));
            return;
        }

        match capture.next_packet() {
            Ok(packet) => {
                let packet_number = session.packet_count() + 1;
                match wire::analyze_frame_bytes(packet.data, input) {
                    Ok(analysis) => session.observe_decoded(
                        packet_number,
                        DecodedPacketObservation {
                            frame_bytes: analysis.frame_bytes,
                            bvlc_bytes: analysis.bvlc_bytes,
                            bvlc: analysis.bvlc,
                            service: analysis.service,
                            flow: analysis.flow.map(|flow| flow.to_string()),
                            captured_len: packet.header.caplen,
                            original_len: packet.header.len,
                        },
                    ),
                    Err(e) => session.observe_error(
                        packet_number,
                        packet.data.len(),
                        packet.header.caplen,
                        packet.header.len,
                        e,
                    ),
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => {
                session.finish(format!("pcap read error: {e}"));
                return;
            }
        }
    }
}

#[cfg(any(feature = "pcap", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveCaptureConfig {
    interface: String,
    filter: String,
    snaplen: usize,
    max_packets: usize,
    ring_size: usize,
    timeout_ms: usize,
    promisc: bool,
}

#[cfg(any(feature = "pcap", test))]
impl LiveCaptureConfig {
    fn from_params(params: StartPcapCaptureParams) -> Result<Self, String> {
        Ok(Self {
            interface: bounded_text("interface", &params.interface, MAX_INTERFACE_CHARS)?,
            filter: capture_filter(params.filter)?,
            snaplen: bounded_limit(
                "snaplen",
                params.snaplen,
                DEFAULT_SNAPLEN,
                MAX_SNAPLEN,
                Some(1),
            )?,
            max_packets: bounded_limit(
                "max_packets",
                params.max_packets,
                DEFAULT_MAX_PACKETS,
                MAX_MAX_PACKETS,
                Some(1),
            )?,
            ring_size: bounded_limit(
                "ring_size",
                params.ring_size,
                DEFAULT_RING_SIZE,
                MAX_RING_SIZE,
                Some(1),
            )?,
            timeout_ms: bounded_limit(
                "timeout_ms",
                params.timeout_ms,
                DEFAULT_TIMEOUT_MS,
                MAX_TIMEOUT_MS,
                Some(MIN_TIMEOUT_MS),
            )?,
            promisc: params.promisc.unwrap_or(false),
        })
    }
}

#[cfg(any(feature = "pcap", test))]
fn row_limit(raw: Option<u32>) -> Result<usize, String> {
    bounded_limit("max_rows", raw, DEFAULT_ROW_LIMIT, MAX_ROW_LIMIT, Some(1))
}

#[cfg(any(feature = "pcap", test))]
fn capture_filter(raw: Option<String>) -> Result<String, String> {
    let value = raw.unwrap_or_else(|| DEFAULT_FILTER.to_string());
    bounded_text("filter", &value, MAX_FILTER_CHARS)
}

#[cfg(any(feature = "pcap", test))]
fn bounded_text(name: &str, value: &str, max_chars: usize) -> Result<String, String> {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    if compact.len() > max_chars {
        return Err(format!(
            "{name} is too long: {} chars, max {max_chars}",
            compact.len()
        ));
    }
    Ok(compact)
}

#[cfg(any(feature = "pcap", test))]
fn bounded_limit(
    name: &str,
    raw: Option<u32>,
    default: usize,
    max: usize,
    min: Option<usize>,
) -> Result<usize, String> {
    let limit = raw.unwrap_or(default as u32) as usize;
    let min = min.unwrap_or(1);
    if limit < min || limit > max {
        return Err(format!(
            "{name} {limit} out of range; must be {min}..={max}"
        ));
    }
    Ok(limit)
}

#[cfg(not(feature = "pcap"))]
fn pcap_feature_error() -> String {
    "pcap support is not enabled in this build; rebuild with feature `pcap`".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "pcap"))]
    use crate::config::{DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
    #[cfg(not(feature = "pcap"))]
    use bacnet_objects::database::ObjectDatabase;

    fn start_params() -> StartPcapCaptureParams {
        StartPcapCaptureParams {
            interface: " en0 ".to_string(),
            filter: None,
            snaplen: None,
            max_packets: None,
            ring_size: None,
            timeout_ms: None,
            promisc: None,
        }
    }

    #[test]
    fn live_capture_params_default_and_compact_text() {
        let cfg = LiveCaptureConfig::from_params(start_params()).unwrap();

        assert_eq!(cfg.interface, "en0");
        assert_eq!(cfg.filter, DEFAULT_FILTER);
        assert_eq!(cfg.snaplen, DEFAULT_SNAPLEN);
        assert_eq!(cfg.max_packets, DEFAULT_MAX_PACKETS);
        assert_eq!(cfg.ring_size, DEFAULT_RING_SIZE);
        assert_eq!(cfg.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert!(!cfg.promisc);
    }

    #[test]
    fn live_capture_params_reject_bad_bounds() {
        let mut params = start_params();
        params.timeout_ms = Some((MIN_TIMEOUT_MS - 1) as u32);
        assert!(
            LiveCaptureConfig::from_params(params)
                .unwrap_err()
                .contains("timeout_ms")
        );

        let mut params = start_params();
        params.ring_size = Some((MAX_RING_SIZE + 1) as u32);
        assert!(
            LiveCaptureConfig::from_params(params)
                .unwrap_err()
                .contains("ring_size")
        );

        let mut params = start_params();
        params.filter = Some(" \n\t ".to_string());
        assert!(
            LiveCaptureConfig::from_params(params)
                .unwrap_err()
                .contains("filter must not be empty")
        );
    }

    #[test]
    fn row_limit_rejects_bad_values() {
        assert_eq!(row_limit(None).unwrap(), DEFAULT_ROW_LIMIT);
        assert_eq!(row_limit(Some(1)).unwrap(), 1);
        assert!(row_limit(Some(0)).unwrap_err().contains("max_rows"));
        assert!(
            row_limit(Some((MAX_ROW_LIMIT + 1) as u32))
                .unwrap_err()
                .contains("max_rows")
        );
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn live_capture_tools_report_disabled_feature_without_pcap() {
        let state = GatewayState::new(ObjectDatabase::new(), test_config());

        assert!(
            start_pcap_capture_impl(&state, start_params())
                .unwrap_err()
                .contains("rebuild with feature `pcap`")
        );
        assert!(
            list_pcap_captures_impl(
                &state,
                ListPcapCapturesParams {
                    include_finished: None,
                    max_rows: None,
                },
            )
            .unwrap_err()
            .contains("rebuild with feature `pcap`")
        );
        assert!(
            read_pcap_capture_impl(
                &state,
                ReadPcapCaptureParams {
                    session_id: "pcap-1".to_string(),
                    max_rows: None,
                    include_errors: None,
                },
            )
            .unwrap_err()
            .contains("rebuild with feature `pcap`")
        );
        assert!(
            stop_pcap_capture_impl(
                &state,
                StopPcapCaptureParams {
                    session_id: "pcap-1".to_string(),
                },
            )
            .unwrap_err()
            .contains("rebuild with feature `pcap`")
        );
    }

    #[cfg(not(feature = "pcap"))]
    fn test_config() -> GatewayConfig {
        GatewayConfig {
            mcp: McpConfig::default(),
            device: DeviceConfig {
                instance: 1234,
                name: "Test Gateway".to_string(),
                vendor_id: 999,
                description: "Test".to_string(),
            },
            transports: TransportsConfig::default(),
            bbmd: None,
            foreign_device: None,
            routes: vec![],
            objects: vec![],
        }
    }
}
