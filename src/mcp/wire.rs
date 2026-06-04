//! BACnet/IP wire-analysis MCP tools.
//!
//! This module is pcap-ready but does not depend on libpcap. Live and offline
//! capture code can feed pcap packet bytes into the same parser once capture
//! session management is added behind a feature flag.

use std::net::Ipv4Addr;

use bacnet_encoding::apdu::{self, Apdu};
use bacnet_encoding::npdu;
use bacnet_transport::bvll::{self, BvllMessage};
use bacnet_types::enums::BvlcFunction;
use schemars::JsonSchema;
use serde::Deserialize;

const MAX_ANALYZE_BYTES: usize = 8192;
const DEFAULT_DETAIL_LINES: usize = 16;
const MAX_DETAIL_LINES: usize = 64;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeBacnetIpPacketParams {
    #[schemars(description = "Hex bytes for a BVLC UDP payload or captured frame")]
    pub bytes_hex: String,
    #[schemars(description = "Input byte shape: bvlc, ipv4, ethernet, bsd_null, or linux_sll")]
    #[serde(default)]
    pub input: WireInputKind,
    #[schemars(description = "Response shape: compact (default) or detailed")]
    #[serde(default)]
    pub response_mode: WireResponseMode,
    #[schemars(description = "Detailed line cap (default 16, max 64)")]
    pub max_detail_lines: Option<u32>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WireInputKind {
    #[default]
    Bvlc,
    Ipv4,
    Ethernet,
    BsdNull,
    LinuxSll,
}

impl WireInputKind {
    fn label(self) -> &'static str {
        match self {
            Self::Bvlc => "bvlc",
            Self::Ipv4 => "ipv4",
            Self::Ethernet => "ethernet",
            Self::BsdNull => "bsd_null",
            Self::LinuxSll => "linux_sll",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WireResponseMode {
    #[default]
    Compact,
    Detailed,
}

pub fn analyze_bacnet_ip_packet_impl(
    params: AnalyzeBacnetIpPacketParams,
) -> Result<String, String> {
    let detail_limit = detail_limit(params.max_detail_lines)?;
    let bytes = parse_hex_bytes(&params.bytes_hex)?;
    if bytes.len() > MAX_ANALYZE_BYTES {
        return Err(format!(
            "bytes_hex decodes to {} bytes; max is {MAX_ANALYZE_BYTES}",
            bytes.len()
        ));
    }

    let frame = extract_bacnet_payload(&bytes, params.input)?;
    if frame.payload.is_empty() {
        return Err("BACnet/IP payload is empty".to_string());
    }

    let packet = decode_packet(frame.payload)?;
    let summary = summarize(&packet);

    let mut out = String::new();
    out.push_str("BACnet/IP packet analysis:\n");
    out.push_str(&format!(
        "  input: {} frame_bytes={} bvlc_bytes={}\n",
        params.input.label(),
        bytes.len(),
        frame.payload.len()
    ));
    if let Some(flow) = frame.flow {
        out.push_str(&format!(
            "  udp: {}:{} -> {}:{}\n",
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port
        ));
    }
    out.push_str(&format!(
        "  summary: {} / {}\n",
        summary.bvlc, summary.service
    ));

    if params.response_mode == WireResponseMode::Detailed {
        let lines = format_detail(&packet);
        let emitted = lines.len().min(detail_limit);
        for line in lines.iter().take(emitted) {
            out.push_str(line);
            out.push('\n');
        }
        if lines.len() > emitted {
            out.push_str(&format!(
                "  ... {} detail line(s) omitted; raise max_detail_lines up to {MAX_DETAIL_LINES}\n",
                lines.len() - emitted
            ));
        }
    }

    Ok(out)
}

fn detail_limit(raw: Option<u32>) -> Result<usize, String> {
    let limit = raw.unwrap_or(DEFAULT_DETAIL_LINES as u32);
    if limit == 0 || limit as usize > MAX_DETAIL_LINES {
        return Err(format!(
            "max_detail_lines {limit} out of range; must be 1..={MAX_DETAIL_LINES}"
        ));
    }
    Ok(limit as usize)
}

fn parse_hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    let mut cleaned = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_ascii_whitespace() || ch == ':' || ch == '-' {
            continue;
        }
        if ch == '0' && matches!(chars.peek(), Some('x' | 'X')) {
            chars.next();
            continue;
        }
        if ch.is_ascii_hexdigit() {
            cleaned.push(ch);
            if cleaned.len() > MAX_ANALYZE_BYTES * 2 {
                return Err(format!(
                    "bytes_hex exceeds max decoded size of {MAX_ANALYZE_BYTES} bytes"
                ));
            }
        } else {
            return Err(format!("bytes_hex contains non-hex character '{ch}'"));
        }
    }

    if cleaned.is_empty() {
        return Err("bytes_hex must contain at least one byte".to_string());
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err("bytes_hex must contain an even number of hex digits".to_string());
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
            .map_err(|e| format!("invalid hex byte at digit {i}: {e}"))?;
        out.push(byte);
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
struct ExtractedFrame<'a> {
    payload: &'a [u8],
    flow: Option<UdpFlow>,
}

#[derive(Debug, Clone, Copy)]
struct UdpFlow {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

fn extract_bacnet_payload(raw: &[u8], input: WireInputKind) -> Result<ExtractedFrame<'_>, String> {
    match input {
        WireInputKind::Bvlc => Ok(ExtractedFrame {
            payload: raw,
            flow: None,
        }),
        WireInputKind::Ipv4 => extract_from_ipv4(raw),
        WireInputKind::Ethernet => extract_from_ethernet(raw),
        WireInputKind::BsdNull => extract_from_bsd_null(raw),
        WireInputKind::LinuxSll => extract_from_linux_sll(raw),
    }
}

fn extract_from_ethernet(raw: &[u8]) -> Result<ExtractedFrame<'_>, String> {
    if raw.len() < 14 {
        return Err(format!("ethernet frame too short: {} bytes", raw.len()));
    }

    let mut ether_type = u16::from_be_bytes([raw[12], raw[13]]);
    let mut payload_offset = 14;
    for _ in 0..4 {
        if !matches!(ether_type, 0x8100 | 0x88A8 | 0x9100) {
            break;
        }
        if raw.len() < payload_offset + 4 {
            return Err("ethernet VLAN tag truncated".to_string());
        }
        ether_type = u16::from_be_bytes([raw[payload_offset + 2], raw[payload_offset + 3]]);
        payload_offset += 4;
    }

    if ether_type != 0x0800 {
        return Err(format!("ethernet ethertype 0x{ether_type:04X} is not IPv4"));
    }
    extract_from_ipv4(&raw[payload_offset..])
}

fn extract_from_bsd_null(raw: &[u8]) -> Result<ExtractedFrame<'_>, String> {
    if raw.len() < 4 {
        return Err(format!("bsd_null frame too short: {} bytes", raw.len()));
    }
    let family_le = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let family_be = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
    if family_le != 2 && family_be != 2 {
        return Err(format!(
            "bsd_null address family is not IPv4: le={family_le} be={family_be}"
        ));
    }
    extract_from_ipv4(&raw[4..])
}

fn extract_from_linux_sll(raw: &[u8]) -> Result<ExtractedFrame<'_>, String> {
    if raw.len() < 16 {
        return Err(format!("linux_sll frame too short: {} bytes", raw.len()));
    }
    let protocol = u16::from_be_bytes([raw[14], raw[15]]);
    if protocol != 0x0800 {
        return Err(format!("linux_sll protocol 0x{protocol:04X} is not IPv4"));
    }
    extract_from_ipv4(&raw[16..])
}

fn extract_from_ipv4(raw: &[u8]) -> Result<ExtractedFrame<'_>, String> {
    if raw.len() < 20 {
        return Err(format!("ipv4 packet too short: {} bytes", raw.len()));
    }
    if raw[0] >> 4 != 4 {
        return Err(format!("ip version {} is not IPv4", raw[0] >> 4));
    }

    let ihl = ((raw[0] & 0x0F) as usize) * 4;
    if ihl < 20 {
        return Err(format!("invalid IPv4 header length: {ihl} bytes"));
    }
    if raw.len() < ihl {
        return Err(format!(
            "ipv4 packet truncated before header: need {ihl}, got {}",
            raw.len()
        ));
    }

    let total_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    if total_len < ihl {
        return Err(format!("ipv4 total length {total_len} smaller than header"));
    }
    if raw.len() < total_len {
        return Err(format!(
            "ipv4 packet truncated: total_len={total_len}, got {}",
            raw.len()
        ));
    }

    if raw[9] != 17 {
        return Err(format!("ipv4 protocol {} is not UDP", raw[9]));
    }

    let frag = u16::from_be_bytes([raw[6], raw[7]]);
    if frag & 0x3FFF != 0 {
        return Err("fragmented IPv4 UDP packets cannot be analyzed".to_string());
    }

    if total_len < ihl + 8 {
        return Err("ipv4 packet too short for UDP header".to_string());
    }
    let udp = &raw[ihl..total_len];
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 {
        return Err(format!("udp length {udp_len} smaller than header"));
    }
    if udp.len() < udp_len {
        return Err(format!(
            "udp datagram truncated: udp_len={udp_len}, got {}",
            udp.len()
        ));
    }

    let flow = UdpFlow {
        src_ip: Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]),
        dst_ip: Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]),
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
    };
    Ok(ExtractedFrame {
        payload: &udp[8..udp_len],
        flow: Some(flow),
    })
}

#[derive(Debug)]
struct DecodedPacket {
    bvlc_function: BvlcFunction,
    bvlc_length: usize,
    forwarded_from: Option<([u8; 4], u16)>,
    npdu: Option<DecodedNpdu>,
}

#[derive(Debug)]
struct DecodedNpdu {
    is_network_message: bool,
    expecting_reply: bool,
    priority: String,
    source_network: Option<u16>,
    dest_network: Option<u16>,
    hop_count: u8,
    network_message_type: Option<u8>,
    apdu: Option<DecodedApdu>,
}

#[derive(Debug)]
struct DecodedApdu {
    pdu_type: String,
    invoke_id: Option<u8>,
    segmented: bool,
    service_name: String,
    service_data_len: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct PacketSummary {
    bvlc: String,
    service: String,
}

fn decode_packet(data: &[u8]) -> Result<DecodedPacket, String> {
    let bvll = bvll::decode_bvll(data).map_err(|e| format!("BVLC decode error: {e}"))?;
    let forwarded_from = match (bvll.originating_ip, bvll.originating_port) {
        (Some(ip), Some(port)) => Some((ip, port)),
        _ => None,
    };
    let npdu = if is_npdu_carrier(bvll.function) {
        Some(decode_npdu_layer(&bvll)?)
    } else {
        None
    };

    Ok(DecodedPacket {
        bvlc_function: bvll.function,
        bvlc_length: bvlc_declared_len(data).unwrap_or(data.len()),
        forwarded_from,
        npdu,
    })
}

fn bvlc_declared_len(data: &[u8]) -> Option<usize> {
    data.get(2..4)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
}

fn summarize(packet: &DecodedPacket) -> PacketSummary {
    let bvlc = format!("{}", packet.bvlc_function);
    let service = match &packet.npdu {
        Some(npdu_layer) => match &npdu_layer.apdu {
            Some(apdu_layer) => apdu_layer.service_name.clone(),
            None if npdu_layer.is_network_message => format!(
                "NetworkMessage(0x{:02X})",
                npdu_layer.network_message_type.unwrap_or(0)
            ),
            None => "NPDU".to_string(),
        },
        None => bvlc.clone(),
    };
    PacketSummary { bvlc, service }
}

fn format_detail(packet: &DecodedPacket) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "  BVLC: {} (0x{:02X}), length={}",
        packet.bvlc_function,
        packet.bvlc_function.to_raw(),
        packet.bvlc_length
    ));

    if let Some((ip, port)) = packet.forwarded_from {
        lines.push(format!(
            "  Forwarded-from: {}.{}.{}.{}:{}",
            ip[0], ip[1], ip[2], ip[3], port
        ));
    }

    if let Some(npdu_layer) = &packet.npdu {
        let routing = match (npdu_layer.source_network, npdu_layer.dest_network) {
            (None, None) => "no-routing".to_string(),
            (Some(s), None) => format!("snet={s}"),
            (None, Some(d)) => format!("dnet={d}"),
            (Some(s), Some(d)) => format!("snet={s}, dnet={d}"),
        };
        lines.push(format!(
            "  NPDU: version=1, {routing}, hop={}, reply={}, priority={}",
            npdu_layer.hop_count,
            yes_no(npdu_layer.expecting_reply),
            npdu_layer.priority
        ));

        if let Some(apdu_layer) = &npdu_layer.apdu {
            let invoke = apdu_layer
                .invoke_id
                .map(|id| format!(", invoke-id={id}"))
                .unwrap_or_default();
            lines.push(format!(
                "  APDU: {}{invoke}, seg={}, service-bytes={}",
                apdu_layer.pdu_type,
                yes_no(apdu_layer.segmented),
                apdu_layer.service_data_len
            ));
            lines.push(format!("  Service: {}", apdu_layer.service_name));
        } else if npdu_layer.is_network_message {
            lines.push(format!(
                "  Network-Message: type=0x{:02X}",
                npdu_layer.network_message_type.unwrap_or(0)
            ));
        }
    }
    lines
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn is_npdu_carrier(f: BvlcFunction) -> bool {
    f == BvlcFunction::ORIGINAL_UNICAST_NPDU
        || f == BvlcFunction::ORIGINAL_BROADCAST_NPDU
        || f == BvlcFunction::FORWARDED_NPDU
        || f == BvlcFunction::DISTRIBUTE_BROADCAST_TO_NETWORK
}

fn decode_npdu_layer(bvll: &BvllMessage) -> Result<DecodedNpdu, String> {
    let npdu_result =
        npdu::decode_npdu(bvll.payload.clone()).map_err(|e| format!("NPDU decode error: {e}"))?;
    let apdu = if !npdu_result.is_network_message && !npdu_result.payload.is_empty() {
        Some(decode_apdu_layer(&npdu_result)?)
    } else {
        None
    };

    Ok(DecodedNpdu {
        is_network_message: npdu_result.is_network_message,
        expecting_reply: npdu_result.expecting_reply,
        priority: format!("{:?}", npdu_result.priority),
        source_network: npdu_result.source.as_ref().map(|a| a.network),
        dest_network: npdu_result.destination.as_ref().map(|a| a.network),
        hop_count: npdu_result.hop_count,
        network_message_type: npdu_result.message_type,
        apdu,
    })
}

fn decode_apdu_layer(npdu_data: &npdu::Npdu) -> Result<DecodedApdu, String> {
    let apdu_result = apdu::decode_apdu(npdu_data.payload.clone())
        .map_err(|e| format!("APDU decode error: {e}"))?;
    let decoded = match apdu_result {
        Apdu::ConfirmedRequest(ref pdu) => DecodedApdu {
            pdu_type: "Confirmed-Request".to_string(),
            invoke_id: Some(pdu.invoke_id),
            segmented: pdu.segmented,
            service_name: format!("{}", pdu.service_choice),
            service_data_len: pdu.service_request.len(),
        },
        Apdu::UnconfirmedRequest(ref pdu) => DecodedApdu {
            pdu_type: "Unconfirmed-Request".to_string(),
            invoke_id: None,
            segmented: false,
            service_name: format!("{}", pdu.service_choice),
            service_data_len: pdu.service_request.len(),
        },
        Apdu::SimpleAck(ref pdu) => DecodedApdu {
            pdu_type: "Simple-ACK".to_string(),
            invoke_id: Some(pdu.invoke_id),
            segmented: false,
            service_name: format!("{}-ACK", pdu.service_choice),
            service_data_len: 0,
        },
        Apdu::ComplexAck(ref pdu) => DecodedApdu {
            pdu_type: "Complex-ACK".to_string(),
            invoke_id: Some(pdu.invoke_id),
            segmented: pdu.segmented,
            service_name: format!("{}-ACK", pdu.service_choice),
            service_data_len: pdu.service_ack.len(),
        },
        Apdu::SegmentAck(ref pdu) => DecodedApdu {
            pdu_type: "Segment-ACK".to_string(),
            invoke_id: Some(pdu.invoke_id),
            segmented: false,
            service_name: "SegmentACK".to_string(),
            service_data_len: 0,
        },
        Apdu::Error(ref pdu) => DecodedApdu {
            pdu_type: "Error".to_string(),
            invoke_id: Some(pdu.invoke_id),
            segmented: false,
            service_name: format!("{}-Error", pdu.service_choice),
            service_data_len: pdu.error_data.len(),
        },
        Apdu::Reject(ref pdu) => DecodedApdu {
            pdu_type: "Reject".to_string(),
            invoke_id: Some(pdu.invoke_id),
            segmented: false,
            service_name: format!("Reject({})", pdu.reject_reason),
            service_data_len: 0,
        },
        Apdu::Abort(ref pdu) => DecodedApdu {
            pdu_type: "Abort".to_string(),
            invoke_id: Some(pdu.invoke_id),
            segmented: false,
            service_name: format!("Abort({})", pdu.abort_reason),
            service_data_len: 0,
        },
    };
    Ok(decoded)
}
