//! Feature-gated pcap MCP tools.
//!
//! The MCP tool is always present so the tool schema stays stable. Builds
//! without the `pcap` feature return a clear runtime error; pcap-enabled builds
//! list capture interfaces so operators can plan BACnet/IP captures before
//! opening live sessions.

#[cfg(feature = "pcap")]
use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::Deserialize;

#[cfg(feature = "pcap")]
use crate::mcp::wire::{self, WireInputKind};

#[cfg(any(feature = "pcap", test))]
const DEFAULT_INTERFACE_LIMIT: usize = 100;
#[cfg(any(feature = "pcap", test))]
const MAX_INTERFACE_LIMIT: usize = 500;
#[cfg(any(feature = "pcap", test))]
const MAX_ADDRS_PER_INTERFACE: usize = 8;
#[cfg(any(feature = "pcap", test))]
const DEFAULT_PCAP_PACKET_LIMIT: usize = 5_000;
#[cfg(any(feature = "pcap", test))]
const MAX_PCAP_PACKET_LIMIT: usize = 100_000;
#[cfg(any(feature = "pcap", test))]
const DEFAULT_PCAP_ROW_LIMIT: usize = 25;
#[cfg(any(feature = "pcap", test))]
const MAX_PCAP_ROW_LIMIT: usize = 200;
#[cfg(feature = "pcap")]
const ERROR_TEXT_LIMIT: usize = 140;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListPcapInterfacesParams {
    #[schemars(description = "Max interfaces to return (default 100, hard cap 500)")]
    pub limit: Option<u32>,
    #[schemars(description = "Include interface IP address rows (default true)")]
    pub include_addresses: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzePcapFileParams {
    #[schemars(description = "Local .pcap path to analyze")]
    pub path: String,
    #[schemars(description = "Max packets to scan (default 5000, hard cap 100000)")]
    pub max_packets: Option<u32>,
    #[schemars(description = "Max rows per output section (default 25, hard cap 200)")]
    pub max_rows: Option<u32>,
    #[schemars(description = "Include decode error summaries (default true)")]
    pub include_errors: Option<bool>,
}

#[cfg(feature = "pcap")]
pub fn list_pcap_interfaces_impl(params: ListPcapInterfacesParams) -> Result<String, String> {
    let limit = interface_limit(params.limit)?;
    let include_addresses = params.include_addresses.unwrap_or(true);
    let devices =
        pcap::Device::list().map_err(|e| format!("cannot list pcap capture interfaces: {e}"))?;
    let rows: Vec<InterfaceRow> = devices.into_iter().map(InterfaceRow::from).collect();
    Ok(format_interface_rows(&rows, limit, include_addresses))
}

#[cfg(not(feature = "pcap"))]
pub fn list_pcap_interfaces_impl(params: ListPcapInterfacesParams) -> Result<String, String> {
    let _ = params;
    Err("pcap support is not enabled in this build; rebuild with feature `pcap`".to_string())
}

#[cfg(feature = "pcap")]
pub fn analyze_pcap_file_impl(params: AnalyzePcapFileParams) -> Result<String, String> {
    let packet_limit = packet_limit(params.max_packets)?;
    let row_limit = row_limit(params.max_rows)?;
    let include_errors = params.include_errors.unwrap_or(true);

    let mut capture = pcap::Capture::from_file(&params.path).map_err(|e| {
        format!(
            "cannot open pcap file '{}': {e}",
            compact_text(&params.path)
        )
    })?;
    let datalink = capture.get_datalink();
    let input = wire_input_for_datalink(datalink)?;
    let mut stats = OfflinePcapStats::new(datalink_label(datalink), input, row_limit);

    while stats.scanned < packet_limit {
        match capture.next_packet() {
            Ok(packet) => {
                let packet_number = stats.scanned + 1;
                stats.observe_packet(
                    packet_number,
                    packet.data,
                    packet.header.caplen,
                    packet.header.len,
                );
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                return Err(format!(
                    "pcap read error after {} packet(s): {e}",
                    stats.scanned
                ));
            }
        }
    }

    Ok(format_offline_report(
        &params.path,
        packet_limit,
        include_errors,
        &stats,
    ))
}

#[cfg(not(feature = "pcap"))]
pub fn analyze_pcap_file_impl(params: AnalyzePcapFileParams) -> Result<String, String> {
    let _ = params;
    Err("pcap support is not enabled in this build; rebuild with feature `pcap`".to_string())
}

#[cfg(any(feature = "pcap", test))]
fn interface_limit(raw: Option<u32>) -> Result<usize, String> {
    let limit = raw.unwrap_or(DEFAULT_INTERFACE_LIMIT as u32);
    if limit == 0 || limit as usize > MAX_INTERFACE_LIMIT {
        return Err(format!(
            "limit {limit} out of range; must be 1..={MAX_INTERFACE_LIMIT}"
        ));
    }
    Ok(limit as usize)
}

#[cfg(any(feature = "pcap", test))]
fn packet_limit(raw: Option<u32>) -> Result<usize, String> {
    bounded_limit(
        "max_packets",
        raw,
        DEFAULT_PCAP_PACKET_LIMIT,
        MAX_PCAP_PACKET_LIMIT,
    )
}

#[cfg(any(feature = "pcap", test))]
fn row_limit(raw: Option<u32>) -> Result<usize, String> {
    bounded_limit("max_rows", raw, DEFAULT_PCAP_ROW_LIMIT, MAX_PCAP_ROW_LIMIT)
}

#[cfg(any(feature = "pcap", test))]
fn bounded_limit(
    name: &str,
    raw: Option<u32>,
    default: usize,
    max: usize,
) -> Result<usize, String> {
    let limit = raw.unwrap_or(default as u32);
    if limit == 0 || limit as usize > max {
        return Err(format!("{name} {limit} out of range; must be 1..={max}"));
    }
    Ok(limit as usize)
}

#[cfg(feature = "pcap")]
pub(crate) fn wire_input_for_datalink(linktype: pcap::Linktype) -> Result<WireInputKind, String> {
    if linktype == pcap::Linktype::ETHERNET {
        Ok(WireInputKind::Ethernet)
    } else if linktype == pcap::Linktype::NULL {
        Ok(WireInputKind::BsdNull)
    } else if linktype == pcap::Linktype::RAW || linktype == pcap::Linktype(12) {
        Ok(WireInputKind::Ipv4)
    } else if linktype == pcap::Linktype::LINUX_SLL {
        Ok(WireInputKind::LinuxSll)
    } else {
        Err(format!(
            "unsupported pcap datalink {}; supported: ETHERNET(1), NULL(0), RAW(101), DLT_RAW(12), LINUX_SLL(113)",
            datalink_label(linktype)
        ))
    }
}

#[cfg(feature = "pcap")]
pub(crate) fn datalink_label(linktype: pcap::Linktype) -> String {
    if linktype == pcap::Linktype::ETHERNET {
        "ETHERNET(1)".to_string()
    } else if linktype == pcap::Linktype::NULL {
        "NULL(0)".to_string()
    } else if linktype == pcap::Linktype::RAW {
        "RAW(101)".to_string()
    } else if linktype == pcap::Linktype(12) {
        "DLT_RAW(12)".to_string()
    } else if linktype == pcap::Linktype::LINUX_SLL {
        "LINUX_SLL(113)".to_string()
    } else {
        format!("DLT({})", linktype.0)
    }
}

#[cfg(feature = "pcap")]
#[derive(Debug)]
struct OfflinePcapStats {
    datalink: String,
    input: WireInputKind,
    row_limit: usize,
    scanned: usize,
    decoded: usize,
    decode_errors: usize,
    truncated: usize,
    total_frame_bytes: usize,
    total_bvlc_bytes: usize,
    samples: Vec<String>,
    bvlc_counts: BTreeMap<String, usize>,
    service_counts: BTreeMap<String, usize>,
    peer_counts: BTreeMap<String, usize>,
    error_counts: BTreeMap<String, usize>,
}

#[cfg(feature = "pcap")]
impl OfflinePcapStats {
    fn new(datalink: String, input: WireInputKind, row_limit: usize) -> Self {
        Self {
            datalink,
            input,
            row_limit,
            scanned: 0,
            decoded: 0,
            decode_errors: 0,
            truncated: 0,
            total_frame_bytes: 0,
            total_bvlc_bytes: 0,
            samples: Vec::new(),
            bvlc_counts: BTreeMap::new(),
            service_counts: BTreeMap::new(),
            peer_counts: BTreeMap::new(),
            error_counts: BTreeMap::new(),
        }
    }

    fn observe_packet(
        &mut self,
        packet_number: usize,
        data: &[u8],
        captured_len: u32,
        original_len: u32,
    ) {
        self.scanned += 1;
        self.total_frame_bytes += data.len();
        if captured_len < original_len {
            self.truncated += 1;
        }

        match wire::analyze_frame_bytes(data, self.input) {
            Ok(analysis) => {
                self.decoded += 1;
                self.total_bvlc_bytes += analysis.bvlc_bytes;
                increment(&mut self.bvlc_counts, analysis.bvlc.clone());
                increment(&mut self.service_counts, analysis.service.clone());
                if let Some(flow) = analysis.flow {
                    increment(&mut self.peer_counts, flow.to_string());
                }
                if self.samples.len() < self.row_limit {
                    self.samples
                        .push(format_packet_sample(packet_number, &analysis));
                }
            }
            Err(e) => {
                self.decode_errors += 1;
                increment(&mut self.error_counts, compact_error(&e));
            }
        }
    }
}

#[cfg(feature = "pcap")]
fn increment(counts: &mut BTreeMap<String, usize>, key: String) {
    *counts.entry(key).or_insert(0) += 1;
}

#[cfg(feature = "pcap")]
fn format_packet_sample(packet_number: usize, analysis: &wire::WireAnalysis) -> String {
    let flow = analysis
        .flow
        .map(|flow| flow.to_string())
        .unwrap_or_else(|| "-".to_string());
    format!(
        "  #{packet_number} {flow} {} / {} frame_bytes={} bvlc_bytes={}",
        analysis.bvlc, analysis.service, analysis.frame_bytes, analysis.bvlc_bytes
    )
}

#[cfg(feature = "pcap")]
fn compact_error(value: &str) -> String {
    let compact = compact_text(value);
    truncate_text(&compact, ERROR_TEXT_LIMIT)
}

#[cfg(feature = "pcap")]
fn truncate_text(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let take = max.saturating_sub(3);
    let mut out: String = value.chars().take(take).collect();
    out.push_str("...");
    out
}

#[cfg(feature = "pcap")]
fn format_offline_report(
    path: &str,
    packet_limit: usize,
    include_errors: bool,
    stats: &OfflinePcapStats,
) -> String {
    let mut out = String::new();
    out.push_str("offline pcap BACnet/IP analysis:\n");
    out.push_str(&format!("  path: {}\n", compact_text(path)));
    out.push_str(&format!(
        "  datalink: {} input={}\n",
        stats.datalink,
        stats.input.label()
    ));
    out.push_str(&format!(
        "  scanned: {} limit={} decoded={} errors={} truncated={}\n",
        stats.scanned, packet_limit, stats.decoded, stats.decode_errors, stats.truncated
    ));
    out.push_str(&format!(
        "  bytes: frame={} bvlc={}\n",
        stats.total_frame_bytes, stats.total_bvlc_bytes
    ));
    out.push_str("packets:\n");
    if stats.samples.is_empty() {
        out.push_str("  -\n");
    } else {
        for sample in &stats.samples {
            out.push_str(sample);
            out.push('\n');
        }
        if stats.decoded > stats.samples.len() {
            out.push_str(&format!(
                "  ... {} decoded packet(s) omitted; raise max_rows up to {MAX_PCAP_ROW_LIMIT}\n",
                stats.decoded - stats.samples.len()
            ));
        }
    }
    push_count_section(&mut out, "services", &stats.service_counts, stats.row_limit);
    push_count_section(&mut out, "bvlc", &stats.bvlc_counts, stats.row_limit);
    push_count_section(&mut out, "peers", &stats.peer_counts, stats.row_limit);
    if include_errors {
        push_count_section(
            &mut out,
            "decode_errors",
            &stats.error_counts,
            stats.row_limit,
        );
    }
    out
}

#[cfg(feature = "pcap")]
fn push_count_section(
    out: &mut String,
    title: &str,
    counts: &BTreeMap<String, usize>,
    row_limit: usize,
) {
    out.push_str(title);
    out.push_str(":\n");
    let rows = sorted_counts(counts);
    if rows.is_empty() {
        out.push_str("  -\n");
        return;
    }
    let shown = rows.len().min(row_limit);
    for (key, count) in rows.into_iter().take(shown) {
        out.push_str(&format!("  {key}: {count}\n"));
    }
    if counts.len() > shown {
        out.push_str(&format!(
            "  ... {} row(s) omitted; raise max_rows up to {MAX_PCAP_ROW_LIMIT}\n",
            counts.len() - shown
        ));
    }
}

#[cfg(feature = "pcap")]
fn sorted_counts(counts: &BTreeMap<String, usize>) -> Vec<(&str, usize)> {
    let mut rows: Vec<(&str, usize)> = counts
        .iter()
        .map(|(key, count)| (key.as_str(), *count))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    rows
}

#[cfg(any(feature = "pcap", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct InterfaceRow {
    name: String,
    desc: Option<String>,
    addresses: Vec<String>,
}

#[cfg(feature = "pcap")]
impl From<pcap::Device> for InterfaceRow {
    fn from(device: pcap::Device) -> Self {
        Self {
            name: compact_text(&device.name),
            desc: device.desc.as_deref().map(compact_text),
            addresses: device.addresses.iter().map(format_address).collect(),
        }
    }
}

#[cfg(feature = "pcap")]
fn format_address(addr: &pcap::Address) -> String {
    let mut parts = vec![addr.addr.to_string()];
    if let Some(netmask) = addr.netmask {
        parts.push(format!("netmask={netmask}"));
    }
    if let Some(broadcast) = addr.broadcast_addr {
        parts.push(format!("broadcast={broadcast}"));
    }
    if let Some(dst) = addr.dst_addr {
        parts.push(format!("dst={dst}"));
    }
    parts.join(" ")
}

#[cfg(any(feature = "pcap", test))]
fn compact_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(any(feature = "pcap", test))]
fn format_interface_rows(rows: &[InterfaceRow], limit: usize, include_addresses: bool) -> String {
    if rows.is_empty() {
        return "No pcap capture interfaces found.".to_string();
    }

    let mut sorted: Vec<&InterfaceRow> = rows.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let shown = sorted.len().min(limit);
    let mut out = format!(
        "pcap capture interfaces (showing {shown}/{}):\n",
        sorted.len()
    );
    for row in sorted.into_iter().take(shown) {
        out.push_str("  ");
        out.push_str(&row.name);
        if let Some(desc) = &row.desc
            && !desc.is_empty()
        {
            out.push_str(" desc=\"");
            out.push_str(desc);
            out.push('"');
        }
        if include_addresses {
            let addr_count = row.addresses.len();
            if addr_count == 0 {
                out.push_str(" addrs=-");
            } else {
                let emitted = addr_count.min(MAX_ADDRS_PER_INTERFACE);
                out.push_str(" addrs=");
                out.push_str(&row.addresses[..emitted].join(","));
                if addr_count > emitted {
                    out.push_str(&format!(" (+{} more)", addr_count - emitted));
                }
            }
        } else {
            out.push_str(" addrs=omitted");
        }
        out.push('\n');
    }
    if rows.len() > shown {
        out.push_str(&format!(
            "... {} interface(s) omitted; raise limit up to {MAX_INTERFACE_LIMIT}\n",
            rows.len() - shown
        ));
    }
    out
}

#[cfg(test)]
mod tests;
