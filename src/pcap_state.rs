//! Shared BACnet/IP pcap capture session state.
//!
//! The registry is intentionally independent of libpcap. Feature-gated MCP
//! workers feed decoded packet observations into it, while tests can exercise
//! the bounded session and summary behavior without capture privileges.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

pub const MAX_ACTIVE_CAPTURE_SESSIONS: usize = 8;
pub const MAX_CAPTURE_SESSIONS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSessionMeta {
    pub id: String,
    pub interface: String,
    pub filter: String,
    pub datalink: String,
    pub input: String,
    pub snaplen: usize,
    pub promisc: bool,
    pub max_packets: usize,
    pub ring_size: usize,
    pub started_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CaptureStatus {
    Running,
    StopRequested,
    Finished,
}

impl CaptureStatus {
    fn label(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::StopRequested => "stop_requested",
            Self::Finished => "finished",
        }
    }
}

#[derive(Debug)]
pub struct CaptureSession {
    meta: CaptureSessionMeta,
    stop_requested: AtomicBool,
    summary: Mutex<CaptureSummary>,
}

impl CaptureSession {
    fn new(meta: CaptureSessionMeta) -> Self {
        let ring_size = meta.ring_size;
        Self {
            meta,
            stop_requested: AtomicBool::new(false),
            summary: Mutex::new(CaptureSummary::new(ring_size)),
        }
    }

    pub fn id(&self) -> &str {
        &self.meta.id
    }

    pub fn should_stop(&self) -> bool {
        self.stop_requested.load(Ordering::Relaxed)
    }

    pub fn request_stop(&self) {
        self.stop_requested.store(true, Ordering::Relaxed);
        let mut summary = self.summary.lock();
        if summary.status == CaptureStatus::Running {
            summary.status = CaptureStatus::StopRequested;
        }
    }

    pub fn packet_count(&self) -> usize {
        self.summary.lock().scanned
    }

    pub fn observe_decoded(&self, packet_number: usize, decoded: DecodedPacketObservation) {
        let mut summary = self.summary.lock();
        summary.scanned += 1;
        summary.decoded += 1;
        summary.total_frame_bytes += decoded.frame_bytes;
        summary.total_bvlc_bytes += decoded.bvlc_bytes;
        if decoded.captured_len < decoded.original_len {
            summary.truncated += 1;
        }
        increment(&mut summary.bvlc_counts, decoded.bvlc.clone());
        increment(&mut summary.service_counts, decoded.service.clone());
        if let Some(flow) = decoded.flow.as_ref() {
            increment(&mut summary.peer_counts, flow.clone());
        }
        summary.push_sample(format!(
            "  #{packet_number} {} {} / {} frame_bytes={} bvlc_bytes={}",
            decoded.flow.as_deref().unwrap_or("-"),
            decoded.bvlc,
            decoded.service,
            decoded.frame_bytes,
            decoded.bvlc_bytes
        ));
    }

    pub fn observe_error(
        &self,
        packet_number: usize,
        frame_bytes: usize,
        captured_len: u32,
        original_len: u32,
        error: String,
    ) {
        let mut summary = self.summary.lock();
        summary.scanned += 1;
        summary.decode_errors += 1;
        summary.total_frame_bytes += frame_bytes;
        if captured_len < original_len {
            summary.truncated += 1;
        }
        let compact = truncate_text(&compact_text(&error), 140);
        increment(&mut summary.error_counts, compact.clone());
        summary.push_sample(format!("  #{packet_number} decode_error {compact}"));
    }

    pub fn finish(&self, reason: impl Into<String>) {
        let mut summary = self.summary.lock();
        summary.status = CaptureStatus::Finished;
        summary.finish_reason = Some(reason.into());
    }

    fn is_active(&self) -> bool {
        !matches!(self.summary.lock().status, CaptureStatus::Finished)
    }

    fn list_line(&self) -> String {
        let summary = self.summary.lock();
        format!(
            "  {} status={} iface={} input={} decoded={} errors={} packets={} filter=\"{}\"",
            self.meta.id,
            summary.status.label(),
            self.meta.interface,
            self.meta.input,
            summary.decoded,
            summary.decode_errors,
            summary.scanned,
            self.meta.filter
        )
    }

    pub fn format_summary(&self, max_rows: usize, include_errors: bool) -> String {
        let summary = self.summary.lock();
        let mut out = String::new();
        out.push_str("pcap capture summary:\n");
        out.push_str(&format!("  session: {}\n", self.meta.id));
        out.push_str(&format!(
            "  status: {}{}\n",
            summary.status.label(),
            summary
                .finish_reason
                .as_ref()
                .map(|r| format!(" reason=\"{}\"", compact_text(r)))
                .unwrap_or_default()
        ));
        out.push_str(&format!(
            "  iface: {} datalink={} input={} filter=\"{}\"\n",
            self.meta.interface, self.meta.datalink, self.meta.input, self.meta.filter
        ));
        out.push_str(&format!(
            "  scanned: {} decoded={} errors={} truncated={} max_packets={}\n",
            summary.scanned,
            summary.decoded,
            summary.decode_errors,
            summary.truncated,
            self.meta.max_packets
        ));
        out.push_str(&format!(
            "  bytes: frame={} bvlc={}\n",
            summary.total_frame_bytes, summary.total_bvlc_bytes
        ));
        out.push_str("recent_packets:\n");
        push_recent_samples(&mut out, &summary.samples, max_rows);
        push_count_section(&mut out, "services", &summary.service_counts, max_rows);
        push_count_section(&mut out, "bvlc", &summary.bvlc_counts, max_rows);
        push_count_section(&mut out, "peers", &summary.peer_counts, max_rows);
        if include_errors {
            push_count_section(&mut out, "decode_errors", &summary.error_counts, max_rows);
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPacketObservation {
    pub frame_bytes: usize,
    pub bvlc_bytes: usize,
    pub bvlc: String,
    pub service: String,
    pub flow: Option<String>,
    pub captured_len: u32,
    pub original_len: u32,
}

#[derive(Debug)]
struct CaptureSummary {
    status: CaptureStatus,
    finish_reason: Option<String>,
    ring_size: usize,
    scanned: usize,
    decoded: usize,
    decode_errors: usize,
    truncated: usize,
    total_frame_bytes: usize,
    total_bvlc_bytes: usize,
    samples: VecDeque<String>,
    bvlc_counts: BTreeMap<String, usize>,
    service_counts: BTreeMap<String, usize>,
    peer_counts: BTreeMap<String, usize>,
    error_counts: BTreeMap<String, usize>,
}

impl CaptureSummary {
    fn new(ring_size: usize) -> Self {
        Self {
            status: CaptureStatus::Running,
            finish_reason: None,
            ring_size,
            scanned: 0,
            decoded: 0,
            decode_errors: 0,
            truncated: 0,
            total_frame_bytes: 0,
            total_bvlc_bytes: 0,
            samples: VecDeque::with_capacity(ring_size),
            bvlc_counts: BTreeMap::new(),
            service_counts: BTreeMap::new(),
            peer_counts: BTreeMap::new(),
            error_counts: BTreeMap::new(),
        }
    }

    fn push_sample(&mut self, sample: String) {
        if self.samples.len() == self.ring_size {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }
}

#[derive(Debug)]
pub struct PcapCaptureRegistry {
    next_id: AtomicU64,
    sessions: Mutex<BTreeMap<String, Arc<CaptureSession>>>,
}

impl Default for PcapCaptureRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PcapCaptureRegistry {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            sessions: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn next_session_id(&self) -> String {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("pcap-{id}")
    }

    pub fn active_count(&self) -> usize {
        self.sessions
            .lock()
            .values()
            .filter(|session| session.is_active())
            .count()
    }

    pub fn insert_running(&self, meta: CaptureSessionMeta) -> Result<Arc<CaptureSession>, String> {
        let mut sessions = self.sessions.lock();
        if sessions.values().filter(|s| s.is_active()).count() >= MAX_ACTIVE_CAPTURE_SESSIONS {
            return Err(format!(
                "too many active pcap captures; max is {MAX_ACTIVE_CAPTURE_SESSIONS}"
            ));
        }
        prune_finished_locked(&mut sessions);
        if sessions.len() >= MAX_CAPTURE_SESSIONS {
            return Err(format!(
                "too many retained pcap captures; stop or wait for old sessions to finish (max {MAX_CAPTURE_SESSIONS})"
            ));
        }
        let id = meta.id.clone();
        let session = Arc::new(CaptureSession::new(meta));
        sessions.insert(id, Arc::clone(&session));
        Ok(session)
    }

    pub fn get(&self, session_id: &str) -> Result<Arc<CaptureSession>, String> {
        self.sessions
            .lock()
            .get(session_id)
            .cloned()
            .ok_or_else(|| format!("unknown pcap capture session '{session_id}'"))
    }

    pub fn request_stop(&self, session_id: &str) -> Result<String, String> {
        let session = self.get(session_id)?;
        session.request_stop();
        Ok(format!(
            "pcap capture {} stop requested; poll read_pcap_capture for final status",
            session.id()
        ))
    }

    pub fn format_list(&self, include_finished: bool, max_rows: usize) -> String {
        let sessions = self.sessions.lock();
        let mut rows: Vec<&Arc<CaptureSession>> = sessions
            .values()
            .filter(|session| include_finished || session.is_active())
            .collect();
        rows.sort_by_key(|session| std::cmp::Reverse(session.meta.started_ms));
        let total = rows.len();
        let shown = total.min(max_rows);
        let mut out = format!("pcap capture sessions (showing {shown}/{total}):\n");
        for session in rows.into_iter().take(shown) {
            out.push_str(&session.list_line());
            out.push('\n');
        }
        if shown == 0 {
            out.push_str("  -\n");
        }
        if total > shown {
            out.push_str(&format!(
                "... {} session(s) omitted; raise max_rows\n",
                total - shown
            ));
        }
        out
    }
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn prune_finished_locked(sessions: &mut BTreeMap<String, Arc<CaptureSession>>) {
    while sessions.len() >= MAX_CAPTURE_SESSIONS {
        let Some(oldest_finished) = sessions
            .iter()
            .filter(|(_, session)| !session.is_active())
            .min_by_key(|(_, session)| session.meta.started_ms)
            .map(|(id, _)| id.clone())
        else {
            break;
        };
        sessions.remove(&oldest_finished);
    }
}

fn push_recent_samples(out: &mut String, samples: &VecDeque<String>, max_rows: usize) {
    if samples.is_empty() {
        out.push_str("  -\n");
        return;
    }
    let skip = samples.len().saturating_sub(max_rows);
    for sample in samples.iter().skip(skip) {
        out.push_str(sample);
        out.push('\n');
    }
    if skip > 0 {
        out.push_str(&format!("  ... {skip} older packet sample(s) omitted\n"));
    }
}

fn push_count_section(
    out: &mut String,
    title: &str,
    counts: &BTreeMap<String, usize>,
    max_rows: usize,
) {
    out.push_str(title);
    out.push_str(":\n");
    let rows = sorted_counts(counts);
    if rows.is_empty() {
        out.push_str("  -\n");
        return;
    }
    let shown = rows.len().min(max_rows);
    for (key, count) in rows.into_iter().take(shown) {
        out.push_str(&format!("  {key}: {count}\n"));
    }
    if counts.len() > shown {
        out.push_str(&format!("  ... {} row(s) omitted\n", counts.len() - shown));
    }
}

fn sorted_counts(counts: &BTreeMap<String, usize>) -> Vec<(&str, usize)> {
    let mut rows: Vec<(&str, usize)> = counts
        .iter()
        .map(|(key, count)| (key.as_str(), *count))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    rows
}

fn increment(counts: &mut BTreeMap<String, usize>, key: String) {
    *counts.entry(key).or_insert(0) += 1;
}

fn compact_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_text(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let take = max.saturating_sub(3);
    let mut out: String = value.chars().take(take).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: &str) -> CaptureSessionMeta {
        CaptureSessionMeta {
            id: id.to_string(),
            interface: "en0".to_string(),
            filter: "udp port 47808".to_string(),
            datalink: "ETHERNET(1)".to_string(),
            input: "ethernet".to_string(),
            snaplen: 65_535,
            promisc: false,
            max_packets: 100,
            ring_size: 2,
            started_ms: now_ms(),
        }
    }

    #[test]
    fn registry_tracks_bounded_recent_samples_and_counts() {
        let registry = PcapCaptureRegistry::new();
        let session = registry.insert_running(meta("pcap-1")).unwrap();

        for packet_number in 1..=3 {
            session.observe_decoded(
                packet_number,
                DecodedPacketObservation {
                    frame_bytes: 64,
                    bvlc_bytes: 8,
                    bvlc: "ORIGINAL_BROADCAST_NPDU".to_string(),
                    service: "WHO_IS".to_string(),
                    flow: Some("192.168.1.10:47808 -> 192.168.1.255:47808".to_string()),
                    captured_len: 64,
                    original_len: 64,
                },
            );
        }

        let out = session.format_summary(10, true);
        assert!(out.contains("scanned: 3 decoded=3 errors=0"));
        assert!(out.contains("WHO_IS: 3"));
        assert!(!out.contains("#1 "));
        assert!(out.contains("#2 "));
        assert!(out.contains("#3 "));
    }

    #[test]
    fn stop_and_finish_update_status() {
        let registry = PcapCaptureRegistry::new();
        let session = registry.insert_running(meta("pcap-1")).unwrap();

        assert!(!session.should_stop());
        assert!(
            registry
                .request_stop("pcap-1")
                .unwrap()
                .contains("stop requested")
        );
        assert!(session.should_stop());
        assert!(session.format_summary(10, true).contains("stop_requested"));

        session.finish("stopped by request");
        let out = session.format_summary(10, true);
        assert!(out.contains("status: finished"));
        assert!(out.contains("stopped by request"));
    }

    #[test]
    fn list_can_hide_finished_sessions() {
        let registry = PcapCaptureRegistry::new();
        let first = registry.insert_running(meta("pcap-1")).unwrap();
        first.finish("done");
        let _second = registry.insert_running(meta("pcap-2")).unwrap();

        let active = registry.format_list(false, 10);
        assert!(!active.contains("pcap-1"));
        assert!(active.contains("pcap-2"));
        assert!(!active.contains("omitted"));

        let all = registry.format_list(true, 10);
        assert!(all.contains("pcap-1"));
        assert!(all.contains("pcap-2"));
    }
}
