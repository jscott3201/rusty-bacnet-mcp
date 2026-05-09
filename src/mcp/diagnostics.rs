//! Diagnostic MCP tools — `ping_device`, `probe_bbmd`.
//!
//! `ping_device` is the BACnet equivalent of `ping(8)`: a confirmed
//! ReadProperty round-trip to a small, universally-required Device property
//! used as a liveness + latency probe. Unlike ICMP, it traverses the full
//! BACnet stack — TSM allocation, segmentation negotiation, transport — so
//! a successful ping confirms the device is reachable *as a BACnet peer*,
//! not just IP-reachable.
//!
//! `probe_bbmd` reads the Broadcast Distribution Table and Foreign Device
//! Table from a BACnet/IP BBMD (Annex J), giving operators and agents a
//! complete view of the BBMD's topology role: which peer BBMDs it forwards
//! broadcasts to, and which foreign devices have registered with it.
//!
//! Both tools are read-only; they bypass the write-policy / audit log.

use std::time::Duration;

use schemars::JsonSchema;
use serde::Deserialize;
use tokio::time::Instant;

use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::ObjectIdentifier;

use crate::parse::decode_raw_property_to_json_with_context;
use crate::state::GatewayState;

/// Default ping count when the caller omits the field. One ping is the
/// agent's "is this device alive right now?" check; sequences of pings are
/// for latency / jitter sampling and are explicit opt-in.
const DEFAULT_COUNT: u32 = 1;

/// Hard cap on per-call ping count. Each ping is a confirmed request with
/// its own TSM slot and per-attempt timeout — letting agents request
/// hundreds of pings would tie up the TSM and bloat tool output. 10 is
/// enough to spot jitter, small enough to bound the worst-case latency.
const MAX_COUNT: u32 = 10;

/// Hard cap on the per-ping wait. Confirmed requests already inherit the
/// client-level apdu_timeout_ms, but exposing a per-call override gives
/// agents control on slow networks. 30 s matches the discover_devices cap.
const MAX_TIMEOUT_SECS: u64 = 30;

/// Hard cap on the inter-ping delay. Pings are diagnostic, not load tests —
/// long sleeps belong in the agent's scheduler, not inside one tool call.
const MAX_INTERVAL_MS: u64 = 5000;

/// Property used as the ping target. `system-status` is in the required
/// property list of every B-* device profile (Annex L) and encodes as a
/// 4-byte enumerated, so the response never segments. Cheap, safe, present.
const PING_PROPERTY: PropertyIdentifier = PropertyIdentifier::SYSTEM_STATUS;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PingDeviceParams {
    #[schemars(
        description = "Device instance number (must be in the device table from a prior discover)"
    )]
    pub device_instance: u32,
    /// Number of confirmed reads to send. Default 1, max 10.
    #[schemars(description = "Number of pings to send (default 1, max 10)")]
    pub count: Option<u32>,
    /// Per-ping timeout. Default uses the client's configured apdu_timeout_ms;
    /// override raises or lowers it for this call only.
    #[schemars(
        description = "Per-ping timeout in seconds (1..=30, default uses client apdu_timeout)"
    )]
    pub timeout_seconds: Option<u64>,
    /// Sleep between pings. Useful for sampling jitter without back-to-back
    /// requests landing in the same TSM window.
    #[schemars(description = "Delay between pings in ms (0..=5000, default 0)")]
    pub interval_ms: Option<u64>,
}

pub async fn ping_device_impl(
    state: &GatewayState,
    params: PingDeviceParams,
) -> Result<String, String> {
    // Pre-dispatch validation: range-check the agent's inputs before we
    // touch the client / device table. Codex callout pattern from PRs
    // #3-#6 — clear validation errors beat a generic "client not started"
    // when the input is wrong.
    let count = params.count.unwrap_or(DEFAULT_COUNT);
    if count == 0 || count > MAX_COUNT {
        return Err(format!(
            "count {count} out of range; must be 1..={MAX_COUNT}"
        ));
    }
    if let Some(t) = params.timeout_seconds
        && (t == 0 || t > MAX_TIMEOUT_SECS)
    {
        return Err(format!(
            "timeout_seconds {t} out of range; must be 1..={MAX_TIMEOUT_SECS}"
        ));
    }
    if let Some(i) = params.interval_ms
        && i > MAX_INTERVAL_MS
    {
        return Err(format!(
            "interval_ms {i} out of range; must be 0..={MAX_INTERVAL_MS}"
        ));
    }
    let device_oid = ObjectIdentifier::new(ObjectType::DEVICE, params.device_instance)
        .map_err(|e| format!("invalid device instance: {e}"))?;

    let client = state.require_client()?;
    let entry = state.resolve_device(params.device_instance).await?;
    let mac = entry.mac_address.clone();
    let interval = Duration::from_millis(params.interval_ms.unwrap_or(0));
    let per_attempt_timeout = params.timeout_seconds.map(Duration::from_secs);

    let mut attempts: Vec<AttemptResult> = Vec::with_capacity(count as usize);
    for seq in 1..=count {
        if seq > 1 && !interval.is_zero() {
            tokio::time::sleep(interval).await;
        }
        let started = Instant::now();
        let read_fut = client.read_property(&mac, device_oid, PING_PROPERTY, None);
        let outcome = match per_attempt_timeout {
            Some(t) => match tokio::time::timeout(t, read_fut).await {
                Ok(r) => r.map_err(|e| format!("{e}")),
                Err(_) => Err(format!("timed out after {}s", t.as_secs())),
            },
            None => read_fut.await.map_err(|e| format!("{e}")),
        };
        let elapsed = started.elapsed();
        attempts.push(match outcome {
            Ok(ack) => {
                let status_json =
                    decode_raw_property_to_json_with_context(&ack.property_value, PING_PROPERTY);
                let status = status_json
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| status_json.to_string());
                AttemptResult::Ok {
                    rtt_ms: ms_from(elapsed),
                    status,
                }
            }
            Err(msg) => AttemptResult::Err {
                rtt_ms: ms_from(elapsed),
                message: msg,
            },
        });
    }

    Ok(format_report(params.device_instance, &attempts))
}

#[derive(Debug)]
enum AttemptResult {
    Ok { rtt_ms: f64, status: String },
    Err { rtt_ms: f64, message: String },
}

impl AttemptResult {
    fn rtt_ms(&self) -> f64 {
        match self {
            AttemptResult::Ok { rtt_ms, .. } | AttemptResult::Err { rtt_ms, .. } => *rtt_ms,
        }
    }
    fn is_ok(&self) -> bool {
        matches!(self, AttemptResult::Ok { .. })
    }
}

fn ms_from(d: Duration) -> f64 {
    // Carry sub-ms precision — RTTs on a local BACnet/IP segment can be
    // under a millisecond, and rounding to integer ms hides jitter.
    (d.as_micros() as f64) / 1000.0
}

fn format_report(device_instance: u32, attempts: &[AttemptResult]) -> String {
    let mut out = format!(
        "ping device:{} via Device.system-status (n={}):\n",
        device_instance,
        attempts.len(),
    );
    for (i, a) in attempts.iter().enumerate() {
        let n = i + 1;
        match a {
            AttemptResult::Ok { rtt_ms, status } => {
                out.push_str(&format!("  [{n}] ok  rtt={rtt_ms:.2}ms status={status}\n"));
            }
            AttemptResult::Err { rtt_ms, message } => {
                out.push_str(&format!("  [{n}] err rtt={rtt_ms:.2}ms — {message}\n"));
            }
        }
    }
    out.push_str(&format_summary(attempts));
    out
}

fn format_summary(attempts: &[AttemptResult]) -> String {
    let total = attempts.len();
    let ok_count = attempts.iter().filter(|a| a.is_ok()).count();
    let loss = total - ok_count;
    let loss_pct = if total == 0 {
        0.0
    } else {
        (loss as f64) * 100.0 / (total as f64)
    };
    // Compute min/max/avg only over successful attempts. Including failed
    // attempts (which carry the timeout duration) would skew stats and hide
    // the real network latency on the successful subset.
    let ok_rtts: Vec<f64> = attempts
        .iter()
        .filter(|a| a.is_ok())
        .map(|a| a.rtt_ms())
        .collect();
    if ok_rtts.is_empty() {
        return format!("  --- {total} sent, 0 received, {loss_pct:.0}% loss ---\n");
    }
    let min = ok_rtts.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = ok_rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let avg = ok_rtts.iter().sum::<f64>() / (ok_rtts.len() as f64);
    format!(
        "  --- {total} sent, {ok_count} received, {loss_pct:.0}% loss --- min={min:.2}ms avg={avg:.2}ms max={max:.2}ms\n"
    )
}

// ─── probe_bbmd ─────────────────────────────────────────────────────────────

/// Per-table read timeout. Read-BDT and Read-FDT are unconfirmed BVLL
/// requests with their own correlation channel — the upstream transport
/// uses a 2-second internal timeout, but exposing an override gives agents
/// control on slow networks. 30 s matches the ping_device cap.
const PROBE_MAX_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProbeBbmdParams {
    /// BBMD address as `ip:port` (e.g. `"192.168.1.10:47808"`). BBMDs are
    /// addressed by IP rather than BACnet device instance because they're
    /// routing infrastructure and may not appear in the discovered-devices
    /// table.
    #[schemars(description = "BBMD address as ip:port (e.g. '192.168.1.10:47808')")]
    pub target: String,
    /// Per-table read timeout. Default uses the transport's internal value;
    /// override raises or lowers it for this call only.
    #[schemars(description = "Per-table read timeout in seconds (1..=30, default uses transport)")]
    pub timeout_seconds: Option<u64>,
}

pub async fn probe_bbmd_impl(
    state: &GatewayState,
    params: ProbeBbmdParams,
) -> Result<String, String> {
    // Pre-dispatch: validate the target string and timeout range before
    // touching the client. Same Phase 2 ordering pattern as ping_device.
    let addr: std::net::SocketAddrV4 = params
        .target
        .parse()
        .map_err(|e| format!("invalid target address '{}': {e}", params.target))?;
    if let Some(t) = params.timeout_seconds
        && (t == 0 || t > PROBE_MAX_TIMEOUT_SECS)
    {
        return Err(format!(
            "timeout_seconds {t} out of range; must be 1..={PROBE_MAX_TIMEOUT_SECS}"
        ));
    }

    let client = state.require_client()?;
    let mac = crate::parse::socket_addr_to_mac(addr);
    let per_read_timeout = params.timeout_seconds.map(Duration::from_secs);

    // Issue the two reads concurrently — they're independent BVLL
    // request/response pairs against the same BBMD, so back-to-back serial
    // reads would double the round-trip time for no benefit.
    let started = Instant::now();
    let (bdt_result, fdt_result) = tokio::join!(
        run_with_optional_timeout(per_read_timeout, client.read_bdt(&mac)),
        run_with_optional_timeout(per_read_timeout, client.read_fdt(&mac)),
    );
    let elapsed = started.elapsed();

    Ok(format_bbmd_report(
        &params.target,
        elapsed,
        bdt_result,
        fdt_result,
    ))
}

/// Wrap a future with a tokio timeout when the caller specified one;
/// pass through unwrapped otherwise.
async fn run_with_optional_timeout<F, T, E>(timeout: Option<Duration>, fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    match timeout {
        Some(t) => match tokio::time::timeout(t, fut).await {
            Ok(r) => r.map_err(|e| format!("{e}")),
            Err(_) => Err(format!("timed out after {}s", t.as_secs())),
        },
        None => fut.await.map_err(|e| format!("{e}")),
    }
}

fn format_bbmd_report(
    target: &str,
    elapsed: Duration,
    bdt_result: Result<Vec<bacnet_transport::bbmd::BdtEntry>, String>,
    fdt_result: Result<Vec<bacnet_transport::bbmd::FdtEntryWire>, String>,
) -> String {
    let mut out = format!("probe_bbmd {} (rtt={:.2}ms):\n", target, ms_from(elapsed),);
    out.push_str(&format_bdt_section(&bdt_result));
    out.push_str(&format_fdt_section(&fdt_result));
    out
}

fn format_bdt_section(result: &Result<Vec<bacnet_transport::bbmd::BdtEntry>, String>) -> String {
    match result {
        Ok(entries) if entries.is_empty() => {
            "  BDT: <empty> — BBMD does not forward broadcasts to any peers\n".into()
        }
        Ok(entries) => {
            let mut s = format!(
                "  BDT ({} entr{}):\n",
                entries.len(),
                if entries.len() == 1 { "y" } else { "ies" }
            );
            for e in entries {
                let mask = e
                    .broadcast_mask
                    .iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<_>>()
                    .join(".");
                s.push_str(&format!(
                    "    {}.{}.{}.{}:{} mask={mask}\n",
                    e.ip[0], e.ip[1], e.ip[2], e.ip[3], e.port,
                ));
            }
            s
        }
        Err(msg) => format!("  BDT: <error> {msg}\n"),
    }
}

fn format_fdt_section(
    result: &Result<Vec<bacnet_transport::bbmd::FdtEntryWire>, String>,
) -> String {
    match result {
        Ok(entries) if entries.is_empty() => {
            "  FDT: <empty> — no foreign devices registered\n".into()
        }
        Ok(entries) => {
            let mut s = format!(
                "  FDT ({} entr{}):\n",
                entries.len(),
                if entries.len() == 1 { "y" } else { "ies" }
            );
            for e in entries {
                s.push_str(&format!(
                    "    {}.{}.{}.{}:{} ttl={}s remaining={}s\n",
                    e.ip[0], e.ip[1], e.ip[2], e.ip[3], e.port, e.ttl, e.seconds_remaining,
                ));
            }
            s
        }
        Err(msg) => format!("  FDT: <error> {msg}\n"),
    }
}
