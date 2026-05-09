//! Diagnostic MCP tools — `ping_device` (and, in a follow-up, `probe_bbmd`).
//!
//! `ping_device` is the BACnet equivalent of `ping(8)`: a confirmed
//! ReadProperty round-trip to a small, universally-required Device property
//! used as a liveness + latency probe. Unlike ICMP, it traverses the full
//! BACnet stack — TSM allocation, segmentation negotiation, transport — so
//! a successful ping confirms the device is reachable *as a BACnet peer*,
//! not just IP-reachable.
//!
//! Read-only. Bypasses the write-policy / audit log.

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
