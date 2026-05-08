//! MCP alarm + event tools.
//!
//! Three tools:
//!
//! - **`get_alarm_summary`** — ASHRAE 135-2020 Clause 13.7 (legacy) — lists
//!   active alarms on a remote device with object identifier, alarm state,
//!   and ack transitions. The simplest "what's wrong right now?" call.
//! - **`get_event_information`** — Clause 13.10 — modern replacement for
//!   alarm summary. Returns a richer per-event payload (timestamps for each
//!   transition, ack transitions, notify type, priorities, notification
//!   class) with paging via `last_received_object_identifier`.
//! - **`acknowledge_alarm`** — Clause 13.6 — ack a pending event transition.
//!   Write tool: routed through the safety control plane (`require_writable`,
//!   `WritePolicy::evaluate`, audit log) the same way `write_property` and
//!   `relinquish_at_priority` are.
//!
//! `get_alarm_summary` and `get_event_information` are read-only. Both are
//! convenient first-pass discovery tools for incident response — agents can
//! ask "what events are active?" without an upstream subscription path.

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_services::alarm_event::{AcknowledgeAlarmRequest, GetEventInformationAck};
use bacnet_services::alarm_summary::GetAlarmSummaryAck;
use bacnet_types::enums::{ConfirmedServiceChoice, ObjectType};
use bacnet_types::primitives::{BACnetTimeStamp, ObjectIdentifier};

use crate::audit::AuditEntry;
use crate::parse::{object_type_name, parse_object_specifier};
use crate::safety::PolicyDecision;
use crate::state::GatewayState;

/// EventState enum range per ASHRAE 135-2020 Clause 21. Values 0..=15 are
/// the valid raw enumerated forms; 0 = normal, 1 = fault, 2 = offnormal,
/// 3 = high-limit, 4 = low-limit, 5 = life-safety-alarm. Higher values are
/// reserved for future use; we cap at 15 to allow forward-compat without
/// silently sending nonsense to a strict device.
const MAX_EVENT_STATE_RAW: u32 = 15;

// ─── get_alarm_summary ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AlarmSummaryParams {
    #[schemars(description = "Device instance number")]
    pub device_instance: u32,
}

pub async fn get_alarm_summary_impl(
    state: &GatewayState,
    params: AlarmSummaryParams,
) -> Result<String, String> {
    let client = state.require_client()?;
    let dev = state.resolve_device(params.device_instance).await?;

    // GetAlarmSummary-Request takes no parameters; we send an empty payload
    // and decode the response.
    let response = client
        .confirmed_request(
            &dev.mac_address,
            ConfirmedServiceChoice::GET_ALARM_SUMMARY,
            &[],
        )
        .await
        .map_err(|e| format!("GetAlarmSummary failed: {e}"))?;

    let ack = GetAlarmSummaryAck::decode(&response).map_err(|e| format!("decode summary: {e}"))?;

    if ack.entries.is_empty() {
        return Ok(format!(
            "device:{} reports no active alarms\n",
            params.device_instance
        ));
    }

    let mut out = format!(
        "device:{} reports {} alarm(s):\n",
        params.device_instance,
        ack.entries.len()
    );
    for e in &ack.entries {
        let acked_byte = e.acknowledged_transitions.1.first().copied().unwrap_or(0);
        out.push_str(&format!(
            "  {}:{} state={} acked-transitions={}\n",
            object_type_name(e.object_identifier.object_type()),
            e.object_identifier.instance_number(),
            e.alarm_state.to_raw(),
            format_transitions_wire(acked_byte),
        ));
    }
    Ok(out)
}

/// Format a wire-aligned 3-bit BIT STRING byte (high-bit-first) into
/// human-readable transition names. Used by GetAlarmSummary, which
/// surfaces the raw wire byte: bit 0x80 = TO_OFFNORMAL, 0x40 = TO_FAULT,
/// 0x20 = TO_NORMAL.
fn format_transitions_wire(byte: u8) -> String {
    let mut parts = Vec::new();
    if byte & 0x80 != 0 {
        parts.push("to-offnormal");
    }
    if byte & 0x40 != 0 {
        parts.push("to-fault");
    }
    if byte & 0x20 != 0 {
        parts.push("to-normal");
    }
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join("|")
    }
}

/// Format a normalized 3-bit value (LSB-aligned) into human-readable
/// transition names. Used by GetEventInformation, where bacnet-services
/// already right-shifts the BIT STRING data by 5 (`data[pos+1] >> 5`)
/// before populating `EventSummary.acknowledged_transitions` and
/// `event_enable`. Codex flagged the previous code as feeding the LSB
/// form into a wire-mask formatter, which silently rendered active
/// transitions as `none`.
///
/// Bit positions after the right-shift:
/// - 0x04 (bit 2) = TO_OFFNORMAL
/// - 0x02 (bit 1) = TO_FAULT
/// - 0x01 (bit 0) = TO_NORMAL
fn format_transitions_normalized(byte: u8) -> String {
    let mut parts = Vec::new();
    if byte & 0x04 != 0 {
        parts.push("to-offnormal");
    }
    if byte & 0x02 != 0 {
        parts.push("to-fault");
    }
    if byte & 0x01 != 0 {
        parts.push("to-normal");
    }
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join("|")
    }
}

// ─── get_event_information ──────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EventInformationParams {
    #[schemars(description = "Device instance number")]
    pub device_instance: u32,
    /// Optional last-received object identifier for paging. Pass the last
    /// object's `"<type>:<instance>"` from a previous response when the
    /// `more_events` flag was set.
    #[schemars(
        description = "Optional 'type:instance' (e.g. 'analog-input:42') for paging — pass the last object from a previous response when more_events was set"
    )]
    #[serde(default)]
    pub after: Option<String>,
}

pub async fn get_event_information_impl(
    state: &GatewayState,
    params: EventInformationParams,
) -> Result<String, String> {
    // Parse the `after` paging cursor BEFORE touching the network — agents
    // get a clear "unknown object type" / "invalid specifier" error rather
    // than a generic "client not started" when they pass garbage.
    let last = match &params.after {
        Some(s) => {
            let (ot, inst) = parse_object_specifier(s)?;
            Some(ObjectIdentifier::new(ot, inst).map_err(|e| format!("{e}"))?)
        }
        None => None,
    };

    let client = state.require_client()?;
    let dev = state.resolve_device(params.device_instance).await?;

    let response = client
        .get_event_information(&dev.mac_address, last)
        .await
        .map_err(|e| format!("GetEventInformation failed: {e}"))?;

    let ack: GetEventInformationAck =
        GetEventInformationAck::decode(&response).map_err(|e| format!("decode events: {e}"))?;

    if ack.list_of_event_summaries.is_empty() {
        return Ok(format!(
            "device:{} reports no active events\n",
            params.device_instance
        ));
    }

    let mut out = format!(
        "device:{} reports {} event(s){}:\n",
        params.device_instance,
        ack.list_of_event_summaries.len(),
        if ack.more_events {
            " (more available — pass last object as `after` to page)"
        } else {
            ""
        }
    );
    for e in &ack.list_of_event_summaries {
        out.push_str(&format!(
            "  {}:{} state={} class={} priority=[off={},flt={},nrm={}] notify={} acked={} enabled={}\n    timestamps: off={} flt={} nrm={}\n",
            object_type_name(e.object_identifier.object_type()),
            e.object_identifier.instance_number(),
            e.event_state,
            e.notification_class,
            e.event_priorities[0],
            e.event_priorities[1],
            e.event_priorities[2],
            e.notify_type,
            format_transitions_normalized(e.acknowledged_transitions),
            format_transitions_normalized(e.event_enable),
            format_timestamp(&e.event_timestamps[0]),
            format_timestamp(&e.event_timestamps[1]),
            format_timestamp(&e.event_timestamps[2]),
        ));
    }
    Ok(out)
}

/// Format a BACnetTimeStamp for display. Codex flagged two issues with
/// the previous version:
///
/// - **Wildcard handling**: BACnet uses `0xFF` to mark unspecified date/time
///   components (e.g. an event timestamp for a transition that has not
///   occurred). Rendering those as literal numbers produced misleading
///   output like `2155-255-255 255:255:255`. We now emit `"unspecified"`
///   for any field that is `0xFF`.
/// - **Hundredths precision**: `Time` and `DateTime` carry a `hundredths`
///   field that lets operators correlate sub-second events; the previous
///   format dropped it.
fn format_timestamp(ts: &BACnetTimeStamp) -> String {
    match ts {
        BACnetTimeStamp::Time(t) => format_time(t),
        BACnetTimeStamp::SequenceNumber(n) => format!("seq#{n}"),
        BACnetTimeStamp::DateTime { date, time } => {
            format!("{} {}", format_date(date), format_time(time))
        }
    }
}

fn format_date(d: &bacnet_types::primitives::Date) -> String {
    if d.year == 0xFF && d.month == 0xFF && d.day == 0xFF {
        return "unspecified".into();
    }
    let year = if d.year == 0xFF {
        "????".to_string()
    } else {
        format!("{:04}", 1900u16.saturating_add(d.year as u16))
    };
    let month = wildcard_or(d.month, "??");
    let day = wildcard_or(d.day, "??");
    format!("{year}-{month}-{day}")
}

fn format_time(t: &bacnet_types::primitives::Time) -> String {
    if t.hour == 0xFF && t.minute == 0xFF && t.second == 0xFF {
        return "unspecified".into();
    }
    let hh = wildcard_or(t.hour, "??");
    let mm = wildcard_or(t.minute, "??");
    let ss = wildcard_or(t.second, "??");
    // Hundredths only displayed when present (non-zero, non-wildcard) so
    // typical second-precision timestamps stay terse.
    if t.hundredths != 0xFF && t.hundredths != 0 {
        format!("{hh}:{mm}:{ss}.{:02}", t.hundredths)
    } else {
        format!("{hh}:{mm}:{ss}")
    }
}

fn wildcard_or(v: u8, marker: &str) -> String {
    if v == 0xFF {
        marker.into()
    } else {
        format!("{v:02}")
    }
}

// ─── acknowledge_alarm ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AcknowledgeAlarmParams {
    #[schemars(description = "Device instance number hosting the event")]
    pub device_instance: u32,
    #[schemars(description = "Event object type (e.g. 'analog-input', 'binary-value')")]
    pub object_type: String,
    #[schemars(description = "Event object instance number")]
    pub object_instance: u32,
    /// EventState being acknowledged (raw enumerated value): 0=normal,
    /// 1=fault, 2=offnormal, 3=high-limit, 4=low-limit, 5=life-safety-alarm.
    #[schemars(
        description = "EventState being acked (raw enum: 0=normal, 1=fault, 2=offnormal, 3=high-limit, 4=low-limit, 5=life-safety-alarm)"
    )]
    pub event_state_acknowledged: u32,
    /// Free-text source identifier — appears in the device's audit log.
    #[schemars(
        description = "Source identifier (free text — appears in the device's own audit log)"
    )]
    pub acknowledgment_source: String,
    /// Process identifier of the acknowledging client. Defaults to 1 if
    /// the caller doesn't track its own.
    #[schemars(description = "Acknowledging process identifier (default 1)")]
    #[serde(default = "default_ack_pid")]
    pub acknowledging_process_identifier: u32,
    /// Transition timestamp from the original event notification. BACnet's
    /// AcknowledgeAlarm uses this to match the specific pending transition;
    /// strict devices reject acks that don't supply it. Get it from
    /// `get_event_information`'s per-transition `event_timestamps`. Pass as
    /// either a sequence number (`"seq#42"` or just `"42"`) or a datetime
    /// (`"YYYY-MM-DD HH:MM:SS"`). Optional — defaults to sequence#0
    /// (the previous behaviour, which works on permissive devices).
    #[schemars(
        description = "Transition timestamp ('seq#N' or 'YYYY-MM-DD HH:MM:SS') from the original event notification — strict devices require this for matching"
    )]
    #[serde(default)]
    pub transition_timestamp: Option<String>,
    /// Dry-run mode — runs the safety + audit pipeline without sending the APDU.
    #[schemars(
        description = "If true, validate against policy + audit but do not send the AcknowledgeAlarm APDU (default false)"
    )]
    #[serde(default)]
    pub dry_run: bool,
}

fn default_ack_pid() -> u32 {
    1
}

/// Parse a user-supplied transition timestamp string into a BACnet
/// timestamp. Two accepted forms:
///
/// - `"seq#N"` (or just `"N"`) → `BACnetTimeStamp::SequenceNumber(N)`
/// - `"YYYY-MM-DD HH:MM:SS"` → `BACnetTimeStamp::DateTime`
///
/// `None` returns the sequence#0 sentinel — matches the previous behaviour
/// where the upstream client wrapper hardcoded that value. Codex flagged
/// the previous fully-hardcoded approach as P1: strict devices validate
/// the timestamp during request matching and reject acks without one.
fn parse_transition_timestamp(s: Option<&str>) -> Result<BACnetTimeStamp, String> {
    let Some(raw) = s else {
        return Ok(BACnetTimeStamp::SequenceNumber(0));
    };
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("seq#") {
        let n: u64 = rest
            .parse()
            .map_err(|e| format!("transition_timestamp 'seq#N': {e}"))?;
        return Ok(BACnetTimeStamp::SequenceNumber(n));
    }
    if let Ok(n) = trimmed.parse::<u64>() {
        return Ok(BACnetTimeStamp::SequenceNumber(n));
    }
    let (date, time) = parse_iso_datetime_for_ack(trimmed)?;
    Ok(BACnetTimeStamp::DateTime { date, time })
}

fn parse_iso_datetime_for_ack(
    s: &str,
) -> Result<
    (
        bacnet_types::primitives::Date,
        bacnet_types::primitives::Time,
    ),
    String,
> {
    let normalized = s.replace('T', " ");
    let mut parts = normalized.splitn(2, ' ');
    let date_s = parts
        .next()
        .ok_or("transition_timestamp missing date part")?;
    let time_s = parts
        .next()
        .ok_or("transition_timestamp missing time part (need 'YYYY-MM-DD HH:MM:SS')")?;

    let mut d = date_s.split('-');
    let yyyy: u16 = d
        .next()
        .ok_or("missing year")?
        .parse()
        .map_err(|e| format!("year: {e}"))?;
    let mm: u8 = d
        .next()
        .ok_or("missing month")?
        .parse()
        .map_err(|e| format!("month: {e}"))?;
    let dd: u8 = d
        .next()
        .ok_or("missing day")?
        .parse()
        .map_err(|e| format!("day: {e}"))?;

    let mut t = time_s.split(':');
    let hh: u8 = t
        .next()
        .ok_or("missing hour")?
        .parse()
        .map_err(|e| format!("hour: {e}"))?;
    let mi: u8 = t
        .next()
        .ok_or("missing minute")?
        .parse()
        .map_err(|e| format!("minute: {e}"))?;
    let ss: u8 = match t.next() {
        Some("") | None => 0,
        Some(tok) => tok.parse().map_err(|e| format!("second: {e}"))?,
    };

    if !(1900..=2155).contains(&yyyy) {
        return Err(format!("year {yyyy} out of BACnet range 1900..=2155"));
    }
    if !(1..=12).contains(&mm) {
        return Err(format!("month {mm} out of range 1..=12"));
    }
    if !(1..=31).contains(&dd) {
        return Err(format!("day {dd} out of range 1..=31"));
    }
    if hh > 23 {
        return Err(format!("hour {hh} out of range 0..=23"));
    }
    if mi > 59 {
        return Err(format!("minute {mi} out of range 0..=59"));
    }
    if ss > 59 {
        return Err(format!("second {ss} out of range 0..=59"));
    }
    Ok((
        bacnet_types::primitives::Date {
            year: (yyyy - 1900) as u8,
            month: mm,
            day: dd,
            day_of_week: 0xFF,
        },
        bacnet_types::primitives::Time {
            hour: hh,
            minute: mi,
            second: ss,
            hundredths: 0,
        },
    ))
}

pub async fn acknowledge_alarm_impl(
    state: &GatewayState,
    params: AcknowledgeAlarmParams,
) -> Result<String, String> {
    // Acknowledge is a write — flow through the same control plane as
    // write_property and relinquish_at_priority.
    let target = format!("{}:{}", params.object_type, params.object_instance);
    let mk_audit = |decision: &'static str, reason: String| -> String {
        state.audit.append(AuditEntry::now(
            "acknowledge_alarm",
            Some(target.clone()),
            None,
            None,
            params.dry_run,
            decision,
            reason.clone(),
        ));
        reason
    };

    state.require_writable().map_err(|m| mk_audit("deny", m))?;

    let obj_type =
        crate::parse::parse_object_type(&params.object_type).map_err(|m| mk_audit("deny", m))?;
    let oid = ObjectIdentifier::new(obj_type, params.object_instance)
        .map_err(|e| mk_audit("deny", format!("{e}")))?;

    // Codex P2: range-check event_state_acknowledged so invalid values fail
    // local validation rather than getting dispatched to the device.
    if params.event_state_acknowledged > MAX_EVENT_STATE_RAW {
        return Err(mk_audit(
            "deny",
            format!(
                "event_state_acknowledged {} is out of EventState range 0..={MAX_EVENT_STATE_RAW} \
                 (0=normal, 1=fault, 2=offnormal, 3=high-limit, 4=low-limit, 5=life-safety-alarm)",
                params.event_state_acknowledged,
            ),
        ));
    }

    // Codex P1: parse the transition timestamp BEFORE any device contact.
    // Strict devices reject acks where the timestamp doesn't match the
    // pending transition; we now let the caller pass it through.
    let timestamp = parse_transition_timestamp(params.transition_timestamp.as_deref())
        .map_err(|m| mk_audit("deny", m))?;

    if let PolicyDecision::Deny(reason) = state.flags.policy().evaluate(oid, None) {
        return Err(format!("Policy denied: {}", mk_audit("deny", reason)));
    }

    if params.dry_run {
        mk_audit("allow", String::new());
        return Ok(format!(
            "[dry-run] Would acknowledge {}:{} state={} (source: {:?}, ts={})",
            object_type_name(obj_type),
            params.object_instance,
            params.event_state_acknowledged,
            params.acknowledgment_source,
            format_timestamp(&timestamp),
        ));
    }

    let client = state.require_client().map_err(|m| mk_audit("error", m))?;
    let dev = state
        .resolve_device(params.device_instance)
        .await
        .map_err(|m| mk_audit("error", m))?;

    // Build the AcknowledgeAlarmRequest directly so we can supply the
    // caller-provided transition timestamp. The bacnet-client wrapper
    // hardcodes BACnetTimeStamp::SequenceNumber(0) for both the transition
    // and time_of_acknowledgment fields, which Codex flagged as P1: it
    // breaks ack matching on strict devices.
    let request = AcknowledgeAlarmRequest {
        acknowledging_process_identifier: params.acknowledging_process_identifier,
        event_object_identifier: oid,
        event_state_acknowledged: params.event_state_acknowledged,
        timestamp: timestamp.clone(),
        acknowledgment_source: params.acknowledgment_source.clone(),
        // time_of_acknowledgment: the time the client is sending the ack.
        // We keep the historical sentinel here for backward compatibility;
        // future work can populate this from system clock once we add a
        // BACnetTimeStamp::now() helper.
        time_of_acknowledgment: BACnetTimeStamp::SequenceNumber(0),
    };
    let mut buf = bytes::BytesMut::new();
    request
        .encode(&mut buf)
        .map_err(|e| mk_audit("error", format!("encode: {e}")))?;

    // Pre-await intent record (matches write_property pattern).
    mk_audit("allow", String::new());

    match client
        .confirmed_request(
            &dev.mac_address,
            ConfirmedServiceChoice::ACKNOWLEDGE_ALARM,
            &buf,
        )
        .await
    {
        Ok(_) => Ok(format!(
            "Acknowledged {}:{} state={} ts={}",
            object_type_name(obj_type),
            params.object_instance,
            params.event_state_acknowledged,
            format_timestamp(&timestamp),
        )),
        Err(e) => Err(format!(
            "AcknowledgeAlarm failed: {}",
            mk_audit("error", format!("{e}"))
        )),
    }
}

// `ObjectType` import silences the unused-import lint when only the name
// helpers are used in tests.
#[allow(dead_code)]
type _UnusedObjectType = ObjectType;

// (no items below the test module — clippy::items_after_test_module enforced)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_wire_format_msb_aligned() {
        // GetAlarmSummary path: raw wire byte (high-bit-first).
        assert_eq!(format_transitions_wire(0x00), "none");
        assert_eq!(format_transitions_wire(0x80), "to-offnormal");
        assert_eq!(format_transitions_wire(0x40), "to-fault");
        assert_eq!(format_transitions_wire(0x20), "to-normal");
        assert_eq!(
            format_transitions_wire(0xE0),
            "to-offnormal|to-fault|to-normal"
        );
    }

    #[test]
    fn transitions_normalized_format_lsb_aligned() {
        // GetEventInformation path: bacnet-services already shifts the
        // BIT STRING data byte right by 5, leaving the 3 bits in the low
        // nibble. Codex P1: the previous code fed these into the wire
        // formatter which rendered active flags as `none`.
        assert_eq!(format_transitions_normalized(0x00), "none");
        assert_eq!(format_transitions_normalized(0x04), "to-offnormal");
        assert_eq!(format_transitions_normalized(0x02), "to-fault");
        assert_eq!(format_transitions_normalized(0x01), "to-normal");
        assert_eq!(
            format_transitions_normalized(0x07),
            "to-offnormal|to-fault|to-normal"
        );
        // Pin Codex's exact callout example — 0b101 (off-normal + normal,
        // no fault) was silently rendering as `none` in the prior code.
        assert_eq!(
            format_transitions_normalized(0b101),
            "to-offnormal|to-normal"
        );
    }

    #[test]
    fn timestamp_with_wildcard_components() {
        // BACnet 0xFF marks unspecified date/time components — used in
        // event-timestamp slots for transitions that haven't occurred.
        // Previously rendered as literal numbers ("2155-255-255 ...").
        let ts = BACnetTimeStamp::DateTime {
            date: bacnet_types::primitives::Date {
                year: 0xFF,
                month: 0xFF,
                day: 0xFF,
                day_of_week: 0xFF,
            },
            time: bacnet_types::primitives::Time {
                hour: 0xFF,
                minute: 0xFF,
                second: 0xFF,
                hundredths: 0xFF,
            },
        };
        assert_eq!(format_timestamp(&ts), "unspecified unspecified");
    }

    #[test]
    fn timestamp_with_partial_wildcards() {
        // Year wildcard but specified month/day — emits "????-MM-DD".
        let ts = BACnetTimeStamp::DateTime {
            date: bacnet_types::primitives::Date {
                year: 0xFF,
                month: 7,
                day: 4,
                day_of_week: 0xFF,
            },
            time: bacnet_types::primitives::Time {
                hour: 13,
                minute: 30,
                second: 0,
                hundredths: 0,
            },
        };
        assert_eq!(format_timestamp(&ts), "????-07-04 13:30:00");
    }

    #[test]
    fn timestamp_includes_hundredths_when_present() {
        let ts = BACnetTimeStamp::Time(bacnet_types::primitives::Time {
            hour: 14,
            minute: 5,
            second: 30,
            hundredths: 75,
        });
        assert_eq!(format_timestamp(&ts), "14:05:30.75");
    }

    #[test]
    fn parse_transition_timestamp_seq_form() {
        let ts = parse_transition_timestamp(Some("seq#42")).unwrap();
        assert!(matches!(ts, BACnetTimeStamp::SequenceNumber(42)));
    }

    #[test]
    fn parse_transition_timestamp_bare_seq() {
        let ts = parse_transition_timestamp(Some("100")).unwrap();
        assert!(matches!(ts, BACnetTimeStamp::SequenceNumber(100)));
    }

    #[test]
    fn parse_transition_timestamp_datetime_form() {
        let ts = parse_transition_timestamp(Some("2026-05-08 14:30:45")).unwrap();
        match ts {
            BACnetTimeStamp::DateTime { date, time } => {
                assert_eq!(date.year, 126);
                assert_eq!(date.month, 5);
                assert_eq!(time.hour, 14);
                assert_eq!(time.second, 45);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_transition_timestamp_none_yields_seq_zero() {
        let ts = parse_transition_timestamp(None).unwrap();
        assert!(matches!(ts, BACnetTimeStamp::SequenceNumber(0)));
    }

    #[test]
    fn parse_transition_timestamp_rejects_garbage() {
        assert!(parse_transition_timestamp(Some("not-a-thing")).is_err());
        // Out-of-range datetime component.
        assert!(parse_transition_timestamp(Some("2026-13-01 00:00:00")).is_err());
    }

    #[test]
    fn timestamp_format_time() {
        let ts = BACnetTimeStamp::Time(bacnet_types::primitives::Time {
            hour: 14,
            minute: 5,
            second: 30,
            hundredths: 0,
        });
        assert_eq!(format_timestamp(&ts), "14:05:30");
    }

    #[test]
    fn timestamp_format_sequence() {
        let ts = BACnetTimeStamp::SequenceNumber(42);
        assert_eq!(format_timestamp(&ts), "seq#42");
    }

    #[test]
    fn timestamp_format_datetime() {
        let ts = BACnetTimeStamp::DateTime {
            date: bacnet_types::primitives::Date {
                year: 124,
                month: 7,
                day: 4,
                day_of_week: 4,
            },
            time: bacnet_types::primitives::Time {
                hour: 13,
                minute: 30,
                second: 0,
                hundredths: 0,
            },
        };
        assert_eq!(format_timestamp(&ts), "2024-07-04 13:30:00");
    }
}
