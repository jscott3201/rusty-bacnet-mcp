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

use bacnet_services::alarm_event::GetEventInformationAck;
use bacnet_services::alarm_summary::GetAlarmSummaryAck;
use bacnet_types::enums::{ConfirmedServiceChoice, ObjectType};
use bacnet_types::primitives::{BACnetTimeStamp, ObjectIdentifier};

use crate::audit::AuditEntry;
use crate::parse::{object_type_name, parse_object_specifier};
use crate::safety::PolicyDecision;
use crate::state::GatewayState;

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
            format_ack_transitions(acked_byte),
        ));
    }
    Ok(out)
}

fn format_ack_transitions(byte: u8) -> String {
    // Bits per ASHRAE 135-2020: 0x80 to-offnormal, 0x40 to-fault, 0x20 to-normal.
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
            format_ack_transitions(e.acknowledged_transitions),
            format_ack_transitions(e.event_enable),
            format_timestamp(&e.event_timestamps[0]),
            format_timestamp(&e.event_timestamps[1]),
            format_timestamp(&e.event_timestamps[2]),
        ));
    }
    Ok(out)
}

fn format_timestamp(ts: &BACnetTimeStamp) -> String {
    match ts {
        BACnetTimeStamp::Time(t) => format!("{:02}:{:02}:{:02}", t.hour, t.minute, t.second),
        BACnetTimeStamp::SequenceNumber(n) => format!("seq#{n}"),
        BACnetTimeStamp::DateTime { date, time } => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            1900u16.saturating_add(date.year as u16),
            date.month,
            date.day,
            time.hour,
            time.minute,
            time.second
        ),
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

    if let PolicyDecision::Deny(reason) = state.flags.policy().evaluate(oid, None) {
        return Err(format!("Policy denied: {}", mk_audit("deny", reason)));
    }

    if params.dry_run {
        mk_audit("allow", String::new());
        return Ok(format!(
            "[dry-run] Would acknowledge {}:{} state={} (source: {:?})",
            object_type_name(obj_type),
            params.object_instance,
            params.event_state_acknowledged,
            params.acknowledgment_source,
        ));
    }

    let client = state.require_client().map_err(|m| mk_audit("error", m))?;
    let dev = state
        .resolve_device(params.device_instance)
        .await
        .map_err(|m| mk_audit("error", m))?;

    // Pre-await intent record (matches write_property pattern).
    mk_audit("allow", String::new());

    match client
        .acknowledge_alarm(
            &dev.mac_address,
            params.acknowledging_process_identifier,
            oid,
            params.event_state_acknowledged,
            &params.acknowledgment_source,
        )
        .await
    {
        Ok(()) => Ok(format!(
            "Acknowledged {}:{} state={}",
            object_type_name(obj_type),
            params.object_instance,
            params.event_state_acknowledged,
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
    fn ack_transitions_format() {
        assert_eq!(format_ack_transitions(0x00), "none");
        assert_eq!(format_ack_transitions(0x80), "to-offnormal");
        assert_eq!(format_ack_transitions(0x40), "to-fault");
        assert_eq!(format_ack_transitions(0x20), "to-normal");
        assert_eq!(
            format_ack_transitions(0xE0),
            "to-offnormal|to-fault|to-normal"
        );
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
