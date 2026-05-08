//! MCP schedule tool — `read_schedule`.
//!
//! Reads scalar metadata from a BACnet Schedule object (object type 17) in
//! one RPM round-trip:
//!
//! - `object-name` / `description` — human label
//! - `present-value` — what the schedule is currently outputting
//! - `schedule-default` — the value when nothing is active
//! - `effective-period` — date range for which this schedule applies
//! - `list-of-object-property-references` — what properties this schedule
//!   writes to (the agent's "what does this schedule control?" question)
//! - `status-flags`, `reliability`, `out-of-service` — health
//!
//! **Deferred:** `weekly-schedule` and `exception-schedule` arrays carry
//! BACnetDailySchedule and BACnetSpecialEvent constructed types respectively.
//! `bacnet-services 0.8` ships no decoders for these, so pulling the actual
//! day-by-day schedule contents requires hand-rolling ASN.1 decode work
//! similar to the trend-log LogRecord decoder. That lives in a follow-up
//! PR. The two array properties are read here as raw payload sizes ("64
//! bytes of weekly-schedule data") so an agent at least knows whether the
//! schedule has any programmed entries.
//!
//! Write tools (write_schedule_weekly, write_schedule_exception) are also
//! deferred to that follow-up PR — they need the matching encoder side of
//! the same constructed types.

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_services::common::PropertyReference;
use bacnet_services::rpm::ReadAccessSpecification;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::ObjectIdentifier;

use crate::parse::decode_raw_property_to_json_with_context;
use crate::state::GatewayState;

/// Properties pulled in the single RPM round-trip. Order matters only for
/// readability of the rendered output — RPM responses preserve request
/// order field-by-field.
const SCHEDULE_PROPERTIES: &[PropertyIdentifier] = &[
    PropertyIdentifier::OBJECT_NAME,
    PropertyIdentifier::DESCRIPTION,
    PropertyIdentifier::PRESENT_VALUE,
    PropertyIdentifier::SCHEDULE_DEFAULT,
    PropertyIdentifier::EFFECTIVE_PERIOD,
    PropertyIdentifier::LIST_OF_OBJECT_PROPERTY_REFERENCES,
    PropertyIdentifier::WEEKLY_SCHEDULE,
    PropertyIdentifier::EXCEPTION_SCHEDULE,
    PropertyIdentifier::STATUS_FLAGS,
    PropertyIdentifier::RELIABILITY,
    PropertyIdentifier::OUT_OF_SERVICE,
];

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadScheduleParams {
    #[schemars(description = "Device instance number hosting the Schedule object")]
    pub device_instance: u32,
    #[schemars(description = "Schedule object instance number")]
    pub schedule_instance: u32,
}

pub async fn read_schedule_impl(
    state: &GatewayState,
    params: ReadScheduleParams,
) -> Result<String, String> {
    let oid = ObjectIdentifier::new(ObjectType::SCHEDULE, params.schedule_instance)
        .map_err(|e| format!("{e}"))?;

    let client = state.require_client()?;
    let dev = state.resolve_device(params.device_instance).await?;

    let spec = ReadAccessSpecification {
        object_identifier: oid,
        list_of_property_references: SCHEDULE_PROPERTIES
            .iter()
            .map(|&p| PropertyReference {
                property_identifier: p,
                property_array_index: None,
            })
            .collect(),
    };

    let ack = client
        .read_property_multiple(&dev.mac_address, vec![spec])
        .await
        .map_err(|e| format!("ReadPropertyMultiple failed: {e}"))?;

    let mut out = format!(
        "schedule:{} on device:{}\n",
        params.schedule_instance, params.device_instance
    );

    for elem in ack
        .list_of_read_access_results
        .into_iter()
        .flat_map(|r| r.list_of_results.into_iter())
    {
        let prop = elem.property_identifier;
        let line = if let Some(raw) = &elem.property_value {
            // The two array properties hold constructed types we don't
            // decode in this PR — surface their byte length so an agent
            // can tell empty vs populated schedules apart. Everything
            // else flows through the standard property-aware decoder.
            let body = match prop {
                PropertyIdentifier::WEEKLY_SCHEDULE => {
                    format!(
                        "<{} byte(s) — 7-day BACnetDailySchedule array, decoder deferred>",
                        raw.len()
                    )
                }
                PropertyIdentifier::EXCEPTION_SCHEDULE => {
                    format!(
                        "<{} byte(s) — BACnetSpecialEvent array, decoder deferred>",
                        raw.len()
                    )
                }
                _ => format_property(raw, prop),
            };
            format!("  {} = {}\n", property_label(prop), body)
        } else if let Some((class, code)) = &elem.error {
            format!(
                "  {} = <error class={:?} code={:?}>\n",
                property_label(prop),
                class,
                code,
            )
        } else {
            format!("  {} = <empty result>\n", property_label(prop))
        };
        out.push_str(&line);
    }

    Ok(out)
}

fn property_label(p: PropertyIdentifier) -> String {
    crate::parse::property_name(p).to_string()
}

fn format_property(raw: &[u8], prop: PropertyIdentifier) -> String {
    let val = decode_raw_property_to_json_with_context(raw, prop);
    val.get("value")
        .map(|v| format!("{v}"))
        .unwrap_or_else(|| format!("{val}"))
}

// (no items below the test module — clippy::items_after_test_module enforced)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_properties_count_matches_planned_set() {
        // Pin the RPM request shape — if a future PR adds weekly/exception
        // decoders or expands the read set, this test fails with a clear
        // count mismatch so the operator knows to update CHANGELOG and
        // tool description text.
        assert_eq!(SCHEDULE_PROPERTIES.len(), 11);
    }

    #[test]
    fn schedule_properties_include_present_value_and_default() {
        // The two most agentically useful properties — what the schedule
        // is doing right now and what it falls back to.
        assert!(SCHEDULE_PROPERTIES.contains(&PropertyIdentifier::PRESENT_VALUE));
        assert!(SCHEDULE_PROPERTIES.contains(&PropertyIdentifier::SCHEDULE_DEFAULT));
    }

    #[test]
    fn property_label_uses_canonical_kebab_case() {
        // Output uses kebab-case names matching the public MCP vocabulary
        // (not raw enum values).
        assert_eq!(
            property_label(PropertyIdentifier::PRESENT_VALUE),
            "present-value"
        );
        assert_eq!(
            property_label(PropertyIdentifier::SCHEDULE_DEFAULT),
            "schedule-default"
        );
    }
}
