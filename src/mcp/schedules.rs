//! MCP schedule tools — `read_schedule`, `read_schedule_weekly`,
//! `read_schedule_exceptions`.
//!
//! `read_schedule` returns scalar metadata from a BACnet Schedule object
//! (object type 17) in one RPM round-trip:
//!
//! - `object-name` / `description` — human label
//! - `present-value` — what the schedule is currently outputting
//! - `schedule-default` — the value when nothing is active
//! - `effective-period` — date range for which this schedule applies
//! - `list-of-object-property-references` — what properties this schedule
//!   writes to (the agent's "what does this schedule control?" question).
//!   Decoded into a list of `<device:N>/type:instance/property[idx]` lines.
//! - `status-flags`, `reliability`, `out-of-service` — health
//!
//! `read_schedule_weekly` and `read_schedule_exceptions` each issue a single
//! ReadProperty for the matching constructed-array property and decode it
//! via the `bacnet-services::schedule` codecs. They live as separate tools
//! because Codex flagged (PR #6) that bundling these into the metadata RPM
//! is unsafe — large populated arrays can blow Max-APDU on devices without
//! segmentation, failing the whole RPM and surfacing none of the scalar
//! fields. Single-property reads keep that risk off the metadata path.
//!
//! Write tools (`write_schedule_weekly`, `write_schedule_exceptions`) are a
//! deferred follow-up — `bacnet-services 0.9` ships the matching encoders
//! (`encode_weekly_schedule`, `encode_exception_schedule`), but writes need
//! to integrate with the safety policy + audit log the same way other
//! commandable property writes do.

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_encoding::primitives::decode_unsigned;
use bacnet_encoding::tags::decode_tag;
use bacnet_services::common::PropertyReference;
use bacnet_services::rpm::ReadAccessSpecification;
use bacnet_services::schedule::{decode_exception_schedule, decode_weekly_schedule};
use bacnet_types::constructed::{
    BACnetCalendarEntry, BACnetSpecialEvent, BACnetTimeValue, BACnetWeekNDay, SpecialEventPeriod,
};
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{Date, ObjectIdentifier, Time};

use crate::parse::{
    decode_raw_property_to_json, decode_raw_property_to_json_with_context, object_type_name,
    property_name,
};
use crate::state::GatewayState;

/// Properties pulled in the single RPM round-trip. Codex flagged the
/// previous 11-property list (which bundled `weekly-schedule` and
/// `exception-schedule`) as fragile on devices with small Max-APDU or no
/// response segmentation — a populated schedule array can blow the APDU
/// size and fail the whole RPM, surfacing none of the scalar fields. This
/// list is now scalar-only. `list-of-object-property-references` stays in
/// because its size is bounded by the small number of schedule targets.
const SCHEDULE_PROPERTIES: &[PropertyIdentifier] = &[
    PropertyIdentifier::OBJECT_NAME,
    PropertyIdentifier::DESCRIPTION,
    PropertyIdentifier::PRESENT_VALUE,
    PropertyIdentifier::SCHEDULE_DEFAULT,
    PropertyIdentifier::EFFECTIVE_PERIOD,
    PropertyIdentifier::LIST_OF_OBJECT_PROPERTY_REFERENCES,
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
            // `list-of-object-property-references` is the load-bearing
            // "what does this schedule control?" answer. Codex P2 flagged
            // that the generic primitive decoder produces opaque output
            // for these constructed entries — handle them with a focused
            // decoder so agents see real targets.
            let body = if prop == PropertyIdentifier::LIST_OF_OBJECT_PROPERTY_REFERENCES {
                match decode_object_property_references(raw) {
                    Ok(refs) if refs.is_empty() => "<empty list>".into(),
                    Ok(refs) => {
                        let lines: Vec<String> = refs.iter().map(format_reference).collect();
                        format!("\n    {}", lines.join("\n    "))
                    }
                    Err(e) => format!("<decode failed: {e}; {} byte(s) raw>", raw.len()),
                }
            } else {
                format_property(raw, prop)
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

/// Decoded `BACnetDeviceObjectPropertyReference` — the entries that make up
/// a Schedule's `list-of-object-property-references`.
///
/// Encoding per ASHRAE 135-2020 Clause 21:
/// ```text
/// SEQUENCE {
///   objectIdentifier   [0] BACnetObjectIdentifier,
///   propertyIdentifier [1] BACnetPropertyIdentifier,
///   propertyArrayIndex [2] Unsigned OPTIONAL,
///   deviceIdentifier   [3] BACnetObjectIdentifier OPTIONAL
/// }
/// ```
/// The list is a simple concatenation of these — each new reference begins
/// with `[0]`, so we keep decoding until we run out of bytes.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct DecodedReference {
    pub object_id: ObjectIdentifier,
    pub property_id: u32,
    pub array_index: Option<u32>,
    pub device_id: Option<ObjectIdentifier>,
}

fn decode_object_property_references(data: &[u8]) -> Result<Vec<DecodedReference>, String> {
    let mut refs = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let (r, next) = decode_one_reference(data, offset)
            .map_err(|e| format!("reference {}: {e}", refs.len()))?;
        refs.push(r);
        offset = next;
    }
    Ok(refs)
}

fn decode_one_reference(data: &[u8], offset: usize) -> Result<(DecodedReference, usize), String> {
    // [0] objectIdentifier — context-tagged, length 4.
    let (oid_tag, oid_pos) = decode_tag(data, offset).map_err(|e| format!("[0] tag: {e}"))?;
    if !oid_tag.is_context(0) {
        return Err(format!("expected [0] context tag at offset {offset}"));
    }
    if oid_tag.length != 4 {
        return Err(format!(
            "[0] objectIdentifier length must be 4, got {}",
            oid_tag.length
        ));
    }
    let oid_end = oid_pos + 4;
    if oid_end > data.len() {
        return Err("truncated objectIdentifier".into());
    }
    let object_id = ObjectIdentifier::decode(&data[oid_pos..oid_end])
        .map_err(|e| format!("decode objectIdentifier: {e}"))?;
    let mut pos = oid_end;

    // [1] propertyIdentifier — context-tagged unsigned (variable length).
    let (prop_tag, prop_pos) = decode_tag(data, pos).map_err(|e| format!("[1] tag: {e}"))?;
    if !prop_tag.is_context(1) {
        return Err(format!("expected [1] context tag at offset {pos}"));
    }
    let prop_len = prop_tag.length as usize;
    let prop_end = prop_pos + prop_len;
    if prop_end > data.len() {
        return Err("truncated propertyIdentifier".into());
    }
    let property_id = decode_unsigned(&data[prop_pos..prop_end])
        .map_err(|e| format!("decode propertyIdentifier: {e}"))? as u32;
    pos = prop_end;

    // [2] propertyArrayIndex — OPTIONAL.
    let mut array_index = None;
    if pos < data.len() {
        let (peek, peek_pos) = decode_tag(data, pos).map_err(|e| format!("[2] tag: {e}"))?;
        if peek.is_context(2) {
            let len = peek.length as usize;
            let end = peek_pos + len;
            if end > data.len() {
                return Err("truncated propertyArrayIndex".into());
            }
            array_index = Some(
                decode_unsigned(&data[peek_pos..end])
                    .map_err(|e| format!("decode propertyArrayIndex: {e}"))? as u32,
            );
            pos = end;
        }
    }

    // [3] deviceIdentifier — OPTIONAL, length 4.
    let mut device_id = None;
    if pos < data.len() {
        let (peek, peek_pos) = decode_tag(data, pos).map_err(|e| format!("[3] tag: {e}"))?;
        if peek.is_context(3) {
            if peek.length != 4 {
                return Err(format!(
                    "[3] deviceIdentifier length must be 4, got {}",
                    peek.length
                ));
            }
            let end = peek_pos + 4;
            if end > data.len() {
                return Err("truncated deviceIdentifier".into());
            }
            device_id = Some(
                ObjectIdentifier::decode(&data[peek_pos..end])
                    .map_err(|e| format!("decode deviceIdentifier: {e}"))?,
            );
            pos = end;
        }
    }

    Ok((
        DecodedReference {
            object_id,
            property_id,
            array_index,
            device_id,
        },
        pos,
    ))
}

fn format_reference(r: &DecodedReference) -> String {
    let device_part = r
        .device_id
        .map(|d| format!("device:{}/", d.instance_number()))
        .unwrap_or_default();
    let object_part = format!(
        "{}:{}",
        object_type_name(r.object_id.object_type()),
        r.object_id.instance_number(),
    );
    let property_part = property_name(bacnet_types::enums::PropertyIdentifier::from_raw(
        r.property_id,
    ));
    let array_part = r.array_index.map(|i| format!("[{i}]")).unwrap_or_default();
    format!("{device_part}{object_part}/{property_part}{array_part}")
}

// ─── read_schedule_weekly ───────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadScheduleWeeklyParams {
    #[schemars(description = "Device instance number hosting the Schedule object")]
    pub device_instance: u32,
    #[schemars(description = "Schedule object instance number")]
    pub schedule_instance: u32,
}

pub async fn read_schedule_weekly_impl(
    state: &GatewayState,
    params: ReadScheduleWeeklyParams,
) -> Result<String, String> {
    // OID validation precedes transport so an out-of-range instance number
    // surfaces as a parse error, not "client not started".
    let oid = ObjectIdentifier::new(ObjectType::SCHEDULE, params.schedule_instance)
        .map_err(|e| format!("{e}"))?;

    let client = state.require_client()?;
    let dev = state.resolve_device(params.device_instance).await?;

    // Single ReadProperty (not RPM) for the array property — keeps a
    // populated weekly-schedule from blowing Max-APDU on small devices and
    // taking down a bundled scalar fetch with it.
    let ack = client
        .read_property(
            &dev.mac_address,
            oid,
            PropertyIdentifier::WEEKLY_SCHEDULE,
            None,
        )
        .await
        .map_err(|e| format!("ReadProperty(weekly-schedule) failed: {e}"))?;

    let days = decode_weekly_schedule(&ack.property_value)
        .map_err(|e| format!("decode weekly-schedule: {e}"))?;

    Ok(format_weekly_schedule(
        params.device_instance,
        params.schedule_instance,
        &days,
    ))
}

fn format_weekly_schedule(
    device_instance: u32,
    schedule_instance: u32,
    days: &[Vec<BACnetTimeValue>; 7],
) -> String {
    // BACnet day-of-week numbering is 1=Monday..7=Sunday; the codec doc
    // confirms `days[0]` is Monday.
    const DAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let mut out =
        format!("schedule:{schedule_instance} on device:{device_instance} weekly-schedule:\n");
    let total: usize = days.iter().map(|d| d.len()).sum();
    if total == 0 {
        out.push_str("  <empty> — schedule outputs schedule-default every day\n");
        return out;
    }
    for (i, day) in days.iter().enumerate() {
        if day.is_empty() {
            out.push_str(&format!("  {}: <no entries>\n", DAY_NAMES[i]));
            continue;
        }
        out.push_str(&format!("  {}:\n", DAY_NAMES[i]));
        for tv in day {
            out.push_str(&format!(
                "    {} = {}\n",
                format_time(&tv.time),
                format_time_value(tv)
            ));
        }
    }
    out
}

// ─── read_schedule_exceptions ───────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadScheduleExceptionsParams {
    #[schemars(description = "Device instance number hosting the Schedule object")]
    pub device_instance: u32,
    #[schemars(description = "Schedule object instance number")]
    pub schedule_instance: u32,
}

pub async fn read_schedule_exceptions_impl(
    state: &GatewayState,
    params: ReadScheduleExceptionsParams,
) -> Result<String, String> {
    let oid = ObjectIdentifier::new(ObjectType::SCHEDULE, params.schedule_instance)
        .map_err(|e| format!("{e}"))?;

    let client = state.require_client()?;
    let dev = state.resolve_device(params.device_instance).await?;

    let ack = client
        .read_property(
            &dev.mac_address,
            oid,
            PropertyIdentifier::EXCEPTION_SCHEDULE,
            None,
        )
        .await
        .map_err(|e| format!("ReadProperty(exception-schedule) failed: {e}"))?;

    let events = decode_exception_schedule(&ack.property_value)
        .map_err(|e| format!("decode exception-schedule: {e}"))?;

    Ok(format_exception_schedule(
        params.device_instance,
        params.schedule_instance,
        &events,
    ))
}

fn format_exception_schedule(
    device_instance: u32,
    schedule_instance: u32,
    events: &[BACnetSpecialEvent],
) -> String {
    let mut out = format!(
        "schedule:{schedule_instance} on device:{device_instance} exception-schedule ({} entr{}):\n",
        events.len(),
        if events.len() == 1 { "y" } else { "ies" },
    );
    if events.is_empty() {
        out.push_str("  <empty> — no exception periods configured\n");
        return out;
    }
    for (i, event) in events.iter().enumerate() {
        out.push_str(&format!(
            "  [{}] {} priority={}:\n",
            i + 1,
            format_special_event_period(&event.period),
            event.event_priority,
        ));
        if event.list_of_time_values.is_empty() {
            out.push_str("      <no time-values>\n");
            continue;
        }
        for tv in &event.list_of_time_values {
            out.push_str(&format!(
                "      {} = {}\n",
                format_time(&tv.time),
                format_time_value(tv),
            ));
        }
    }
    out
}

// ─── shared formatters ──────────────────────────────────────────────────────

/// Render a BACnetTimeValue's polymorphic `value` field. The bytes are
/// raw application-tagged BACnet encoding, so we route them through the
/// same decoder used for scalar property values to keep output consistent.
fn format_time_value(tv: &BACnetTimeValue) -> String {
    if tv.value.is_empty() {
        return "<empty>".into();
    }
    let json = decode_raw_property_to_json(&tv.value);
    match json.get("value") {
        Some(v) => v.to_string(),
        None => json.to_string(),
    }
}

fn format_time(t: &Time) -> String {
    let h = field_or_star(t.hour);
    let m = field_or_star(t.minute);
    let s = field_or_star(t.second);
    if t.hundredths == Time::UNSPECIFIED || t.hundredths == 0 {
        format!("{h}:{m}:{s}")
    } else {
        format!("{h}:{m}:{s}.{:02}", t.hundredths)
    }
}

fn format_date(d: &Date) -> String {
    // BACnet Date carries pattern semantics, not just calendar values:
    //   month: 1-12 normal, 13=odd, 14=even, 0xFF=any
    //   day:   1-31 normal, 32=last-of-month, 33=odd, 34=even, 0xFF=any
    //   day_of_week: 1=Mon..7=Sun, 0xFF=any
    // Codex P2 flagged that printing these raw makes patterns look like
    // impossible calendar dates and that dropping day_of_week makes
    // distinct exception patterns collapse to the same string.
    let y = if d.year == Date::UNSPECIFIED {
        "****".to_string()
    } else {
        format!("{:04}", 1900 + d.year as u16)
    };
    let m = match d.month {
        Date::UNSPECIFIED => "**".to_string(),
        13 => "odd".into(),
        14 => "even".into(),
        n => format!("{n:02}"),
    };
    let day = match d.day {
        Date::UNSPECIFIED => "**".to_string(),
        32 => "last".into(),
        33 => "odd".into(),
        34 => "even".into(),
        n => format!("{n:02}"),
    };
    let dow = if d.day_of_week == Date::UNSPECIFIED {
        String::new()
    } else {
        const NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
        let idx = (d.day_of_week as usize).saturating_sub(1).min(6);
        format!("-{}", NAMES[idx])
    };
    format!("{y}-{m}-{day}{dow}")
}

fn field_or_star(v: u8) -> String {
    if v == 0xFF {
        "**".into()
    } else {
        format!("{v:02}")
    }
}

fn format_calendar_entry(e: &BACnetCalendarEntry) -> String {
    match e {
        BACnetCalendarEntry::Date(d) => format!("date={}", format_date(d)),
        BACnetCalendarEntry::DateRange(r) => format!(
            "date-range={}..{}",
            format_date(&r.start_date),
            format_date(&r.end_date),
        ),
        BACnetCalendarEntry::WeekNDay(w) => format!("week-n-day={}", format_week_n_day(w)),
    }
}

fn format_week_n_day(w: &BACnetWeekNDay) -> String {
    // Compact `month/week-of-month/day-of-week` rendering with `*` for
    // wildcards. Spec values for `month` 13/14 mean odd/even; surface those
    // explicitly so an agent doesn't need to look up the magic numbers.
    let month = match w.month {
        BACnetWeekNDay::ANY => "*".to_string(),
        13 => "odd".into(),
        14 => "even".into(),
        n => n.to_string(),
    };
    let week = if w.week_of_month == BACnetWeekNDay::ANY {
        "*".into()
    } else {
        w.week_of_month.to_string()
    };
    let dow = if w.day_of_week == BACnetWeekNDay::ANY {
        "*".to_string()
    } else {
        // 1=Mon..7=Sun matches BACnet day-of-week numbering.
        const NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
        let idx = (w.day_of_week as usize).saturating_sub(1).min(6);
        NAMES[idx].to_string()
    };
    format!("{month}/{week}/{dow}")
}

fn format_special_event_period(p: &SpecialEventPeriod) -> String {
    match p {
        SpecialEventPeriod::CalendarEntry(e) => format_calendar_entry(e),
        SpecialEventPeriod::CalendarReference(oid) => format!(
            "calendar-ref={}:{}",
            object_type_name(oid.object_type()),
            oid.instance_number(),
        ),
    }
}

// (no items below the test module — clippy::items_after_test_module enforced)

#[cfg(test)]
mod tests {
    use super::*;

    use bacnet_encoding::tags::{TagClass, encode_tag};
    use bytes::BytesMut;

    #[test]
    fn schedule_properties_count_matches_planned_set() {
        // Pin the RPM request shape. Codex flagged the previous 11-property
        // list as risky on small-Max-APDU devices because it bundled the
        // weekly-schedule and exception-schedule arrays. The new 9-property
        // set is scalar-only (plus list-of-object-property-references which
        // is small and now decoded properly).
        assert_eq!(SCHEDULE_PROPERTIES.len(), 9);
        assert!(!SCHEDULE_PROPERTIES.contains(&PropertyIdentifier::WEEKLY_SCHEDULE));
        assert!(!SCHEDULE_PROPERTIES.contains(&PropertyIdentifier::EXCEPTION_SCHEDULE));
    }

    #[test]
    fn schedule_properties_include_present_value_and_default() {
        assert!(SCHEDULE_PROPERTIES.contains(&PropertyIdentifier::PRESENT_VALUE));
        assert!(SCHEDULE_PROPERTIES.contains(&PropertyIdentifier::SCHEDULE_DEFAULT));
        assert!(
            SCHEDULE_PROPERTIES.contains(&PropertyIdentifier::LIST_OF_OBJECT_PROPERTY_REFERENCES)
        );
    }

    #[test]
    fn property_label_uses_canonical_kebab_case() {
        assert_eq!(
            property_label(PropertyIdentifier::PRESENT_VALUE),
            "present-value"
        );
        assert_eq!(
            property_label(PropertyIdentifier::SCHEDULE_DEFAULT),
            "schedule-default"
        );
    }

    // ─── format_date — BACnet pattern semantics (Codex P2 PR #11) ───────────

    #[test]
    fn format_date_concrete_includes_day_of_week_when_specified() {
        // 2026-12-25 was a Friday. BACnet day-of-week 5 = Fri.
        let d = Date {
            year: 126, // 1900 + 126 = 2026
            month: 12,
            day: 25,
            day_of_week: 5,
        };
        assert_eq!(format_date(&d), "2026-12-25-Fri");
    }

    #[test]
    fn format_date_concrete_omits_unspecified_day_of_week() {
        let d = Date {
            year: 126,
            month: 12,
            day: 25,
            day_of_week: Date::UNSPECIFIED,
        };
        assert_eq!(format_date(&d), "2026-12-25");
    }

    #[test]
    fn format_date_renders_month_sentinels() {
        // month=13 = odd-numbered months, month=14 = even-numbered months.
        // Codex P2: must not render these as calendar 13/14.
        let odd = Date {
            year: Date::UNSPECIFIED,
            month: 13,
            day: 1,
            day_of_week: Date::UNSPECIFIED,
        };
        let even = Date {
            year: Date::UNSPECIFIED,
            month: 14,
            day: 1,
            day_of_week: Date::UNSPECIFIED,
        };
        assert_eq!(format_date(&odd), "****-odd-01");
        assert_eq!(format_date(&even), "****-even-01");
    }

    #[test]
    fn format_date_renders_day_sentinels() {
        // day=32 = last-of-month, 33 = odd-numbered days, 34 = even.
        // Renders should make these unambiguous instead of "32".
        let last = Date {
            year: Date::UNSPECIFIED,
            month: Date::UNSPECIFIED,
            day: 32,
            day_of_week: Date::UNSPECIFIED,
        };
        let odd_day = Date {
            year: Date::UNSPECIFIED,
            month: Date::UNSPECIFIED,
            day: 33,
            day_of_week: Date::UNSPECIFIED,
        };
        let even_day = Date {
            year: Date::UNSPECIFIED,
            month: Date::UNSPECIFIED,
            day: 34,
            day_of_week: Date::UNSPECIFIED,
        };
        assert_eq!(format_date(&last), "****-**-last");
        assert_eq!(format_date(&odd_day), "****-**-odd");
        assert_eq!(format_date(&even_day), "****-**-even");
    }

    #[test]
    fn format_date_combines_pattern_with_day_of_week() {
        // "every Monday in odd-numbered months" — distinct from "every
        // Tuesday in odd-numbered months", but without day_of_week the two
        // would render identically.
        let mon = Date {
            year: Date::UNSPECIFIED,
            month: 13,
            day: Date::UNSPECIFIED,
            day_of_week: 1,
        };
        let tue = Date {
            year: Date::UNSPECIFIED,
            month: 13,
            day: Date::UNSPECIFIED,
            day_of_week: 2,
        };
        assert_eq!(format_date(&mon), "****-odd-**-Mon");
        assert_eq!(format_date(&tue), "****-odd-**-Tue");
    }

    fn encode_object_id(buf: &mut BytesMut, tag: u8, ot: ObjectType, instance: u32) {
        // BACnet object id is 22 bits of instance | 10 bits of object type.
        let raw = ((ot.to_raw() & 0x3FF) << 22) | (instance & 0x3F_FFFF);
        encode_tag(buf, tag, TagClass::Context, 4);
        buf.extend_from_slice(&raw.to_be_bytes());
    }

    fn encode_ctx_unsigned(buf: &mut BytesMut, tag: u8, value: u32) {
        // Minimal big-endian length per BACnet unsigned encoding.
        let bytes = if value <= 0xFF {
            vec![value as u8]
        } else if value <= 0xFFFF {
            vec![(value >> 8) as u8, value as u8]
        } else if value <= 0xFF_FFFF {
            vec![(value >> 16) as u8, (value >> 8) as u8, value as u8]
        } else {
            value.to_be_bytes().to_vec()
        };
        encode_tag(buf, tag, TagClass::Context, bytes.len() as u32);
        buf.extend_from_slice(&bytes);
    }

    #[test]
    fn decode_single_local_reference() {
        // Schedule writes to AnalogValue:42 / present-value, no array index,
        // no device (= local).
        let mut buf = BytesMut::new();
        encode_object_id(&mut buf, 0, ObjectType::ANALOG_VALUE, 42);
        encode_ctx_unsigned(&mut buf, 1, PropertyIdentifier::PRESENT_VALUE.to_raw());
        let refs = decode_object_property_references(&buf).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].object_id.instance_number(), 42);
        assert_eq!(
            refs[0].property_id,
            PropertyIdentifier::PRESENT_VALUE.to_raw()
        );
        assert!(refs[0].array_index.is_none());
        assert!(refs[0].device_id.is_none());
    }

    #[test]
    fn decode_remote_reference_with_array_index() {
        // Schedule writes to a remote device's AnalogOutput:5 /
        // priority-array[10].
        let mut buf = BytesMut::new();
        encode_object_id(&mut buf, 0, ObjectType::ANALOG_OUTPUT, 5);
        encode_ctx_unsigned(&mut buf, 1, PropertyIdentifier::PRIORITY_ARRAY.to_raw());
        encode_ctx_unsigned(&mut buf, 2, 10);
        encode_object_id(&mut buf, 3, ObjectType::DEVICE, 1234);
        let refs = decode_object_property_references(&buf).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].array_index, Some(10));
        assert_eq!(refs[0].device_id.unwrap().instance_number(), 1234);
    }

    #[test]
    fn decode_multiple_references_back_to_back() {
        let mut buf = BytesMut::new();
        for i in 0..3 {
            encode_object_id(&mut buf, 0, ObjectType::ANALOG_VALUE, i);
            encode_ctx_unsigned(&mut buf, 1, PropertyIdentifier::PRESENT_VALUE.to_raw());
        }
        let refs = decode_object_property_references(&buf).unwrap();
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].object_id.instance_number(), 0);
        assert_eq!(refs[2].object_id.instance_number(), 2);
    }

    #[test]
    fn format_reference_renders_local() {
        let r = DecodedReference {
            object_id: ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 42).unwrap(),
            property_id: PropertyIdentifier::PRESENT_VALUE.to_raw(),
            array_index: None,
            device_id: None,
        };
        assert_eq!(format_reference(&r), "analog-value:42/present-value");
    }

    #[test]
    fn format_reference_renders_remote_with_array() {
        let r = DecodedReference {
            object_id: ObjectIdentifier::new(ObjectType::ANALOG_OUTPUT, 5).unwrap(),
            property_id: PropertyIdentifier::PRIORITY_ARRAY.to_raw(),
            array_index: Some(10),
            device_id: Some(ObjectIdentifier::new(ObjectType::DEVICE, 1234).unwrap()),
        };
        assert_eq!(
            format_reference(&r),
            "device:1234/analog-output:5/priority-array[10]"
        );
    }

    #[test]
    fn decode_truncated_reference_errors() {
        let mut buf = BytesMut::new();
        encode_object_id(&mut buf, 0, ObjectType::ANALOG_VALUE, 1);
        // No [1] propertyIdentifier — should error rather than panic.
        let err = decode_object_property_references(&buf).unwrap_err();
        assert!(err.contains("[1]") || err.contains("propertyIdentifier"));
    }
}
