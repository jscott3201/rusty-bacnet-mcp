//! MCP trend-log tools backed by ReadPropertyMultiple + ReadRange.
//!
//! Two tools:
//!
//! - **`get_trend_log_info`** — RPM round-trip for a TrendLog object's
//!   metadata: object-name, log-enable, log-interval, buffer-size,
//!   record-count, total-record-count, log-device-object-property (the
//!   trended source). Lets an agent answer "is this trend running, what is
//!   it logging, and how many records are buffered?" in one call.
//!
//! - **`read_trend_log`** — uses the BACnet ReadRange service to fetch a
//!   window of records from `log-buffer`. Three range modes per ASHRAE
//!   135-2020 Clause 15.8: by-position, by-sequence-number, by-time. The
//!   service-level `item_data` bytes are decoded into one
//!   `BACnetLogRecord` per record (timestamp + datum + optional status).
//!
//! Both tools are read-only — neither consults `WritePolicy` or appends
//! audit entries.

mod decode;

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_services::read_range::{RangeSpec, ReadRangeAck};
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{Date, ObjectIdentifier, Time};

use crate::parse::decode_raw_property_to_json_with_context;
use crate::state::GatewayState;
use decode::{decode_log_records, format_datum};

// ─── get_trend_log_info ─────────────────────────────────────────────────────

/// Parameters for `get_trend_log_info`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TrendLogInfoParams {
    #[schemars(description = "Device instance number hosting the TrendLog object")]
    pub device_instance: u32,
    #[schemars(description = "TrendLog object instance number")]
    pub trend_log_instance: u32,
}

const TREND_INFO_PROPERTIES: &[PropertyIdentifier] = &[
    PropertyIdentifier::OBJECT_NAME,
    PropertyIdentifier::DESCRIPTION,
    PropertyIdentifier::LOG_ENABLE,
    PropertyIdentifier::LOG_INTERVAL,
    PropertyIdentifier::BUFFER_SIZE,
    PropertyIdentifier::RECORD_COUNT,
    PropertyIdentifier::TOTAL_RECORD_COUNT,
    PropertyIdentifier::LOG_DEVICE_OBJECT_PROPERTY,
    PropertyIdentifier::START_TIME,
    PropertyIdentifier::STOP_TIME,
    PropertyIdentifier::LOGGING_TYPE,
    PropertyIdentifier::STATUS_FLAGS,
    PropertyIdentifier::EVENT_STATE,
];

pub async fn get_trend_log_info_impl(
    state: &GatewayState,
    params: TrendLogInfoParams,
) -> Result<String, String> {
    let client = state.require_client()?;
    let oid = ObjectIdentifier::new(ObjectType::TREND_LOG, params.trend_log_instance)
        .map_err(|e| format!("{e}"))?;
    let dev = state.resolve_device(params.device_instance).await?;

    use bacnet_services::common::PropertyReference;
    use bacnet_services::rpm::ReadAccessSpecification;
    let spec = ReadAccessSpecification {
        object_identifier: oid,
        list_of_property_references: TREND_INFO_PROPERTIES
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
        "trend-log:{} on device:{}\n",
        params.trend_log_instance, params.device_instance
    );
    for elem in ack
        .list_of_read_access_results
        .into_iter()
        .flat_map(|r| r.list_of_results.into_iter())
    {
        let prop = elem.property_identifier;
        let line = if let Some(raw) = &elem.property_value {
            let val = decode_raw_property_to_json_with_context(raw, prop);
            let display = val
                .get("value")
                .map(|v| format!("{v}"))
                .unwrap_or_else(|| format!("{val}"));
            format!("  {} = {}\n", prop_name(prop), display)
        } else if let Some((class, code)) = &elem.error {
            format!(
                "  {} = <error class={:?} code={:?}>\n",
                prop_name(prop),
                class,
                code,
            )
        } else {
            format!("  {} = <empty result>\n", prop_name(prop))
        };
        out.push_str(&line);
    }
    Ok(out)
}

fn prop_name(p: PropertyIdentifier) -> String {
    crate::parse::property_name(p).to_string()
}

// ─── read_trend_log ─────────────────────────────────────────────────────────

/// Range mode for `read_trend_log`. Mirrors ASHRAE 135-2020 ReadRange
/// `Range` CHOICE: by-position, by-sequence, by-time.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RangeMode {
    /// Index into `log-buffer` array. `reference` is the 1-based index of
    /// the first record to return; `count` is the number to return (negative
    /// reads backwards from `reference`).
    ByPosition,
    /// `reference` is a sequence number; `count` is the number of records
    /// to return forward (positive) or backward (negative) of it.
    BySequence,
    /// `reference` is an ISO8601-ish "YYYY-MM-DD HH:MM:SS" stamp; `count`
    /// is records forward (positive) or backward (negative) of that time.
    ByTime,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadTrendLogParams {
    #[schemars(description = "Device instance number hosting the TrendLog object")]
    pub device_instance: u32,
    #[schemars(description = "TrendLog object instance number")]
    pub trend_log_instance: u32,
    #[schemars(description = "Range mode: 'by_position', 'by_sequence', or 'by_time'")]
    pub mode: RangeMode,
    /// Range reference. For by_position: 1-based index. For by_sequence:
    /// sequence number. For by_time: "YYYY-MM-DD HH:MM:SS".
    #[schemars(
        description = "Reference value (mode-dependent: index, sequence number, or 'YYYY-MM-DD HH:MM:SS')"
    )]
    pub reference: String,
    /// Records to return. Positive = forward, negative = backward.
    /// Server-side capped at the device's max-records-per-response.
    #[schemars(description = "Records to return (positive=forward, negative=backward)")]
    pub count: i32,
}

pub async fn read_trend_log_impl(
    state: &GatewayState,
    params: ReadTrendLogParams,
) -> Result<String, String> {
    // Validate parameters BEFORE touching the network layer so agents get a
    // clear parse error rather than a generic "client not started" when
    // they pass garbage. Pattern matches the bulk-read tools.
    let oid = ObjectIdentifier::new(ObjectType::TREND_LOG, params.trend_log_instance)
        .map_err(|e| format!("{e}"))?;
    let range = build_range_spec(&params.mode, &params.reference, params.count)?;

    let client = state.require_client()?;
    let dev = state.resolve_device(params.device_instance).await?;

    let ack: ReadRangeAck = client
        .read_range(
            &dev.mac_address,
            oid,
            PropertyIdentifier::LOG_BUFFER,
            None,
            Some(range),
        )
        .await
        .map_err(|e| format!("ReadRange failed: {e}"))?;

    let records = decode_log_records(&ack.item_data, ack.item_count)
        .map_err(|e| format!("Decoding LogRecord stream: {e}"))?;

    // bacnet-services 0.8 documents result_flags as `(first_item, last_item,
    // more_items)`; Codex flagged that the previous destructure inverted
    // bits 0 and 2 of the BIT STRING and would mislabel pagination state.
    let (first_item, last_item, more_items) = ack.result_flags;
    let mut out = format!(
        "trend-log:{} on device:{} — {} record(s){}{}{}",
        params.trend_log_instance,
        params.device_instance,
        ack.item_count,
        if first_item { " [first-item]" } else { "" },
        if last_item { " [last-item]" } else { "" },
        if more_items { " [more-follows]" } else { "" },
    );
    if let Some(seq) = ack.first_sequence_number {
        out.push_str(&format!(" first-seq={seq}"));
    }
    out.push('\n');
    for (i, rec) in records.iter().enumerate() {
        out.push_str(&format!(
            "  [{:>3}] {} {}{}\n",
            i,
            format_datetime(rec.date, rec.time),
            format_datum(&rec.datum),
            rec.status_flags
                .map(|f| format!(" status=0x{f:02x}"))
                .unwrap_or_default(),
        ));
    }
    Ok(out)
}

fn build_range_spec(mode: &RangeMode, reference: &str, count: i32) -> Result<RangeSpec, String> {
    // Codex flagged three count issues: zero is invalid per BACnet, the
    // wire field is INTEGER16 (so values outside i16 produce
    // non-conformant requests), and the previous code silently forwarded
    // both. Validate up front.
    if count == 0 {
        return Err(
            "count must be non-zero (BACnet ReadRange requires a record count of at least ±1)"
                .into(),
        );
    }
    if !(i16::MIN as i32..=i16::MAX as i32).contains(&count) {
        return Err(format!(
            "count {count} is outside BACnet INTEGER16 range ({}..={})",
            i16::MIN,
            i16::MAX,
        ));
    }
    match mode {
        RangeMode::ByPosition => {
            let idx: u32 = reference
                .parse()
                .map_err(|e| format!("by_position reference must be a 1-based index: {e}"))?;
            // Codex P2: 1-based index documented but the previous code
            // accepted 0 (only u32 lower bound was implicit). Reject
            // explicitly so the device never has to disambiguate.
            if idx == 0 {
                return Err(
                    "by_position reference must be ≥ 1 (1-based index per BACnet ReadRange)".into(),
                );
            }
            Ok(RangeSpec::ByPosition {
                reference_index: idx,
                count,
            })
        }
        RangeMode::BySequence => {
            let seq: u32 = reference.parse().map_err(|e| {
                format!("by_sequence reference must be an unsigned sequence number: {e}")
            })?;
            Ok(RangeSpec::BySequenceNumber {
                reference_seq: seq,
                count,
            })
        }
        RangeMode::ByTime => {
            let (date, time) = parse_iso_datetime(reference)?;
            Ok(RangeSpec::ByTime {
                reference_time: (date, time),
                count,
            })
        }
    }
}

fn parse_iso_datetime(s: &str) -> Result<(Date, Time), String> {
    // Accept "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DDTHH:MM:SS"; seconds optional.
    let normalized = s.replace('T', " ");
    let mut parts = normalized.splitn(2, ' ');
    let date_s = parts
        .next()
        .ok_or_else(|| "datetime missing date part".to_string())?;
    let time_s = parts
        .next()
        .ok_or_else(|| "datetime missing time part (need 'YYYY-MM-DD HH:MM:SS')".to_string())?;

    // Codex flagged silent corruption / acceptance of garbage in the
    // previous parse: out-of-range years truncated mod 256, non-numeric
    // seconds silently became 0, no field-range validation. All fixed
    // below — every malformed component now returns a typed error.
    let mut d = date_s.split('-');
    let yyyy: u16 = d
        .next()
        .ok_or("date missing year")?
        .parse()
        .map_err(|e| format!("year: {e}"))?;
    let mm: u8 = d
        .next()
        .ok_or("date missing month")?
        .parse()
        .map_err(|e| format!("month: {e}"))?;
    let dd: u8 = d
        .next()
        .ok_or("date missing day")?
        .parse()
        .map_err(|e| format!("day: {e}"))?;

    let mut t = time_s.split(':');
    let hh: u8 = t
        .next()
        .ok_or("time missing hour")?
        .parse()
        .map_err(|e| format!("hour: {e}"))?;
    let mi: u8 = t
        .next()
        .ok_or("time missing minute")?
        .parse()
        .map_err(|e| format!("minute: {e}"))?;
    // Seconds default to 0 when omitted ("YYYY-MM-DD HH:MM"), but if a
    // non-numeric token is present we MUST reject it — silently mapping
    // "xx" to 0 changes the time window.
    let ss: u8 = match t.next() {
        Some("") | None => 0,
        Some(token) => token.parse().map_err(|e| format!("second: {e}"))?,
    };

    // BACnet Date.year is years-since-1900 stored as u8 → 1900..=2155.
    // Anything outside this is garbage; do NOT silently truncate.
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

    let year_tens = (yyyy - 1900) as u8;
    Ok((
        Date {
            year: year_tens,
            month: mm,
            day: dd,
            day_of_week: 0xFF, // unspecified
        },
        Time {
            hour: hh,
            minute: mi,
            second: ss,
            hundredths: 0,
        },
    ))
}

/// Render a BACnet (Date, Time) pair as `YYYY-MM-DD HH:MM:SS`. Date.year is
/// years-since-1900 per the spec.
fn format_datetime(date: Date, time: Time) -> String {
    let yyyy = 1900u16.saturating_add(date.year as u16);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        yyyy, date.month, date.day, time.hour, time.minute, time.second
    )
}

// (no items below the test module — clippy::items_after_test_module enforced)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_iso_datetime_full() {
        let (d, t) = parse_iso_datetime("2026-05-08 14:30:45").unwrap();
        assert_eq!(d.year, 126); // 2026 - 1900
        assert_eq!(d.month, 5);
        assert_eq!(d.day, 8);
        assert_eq!(t.hour, 14);
        assert_eq!(t.minute, 30);
        assert_eq!(t.second, 45);
    }

    #[test]
    fn parse_iso_datetime_t_separator() {
        let (_, t) = parse_iso_datetime("2026-05-08T09:00").unwrap();
        assert_eq!(t.hour, 9);
        assert_eq!(t.second, 0);
    }

    #[test]
    fn parse_iso_datetime_rejects_garbage() {
        assert!(parse_iso_datetime("not a date").is_err());
    }

    #[test]
    fn build_range_spec_by_position() {
        let spec = build_range_spec(&RangeMode::ByPosition, "10", -5).unwrap();
        match spec {
            RangeSpec::ByPosition {
                reference_index,
                count,
            } => {
                assert_eq!(reference_index, 10);
                assert_eq!(count, -5);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn build_range_spec_by_sequence() {
        let spec = build_range_spec(&RangeMode::BySequence, "12345", 50).unwrap();
        match spec {
            RangeSpec::BySequenceNumber {
                reference_seq,
                count,
            } => {
                assert_eq!(reference_seq, 12345);
                assert_eq!(count, 50);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn build_range_spec_by_time_with_garbage_errors() {
        let r = build_range_spec(&RangeMode::ByTime, "garbage", 10);
        assert!(r.is_err());
    }

    // --- Validation tests pinning Codex PR #4 review fixes ---

    #[test]
    fn count_zero_is_rejected() {
        let r = build_range_spec(&RangeMode::ByPosition, "1", 0);
        assert!(r.unwrap_err().to_lowercase().contains("non-zero"));
    }

    #[test]
    fn count_outside_i16_is_rejected() {
        let too_big = build_range_spec(&RangeMode::ByPosition, "1", 40_000);
        assert!(too_big.unwrap_err().contains("INTEGER16"));
        let too_small = build_range_spec(&RangeMode::ByPosition, "1", -40_000);
        assert!(too_small.unwrap_err().contains("INTEGER16"));
    }

    #[test]
    fn by_position_reference_zero_is_rejected() {
        let r = build_range_spec(&RangeMode::ByPosition, "0", 10);
        assert!(r.unwrap_err().contains("≥ 1"));
    }

    #[test]
    fn parse_iso_datetime_rejects_non_numeric_seconds() {
        // Previously `unwrap_or(0)` silently turned "xx" into 0:00.
        let err = parse_iso_datetime("2026-05-08 14:30:xx").unwrap_err();
        assert!(err.contains("second"), "got: {err}");
    }

    #[test]
    fn parse_iso_datetime_rejects_year_below_1900() {
        let err = parse_iso_datetime("1850-01-01 00:00:00").unwrap_err();
        assert!(err.contains("1900"), "got: {err}");
    }

    #[test]
    fn parse_iso_datetime_rejects_year_above_2155() {
        let err = parse_iso_datetime("2200-01-01 00:00:00").unwrap_err();
        assert!(err.contains("2155"), "got: {err}");
    }

    #[test]
    fn parse_iso_datetime_rejects_out_of_range_components() {
        assert!(parse_iso_datetime("2026-13-01 00:00:00").is_err());
        assert!(parse_iso_datetime("2026-01-32 00:00:00").is_err());
        assert!(parse_iso_datetime("2026-01-01 25:00:00").is_err());
        assert!(parse_iso_datetime("2026-01-01 00:60:00").is_err());
        assert!(parse_iso_datetime("2026-01-01 00:00:60").is_err());
    }
}
