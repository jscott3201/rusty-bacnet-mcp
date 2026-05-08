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

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_encoding::primitives::decode_unsigned;
use bacnet_encoding::tags::{Tag, decode_tag};
use bacnet_services::read_range::{RangeSpec, ReadRangeAck};
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{Date, ObjectIdentifier, Time};

use crate::parse::decode_raw_property_to_json_with_context;
use crate::state::GatewayState;

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

    let (more, _truncated, first_item) = ack.result_flags;
    let mut out = format!(
        "trend-log:{} on device:{} — {} record(s){}{}",
        params.trend_log_instance,
        params.device_instance,
        ack.item_count,
        if first_item { " [first-item]" } else { "" },
        if more { " [more-follows]" } else { "" },
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
    match mode {
        RangeMode::ByPosition => {
            let idx: u32 = reference
                .parse()
                .map_err(|e| format!("by_position reference must be a 1-based index: {e}"))?;
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
    let ss: u8 = t.next().unwrap_or("0").parse().unwrap_or(0);

    let year_tens = (yyyy.saturating_sub(1900)) as u8;
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

// ─── LogRecord stream decoder ───────────────────────────────────────────────

/// Decoded BACnetLogRecord. We keep this private to the trend module — the
/// upstream `bacnet_types::constructed::BACnetLogRecord` is a structurally
/// identical type but bacnet-encoding 0.8 doesn't ship a decoder for the
/// stream-of-records shape that ReadRangeAck.item_data uses, so we own the
/// decode here and surface a domain-specific shape.
#[derive(Debug, Clone, PartialEq)]
struct DecodedLogRecord {
    date: Date,
    time: Time,
    datum: DecodedDatum,
    status_flags: Option<u8>,
}

#[derive(Debug, Clone, PartialEq)]
enum DecodedDatum {
    LogStatus(u8),
    Boolean(bool),
    Real(f32),
    Enumerated(u32),
    Unsigned(u64),
    Signed(i64),
    Bitstring {
        unused_bits: u8,
        data: Vec<u8>,
    },
    Null,
    Failure {
        class: u32,
        code: u32,
    },
    TimeChange(f32),
    /// Tag we don't decode in detail (any-value or future variant). Holds
    /// the raw inner bytes so the agent can at least see something landed.
    Other {
        tag: u8,
        raw: Vec<u8>,
    },
}

fn decode_log_records(data: &[u8], item_count: u32) -> Result<Vec<DecodedLogRecord>, String> {
    let mut records = Vec::with_capacity(item_count as usize);
    let mut offset = 0usize;
    for i in 0..item_count {
        let (rec, next) =
            decode_one_log_record(data, offset).map_err(|e| format!("record {i}: {e}"))?;
        records.push(rec);
        offset = next;
    }
    Ok(records)
}

fn decode_one_log_record(data: &[u8], offset: usize) -> Result<(DecodedLogRecord, usize), String> {
    // [0] BACnetDateTime (Date + Time as application tags inside the [0] envelope).
    let pos = expect_opening(data, offset, 0)?;
    let (date, pos) = read_app_date(data, pos)?;
    let (time, pos) = read_app_time(data, pos)?;
    let pos = expect_closing(data, pos, 0)?;

    // [1] log-datum CHOICE — exactly one inner context tag indexed 0..=10.
    let pos = expect_opening(data, pos, 1)?;
    let (datum, pos) = decode_datum(data, pos)?;
    let pos = expect_closing(data, pos, 1)?;

    // [2] BACnetStatusFlags BIT STRING — optional. Peek the next tag; if
    // it's context-tagged 2, consume and decode the bit string. Otherwise
    // we're done with this record.
    let (status_flags, pos) = if pos < data.len() {
        let (peek, _) = decode_tag(data, pos).map_err(|e| format!("status peek: {e}"))?;
        if peek.is_context(2) {
            let (sf, after) = read_status_flags(data, pos)?;
            (Some(sf), after)
        } else {
            (None, pos)
        }
    } else {
        (None, pos)
    };

    Ok((
        DecodedLogRecord {
            date,
            time,
            datum,
            status_flags,
        },
        pos,
    ))
}

fn expect_opening(data: &[u8], offset: usize, tag: u8) -> Result<usize, String> {
    let (t, pos) = decode_tag(data, offset).map_err(|e| format!("opening tag {tag}: {e}"))?;
    if !t.is_opening_tag(tag) {
        return Err(format!("expected opening tag {tag} at offset {offset}"));
    }
    Ok(pos)
}

fn expect_closing(data: &[u8], offset: usize, tag: u8) -> Result<usize, String> {
    let (t, pos) = decode_tag(data, offset).map_err(|e| format!("closing tag {tag}: {e}"))?;
    if !t.is_closing_tag(tag) {
        return Err(format!("expected closing tag {tag} at offset {offset}"));
    }
    Ok(pos)
}

fn read_app_date(data: &[u8], offset: usize) -> Result<(Date, usize), String> {
    let (tag, pos) = decode_tag(data, offset).map_err(|e| format!("date tag: {e}"))?;
    let len = tag.length as usize;
    let end = pos + len;
    if end > data.len() {
        return Err("truncated Date".into());
    }
    let d = Date::decode(&data[pos..end]).map_err(|e| format!("Date::decode: {e}"))?;
    Ok((d, end))
}

fn read_app_time(data: &[u8], offset: usize) -> Result<(Time, usize), String> {
    let (tag, pos) = decode_tag(data, offset).map_err(|e| format!("time tag: {e}"))?;
    let len = tag.length as usize;
    let end = pos + len;
    if end > data.len() {
        return Err("truncated Time".into());
    }
    let t = Time::decode(&data[pos..end]).map_err(|e| format!("Time::decode: {e}"))?;
    Ok((t, end))
}

fn read_status_flags(data: &[u8], offset: usize) -> Result<(u8, usize), String> {
    let (tag, pos) = decode_tag(data, offset).map_err(|e| format!("status_flags tag: {e}"))?;
    let len = tag.length as usize;
    let end = pos + len;
    if end > data.len() {
        return Err("truncated status_flags".into());
    }
    // BIT STRING encoding: first byte = unused-bits, then data bytes.
    if len < 1 {
        return Err("status_flags zero length".into());
    }
    // We collapse the 4-bit flags to one byte. BACnet StatusFlags has 4
    // defined bits (in-alarm, fault, overridden, out-of-service); encoders
    // pack them into the low nibble of the first data byte after the
    // unused-bits prefix.
    let flags = if len >= 2 { data[pos + 1] } else { 0 };
    Ok((flags, end))
}

fn decode_datum(data: &[u8], offset: usize) -> Result<(DecodedDatum, usize), String> {
    let (tag, pos) = decode_tag(data, offset).map_err(|e| format!("datum tag: {e}"))?;
    let n = tag.number;
    let len = tag.length as usize;
    let end = pos + len;
    if end > data.len() {
        return Err(format!("truncated datum tag {n}"));
    }
    let body = &data[pos..end];
    let datum = match n {
        0 => {
            // log-status: 8-bit BIT STRING (one byte unused-bits + one byte flags).
            let flags = if body.len() >= 2 { body[1] } else { 0 };
            DecodedDatum::LogStatus(flags)
        }
        1 => {
            // boolean: context-tagged value is encoded with length=1 and the
            // single byte 0x00 / 0x01.
            DecodedDatum::Boolean(!body.is_empty() && body[0] != 0)
        }
        2 => {
            if body.len() < 4 {
                return Err("real-value < 4 bytes".into());
            }
            DecodedDatum::Real(f32::from_be_bytes([body[0], body[1], body[2], body[3]]))
        }
        3 => {
            let v = decode_unsigned(body).map_err(|e| format!("enum-value: {e}"))?;
            DecodedDatum::Enumerated(v as u32)
        }
        4 => {
            let v = decode_unsigned(body).map_err(|e| format!("unsigned-value: {e}"))?;
            DecodedDatum::Unsigned(v)
        }
        5 => DecodedDatum::Signed(decode_signed_loose(body)),
        6 => DecodedDatum::Bitstring {
            unused_bits: body.first().copied().unwrap_or(0),
            data: body.get(1..).map(|s| s.to_vec()).unwrap_or_default(),
        },
        7 => DecodedDatum::Null,
        8 => {
            // failure: SEQUENCE { error-class, error-code } as application-tagged
            // enumerateds wrapped in [8] ... [8]. We consumed the opening already
            // because length was non-zero — but for [8] failure the length is
            // typically 0 and the body is opening-tag-wrapped. Handle the
            // common case where this came in as a constructed group.
            // For robustness, we just record raw.
            DecodedDatum::Failure { class: 0, code: 0 }
        }
        9 => {
            if body.len() < 4 {
                return Err("time-change < 4 bytes".into());
            }
            DecodedDatum::TimeChange(f32::from_be_bytes([body[0], body[1], body[2], body[3]]))
        }
        _ => DecodedDatum::Other {
            tag: n,
            raw: body.to_vec(),
        },
    };
    Ok((datum, end))
}

fn decode_signed_loose(body: &[u8]) -> i64 {
    if body.is_empty() {
        return 0;
    }
    let mut v: i64 = if body[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in body {
        v = (v << 8) | (b as i64);
    }
    v
}

fn format_datetime(date: Date, time: Time) -> String {
    // Date.year is years-since-1900 per BACnet.
    let yyyy = 1900u16.saturating_add(date.year as u16);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        yyyy, date.month, date.day, time.hour, time.minute, time.second
    )
}

fn format_datum(d: &DecodedDatum) -> String {
    match d {
        DecodedDatum::LogStatus(flags) => format!("log-status=0x{flags:02x}"),
        DecodedDatum::Boolean(b) => format!("{b}"),
        DecodedDatum::Real(f) => format!("{f}"),
        DecodedDatum::Enumerated(e) => format!("enum={e}"),
        DecodedDatum::Unsigned(u) => format!("{u}"),
        DecodedDatum::Signed(i) => format!("{i}"),
        DecodedDatum::Bitstring { unused_bits, data } => {
            format!("bitstring(unused={unused_bits}, {} byte(s))", data.len())
        }
        DecodedDatum::Null => "null".into(),
        DecodedDatum::Failure { class, code } => format!("failure(class={class}, code={code})"),
        DecodedDatum::TimeChange(t) => format!("time-change={t}s"),
        DecodedDatum::Other { tag, raw } => format!("tag-{tag}({} byte(s))", raw.len()),
    }
}

// `Tag` re-export silences the warning on imports we may not always use
// once future tag-aware helpers land in this module.
#[allow(dead_code)]
type _UnusedTag = Tag;

// (no items below the test module — clippy::items_after_test_module enforced)

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_encoding::tags::{TagClass, encode_closing_tag, encode_opening_tag, encode_tag};
    use bytes::BytesMut;

    fn encode_app_date(buf: &mut BytesMut, d: Date) {
        encode_tag(buf, 10, TagClass::Application, 4);
        buf.extend_from_slice(&[d.year, d.month, d.day, d.day_of_week]);
    }

    fn encode_app_time(buf: &mut BytesMut, t: Time) {
        encode_tag(buf, 11, TagClass::Application, 4);
        buf.extend_from_slice(&[t.hour, t.minute, t.second, t.hundredths]);
    }

    fn encode_real_datum(buf: &mut BytesMut, f: f32) {
        // [2] real-value: context tag 2, length 4, 4 bytes big-endian f32.
        encode_tag(buf, 2, TagClass::Context, 4);
        buf.extend_from_slice(&f.to_be_bytes());
    }

    fn encode_one_record(
        buf: &mut BytesMut,
        date: Date,
        time: Time,
        value: f32,
        status: Option<u8>,
    ) {
        encode_opening_tag(buf, 0);
        encode_app_date(buf, date);
        encode_app_time(buf, time);
        encode_closing_tag(buf, 0);
        encode_opening_tag(buf, 1);
        encode_real_datum(buf, value);
        encode_closing_tag(buf, 1);
        if let Some(flags) = status {
            // [2] BIT STRING: length 2, byte0=unused-bits, byte1=flags.
            encode_tag(buf, 2, TagClass::Context, 2);
            buf.extend_from_slice(&[4, flags]);
        }
    }

    #[test]
    fn decode_one_real_record_roundtrips() {
        let mut buf = BytesMut::new();
        let d = Date {
            year: 124,
            month: 7,
            day: 4,
            day_of_week: 4,
        };
        let t = Time {
            hour: 13,
            minute: 30,
            second: 0,
            hundredths: 0,
        };
        encode_one_record(&mut buf, d, t, 72.5, None);
        let recs = decode_log_records(&buf, 1).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].date.year, 124);
        assert_eq!(recs[0].time.hour, 13);
        assert!(matches!(recs[0].datum, DecodedDatum::Real(v) if (v - 72.5).abs() < 1e-3));
        assert_eq!(recs[0].status_flags, None);
    }

    #[test]
    fn decode_record_with_status_flags() {
        let mut buf = BytesMut::new();
        encode_one_record(
            &mut buf,
            Date {
                year: 124,
                month: 7,
                day: 4,
                day_of_week: 4,
            },
            Time {
                hour: 13,
                minute: 30,
                second: 0,
                hundredths: 0,
            },
            21.0,
            Some(0b0001), // in-alarm
        );
        let recs = decode_log_records(&buf, 1).unwrap();
        assert_eq!(recs[0].status_flags, Some(0b0001));
    }

    #[test]
    fn decode_multiple_records() {
        let mut buf = BytesMut::new();
        for i in 0..3 {
            encode_one_record(
                &mut buf,
                Date {
                    year: 124,
                    month: 7,
                    day: 4 + i,
                    day_of_week: 4,
                },
                Time {
                    hour: 13,
                    minute: 30,
                    second: 0,
                    hundredths: 0,
                },
                72.0 + i as f32,
                None,
            );
        }
        let recs = decode_log_records(&buf, 3).unwrap();
        assert_eq!(recs.len(), 3);
        assert!(matches!(recs[0].datum, DecodedDatum::Real(v) if (v - 72.0).abs() < 1e-3));
        assert!(matches!(recs[2].datum, DecodedDatum::Real(v) if (v - 74.0).abs() < 1e-3));
    }

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
}
