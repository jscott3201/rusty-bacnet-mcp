//! BACnetLogRecord stream decoder.
//!
//! Split out of `trend/mod.rs` to keep both files under the 700 LOC cap.
//! The decoder is the heaviest piece of the trend tools — every path that
//! calls `read_trend_log` flows through `decode_log_records` to turn raw
//! `ReadRangeAck.item_data` bytes into a structured record list.
//!
//! Visibility: types and functions are `pub(super)` so `trend/mod.rs` can
//! call them directly. Nothing here is part of the public crate API — the
//! exported MCP tool surface lives in `mod.rs`.

use bacnet_encoding::primitives::decode_unsigned;
use bacnet_encoding::tags::decode_tag;
use bacnet_types::primitives::{Date, Time};

#[derive(Debug, Clone, PartialEq)]
pub(super) struct DecodedLogRecord {
    pub date: Date,
    pub time: Time,
    pub datum: DecodedDatum,
    pub status_flags: Option<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum DecodedDatum {
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

pub(super) fn decode_log_records(
    data: &[u8],
    item_count: u32,
) -> Result<Vec<DecodedLogRecord>, String> {
    // Codex flagged the previous `Vec::with_capacity(item_count as usize)`
    // as an OOM vector — a malicious or malformed ReadRangeAck could
    // advertise an enormous count and trigger a multi-GB allocation
    // before any payload validation. Cap pre-allocation at a sane bound
    // (real BACnet TrendLog buffers max out in the low thousands; the
    // ReadRange APDU itself caps records-per-response well below this).
    // The decode loop still walks `item_count` records, but `Vec::push`
    // grows incrementally, so a bogus count just fails at the first
    // truncated record instead of OOM-ing on the allocator.
    const MAX_PREALLOC: usize = 4_096;
    let prealloc = (item_count as usize).min(MAX_PREALLOC);
    let mut records = Vec::with_capacity(prealloc);
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
    if len < 1 {
        return Err("status_flags zero length".into());
    }
    // BIT STRING: first byte = unused-bits, then data bytes. BACnet
    // StatusFlags has 4 defined bits packed into the low nibble.
    let flags = if len >= 2 { data[pos + 1] } else { 0 };
    Ok((flags, end))
}

fn decode_datum(data: &[u8], offset: usize) -> Result<(DecodedDatum, usize), String> {
    let (tag, pos) = decode_tag(data, offset).map_err(|e| format!("datum tag: {e}"))?;
    let n = tag.number;

    // [8] failure and [10] any-value are CONSTRUCTED wrappers (opening +
    // payload + closing). Everything else (0–7, 9) is a primitive context
    // tag carrying the value bytes directly. Codex flagged the previous
    // implementation as broken on failure records: it treated [8] as a
    // primitive with length 0, returned a placeholder, and left the inner
    // BACnetError + closing tag unread — which then caused the outer [1]
    // closing-tag check to fail and tank the whole record stream.
    if tag.is_opening_tag(n) {
        return decode_constructed_datum(data, pos, n);
    }

    let len = tag.length as usize;
    let end = pos + len;
    if end > data.len() {
        return Err(format!("truncated datum tag {n}"));
    }
    let body = &data[pos..end];
    let datum = match n {
        0 => {
            let flags = if body.len() >= 2 { body[1] } else { 0 };
            DecodedDatum::LogStatus(flags)
        }
        1 => DecodedDatum::Boolean(!body.is_empty() && body[0] != 0),
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

fn decode_constructed_datum(
    data: &[u8],
    pos: usize,
    n: u8,
) -> Result<(DecodedDatum, usize), String> {
    match n {
        8 => {
            // BACnetError = SEQUENCE { error-class [9 ENUMERATED], error-code [9 ENUMERATED] }
            // — both are application-tagged enumerateds. Read them, then the
            // closing [8].
            let (cls_tag, cls_pos) =
                decode_tag(data, pos).map_err(|e| format!("error-class tag: {e}"))?;
            let cls_end = cls_pos + cls_tag.length as usize;
            if cls_end > data.len() {
                return Err("truncated error-class".into());
            }
            let class = decode_unsigned(&data[cls_pos..cls_end])
                .map_err(|e| format!("error-class: {e}"))? as u32;

            let (code_tag, code_pos) =
                decode_tag(data, cls_end).map_err(|e| format!("error-code tag: {e}"))?;
            let code_end = code_pos + code_tag.length as usize;
            if code_end > data.len() {
                return Err("truncated error-code".into());
            }
            let code = decode_unsigned(&data[code_pos..code_end])
                .map_err(|e| format!("error-code: {e}"))? as u32;

            let (close_tag, after) =
                decode_tag(data, code_end).map_err(|e| format!("failure close tag: {e}"))?;
            if !close_tag.is_closing_tag(8) {
                return Err("expected closing [8] for failure datum".into());
            }
            Ok((DecodedDatum::Failure { class, code }, after))
        }
        10 => {
            // any-value: arbitrary application-tagged primitive(s) wrapped in
            // [10] ... [10]. We accumulate raw bytes between the opening and
            // closing so the agent at least sees a payload size; full decode
            // would require knowing the trended source's type.
            let mut cursor = pos;
            let mut raw = Vec::new();
            loop {
                let (peek, _) =
                    decode_tag(data, cursor).map_err(|e| format!("any-value scan: {e}"))?;
                if peek.is_closing_tag(10) {
                    break;
                }
                let (next_tag, body_pos) =
                    decode_tag(data, cursor).map_err(|e| format!("any-value tag: {e}"))?;
                let body_end = body_pos + next_tag.length as usize;
                if body_end > data.len() {
                    return Err("truncated any-value payload".into());
                }
                raw.extend_from_slice(&data[cursor..body_end]);
                cursor = body_end;
            }
            let (_, after) =
                decode_tag(data, cursor).map_err(|e| format!("any-value close: {e}"))?;
            Ok((DecodedDatum::Other { tag: 10, raw }, after))
        }
        other => Err(format!(
            "unexpected constructed datum tag {other} (only [8] and [10] are constructed)"
        )),
    }
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

pub(super) fn format_datum(d: &DecodedDatum) -> String {
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
            encode_tag(buf, 2, TagClass::Context, 2);
            buf.extend_from_slice(&[4, flags]);
        }
    }

    fn date_124_7_4() -> Date {
        Date {
            year: 124,
            month: 7,
            day: 4,
            day_of_week: 4,
        }
    }

    fn time_13_30() -> Time {
        Time {
            hour: 13,
            minute: 30,
            second: 0,
            hundredths: 0,
        }
    }

    #[test]
    fn decode_one_real_record_roundtrips() {
        let mut buf = BytesMut::new();
        encode_one_record(&mut buf, date_124_7_4(), time_13_30(), 72.5, None);
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
        encode_one_record(&mut buf, date_124_7_4(), time_13_30(), 21.0, Some(0b0001));
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
                time_13_30(),
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
    fn decode_failure_record_consumes_payload() {
        // Pin Codex P1: failure datum [8] is a CONSTRUCTED wrapper. The
        // previous decode left bytes unread, breaking the outer [1]
        // closing-tag check on subsequent records. This test encodes one
        // failure record and one real record back-to-back; before the fix,
        // the decoder failed on record 1 ("expected closing tag 1").
        let mut buf = BytesMut::new();
        let date = date_124_7_4();
        let time = time_13_30();

        // Record 0: failure datum.
        encode_opening_tag(&mut buf, 0);
        encode_app_date(&mut buf, date);
        encode_app_time(&mut buf, time);
        encode_closing_tag(&mut buf, 0);
        encode_opening_tag(&mut buf, 1);
        encode_opening_tag(&mut buf, 8);
        encode_tag(&mut buf, 9, TagClass::Application, 1);
        buf.extend_from_slice(&[2]); // class = 2 (PROPERTY)
        encode_tag(&mut buf, 9, TagClass::Application, 1);
        buf.extend_from_slice(&[32]); // code = 32 (UNKNOWN_PROPERTY)
        encode_closing_tag(&mut buf, 8);
        encode_closing_tag(&mut buf, 1);

        // Record 1: a normal real record.
        encode_one_record(&mut buf, date, time, 99.0, None);

        let recs = decode_log_records(&buf, 2).unwrap();
        assert_eq!(recs.len(), 2);
        assert!(matches!(
            recs[0].datum,
            DecodedDatum::Failure { class: 2, code: 32 }
        ));
        assert!(matches!(recs[1].datum, DecodedDatum::Real(v) if (v - 99.0).abs() < 1e-3));
    }
}
