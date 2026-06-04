//! MCP file-object tools backed by AtomicReadFile.
//!
//! File objects can hold logs, controller config blobs, or backup data. The
//! MCP surface intentionally exposes bounded chunk reads only: callers get
//! enough bytes and continuation hints to page through a file without dumping
//! an unbounded BACnet payload into model context.

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_services::file::{AtomicReadFileAck, FileAccessMethod, FileReadAckMethod};
use bacnet_types::enums::ObjectType;
use bacnet_types::primitives::ObjectIdentifier;

use crate::state::GatewayState;

const DEFAULT_STREAM_OCTETS: u32 = 512;
const MAX_STREAM_OCTETS: u32 = 2_048;
const DEFAULT_RECORD_COUNT: u32 = 1;
const MAX_RECORD_COUNT: u32 = 16;
const MAX_DISPLAY_BYTES: usize = 2_048;
const MAX_RECORD_DISPLAY_BYTES_TOTAL: usize = 2_048;

#[derive(Debug, Default, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileAccessMode {
    #[default]
    Stream,
    Record,
}

#[derive(Debug, Default, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilePayloadFormat {
    #[default]
    Auto,
    Text,
    Hex,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadFileChunkParams {
    #[schemars(description = "Device instance number hosting the File object")]
    pub device_instance: u32,
    #[schemars(description = "File object instance number")]
    pub file_instance: u32,
    #[schemars(description = "Access mode: 'stream' for bytes or 'record' for records")]
    #[serde(default)]
    pub mode: FileAccessMode,
    #[schemars(description = "Zero-based file position or record number (default 0)")]
    #[serde(default)]
    pub start: i32,
    #[schemars(description = "Octets for stream, records for record; mode-specific default")]
    #[serde(default)]
    pub count: Option<u32>,
    #[schemars(description = "Payload format: 'auto', 'text', or 'hex'")]
    #[serde(default)]
    pub format: FilePayloadFormat,
}

pub async fn read_file_chunk_impl(
    state: &GatewayState,
    params: ReadFileChunkParams,
) -> Result<String, String> {
    let (file_identifier, access) = build_file_read_request(&params)?;
    let client = state.require_client()?;
    let entry = state.resolve_device(params.device_instance).await?;

    let response = client
        .atomic_read_file(&entry.mac_address, file_identifier, access)
        .await
        .map_err(|e| format!("AtomicReadFile failed: {e}"))?;
    let ack = AtomicReadFileAck::decode(&response)
        .map_err(|e| format!("decode AtomicReadFileAck: {e}"))?;

    Ok(format_file_read_ack(
        params.device_instance,
        params.file_instance,
        params.format,
        &ack,
    ))
}

fn build_file_read_request(
    params: &ReadFileChunkParams,
) -> Result<(ObjectIdentifier, FileAccessMethod), String> {
    if params.start < 0 {
        return Err(format!(
            "start {} is invalid; file chunk reads require a non-negative start",
            params.start
        ));
    }

    let file_identifier = ObjectIdentifier::new(ObjectType::FILE, params.file_instance)
        .map_err(|e| format!("{e}"))?;

    let access = match params.mode {
        FileAccessMode::Stream => {
            let count = validate_count(
                params.count.unwrap_or(DEFAULT_STREAM_OCTETS),
                MAX_STREAM_OCTETS,
                "stream octet count",
            )?;
            FileAccessMethod::Stream {
                file_start_position: params.start,
                requested_octet_count: count,
            }
        }
        FileAccessMode::Record => {
            let count = validate_count(
                params.count.unwrap_or(DEFAULT_RECORD_COUNT),
                MAX_RECORD_COUNT,
                "record count",
            )?;
            FileAccessMethod::Record {
                file_start_record: params.start,
                requested_record_count: count,
            }
        }
    };

    Ok((file_identifier, access))
}

fn validate_count(count: u32, max: u32, label: &str) -> Result<u32, String> {
    if count == 0 {
        return Err(format!("{label} must be between 1 and {max}"));
    }
    if count > max {
        return Err(format!("{label} {count} exceeds max {max}"));
    }
    Ok(count)
}

fn format_file_read_ack(
    device_instance: u32,
    file_instance: u32,
    format: FilePayloadFormat,
    ack: &AtomicReadFileAck,
) -> String {
    match &ack.access {
        FileReadAckMethod::Stream {
            file_start_position,
            file_data,
        } => {
            let next_start = file_start_position.saturating_add(file_data.len() as i32);
            format!(
                "file:{} on device:{} stream start={} bytes={} eof={} next_start={} {}\n",
                file_instance,
                device_instance,
                file_start_position,
                file_data.len(),
                ack.end_of_file,
                next_start,
                format_payload(file_data, format)
            )
        }
        FileReadAckMethod::Record {
            file_start_record,
            returned_record_count,
            file_record_data,
        } => {
            let next_record = file_start_record.saturating_add(*returned_record_count as i32);
            let total_bytes = file_record_data
                .iter()
                .fold(0usize, |acc, record| acc.saturating_add(record.len()));
            let mut out = format!(
                "file:{} on device:{} record start={} returned={} records={} total_bytes={} eof={} next_record={}",
                file_instance,
                device_instance,
                file_start_record,
                returned_record_count,
                file_record_data.len(),
                total_bytes,
                ack.end_of_file,
                next_record
            );
            if total_bytes > MAX_RECORD_DISPLAY_BYTES_TOTAL {
                out.push_str(&format!(
                    " display_cap_bytes={MAX_RECORD_DISPLAY_BYTES_TOTAL}"
                ));
            }
            out.push('\n');

            let mut remaining_display_bytes = MAX_RECORD_DISPLAY_BYTES_TOTAL;
            for (i, record) in file_record_data.iter().enumerate() {
                let display_limit = remaining_display_bytes.min(MAX_DISPLAY_BYTES);
                let displayed = record.len().min(display_limit);
                remaining_display_bytes = remaining_display_bytes.saturating_sub(displayed);
                out.push_str(&format!(
                    "  [{}] bytes={} {}\n",
                    i,
                    record.len(),
                    format_payload_limited(record, format, display_limit)
                ));
            }
            out
        }
    }
}

fn format_payload(bytes: &[u8], format: FilePayloadFormat) -> String {
    format_payload_limited(bytes, format, MAX_DISPLAY_BYTES)
}

fn format_payload_limited(
    bytes: &[u8],
    format: FilePayloadFormat,
    max_visible_bytes: usize,
) -> String {
    let visible_len = bytes.len().min(max_visible_bytes);
    let visible = &bytes[..visible_len];
    let omitted = bytes.len().saturating_sub(visible_len);

    if visible.is_empty() && !bytes.is_empty() {
        return format!("payload=<omitted> truncated_bytes={omitted}");
    }

    let mut rendered = match format {
        FilePayloadFormat::Auto => match printable_text(visible) {
            Some(text) => format!("text={}", quote_json_string(text)),
            None => format!("hex={}", hex_encode(visible)),
        },
        FilePayloadFormat::Text => match printable_text(visible) {
            Some(text) => format!("text={}", quote_json_string(text)),
            None => format!(
                "text=<invalid-or-control-bytes> hex={}",
                hex_encode(visible)
            ),
        },
        FilePayloadFormat::Hex => format!("hex={}", hex_encode(visible)),
    };

    if omitted > 0 {
        rendered.push_str(&format!(" truncated_bytes={omitted}"));
    }
    rendered
}

fn printable_text(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    if text.chars().all(is_printable_text_char) {
        Some(text)
    } else {
        None
    }
}

fn is_printable_text_char(ch: char) -> bool {
    matches!(ch, '\n' | '\r' | '\t') || !ch.is_control()
}

fn quote_json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"<invalid>\"".into())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_default_to_stream_auto_format() {
        let params: ReadFileChunkParams = serde_json::from_value(serde_json::json!({
            "device_instance": 1234,
            "file_instance": 7
        }))
        .unwrap();
        assert_eq!(params.mode, FileAccessMode::Stream);
        assert_eq!(params.start, 0);
        assert_eq!(params.count, None);
        assert_eq!(params.format, FilePayloadFormat::Auto);
    }

    #[test]
    fn build_stream_request_uses_file_oid_and_default_count() {
        let params = ReadFileChunkParams {
            device_instance: 1234,
            file_instance: 7,
            mode: FileAccessMode::Stream,
            start: 10,
            count: None,
            format: FilePayloadFormat::Auto,
        };
        let (oid, access) = build_file_read_request(&params).unwrap();
        assert_eq!(oid.object_type(), ObjectType::FILE);
        assert_eq!(oid.instance_number(), 7);
        assert_eq!(
            access,
            FileAccessMethod::Stream {
                file_start_position: 10,
                requested_octet_count: DEFAULT_STREAM_OCTETS,
            }
        );
    }

    #[test]
    fn build_record_request_uses_requested_record_count() {
        let params = ReadFileChunkParams {
            device_instance: 1234,
            file_instance: 8,
            mode: FileAccessMode::Record,
            start: 2,
            count: Some(3),
            format: FilePayloadFormat::Auto,
        };
        let (_, access) = build_file_read_request(&params).unwrap();
        assert_eq!(
            access,
            FileAccessMethod::Record {
                file_start_record: 2,
                requested_record_count: 3,
            }
        );
    }

    #[test]
    fn build_request_rejects_negative_start_and_bad_counts() {
        let mut params = ReadFileChunkParams {
            device_instance: 1234,
            file_instance: 1,
            mode: FileAccessMode::Stream,
            start: -1,
            count: None,
            format: FilePayloadFormat::Auto,
        };
        assert!(
            build_file_read_request(&params)
                .unwrap_err()
                .contains("non-negative")
        );

        params.start = 0;
        params.count = Some(0);
        assert!(
            build_file_read_request(&params)
                .unwrap_err()
                .contains("between 1")
        );

        params.count = Some(MAX_STREAM_OCTETS + 1);
        assert!(
            build_file_read_request(&params)
                .unwrap_err()
                .contains("exceeds max")
        );

        params.mode = FileAccessMode::Record;
        params.count = Some(MAX_RECORD_COUNT + 1);
        assert!(
            build_file_read_request(&params)
                .unwrap_err()
                .contains("exceeds max")
        );
    }

    #[test]
    fn format_stream_ack_includes_text_and_continuation_hint() {
        let ack = AtomicReadFileAck {
            end_of_file: false,
            access: FileReadAckMethod::Stream {
                file_start_position: 5,
                file_data: b"line 1\nline 2".to_vec(),
            },
        };
        let out = format_file_read_ack(1234, 7, FilePayloadFormat::Auto, &ack);
        assert!(out.contains("file:7 on device:1234 stream start=5 bytes=13"));
        assert!(out.contains("eof=false next_start=18"));
        assert!(out.contains(r#"text="line 1\nline 2""#));
    }

    #[test]
    fn format_stream_ack_uses_hex_for_binary() {
        let ack = AtomicReadFileAck {
            end_of_file: true,
            access: FileReadAckMethod::Stream {
                file_start_position: 0,
                file_data: vec![0, 1, 0xfe, 0xff],
            },
        };
        let out = format_file_read_ack(1234, 7, FilePayloadFormat::Auto, &ack);
        assert!(out.contains("hex=0001feff"));
        assert!(out.contains("eof=true"));
    }

    #[test]
    fn format_record_ack_lists_records_and_next_record() {
        let ack = AtomicReadFileAck {
            end_of_file: false,
            access: FileReadAckMethod::Record {
                file_start_record: 4,
                returned_record_count: 2,
                file_record_data: vec![b"first".to_vec(), vec![0xaa, 0xbb]],
            },
        };
        let out = format_file_read_ack(1234, 9, FilePayloadFormat::Auto, &ack);
        assert!(
            out.contains(
                "record start=4 returned=2 records=2 total_bytes=7 eof=false next_record=6"
            )
        );
        assert!(out.contains(r#"[0] bytes=5 text="first""#));
        assert!(out.contains("[1] bytes=2 hex=aabb"));
    }

    #[test]
    fn format_record_ack_caps_aggregate_display_bytes() {
        let ack = AtomicReadFileAck {
            end_of_file: false,
            access: FileReadAckMethod::Record {
                file_start_record: 0,
                returned_record_count: 2,
                file_record_data: vec![
                    vec![b'a'; MAX_RECORD_DISPLAY_BYTES_TOTAL + 3],
                    b"later".to_vec(),
                ],
            },
        };
        let out = format_file_read_ack(1234, 9, FilePayloadFormat::Text, &ack);
        assert!(out.contains("total_bytes=2056"));
        assert!(out.contains("display_cap_bytes=2048"));
        assert!(out.contains("truncated_bytes=3"));
        assert!(out.contains("[1] bytes=5 payload=<omitted> truncated_bytes=5"));
    }

    #[test]
    fn forced_text_invalid_utf8_falls_back_to_hex() {
        let rendered = format_payload(&[0xff, 0x00, b'a'], FilePayloadFormat::Text);
        assert_eq!(rendered, "text=<invalid-or-control-bytes> hex=ff0061");
    }

    #[test]
    fn payload_display_is_capped() {
        let bytes = vec![b'a'; MAX_DISPLAY_BYTES + 3];
        let rendered = format_payload(&bytes, FilePayloadFormat::Text);
        assert!(rendered.contains("truncated_bytes=3"));
        assert!(rendered.len() < MAX_DISPLAY_BYTES + 80);
    }
}
