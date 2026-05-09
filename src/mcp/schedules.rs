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
//!   writes to (the agent's "what does this schedule control?" question).
//!   Decoded into a list of `<device:N>/type:instance/property[idx]` lines.
//! - `status-flags`, `reliability`, `out-of-service` — health
//!
//! **Excluded from this read** (deferred to a follow-up PR): `weekly-schedule`
//! and `exception-schedule`. Codex flagged that bundling them into the metadata
//! RPM was unsafe — large populated arrays can blow Max-APDU on devices without
//! segmentation, failing the whole RPM and surfacing none of the scalar fields.
//!
//! `bacnet-services 0.9` now ships codecs for both arrays
//! (`decode_weekly_schedule`, `decode_exception_schedule`,
//! `encode_weekly_schedule`, `encode_exception_schedule`), so the follow-up
//! work can build dedicated `read_schedule_weekly` / `read_schedule_exceptions`
//! tools — issuing single-property ReadProperty calls (not RPM) so a populated
//! array can't take down the scalar fetch — plus matching write tools.

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_encoding::primitives::decode_unsigned;
use bacnet_encoding::tags::decode_tag;
use bacnet_services::common::PropertyReference;
use bacnet_services::rpm::ReadAccessSpecification;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::ObjectIdentifier;

use crate::parse::{decode_raw_property_to_json_with_context, object_type_name, property_name};
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
