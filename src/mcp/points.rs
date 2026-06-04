//! Compact point-summary MCP tool.
//!
//! `read_point_summary` is a curated RPM wrapper for the common "what are
//! these points doing?" workflow. It trades generic property dumps for one
//! bounded request and one compact line per point.

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_services::common::PropertyReference;
use bacnet_services::rpm::{ReadAccessResult, ReadAccessSpecification, ReadResultElement};
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::primitives::ObjectIdentifier;

use crate::parse::{decode_raw_property_to_json_with_context, object_type_name, parse_object_type};
use crate::state::GatewayState;

const MAX_POINTS: usize = 128;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PointSummaryRequest {
    #[schemars(description = "Object type (e.g., 'analog-input', 'binary-value')")]
    pub object_type: String,
    #[schemars(description = "Object instance number")]
    pub object_instance: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadPointSummaryParams {
    #[schemars(description = "Device instance number (must be in device table)")]
    pub device_instance: u32,
    #[schemars(description = "Points to summarize (1..=128)")]
    pub points: Vec<PointSummaryRequest>,
    #[schemars(description = "Include object-name (default false)")]
    #[serde(default)]
    pub include_names: bool,
    #[schemars(description = "Include units where supported (default false)")]
    #[serde(default)]
    pub include_units: bool,
}

pub async fn read_point_summary_impl(
    state: &GatewayState,
    params: ReadPointSummaryParams,
) -> Result<String, String> {
    let specs = build_point_summary_specs(&params)?;
    let client = state.require_client()?;
    let entry = state.resolve_device(params.device_instance).await?;
    let ack = client
        .read_property_multiple(&entry.mac_address, specs)
        .await
        .map_err(|e| format!("ReadPropertyMultiple(point summary): {e}"))?;

    Ok(format_point_summary_ack(
        params.device_instance,
        &ack,
        params.include_names,
        params.include_units,
    ))
}

fn build_point_summary_specs(
    params: &ReadPointSummaryParams,
) -> Result<Vec<ReadAccessSpecification>, String> {
    if params.points.is_empty() {
        return Err("'points' must contain at least one entry".into());
    }
    if params.points.len() > MAX_POINTS {
        return Err(format!(
            "points length {} exceeds max {MAX_POINTS}",
            params.points.len()
        ));
    }

    let properties = summary_properties(params.include_names, params.include_units);
    let mut specs = Vec::with_capacity(params.points.len());
    for point in &params.points {
        let obj_type = parse_object_type(&point.object_type)?;
        let oid =
            ObjectIdentifier::new(obj_type, point.object_instance).map_err(|e| format!("{e}"))?;
        specs.push(ReadAccessSpecification {
            object_identifier: oid,
            list_of_property_references: properties.clone(),
        });
    }
    Ok(specs)
}

fn summary_properties(include_names: bool, include_units: bool) -> Vec<PropertyReference> {
    let mut props = Vec::with_capacity(6);
    if include_names {
        props.push(prop_ref(PropertyIdentifier::OBJECT_NAME));
    }
    props.push(prop_ref(PropertyIdentifier::PRESENT_VALUE));
    if include_units {
        props.push(prop_ref(PropertyIdentifier::UNITS));
    }
    props.push(prop_ref(PropertyIdentifier::STATUS_FLAGS));
    props.push(prop_ref(PropertyIdentifier::RELIABILITY));
    props.push(prop_ref(PropertyIdentifier::OUT_OF_SERVICE));
    props
}

fn prop_ref(property_identifier: PropertyIdentifier) -> PropertyReference {
    PropertyReference {
        property_identifier,
        property_array_index: None,
    }
}

fn format_point_summary_ack(
    device_instance: u32,
    ack: &bacnet_services::rpm::ReadPropertyMultipleACK,
    include_names: bool,
    include_units: bool,
) -> String {
    if ack.list_of_read_access_results.is_empty() {
        return format!("device:{device_instance} point summary: no results\n");
    }

    let mut out = format!(
        "device:{} point summary ({} point(s)):\n",
        device_instance,
        ack.list_of_read_access_results.len()
    );
    for result in &ack.list_of_read_access_results {
        out.push_str("  ");
        out.push_str(&format_point_line(result, include_names, include_units));
        out.push('\n');
    }
    out
}

fn format_point_line(
    result: &ReadAccessResult,
    include_names: bool,
    include_units: bool,
) -> String {
    let oid = result.object_identifier;
    let mut fields = Vec::with_capacity(6);
    fields.push(format!(
        "{}:{}",
        object_type_name(oid.object_type()),
        oid.instance_number()
    ));
    if include_names {
        fields.push(format!(
            "name={}",
            field_value(result, PropertyIdentifier::OBJECT_NAME).as_name()
        ));
    }
    fields.push(format!(
        "pv={}",
        field_value(result, PropertyIdentifier::PRESENT_VALUE).as_value()
    ));
    if include_units {
        fields.push(format!(
            "units={}",
            field_value(result, PropertyIdentifier::UNITS).as_label()
        ));
    }
    fields.push(format!(
        "status={}",
        format_status_flags(result, PropertyIdentifier::STATUS_FLAGS)
    ));
    fields.push(format!(
        "reliability={}",
        field_value(result, PropertyIdentifier::RELIABILITY).as_label()
    ));
    fields.push(format!(
        "oos={}",
        field_value(result, PropertyIdentifier::OUT_OF_SERVICE).as_value()
    ));
    fields.join(" ")
}

fn field_value(result: &ReadAccessResult, property: PropertyIdentifier) -> SummaryField {
    let Some(elem) = result
        .list_of_results
        .iter()
        .find(|e| e.property_identifier == property)
    else {
        return SummaryField::Missing;
    };
    elem_value(elem)
}

fn elem_value(elem: &ReadResultElement) -> SummaryField {
    if let Some((class, code)) = elem.error {
        return SummaryField::Error(format!("{class:?}/{code:?}"));
    }
    let Some(raw) = &elem.property_value else {
        return SummaryField::Missing;
    };
    let decoded = decode_raw_property_to_json_with_context(raw, elem.property_identifier);
    SummaryField::Value(decoded)
}

fn format_status_flags(result: &ReadAccessResult, property: PropertyIdentifier) -> String {
    match field_value(result, property) {
        SummaryField::Value(decoded) => status_flags_from_json(&decoded)
            .map(format_status_bits)
            .unwrap_or_else(|| compact_json_value(&decoded)),
        other => other.as_value(),
    }
}

fn status_flags_from_json(decoded: &serde_json::Value) -> Option<u8> {
    if decoded.get("type").and_then(|v| v.as_str()) != Some("bit-string") {
        return None;
    }
    let unused = decoded
        .get("unused_bits")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .min(7) as u8;
    let hex = decoded.get("value").and_then(|v| v.as_str())?;
    let first = hex.get(0..2)?;
    let raw = u8::from_str_radix(first, 16).ok()?;
    Some(raw >> unused)
}

fn format_status_bits(bits: u8) -> String {
    let mut parts = Vec::new();
    if bits & 0b1000 != 0 {
        parts.push("in-alarm");
    }
    if bits & 0b0100 != 0 {
        parts.push("fault");
    }
    if bits & 0b0010 != 0 {
        parts.push("overridden");
    }
    if bits & 0b0001 != 0 {
        parts.push("out-of-service");
    }
    if parts.is_empty() {
        "normal".into()
    } else {
        parts.join("|")
    }
}

enum SummaryField {
    Value(serde_json::Value),
    Error(String),
    Missing,
}

impl SummaryField {
    fn as_value(&self) -> String {
        match self {
            SummaryField::Value(v) => compact_json_value(v),
            SummaryField::Error(e) => format!("err({e})"),
            SummaryField::Missing => "missing".into(),
        }
    }

    fn as_label(&self) -> String {
        match self {
            SummaryField::Value(v) => v
                .get("name")
                .and_then(|name| name.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| compact_json_value(v)),
            SummaryField::Error(e) => format!("err({e})"),
            SummaryField::Missing => "missing".into(),
        }
    }

    fn as_name(&self) -> String {
        match self {
            SummaryField::Value(v) => v
                .get("value")
                .and_then(|name| name.as_str())
                .map(quote_json_string)
                .unwrap_or_else(|| compact_json_value(v)),
            SummaryField::Error(e) => format!("err({e})"),
            SummaryField::Missing => "missing".into(),
        }
    }
}

fn compact_json_value(v: &serde_json::Value) -> String {
    if let Some(value) = v.get("value") {
        return json_scalar(value);
    }
    json_scalar(v)
}

fn json_scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => quote_json_string(s),
        _ => value.to_string(),
    }
}

fn quote_json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"<invalid>\"".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_encoding::primitives::encode_property_value;
    use bacnet_types::enums::{EngineeringUnits, ErrorClass, ErrorCode, ObjectType, Reliability};
    use bacnet_types::primitives::PropertyValue;
    use bytes::BytesMut;

    #[test]
    fn params_default_to_compact_metadata() {
        let params: ReadPointSummaryParams = serde_json::from_value(serde_json::json!({
            "device_instance": 1234,
            "points": [{"object_type": "analog-input", "object_instance": 1}]
        }))
        .unwrap();
        assert!(!params.include_names);
        assert!(!params.include_units);
    }

    #[test]
    fn build_specs_validates_and_uses_requested_properties() {
        let params = ReadPointSummaryParams {
            device_instance: 1234,
            points: vec![PointSummaryRequest {
                object_type: "analog-input".into(),
                object_instance: 1,
            }],
            include_names: true,
            include_units: true,
        };
        let specs = build_point_summary_specs(&params).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0].object_identifier.object_type(),
            ObjectType::ANALOG_INPUT
        );
        let props: Vec<_> = specs[0]
            .list_of_property_references
            .iter()
            .map(|p| p.property_identifier)
            .collect();
        assert_eq!(
            props,
            vec![
                PropertyIdentifier::OBJECT_NAME,
                PropertyIdentifier::PRESENT_VALUE,
                PropertyIdentifier::UNITS,
                PropertyIdentifier::STATUS_FLAGS,
                PropertyIdentifier::RELIABILITY,
                PropertyIdentifier::OUT_OF_SERVICE,
            ]
        );
    }

    #[test]
    fn format_point_summary_is_one_compact_line_per_point() {
        let ack = bacnet_services::rpm::ReadPropertyMultipleACK {
            list_of_read_access_results: vec![ReadAccessResult {
                object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap(),
                list_of_results: vec![
                    value_elem(
                        PropertyIdentifier::OBJECT_NAME,
                        PropertyValue::CharacterString("Zone Temp".into()),
                    ),
                    value_elem(PropertyIdentifier::PRESENT_VALUE, PropertyValue::Real(72.5)),
                    value_elem(
                        PropertyIdentifier::UNITS,
                        PropertyValue::Enumerated(EngineeringUnits::DEGREES_FAHRENHEIT.to_raw()),
                    ),
                    value_elem(
                        PropertyIdentifier::STATUS_FLAGS,
                        PropertyValue::BitString {
                            unused_bits: 4,
                            data: vec![0b0101_0000],
                        },
                    ),
                    value_elem(
                        PropertyIdentifier::RELIABILITY,
                        PropertyValue::Enumerated(Reliability::NO_FAULT_DETECTED.to_raw()),
                    ),
                    value_elem(
                        PropertyIdentifier::OUT_OF_SERVICE,
                        PropertyValue::Boolean(true),
                    ),
                ],
            }],
        };
        let out = format_point_summary_ack(1234, &ack, true, true);
        assert!(out.contains("device:1234 point summary (1 point(s))"));
        assert!(out.contains(
            "analog-input:1 name=\"Zone Temp\" pv=72.5 units=degrees-fahrenheit status=fault|out-of-service reliability=no-fault-detected oos=true"
        ));
    }

    #[test]
    fn format_point_summary_surfaces_property_errors_and_missing_values() {
        let ack = bacnet_services::rpm::ReadPropertyMultipleACK {
            list_of_read_access_results: vec![ReadAccessResult {
                object_identifier: ObjectIdentifier::new(ObjectType::BINARY_VALUE, 2).unwrap(),
                list_of_results: vec![
                    ReadResultElement {
                        property_identifier: PropertyIdentifier::PRESENT_VALUE,
                        property_array_index: None,
                        property_value: None,
                        error: Some((ErrorClass::PROPERTY, ErrorCode::UNKNOWN_PROPERTY)),
                    },
                    value_elem(
                        PropertyIdentifier::STATUS_FLAGS,
                        PropertyValue::BitString {
                            unused_bits: 4,
                            data: vec![0],
                        },
                    ),
                    value_elem(
                        PropertyIdentifier::RELIABILITY,
                        PropertyValue::Enumerated(Reliability::COMMUNICATION_FAILURE.to_raw()),
                    ),
                ],
            }],
        };
        let out = format_point_summary_ack(1234, &ack, false, false);
        assert!(out.contains("binary-value:2"));
        assert!(out.contains("pv=err("));
        assert!(out.contains("status=normal"));
        assert!(out.contains("reliability=communication-failure"));
        assert!(out.contains("oos=missing"));
    }

    #[test]
    fn status_flags_support_normalized_low_nibble_shape() {
        let decoded = serde_json::json!({
            "type": "bit-string",
            "unused_bits": 0,
            "value": "0a"
        });
        assert_eq!(
            format_status_bits(status_flags_from_json(&decoded).unwrap()),
            "in-alarm|overridden"
        );
    }

    fn value_elem(
        property_identifier: PropertyIdentifier,
        value: PropertyValue,
    ) -> ReadResultElement {
        let mut buf = BytesMut::new();
        encode_property_value(&mut buf, &value).unwrap();
        ReadResultElement {
            property_identifier,
            property_array_index: None,
            property_value: Some(buf.to_vec()),
            error: None,
        }
    }
}
