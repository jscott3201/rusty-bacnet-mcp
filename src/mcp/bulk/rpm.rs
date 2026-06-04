use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_services::common::PropertyReference;
use bacnet_services::rpm::{ReadAccessSpecification, ReadPropertyMultipleACK};
use bacnet_types::primitives::ObjectIdentifier;

use crate::parse::{object_type_name, parse_object_type, parse_property_name};
use crate::state::GatewayState;

use super::compact::format_compact_rpm_ack;
use super::format_result_element;

const MAX_RPM_OBJECTS: usize = 128;
const MAX_RPM_PROPERTIES_PER_OBJECT: usize = 32;
const MAX_RPM_TOTAL_PROPERTIES: usize = 512;

/// Property identifier as the schema documents it: either a string name
/// (`"present-value"`) or a numeric raw id (`87`). The `#[serde(untagged)]`
/// enum lets MCP clients send either JSON shape; both round-trip through
/// `parse_property_name`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum PropertyId {
    Name(String),
    Number(u32),
}

impl PropertyId {
    fn resolve(&self) -> Result<bacnet_types::enums::PropertyIdentifier, String> {
        match self {
            PropertyId::Name(s) => parse_property_name(s),
            PropertyId::Number(n) => Ok(bacnet_types::enums::PropertyIdentifier::from_raw(*n)),
        }
    }
}

/// One property to read on an object.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PropertyRequest {
    /// Property name (e.g. "present-value") or numeric raw id (e.g. 87).
    /// Both JSON shapes are accepted.
    #[schemars(description = "Property name (string) or numeric raw id (integer)")]
    pub property: PropertyId,
    /// Optional array index for array properties (e.g. priority-array slot).
    #[schemars(description = "Optional array index (1-based)")]
    pub array_index: Option<u32>,
}

/// One object plus the list of properties to read on it.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ObjectRequest {
    #[schemars(description = "Object type (e.g. 'analog-output', 'device')")]
    pub object_type: String,
    #[schemars(description = "Object instance number")]
    pub object_instance: u32,
    /// At least one property must be specified per object. Use the special
    /// names `all`, `required`, or `optional` (BACnet abstract aggregate
    /// property identifiers) to read every property the device exposes.
    #[schemars(
        description = "Properties to read on this object (must be non-empty; use 'all' / 'required' / 'optional' to fetch every property)"
    )]
    pub properties: Vec<PropertyRequest>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadPropertyMultipleParams {
    #[schemars(description = "Device instance number (must be in device table)")]
    pub device_instance: u32,
    #[schemars(description = "List of objects + properties to read (cannot be empty)")]
    pub objects: Vec<ObjectRequest>,
    /// Compact is the default because RPM responses can otherwise dominate the
    /// LLM context window. Detailed keeps the older one-property-per-line shape
    /// with full decoded JSON-ish values for explicit troubleshooting.
    #[schemars(description = "Response shape: compact (default) or detailed")]
    #[serde(default)]
    pub response_mode: RpmResponseMode,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RpmResponseMode {
    #[default]
    Compact,
    Detailed,
}

/// `read_property_multiple` impl wired through `GatewayState`.
pub async fn read_property_multiple_impl(
    state: &GatewayState,
    params: ReadPropertyMultipleParams,
) -> Result<String, String> {
    let specs = build_rpm_specs(&params.objects)?;
    let client = state.require_client()?;
    let entry = state.resolve_device(params.device_instance).await?;

    let ack = client
        .read_property_multiple(&entry.mac_address, specs)
        .await
        .map_err(|e| format!("ReadPropertyMultiple: {e}"))?;

    Ok(format_rpm_ack(&ack, params.response_mode))
}

fn build_rpm_specs(objects: &[ObjectRequest]) -> Result<Vec<ReadAccessSpecification>, String> {
    validate_rpm_request(objects)?;
    let mut specs = Vec::with_capacity(objects.len());
    for obj in objects {
        let obj_type = parse_object_type(&obj.object_type)?;
        let oid =
            ObjectIdentifier::new(obj_type, obj.object_instance).map_err(|e| format!("{e}"))?;
        let mut prop_refs = Vec::with_capacity(obj.properties.len());
        for p in &obj.properties {
            let prop_id = p.property.resolve()?;
            prop_refs.push(PropertyReference {
                property_identifier: prop_id,
                property_array_index: p.array_index,
            });
        }
        specs.push(ReadAccessSpecification {
            object_identifier: oid,
            list_of_property_references: prop_refs,
        });
    }
    Ok(specs)
}

fn validate_rpm_request(objects: &[ObjectRequest]) -> Result<(), String> {
    if objects.is_empty() {
        return Err("'objects' must contain at least one entry".into());
    }
    if objects.len() > MAX_RPM_OBJECTS {
        return Err(format!(
            "objects length {} exceeds max {MAX_RPM_OBJECTS}",
            objects.len()
        ));
    }

    let mut total_properties = 0usize;
    for obj in objects {
        if obj.properties.is_empty() {
            return Err(format!(
                "object {}:{} has no properties listed",
                obj.object_type, obj.object_instance
            ));
        }
        if obj.properties.len() > MAX_RPM_PROPERTIES_PER_OBJECT {
            return Err(format!(
                "object {}:{} requests {} properties; max is {MAX_RPM_PROPERTIES_PER_OBJECT}",
                obj.object_type,
                obj.object_instance,
                obj.properties.len()
            ));
        }
        total_properties = total_properties.saturating_add(obj.properties.len());
        if total_properties > MAX_RPM_TOTAL_PROPERTIES {
            return Err(format!(
                "request has {total_properties} property references; max is {MAX_RPM_TOTAL_PROPERTIES}"
            ));
        }
    }
    Ok(())
}

fn format_rpm_ack(ack: &ReadPropertyMultipleACK, mode: RpmResponseMode) -> String {
    match mode {
        RpmResponseMode::Compact => format_compact_rpm_ack(ack),
        RpmResponseMode::Detailed => format_detailed_rpm_ack(ack),
    }
}

fn format_detailed_rpm_ack(ack: &ReadPropertyMultipleACK) -> String {
    let mut out = String::new();
    for result in &ack.list_of_read_access_results {
        let oid = result.object_identifier;
        out.push_str(&format!(
            "{}:{}\n",
            object_type_name(oid.object_type()),
            oid.instance_number(),
        ));
        for elem in &result.list_of_results {
            out.push_str(&format!("  {}", format_result_element(elem)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_encoding::primitives::encode_property_value;
    use bacnet_services::rpm::{ReadAccessResult, ReadResultElement};
    use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType, PropertyIdentifier, Reliability};
    use bacnet_types::primitives::PropertyValue;
    use bytes::BytesMut;

    #[test]
    fn build_specs_rejects_empty_properties() {
        let req = vec![rpm_object(1, 0)];
        let err = build_rpm_specs(&req).unwrap_err();
        assert!(err.contains("no properties"));
    }

    #[test]
    fn build_specs_handles_array_index() {
        let req = vec![ObjectRequest {
            object_type: "analog-output".into(),
            object_instance: 1,
            properties: vec![PropertyRequest {
                property: PropertyId::Name("priority-array".into()),
                array_index: Some(8),
            }],
        }];
        let specs = build_rpm_specs(&req).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].list_of_property_references.len(), 1);
        assert_eq!(
            specs[0].list_of_property_references[0].property_array_index,
            Some(8)
        );
    }

    #[test]
    fn build_specs_unknown_object_type_errors() {
        let req = vec![ObjectRequest {
            object_type: "nonexistent-type".into(),
            object_instance: 1,
            properties: vec![PropertyRequest {
                property: PropertyId::Name("present-value".into()),
                array_index: None,
            }],
        }];
        let err = build_rpm_specs(&req).unwrap_err();
        assert!(err.contains("nonexistent-type"));
    }

    #[test]
    fn build_specs_rejects_rpm_budget_overages() {
        let too_many_objects: Vec<_> = (0..=MAX_RPM_OBJECTS)
            .map(|i| rpm_object(i as u32, 1))
            .collect();
        let err = build_rpm_specs(&too_many_objects).unwrap_err();
        assert!(err.contains("objects length"), "got: {err}");

        let too_many_props = vec![rpm_object(1, MAX_RPM_PROPERTIES_PER_OBJECT + 1)];
        let err = build_rpm_specs(&too_many_props).unwrap_err();
        assert!(err.contains("properties"), "got: {err}");

        let too_many_total: Vec<_> = (0..17)
            .map(|i| rpm_object(i, MAX_RPM_PROPERTIES_PER_OBJECT))
            .collect();
        let err = build_rpm_specs(&too_many_total).unwrap_err();
        assert!(err.contains("property references"), "got: {err}");
    }

    #[test]
    fn property_id_resolves_string_or_number() {
        assert_eq!(
            PropertyId::Name("present-value".into()).resolve().unwrap(),
            PropertyIdentifier::PRESENT_VALUE,
        );
        assert_eq!(
            PropertyId::Number(87).resolve().unwrap(),
            PropertyIdentifier::PRIORITY_ARRAY,
        );
    }

    #[test]
    fn property_id_deserializes_from_string_and_number_json() {
        let from_string: PropertyId =
            serde_json::from_str("\"present-value\"").expect("string form");
        assert!(matches!(from_string, PropertyId::Name(ref s) if s == "present-value"));

        let from_number: PropertyId = serde_json::from_str("87").expect("number form");
        assert!(matches!(from_number, PropertyId::Number(87)));
    }

    #[test]
    fn rpm_params_default_to_compact_response() {
        let params: ReadPropertyMultipleParams = serde_json::from_value(serde_json::json!({
            "device_instance": 1234,
            "objects": [{
                "object_type": "analog-input",
                "object_instance": 1,
                "properties": [{"property": "present-value"}]
            }]
        }))
        .unwrap();
        assert_eq!(params.response_mode, RpmResponseMode::Compact);
    }

    #[test]
    fn rpm_params_accept_detailed_response() {
        let params: ReadPropertyMultipleParams = serde_json::from_value(serde_json::json!({
            "device_instance": 1234,
            "response_mode": "detailed",
            "objects": [{
                "object_type": "analog-input",
                "object_instance": 1,
                "properties": [{"property": "present-value"}]
            }]
        }))
        .unwrap();
        assert_eq!(params.response_mode, RpmResponseMode::Detailed);
    }

    #[test]
    fn format_rpm_ack_compact_summarizes_values_and_preserves_failures() {
        let ack = sample_rpm_ack();
        let out = format_rpm_ack(&ack, RpmResponseMode::Compact);

        assert!(out.contains("RPM compact: 2 object(s), 3 value(s), 1 error(s), 1 missing"));
        assert!(out.contains(
            "analog-input:1 object-name=\"Zone Temp\" present-value=72.5 reliability=no-fault-detected"
        ));
        assert!(out.contains("binary-value:2"));
        assert!(out.contains("present-value=err("));
        assert!(out.contains("out-of-service=missing"));
        assert!(
            !out.contains("{\"type\""),
            "compact mode should not emit full decoded JSON: {out}"
        );
    }

    #[test]
    fn format_rpm_ack_detailed_retains_full_property_lines() {
        let ack = sample_rpm_ack();
        let out = format_rpm_ack(&ack, RpmResponseMode::Detailed);

        assert!(out.contains("analog-input:1\n"));
        assert!(out.contains("  object-name = \"Zone Temp\"\n"));
        assert!(out.contains("  present-value = 72.5\n"));
        assert!(out.contains("  reliability = 0\n"));
        assert!(out.contains("present-value → ERROR"));
    }

    fn rpm_object(object_instance: u32, property_count: usize) -> ObjectRequest {
        ObjectRequest {
            object_type: "analog-input".into(),
            object_instance,
            properties: (0..property_count)
                .map(|_| PropertyRequest {
                    property: PropertyId::Name("present-value".into()),
                    array_index: None,
                })
                .collect(),
        }
    }

    fn sample_rpm_ack() -> ReadPropertyMultipleACK {
        ReadPropertyMultipleACK {
            list_of_read_access_results: vec![
                ReadAccessResult {
                    object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap(),
                    list_of_results: vec![
                        value_elem(
                            PropertyIdentifier::OBJECT_NAME,
                            PropertyValue::CharacterString("Zone Temp".into()),
                        ),
                        value_elem(PropertyIdentifier::PRESENT_VALUE, PropertyValue::Real(72.5)),
                        value_elem(
                            PropertyIdentifier::RELIABILITY,
                            PropertyValue::Enumerated(Reliability::NO_FAULT_DETECTED.to_raw()),
                        ),
                    ],
                },
                ReadAccessResult {
                    object_identifier: ObjectIdentifier::new(ObjectType::BINARY_VALUE, 2).unwrap(),
                    list_of_results: vec![
                        ReadResultElement {
                            property_identifier: PropertyIdentifier::PRESENT_VALUE,
                            property_array_index: None,
                            property_value: None,
                            error: Some((ErrorClass::PROPERTY, ErrorCode::UNKNOWN_PROPERTY)),
                        },
                        ReadResultElement {
                            property_identifier: PropertyIdentifier::OUT_OF_SERVICE,
                            property_array_index: None,
                            property_value: None,
                            error: None,
                        },
                    ],
                },
            ],
        }
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
