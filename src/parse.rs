//! BACnet value parsing and formatting utilities.
//!
//! Shared between the HTTP API and MCP modules. No HTTP or MCP dependencies —
//! only bacnet-types, bacnet-encoding, and serde_json.

use bacnet_encoding::primitives::decode_application_value;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::PropertyValue;

/// Parse an object specifier like "analog-input:1" into (ObjectType, instance).
pub fn parse_object_specifier(s: &str) -> Result<(ObjectType, u32), String> {
    let (type_str, inst_str) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("expected 'type:instance' format, got '{s}'"))?;

    let obj_type = parse_object_type(type_str)?;
    let instance = inst_str
        .parse::<u32>()
        .map_err(|_| format!("invalid instance number: '{inst_str}'"))?;

    Ok((obj_type, instance))
}

/// Parse an object type name like "analog-input" into ObjectType.
///
/// Accepts (in order): bare numeric raw ids ("128"), the `vendor-N` form that
/// `object_type_name` emits for proprietary types not in `ALL_NAMED`, and
/// canonical hyphen/underscore-normalized names. Round-trips with
/// `object_type_name` so JSON values produced by the decoder always re-parse.
pub fn parse_object_type(s: &str) -> Result<ObjectType, String> {
    let s = s.trim();
    if let Ok(n) = s.parse::<u32>() {
        return Ok(ObjectType::from_raw(n));
    }
    if let Some(rest) = s
        .strip_prefix("vendor-")
        .or_else(|| s.strip_prefix("vendor_"))
        && let Ok(n) = rest.parse::<u32>()
    {
        return Ok(ObjectType::from_raw(n));
    }
    let normalized = s.to_ascii_lowercase().replace('-', "_");
    for &(name, val) in ObjectType::ALL_NAMED {
        if name.eq_ignore_ascii_case(&normalized) {
            return Ok(val);
        }
    }
    Err(format!("unknown object type: '{s}'"))
}

/// Parse a property name like "present-value" into PropertyIdentifier.
pub fn parse_property_name(s: &str) -> Result<PropertyIdentifier, String> {
    let s = s.trim();
    if let Ok(n) = s.parse::<u32>() {
        return Ok(PropertyIdentifier::from_raw(n));
    }
    let normalized = s.to_ascii_lowercase().replace('-', "_");
    for &(name, val) in PropertyIdentifier::ALL_NAMED {
        if name.eq_ignore_ascii_case(&normalized) {
            return Ok(val);
        }
    }
    Err(format!("unknown property: '{s}'"))
}

/// Serialize a PropertyValue to a JSON-friendly representation.
pub fn property_value_to_json(value: &PropertyValue) -> serde_json::Value {
    match value {
        PropertyValue::Null => serde_json::Value::Null,
        PropertyValue::Boolean(b) => serde_json::json!({ "type": "boolean", "value": b }),
        PropertyValue::Unsigned(n) => serde_json::json!({ "type": "unsigned", "value": n }),
        PropertyValue::Signed(n) => serde_json::json!({ "type": "signed", "value": n }),
        PropertyValue::Real(f) => serde_json::json!({ "type": "real", "value": f }),
        PropertyValue::Double(f) => serde_json::json!({ "type": "double", "value": f }),
        PropertyValue::CharacterString(s) => {
            serde_json::json!({ "type": "string", "value": s })
        }
        PropertyValue::Enumerated(e) => serde_json::json!({ "type": "enumerated", "value": e }),
        PropertyValue::ObjectIdentifier(oid) => {
            serde_json::json!({
                "type": "object-identifier",
                "value": format!("{}:{}", object_type_name(oid.object_type()), oid.instance_number())
            })
        }
        PropertyValue::OctetString(bytes) => {
            serde_json::json!({ "type": "octet-string", "value": bytes.iter().map(|b| format!("{b:02x}")).collect::<String>() })
        }
        PropertyValue::BitString { unused_bits, data } => {
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            serde_json::json!({
                "type": "bit-string",
                "unused_bits": unused_bits,
                "value": hex
            })
        }
        PropertyValue::Date(d) => {
            // BACnet year is offset from 1900; 0xFF = unspecified
            let year = if d.year == 0xFF {
                "*".to_string()
            } else {
                format!("{}", 1900u16 + d.year as u16)
            };
            let month = if d.month == 0xFF {
                "*".to_string()
            } else {
                format!("{:02}", d.month)
            };
            let day = if d.day == 0xFF {
                "*".to_string()
            } else {
                format!("{:02}", d.day)
            };
            serde_json::json!({ "type": "date", "value": format!("{year}-{month}-{day}") })
        }
        PropertyValue::Time(t) => {
            let hour = if t.hour == 0xFF {
                "*".to_string()
            } else {
                format!("{:02}", t.hour)
            };
            let min = if t.minute == 0xFF {
                "*".to_string()
            } else {
                format!("{:02}", t.minute)
            };
            let sec = if t.second == 0xFF {
                "*".to_string()
            } else {
                format!("{:02}", t.second)
            };
            let hun = if t.hundredths == 0xFF {
                "*".to_string()
            } else {
                format!("{:02}", t.hundredths)
            };
            serde_json::json!({ "type": "time", "value": format!("{hour}:{min}:{sec}.{hun}") })
        }
        PropertyValue::List(items) => {
            let arr: Vec<serde_json::Value> = items.iter().map(property_value_to_json).collect();
            serde_json::json!({ "type": "list", "value": arr })
        }
    }
}

/// Decode raw BACnet-encoded bytes into JSON.
pub fn decode_raw_property_to_json(data: &[u8]) -> serde_json::Value {
    let mut offset = 0;
    let mut values = Vec::new();
    while offset < data.len() {
        match decode_application_value(data, offset) {
            Ok((value, next)) => {
                values.push(property_value_to_json(&value));
                offset = next;
            }
            Err(_) => {
                let hex: String = data[offset..]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                values.push(serde_json::json!({ "type": "raw", "value": hex }));
                break;
            }
        }
    }
    if values.len() == 1 {
        values.into_iter().next().unwrap()
    } else {
        serde_json::json!({ "type": "list", "value": values })
    }
}

/// Get a human-readable name for an ObjectType (lowercase with hyphens).
pub fn object_type_name(ot: ObjectType) -> String {
    for &(name, val) in ObjectType::ALL_NAMED {
        if val == ot {
            return name.replace('_', "-").to_lowercase();
        }
    }
    format!("vendor-{}", ot.to_raw())
}

/// Get a human-readable name for a PropertyIdentifier (lowercase with hyphens).
pub fn property_name(pi: PropertyIdentifier) -> String {
    for &(name, val) in PropertyIdentifier::ALL_NAMED {
        if val == pi {
            return name.replace('_', "-").to_lowercase();
        }
    }
    format!("proprietary-{}", pi.to_raw())
}

/// Look up a name for an enumerated value given the property context.
///
/// Returns a human-readable name when the property type is known (e.g., units,
/// event-state, reliability), or None for unknown properties/values.
fn enumerated_name_for_property(value: u32, property: PropertyIdentifier) -> Option<String> {
    use bacnet_types::enums::*;

    macro_rules! lookup {
        ($enum_ty:ty) => {
            <$enum_ty>::ALL_NAMED
                .iter()
                .find(|(_, v)| v.to_raw() as u32 == value)
                .map(|(n, _)| n.replace('_', "-").to_lowercase())
        };
    }

    match property {
        PropertyIdentifier::OBJECT_TYPE => lookup!(ObjectType),
        PropertyIdentifier::UNITS => lookup!(EngineeringUnits),
        PropertyIdentifier::EVENT_STATE => lookup!(EventState),
        PropertyIdentifier::RELIABILITY => lookup!(Reliability),
        PropertyIdentifier::SYSTEM_STATUS => lookup!(DeviceStatus),
        PropertyIdentifier::SEGMENTATION_SUPPORTED => lookup!(Segmentation),
        PropertyIdentifier::NOTIFY_TYPE => lookup!(NotifyType),
        _ => None,
    }
}

/// Serialize a PropertyValue to JSON with property-context-aware enum decoding.
///
/// When the property is known (e.g., units, event-state, reliability), the
/// enumerated value is decoded to the correct enum name.
pub fn property_value_to_json_with_context(
    value: &PropertyValue,
    property: PropertyIdentifier,
) -> serde_json::Value {
    match value {
        PropertyValue::Enumerated(e) => {
            let mut obj = serde_json::json!({ "type": "enumerated", "value": e });
            if let Some(name) = enumerated_name_for_property(*e, property) {
                obj["name"] = serde_json::Value::String(name);
            }
            obj
        }
        _ => property_value_to_json(value),
    }
}

/// Decode raw BACnet-encoded bytes into JSON with property-context-aware enum decoding.
pub fn decode_raw_property_to_json_with_context(
    data: &[u8],
    property: PropertyIdentifier,
) -> serde_json::Value {
    let mut offset = 0;
    let mut values = Vec::new();
    while offset < data.len() {
        match decode_application_value(data, offset) {
            Ok((value, next)) => {
                values.push(property_value_to_json_with_context(&value, property));
                offset = next;
            }
            Err(_) => {
                let hex: String = data[offset..]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                values.push(serde_json::json!({ "type": "raw", "value": hex }));
                break;
            }
        }
    }
    if values.len() == 1 {
        values.into_iter().next().unwrap()
    } else {
        serde_json::json!({ "type": "list", "value": values })
    }
}

/// Convert a SocketAddrV4 to a 6-byte BACnet/IP MAC (4 bytes IP + 2 bytes port big-endian).
pub fn socket_addr_to_mac(addr: std::net::SocketAddrV4) -> Vec<u8> {
    let ip = addr.ip().octets();
    let port = addr.port().to_be_bytes();
    vec![ip[0], ip[1], ip[2], ip[3], port[0], port[1]]
}

/// Parse a JSON value into a PropertyValue.
pub fn json_to_property_value(v: &serde_json::Value) -> Result<PropertyValue, String> {
    match v {
        serde_json::Value::Null => Ok(PropertyValue::Null),
        serde_json::Value::Bool(b) => Ok(PropertyValue::Boolean(*b)),
        serde_json::Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if n.is_f64() && f.fract() != 0.0 {
                    Ok(PropertyValue::Real(f as f32))
                } else if let Some(u) = n.as_u64() {
                    Ok(PropertyValue::Unsigned(u))
                } else if let Some(i) = n.as_i64() {
                    i32::try_from(i)
                        .map(PropertyValue::Signed)
                        .map_err(|_| format!("signed value {i} out of BACnet i32 range"))
                } else {
                    Ok(PropertyValue::Real(f as f32))
                }
            } else {
                Err("invalid number".to_string())
            }
        }
        serde_json::Value::String(s) => Ok(PropertyValue::CharacterString(s.clone())),
        serde_json::Value::Object(map) => parse_tagged_value(map),
        serde_json::Value::Array(_) => Err(
            "bare JSON arrays are not yet supported; wrap in {\"type\":\"list\",\"value\":[...]}"
                .to_string(),
        ),
    }
}

/// Parse a tagged ``{"type": "...", "value": ...}`` object into a PropertyValue.
///
/// The shape mirrors what ``property_value_to_json`` emits, so round-tripping
/// is value-preserving for the primitive types.  This is the form the user
/// has to use when the bare JSON encoding would lose BACnet type information
/// (e.g. JSON ``1`` is ambiguous between ``Unsigned`` and ``Enumerated``;
/// JSON ``1.0`` is ambiguous between ``Real`` and ``Double``).
fn parse_tagged_value(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Result<PropertyValue, String> {
    let type_str = map
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| "tagged value missing 'type' field (string)".to_string())?;
    let value = map
        .get("value")
        .ok_or_else(|| format!("tagged value '{type_str}' missing 'value' field"))?;

    match type_str {
        "null" => Ok(PropertyValue::Null),
        "boolean" => value
            .as_bool()
            .map(PropertyValue::Boolean)
            .ok_or_else(|| "boolean: 'value' must be true or false".to_string()),
        "unsigned" => value
            .as_u64()
            .map(PropertyValue::Unsigned)
            .ok_or_else(|| "unsigned: 'value' must be a non-negative integer".to_string()),
        "signed" => match value.as_i64() {
            Some(i) => i32::try_from(i)
                .map(PropertyValue::Signed)
                .map_err(|_| format!("signed value {i} out of BACnet i32 range")),
            None => Err("signed: 'value' must be an integer".to_string()),
        },
        "real" => value
            .as_f64()
            .map(|f| PropertyValue::Real(f as f32))
            .ok_or_else(|| "real: 'value' must be a number".to_string()),
        "double" => value
            .as_f64()
            .map(PropertyValue::Double)
            .ok_or_else(|| "double: 'value' must be a number".to_string()),
        "enumerated" => match value.as_u64() {
            Some(u) => u32::try_from(u)
                .map(PropertyValue::Enumerated)
                .map_err(|_| format!("enumerated value {u} out of BACnet u32 range")),
            None => Err("enumerated: 'value' must be a non-negative integer".to_string()),
        },
        // Both names accepted because the serializer emits "string" while the
        // BACnet variant is named CharacterString.
        "string" | "character-string" => value
            .as_str()
            .map(|s| PropertyValue::CharacterString(s.to_string()))
            .ok_or_else(|| "string: 'value' must be a string".to_string()),
        // Complex types not yet symmetric.  Returning a precise error rather
        // than the previous catch-all so callers know what to ask for.
        "date" | "time" | "object-identifier" | "octet-string" | "bit-string" | "list" => Err(
            format!("tagged form for '{type_str}' is not yet implemented for writes"),
        ),
        other => Err(format!(
            "unknown tagged type '{other}' — expected one of: null, boolean, unsigned, \
             signed, real, double, enumerated, string"
        )),
    }
}

/// Construct a BACnet object by type. Shared between REST and MCP create handlers.
pub fn construct_object(
    obj_type: ObjectType,
    instance: u32,
    name: &str,
    number_of_states: Option<u32>,
) -> Result<Box<dyn bacnet_objects::traits::BACnetObject>, String> {
    let num_states = number_of_states.unwrap_or(2);

    match obj_type {
        ObjectType::ANALOG_INPUT => {
            bacnet_objects::analog::AnalogInputObject::new(instance, name, 95)
                .map(|o| Box::new(o) as Box<dyn bacnet_objects::traits::BACnetObject>)
        }
        ObjectType::ANALOG_OUTPUT => {
            bacnet_objects::analog::AnalogOutputObject::new(instance, name, 95)
                .map(|o| Box::new(o) as _)
        }
        ObjectType::ANALOG_VALUE => {
            bacnet_objects::analog::AnalogValueObject::new(instance, name, 95)
                .map(|o| Box::new(o) as _)
        }
        ObjectType::BINARY_INPUT => {
            bacnet_objects::binary::BinaryInputObject::new(instance, name).map(|o| Box::new(o) as _)
        }
        ObjectType::BINARY_OUTPUT => {
            bacnet_objects::binary::BinaryOutputObject::new(instance, name)
                .map(|o| Box::new(o) as _)
        }
        ObjectType::BINARY_VALUE => {
            bacnet_objects::binary::BinaryValueObject::new(instance, name).map(|o| Box::new(o) as _)
        }
        ObjectType::MULTI_STATE_INPUT => {
            bacnet_objects::multistate::MultiStateInputObject::new(instance, name, num_states)
                .map(|o| Box::new(o) as _)
        }
        ObjectType::MULTI_STATE_OUTPUT => {
            bacnet_objects::multistate::MultiStateOutputObject::new(instance, name, num_states)
                .map(|o| Box::new(o) as _)
        }
        ObjectType::MULTI_STATE_VALUE => {
            bacnet_objects::multistate::MultiStateValueObject::new(instance, name, num_states)
                .map(|o| Box::new(o) as _)
        }
        ObjectType::INTEGER_VALUE => {
            bacnet_objects::value_types::IntegerValueObject::new(instance, name)
                .map(|o| Box::new(o) as _)
        }
        ObjectType::POSITIVE_INTEGER_VALUE => {
            bacnet_objects::value_types::PositiveIntegerValueObject::new(instance, name)
                .map(|o| Box::new(o) as _)
        }
        ObjectType::LARGE_ANALOG_VALUE => {
            bacnet_objects::value_types::LargeAnalogValueObject::new(instance, name)
                .map(|o| Box::new(o) as _)
        }
        ObjectType::CHARACTERSTRING_VALUE => {
            bacnet_objects::value_types::CharacterStringValueObject::new(instance, name)
                .map(|o| Box::new(o) as _)
        }
        _ => {
            return Err(format!(
                "object type '{}' is not supported for creation via the API",
                object_type_name(obj_type),
            ));
        }
    }
    .map_err(|e| format!("{e}"))
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use bacnet_types::primitives::PropertyValue;
    use serde_json::json;

    /// Round-trip every primitive variant the serializer emits with a tagged
    /// envelope so callers can disambiguate the BACnet wire type (e.g. send
    /// {"type":"real","value":100} instead of bare `100`, which would encode
    /// as `Unsigned(100)` and be rejected by AO/AV/AI servers).
    #[test]
    fn tagged_form_round_trip_primitives() {
        let cases = [
            PropertyValue::Null,
            PropertyValue::Boolean(true),
            PropertyValue::Boolean(false),
            PropertyValue::Unsigned(42),
            PropertyValue::Signed(-7),
            PropertyValue::Real(72.5),
            PropertyValue::Double(3.14159265358979_f64),
            PropertyValue::CharacterString("Zone Temp".to_string()),
            PropertyValue::Enumerated(1),
        ];

        for original in cases {
            let serialized = property_value_to_json(&original);
            let parsed = json_to_property_value(&serialized).unwrap_or_else(|e| {
                panic!("round-trip failed for {original:?}: {e}; serialized={serialized}")
            });
            assert_eq!(parsed, original, "round-trip mismatch for {original:?}");
        }
    }

    /// The motivating case: writing `100` to an AnalogOutput.present-value.
    /// Bare JSON int becomes Unsigned and the AO server rejects it as
    /// invalid-data-type.  The tagged form lets the caller force Real.
    #[test]
    fn tagged_real_overrides_default_unsigned_for_integer() {
        // Bare int: defaults to Unsigned (existing, lossy behaviour).
        assert_eq!(
            json_to_property_value(&json!(100)).unwrap(),
            PropertyValue::Unsigned(100)
        );
        // Tagged real: forces Real, which is what AO/AV/AI present-value needs.
        assert_eq!(
            json_to_property_value(&json!({"type": "real", "value": 100})).unwrap(),
            PropertyValue::Real(100.0)
        );
    }

    /// Same disambiguation for binary-value present-value, which requires
    /// Enumerated (0 or 1) per BACnetBinaryPV.  Bare `1` becomes Unsigned and
    /// is rejected by BV servers; tagged enumerated works.
    #[test]
    fn tagged_enumerated_for_binary_present_value() {
        assert_eq!(
            json_to_property_value(&json!({"type": "enumerated", "value": 1})).unwrap(),
            PropertyValue::Enumerated(1)
        );
        assert_eq!(
            json_to_property_value(&json!({"type": "enumerated", "value": 0})).unwrap(),
            PropertyValue::Enumerated(0)
        );
    }

    #[test]
    fn tagged_missing_type_field_is_a_clear_error() {
        let err = json_to_property_value(&json!({"value": 1})).unwrap_err();
        assert!(err.contains("missing 'type'"), "got: {err}");
    }

    #[test]
    fn tagged_missing_value_field_is_a_clear_error() {
        let err = json_to_property_value(&json!({"type": "real"})).unwrap_err();
        assert!(err.contains("missing 'value'"), "got: {err}");
    }

    #[test]
    fn tagged_unknown_type_lists_supported_options() {
        let err = json_to_property_value(&json!({"type": "junk", "value": 0})).unwrap_err();
        assert!(err.contains("unknown tagged type"), "got: {err}");
        assert!(err.contains("real"), "should list supported types: {err}");
        assert!(
            err.contains("enumerated"),
            "should list supported types: {err}"
        );
    }

    #[test]
    fn complex_types_return_targeted_not_yet_implemented_error() {
        // Tagged date/time/object-identifier/etc. were never accepted, but
        // surface a more useful error than the previous catch-all.
        for t in [
            "date",
            "time",
            "object-identifier",
            "octet-string",
            "bit-string",
            "list",
        ] {
            let err = json_to_property_value(&json!({"type": t, "value": "x"})).unwrap_err();
            assert!(
                err.contains("not yet implemented") && err.contains(t),
                "expected targeted error for {t}; got: {err}"
            );
        }
    }

    #[test]
    fn signed_value_out_of_i32_range_is_caught() {
        let too_big = json!({"type": "signed", "value": 5_000_000_000_i64});
        let err = json_to_property_value(&too_big).unwrap_err();
        assert!(err.contains("out of BACnet i32 range"), "got: {err}");
    }

    /// Sanity: existing bare-value behaviour is unchanged.
    #[test]
    fn bare_values_unchanged() {
        assert_eq!(
            json_to_property_value(&json!(null)).unwrap(),
            PropertyValue::Null
        );
        assert_eq!(
            json_to_property_value(&json!(true)).unwrap(),
            PropertyValue::Boolean(true)
        );
        assert_eq!(
            json_to_property_value(&json!(42)).unwrap(),
            PropertyValue::Unsigned(42)
        );
        assert_eq!(
            json_to_property_value(&json!(-3)).unwrap(),
            PropertyValue::Signed(-3)
        );
        assert_eq!(
            json_to_property_value(&json!(2.5)).unwrap(),
            PropertyValue::Real(2.5)
        );
        assert_eq!(
            json_to_property_value(&json!("hi")).unwrap(),
            PropertyValue::CharacterString("hi".to_string())
        );
    }
}
