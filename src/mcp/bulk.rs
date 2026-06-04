//! Bulk-read MCP tools backed by ReadPropertyMultiple (RPM).
//!
//! Four tools share this implementation:
//!
//! - `read_property_multiple` — generic N-objects × M-properties read.
//! - `read_priority_array` — convenience wrapper that returns the 16-slot
//!   priority array, present-value, and relinquish-default for a commandable
//!   object. The agentic "who's overriding this point?" question.
//! - `enumerate_objects` — Device.object_list, plus optional object_name reads.
//! - `get_device_capabilities` — Device profile (services, object types,
//!   segmentation, max APDU, vendor). Lets an agent reason about what services
//!   it can actually call against the device.
//!
//! All four are read-only; the gateway's `read_only` flag does not gate them.

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_services::common::PropertyReference;
use bacnet_services::rpm::{ReadAccessSpecification, ReadResultElement};
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::ObjectIdentifier;

use crate::parse::{
    decode_raw_property_to_json_with_context, object_type_name, parse_object_type,
    parse_property_name, property_name,
};
use crate::state::GatewayState;

mod compact;

use compact::format_compact_object_list;

// ─── read_property_multiple ─────────────────────────────────────────────────

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

/// One object + the list of properties to read on it.
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
}

/// `read_property_multiple` impl — wires RPM through `GatewayState`.
pub async fn read_property_multiple_impl(
    state: &GatewayState,
    params: ReadPropertyMultipleParams,
) -> Result<String, String> {
    if params.objects.is_empty() {
        return Err("'objects' must contain at least one entry".into());
    }
    let client = state.require_client()?;
    let entry = state.resolve_device(params.device_instance).await?;

    let specs = build_rpm_specs(&params.objects)?;
    let ack = client
        .read_property_multiple(&entry.mac_address, specs)
        .await
        .map_err(|e| format!("ReadPropertyMultiple: {e}"))?;

    Ok(format_rpm_ack(&ack))
}

fn build_rpm_specs(objects: &[ObjectRequest]) -> Result<Vec<ReadAccessSpecification>, String> {
    let mut specs = Vec::with_capacity(objects.len());
    for obj in objects {
        if obj.properties.is_empty() {
            return Err(format!(
                "object {}:{} has no properties listed",
                obj.object_type, obj.object_instance
            ));
        }
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

fn format_rpm_ack(ack: &bacnet_services::rpm::ReadPropertyMultipleACK) -> String {
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

fn format_result_element(elem: &ReadResultElement) -> String {
    let prop = property_name(elem.property_identifier);
    let idx = elem
        .property_array_index
        .map(|i| format!("[{i}]"))
        .unwrap_or_default();
    if let Some((class, code)) = elem.error {
        return format!("{prop}{idx} → ERROR class={class:?} code={code:?}\n");
    }
    let Some(bytes) = &elem.property_value else {
        return format!("{prop}{idx} → (no value, no error)\n");
    };
    let json = decode_raw_property_to_json_with_context(bytes, elem.property_identifier);
    let display = json
        .get("value")
        .map(|v| v.to_string())
        .unwrap_or_else(|| json.to_string());
    format!("{prop}{idx} = {display}\n")
}

// ─── read_priority_array ────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadPriorityArrayParams {
    #[schemars(description = "Device instance number")]
    pub device_instance: u32,
    /// Must be a commandable object type (analog-output, analog-value,
    /// binary-output, binary-value, multi-state-*, integer-value, etc.).
    #[schemars(description = "Object type — must be commandable")]
    pub object_type: String,
    #[schemars(description = "Object instance number")]
    pub object_instance: u32,
}

pub async fn read_priority_array_impl(
    state: &GatewayState,
    params: ReadPriorityArrayParams,
) -> Result<String, String> {
    let client = state.require_client()?;
    let entry = state.resolve_device(params.device_instance).await?;

    let obj_type = parse_object_type(&params.object_type)?;
    let oid =
        ObjectIdentifier::new(obj_type, params.object_instance).map_err(|e| format!("{e}"))?;

    // Single RPM round-trip for present-value + priority-array + relinquish-default.
    let prop_refs = vec![
        prop_ref(PropertyIdentifier::PRESENT_VALUE),
        prop_ref(PropertyIdentifier::PRIORITY_ARRAY),
        prop_ref(PropertyIdentifier::RELINQUISH_DEFAULT),
    ];
    let specs = vec![ReadAccessSpecification {
        object_identifier: oid,
        list_of_property_references: prop_refs,
    }];
    let ack = client
        .read_property_multiple(&entry.mac_address, specs)
        .await
        .map_err(|e| format!("ReadPropertyMultiple: {e}"))?;

    let result = ack
        .list_of_read_access_results
        .first()
        .ok_or("RPM ACK returned no results")?;

    let mut out = format!(
        "{}:{} priority report\n",
        object_type_name(obj_type),
        params.object_instance
    );

    for elem in &result.list_of_results {
        out.push_str(&format!("  {}", format_result_element(elem)));
    }

    // Try to identify the highest active priority. The priority-array property
    // is encoded as a 16-element array of (Null | Value). If the device returned
    // it, we surface "winning slot" prose to make the override-audit story easy
    // for an agent to reason about.
    if let Some(active_slot) = highest_priority_slot(result) {
        out.push_str(&format!(
            "\n  → Active priority slot: {active_slot} (highest non-null below — see priority-array decode)\n"
        ));
    }
    Ok(out)
}

fn prop_ref(p: PropertyIdentifier) -> PropertyReference {
    PropertyReference {
        property_identifier: p,
        property_array_index: None,
    }
}

/// Best-effort: locate the priority-array result, JSON-decode it, scan for the
/// first non-null element. Returns the 1-based slot index, or None if the
/// array can't be parsed (devices with non-standard encoding, errors, etc.).
fn highest_priority_slot(result: &bacnet_services::rpm::ReadAccessResult) -> Option<usize> {
    let array_elem = result
        .list_of_results
        .iter()
        .find(|e| e.property_identifier == PropertyIdentifier::PRIORITY_ARRAY)?;
    let bytes = array_elem.property_value.as_ref()?;
    let decoded =
        decode_raw_property_to_json_with_context(bytes, PropertyIdentifier::PRIORITY_ARRAY);
    let arr = decoded.get("value")?.as_array()?;
    for (i, slot) in arr.iter().enumerate() {
        let is_null = slot.is_null()
            || slot
                .get("type")
                .and_then(|t| t.as_str())
                .is_some_and(|t| t == "null");
        if !is_null {
            return Some(i + 1);
        }
    }
    None
}

// ─── enumerate_objects ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EnumerateObjectsParams {
    #[schemars(description = "Device instance number")]
    pub device_instance: u32,
    /// Cap the returned object list. Unbounded reads on devices with thousands
    /// of objects can be slow; default 500.
    #[schemars(description = "Max objects to return (default 500, hard cap 5000)")]
    pub limit: Option<u32>,
    /// Fetch per-object object-name values. Default false keeps output compact
    /// and avoids one extra RPM per chunk of objects.
    #[schemars(description = "Fetch object-name values (default false)")]
    #[serde(default)]
    pub include_names: bool,
}

pub async fn enumerate_objects_impl(
    state: &GatewayState,
    params: EnumerateObjectsParams,
) -> Result<String, String> {
    const HARD_CAP: u32 = 5000;
    let limit = params.limit.unwrap_or(500).min(HARD_CAP);

    let client = state.require_client()?;
    let entry = state.resolve_device(params.device_instance).await?;
    let device_oid = ObjectIdentifier::new(ObjectType::DEVICE, params.device_instance)
        .map_err(|e| format!("{e}"))?;

    let (oids, total_count) =
        read_object_list(client, &entry.mac_address, device_oid, limit).await?;

    if oids.is_empty() {
        return Ok(format!(
            "Device {} reports no objects.",
            params.device_instance
        ));
    }

    if !params.include_names {
        return Ok(format_compact_object_list(
            params.device_instance,
            &oids,
            total_count,
        ));
    }

    // Step 2: chunked RPM for each object's object-name. Chunk size keeps the
    // request APDU small enough for un-segmented devices; 32 entries per round
    // is a conservative default.
    const CHUNK: usize = 32;
    let mut results: Vec<(ObjectIdentifier, String)> = Vec::with_capacity(oids.len());
    for chunk in oids.chunks(CHUNK) {
        let specs: Vec<ReadAccessSpecification> = chunk
            .iter()
            .map(|oid| ReadAccessSpecification {
                object_identifier: *oid,
                list_of_property_references: vec![prop_ref(PropertyIdentifier::OBJECT_NAME)],
            })
            .collect();
        match client
            .read_property_multiple(&entry.mac_address, specs)
            .await
        {
            Ok(ack) => {
                for r in &ack.list_of_read_access_results {
                    let name = r
                        .list_of_results
                        .first()
                        .and_then(|e| e.property_value.as_ref())
                        .map(|bytes| {
                            decode_raw_property_to_json_with_context(
                                bytes,
                                PropertyIdentifier::OBJECT_NAME,
                            )
                        })
                        .and_then(|j| {
                            j.get("value")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                        })
                        .unwrap_or_else(|| "(no name)".into());
                    results.push((r.object_identifier, name));
                }
            }
            Err(e) => {
                // Don't abort the whole enumeration on a chunk failure — surface
                // it inline so the agent sees the partial picture.
                results.push((
                    chunk[0],
                    format!(
                        "(chunk read failed: {e}; recovery skipped {} entries)",
                        chunk.len()
                    ),
                ));
            }
        }
    }

    let mut out = format!(
        "Device {} has {} object(s){}:\n",
        params.device_instance,
        total_count,
        if total_count > oids.len() {
            format!(" (showing first {})", oids.len())
        } else {
            String::new()
        },
    );
    for (oid, name) in &results {
        out.push_str(&format!(
            "  {}:{} \"{}\"\n",
            object_type_name(oid.object_type()),
            oid.instance_number(),
            name,
        ));
    }
    Ok(out)
}

/// Read a device's `object_list`, returning up to `limit` entries plus the
/// total reported size of the list. Tries the simple full-property RPM first
/// (works on segmenting devices); on any failure (APDU too large, missing
/// segmentation support, encode error) falls back to indexed reads — `[0]`
/// returns the array length, then `[1..=count]` are read in chunks.
async fn read_object_list(
    client: &bacnet_client::client::BACnetClient<bacnet_transport::bip::BipTransport>,
    mac: &[u8],
    device_oid: ObjectIdentifier,
    limit: u32,
) -> Result<(Vec<ObjectIdentifier>, usize), String> {
    // Path A: full property read.
    let full_specs = vec![ReadAccessSpecification {
        object_identifier: device_oid,
        list_of_property_references: vec![prop_ref(PropertyIdentifier::OBJECT_LIST)],
    }];
    if let Ok(ack) = client.read_property_multiple(mac, full_specs).await
        && let Some(elem) = ack
            .list_of_read_access_results
            .first()
            .and_then(|r| r.list_of_results.first())
        && elem.error.is_none()
        && let Some(bytes) = &elem.property_value
    {
        let decoded =
            decode_raw_property_to_json_with_context(bytes, PropertyIdentifier::OBJECT_LIST);
        let oids = oids_from_decoded(&decoded);
        let total = oids.len();
        let truncated: Vec<_> = oids.into_iter().take(limit as usize).collect();
        return Ok((truncated, total));
    }
    // Path A failures (transport error, property error code, missing value)
    // fall through to indexed reads.

    // Path B: indexed reads. `[0]` returns the array length per ASHRAE 135.
    let len_specs = vec![ReadAccessSpecification {
        object_identifier: device_oid,
        list_of_property_references: vec![PropertyReference {
            property_identifier: PropertyIdentifier::OBJECT_LIST,
            property_array_index: Some(0),
        }],
    }];
    let len_ack = client
        .read_property_multiple(mac, len_specs)
        .await
        .map_err(|e| format!("ReadPropertyMultiple(object_list[0]): {e}"))?;
    let len_elem = len_ack
        .list_of_read_access_results
        .first()
        .and_then(|r| r.list_of_results.first())
        .ok_or("indexed object_list[0] returned no result")?;
    if let Some((class, code)) = len_elem.error {
        return Err(format!(
            "Device returned error reading object_list[0]: class={class:?} code={code:?}"
        ));
    }
    let count_bytes = len_elem
        .property_value
        .as_ref()
        .ok_or("indexed object_list[0] returned no value")?;
    let count_json =
        decode_raw_property_to_json_with_context(count_bytes, PropertyIdentifier::OBJECT_LIST);
    let count = count_json
        .get("value")
        .and_then(|v| v.as_u64())
        .ok_or("indexed object_list[0] did not decode as an unsigned integer")?
        as u32;

    if count == 0 {
        return Ok((Vec::new(), 0));
    }

    // Indices 1..=count, in chunks. 32 indices per RPM keeps each request
    // small enough for un-segmenting devices.
    const CHUNK: u32 = 32;
    let to_read = count.min(limit);
    let mut oids = Vec::with_capacity(to_read as usize);
    let mut next = 1u32;
    while next <= to_read {
        let end = next.saturating_add(CHUNK).min(to_read + 1);
        let prop_refs: Vec<PropertyReference> = (next..end)
            .map(|i| PropertyReference {
                property_identifier: PropertyIdentifier::OBJECT_LIST,
                property_array_index: Some(i),
            })
            .collect();
        let specs = vec![ReadAccessSpecification {
            object_identifier: device_oid,
            list_of_property_references: prop_refs,
        }];
        let ack = client
            .read_property_multiple(mac, specs)
            .await
            .map_err(|e| format!("ReadPropertyMultiple(object_list[{next}..{end}]): {e}"))?;
        if let Some(result) = ack.list_of_read_access_results.first() {
            for elem in &result.list_of_results {
                if elem.error.is_some() {
                    continue;
                }
                let Some(bytes) = &elem.property_value else {
                    continue;
                };
                let decoded = decode_raw_property_to_json_with_context(
                    bytes,
                    PropertyIdentifier::OBJECT_LIST,
                );
                if let Some(oid) = parse_object_id_from_json(&decoded) {
                    oids.push(oid);
                }
            }
        }
        next = end;
    }
    Ok((oids, count as usize))
}

/// Extract every `ObjectIdentifier` out of a decoded `object_list` JSON value.
///
/// Handles both shapes the decoder emits:
/// - Single-element arrays decode to a scalar `{type: "object-identifier", value: "..."}`.
/// - Multi-element arrays decode to `{type: "list", value: [..]}`.
fn oids_from_decoded(decoded: &serde_json::Value) -> Vec<ObjectIdentifier> {
    // List shape.
    if let Some(arr) = decoded.get("value").and_then(|v| v.as_array()) {
        return arr.iter().filter_map(parse_object_id_from_json).collect();
    }
    // Scalar shape — single-element list collapsed by the decoder.
    if let Some(oid) = parse_object_id_from_json(decoded) {
        return vec![oid];
    }
    Vec::new()
}

fn parse_object_id_from_json(v: &serde_json::Value) -> Option<ObjectIdentifier> {
    // decode_raw_property_to_json_with_context emits ObjectIdentifier values as
    // either {"type": "object-identifier", "value": "type:instance"} or
    // (less commonly) raw "type:instance" strings.
    let s = v
        .get("value")
        .and_then(|s| s.as_str())
        .or_else(|| v.as_str())?;
    let (type_str, inst_str) = s.rsplit_once(':')?;
    let obj_type = crate::parse::parse_object_type(type_str).ok()?;
    let inst: u32 = inst_str.parse().ok()?;
    ObjectIdentifier::new(obj_type, inst).ok()
}

// ─── get_device_capabilities ────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeviceCapabilitiesParams {
    #[schemars(description = "Device instance number")]
    pub device_instance: u32,
}

pub async fn get_device_capabilities_impl(
    state: &GatewayState,
    params: DeviceCapabilitiesParams,
) -> Result<String, String> {
    let client = state.require_client()?;
    let entry = state.resolve_device(params.device_instance).await?;
    let device_oid = ObjectIdentifier::new(ObjectType::DEVICE, params.device_instance)
        .map_err(|e| format!("{e}"))?;

    // Single RPM round-trip for the capability profile. Order is deliberate —
    // the rendered output reads top-down as a profile summary.
    let props = [
        PropertyIdentifier::OBJECT_NAME,
        PropertyIdentifier::VENDOR_NAME,
        PropertyIdentifier::VENDOR_IDENTIFIER,
        PropertyIdentifier::MODEL_NAME,
        PropertyIdentifier::FIRMWARE_REVISION,
        PropertyIdentifier::APPLICATION_SOFTWARE_VERSION,
        PropertyIdentifier::PROTOCOL_VERSION,
        PropertyIdentifier::PROTOCOL_REVISION,
        PropertyIdentifier::MAX_APDU_LENGTH_ACCEPTED,
        PropertyIdentifier::SEGMENTATION_SUPPORTED,
        PropertyIdentifier::PROTOCOL_SERVICES_SUPPORTED,
        PropertyIdentifier::PROTOCOL_OBJECT_TYPES_SUPPORTED,
    ];
    let prop_refs: Vec<_> = props.iter().copied().map(prop_ref).collect();
    let specs = vec![ReadAccessSpecification {
        object_identifier: device_oid,
        list_of_property_references: prop_refs,
    }];

    let ack = client
        .read_property_multiple(&entry.mac_address, specs)
        .await
        .map_err(|e| format!("ReadPropertyMultiple: {e}"))?;

    let mut out = format!("Device {} capabilities:\n", params.device_instance);
    out.push_str(&format!("  MAC: {:02x?}\n", entry.mac_address.as_slice()));
    if let Some(net) = entry.source_network {
        out.push_str(&format!("  Source network: {net}\n"));
    }

    if let Some(result) = ack.list_of_read_access_results.first() {
        for elem in &result.list_of_results {
            out.push_str(&format!("  {}", format_result_element(elem)));
        }
    } else {
        out.push_str("  (no capability properties returned)\n");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_specs_rejects_empty_properties() {
        let req = vec![ObjectRequest {
            object_type: "analog-input".into(),
            object_instance: 1,
            properties: vec![],
        }];
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
    fn property_id_resolves_string_or_number() {
        // String form — canonical name.
        assert_eq!(
            PropertyId::Name("present-value".into()).resolve().unwrap(),
            PropertyIdentifier::PRESENT_VALUE,
        );
        // Number form — raw id, exactly what the docs/schema promise.
        assert_eq!(
            PropertyId::Number(87).resolve().unwrap(),
            PropertyIdentifier::PRIORITY_ARRAY,
        );
    }

    #[test]
    fn property_id_deserializes_from_string_and_number_json() {
        // Serde must accept both JSON shapes per the untagged enum contract.
        // This test guards against regressions that retype the field as a
        // bare String (which was the original Codex callout).
        let from_string: PropertyId =
            serde_json::from_str("\"present-value\"").expect("string form");
        assert!(matches!(from_string, PropertyId::Name(ref s) if s == "present-value"));

        let from_number: PropertyId = serde_json::from_str("87").expect("number form");
        assert!(matches!(from_number, PropertyId::Number(87)));
    }

    #[test]
    fn enumerate_params_default_to_compact_names_omitted() {
        let params: EnumerateObjectsParams =
            serde_json::from_value(serde_json::json!({"device_instance": 1234})).unwrap();
        assert!(!params.include_names);
        assert_eq!(params.limit, None);
    }

    #[test]
    fn enumerate_params_accept_name_detail_flag() {
        let params: EnumerateObjectsParams = serde_json::from_value(serde_json::json!({
            "device_instance": 1234,
            "limit": 25,
            "include_names": true
        }))
        .unwrap();
        assert!(params.include_names);
        assert_eq!(params.limit, Some(25));
    }

    #[test]
    fn parse_object_type_accepts_vendor_form() {
        // Proprietary types round-trip through `vendor-{n}` — the decoder
        // emits this for unknown raw ids and `parse_object_type` must accept
        // it so `enumerate_objects` doesn't silently drop entries.
        let ot = crate::parse::parse_object_type("vendor-513").unwrap();
        assert_eq!(ot.to_raw(), 513);
        let ot = crate::parse::parse_object_type("vendor_700").unwrap();
        assert_eq!(ot.to_raw(), 700);
    }

    #[test]
    fn parse_object_id_from_vendor_form() {
        let v = serde_json::json!({"type": "object-identifier", "value": "vendor-513:42"});
        let oid = parse_object_id_from_json(&v).unwrap();
        assert_eq!(oid.object_type().to_raw(), 513);
        assert_eq!(oid.instance_number(), 42);
    }

    #[test]
    fn oids_from_decoded_handles_singleton_scalar() {
        // Single-element object-list path — decoder emits a scalar instead of
        // a `{type: "list", value: [..]}` envelope. The previous code path
        // failed with "did not decode as an array".
        let decoded = serde_json::json!({
            "type": "object-identifier",
            "value": "device:42"
        });
        let oids = oids_from_decoded(&decoded);
        assert_eq!(oids.len(), 1);
        assert_eq!(oids[0].object_type(), ObjectType::DEVICE);
        assert_eq!(oids[0].instance_number(), 42);
    }

    #[test]
    fn oids_from_decoded_handles_list_envelope() {
        let decoded = serde_json::json!({
            "type": "list",
            "value": [
                {"type": "object-identifier", "value": "analog-input:1"},
                {"type": "object-identifier", "value": "analog-input:2"},
                {"type": "object-identifier", "value": "vendor-600:99"},
            ]
        });
        let oids = oids_from_decoded(&decoded);
        assert_eq!(oids.len(), 3);
        assert_eq!(oids[0].instance_number(), 1);
        assert_eq!(oids[2].object_type().to_raw(), 600);
    }

    #[test]
    fn oids_from_decoded_empty_for_unknown_shape() {
        let decoded = serde_json::json!({"type": "garbage"});
        assert!(oids_from_decoded(&decoded).is_empty());
    }

    #[test]
    fn parse_object_id_from_canonical_string_value() {
        let v = serde_json::json!({"type": "object-identifier", "value": "analog-input:42"});
        let oid = parse_object_id_from_json(&v).unwrap();
        assert_eq!(oid.object_type(), ObjectType::ANALOG_INPUT);
        assert_eq!(oid.instance_number(), 42);
    }

    #[test]
    fn parse_object_id_from_bare_string() {
        let v = serde_json::json!("device:389001");
        let oid = parse_object_id_from_json(&v).unwrap();
        assert_eq!(oid.object_type(), ObjectType::DEVICE);
        assert_eq!(oid.instance_number(), 389001);
    }

    #[test]
    fn parse_object_id_from_garbage_returns_none() {
        let v = serde_json::json!({"foo": "bar"});
        assert!(parse_object_id_from_json(&v).is_none());
    }
}
