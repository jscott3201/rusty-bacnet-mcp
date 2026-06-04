//! MCP local object tools: list, read, write.

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_objects::database::ObjectDatabase;
use bacnet_types::enums::ObjectType;
use bacnet_types::primitives::ObjectIdentifier;

use crate::audit::AuditEntry;
use crate::parse::{
    object_type_name, parse_object_type, parse_property_name, property_name,
    property_value_to_json_with_context,
};
use crate::safety::PolicyDecision;
use crate::state::GatewayState;

pub(crate) const DEFAULT_LIST_LOCAL_OBJECTS_LIMIT: usize = 500;
const MAX_LIST_LOCAL_OBJECTS_LIMIT: usize = 5000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalObjectRow {
    object_type: ObjectType,
    instance: u32,
    name: String,
}

#[derive(Clone, Copy)]
pub(crate) enum LocalObjectListFormat {
    Tool,
    StateResource,
}

/// Parameters for list_local_objects tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListObjectsParams {
    /// Filter by object type (optional, e.g., "analog-value").
    #[schemars(
        description = "Filter by object type (optional, e.g., 'analog-value', 'binary-input')"
    )]
    pub object_type: Option<String>,
    /// Maximum local objects to return. Default 500, hard cap 5000.
    #[schemars(description = "Max objects to return (default 500, hard cap 5000)")]
    pub limit: Option<u32>,
}

/// Parameters for read_local_property tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadLocalPropertyParams {
    /// Object type name.
    #[schemars(description = "Object type (e.g., 'analog-value', 'device')")]
    pub object_type: String,
    /// Object instance number.
    #[schemars(description = "Object instance number")]
    pub object_instance: u32,
    /// Property name.
    #[schemars(description = "Property name (e.g., 'present-value', 'object-name')")]
    pub property: String,
}

/// Parameters for write_local_property tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteLocalPropertyParams {
    /// Object type name.
    #[schemars(description = "Object type (e.g., 'analog-value')")]
    pub object_type: String,
    /// Object instance number.
    #[schemars(description = "Object instance number")]
    pub object_instance: u32,
    /// Property name.
    #[schemars(description = "Property name (e.g., 'present-value')")]
    pub property: String,
    /// Value to write.
    #[schemars(description = "Value to write: number, boolean, string, or null")]
    pub value: serde_json::Value,
    /// Dry-run mode. When true, runs all safety checks and records an audit
    /// entry but does not mutate the local DB.
    #[schemars(
        description = "If true, validate against policy + audit but do not actually mutate the local DB (default false)"
    )]
    #[serde(default)]
    pub dry_run: bool,
}

pub async fn list_local_objects_impl(
    state: &GatewayState,
    params: ListObjectsParams,
) -> Result<String, String> {
    let limit = list_local_objects_limit(params.limit)?;
    let filter_type = match &params.object_type {
        Some(t) => match parse_object_type(t) {
            Ok(ot) => Some(ot),
            Err(e) => return Err(e),
        },
        None => None,
    };

    let db = state.db.read().await;
    let objects = collect_local_object_rows(&db, filter_type);

    if objects.is_empty() {
        return Ok(match &params.object_type {
            Some(t) => format!("No local objects of type '{t}'."),
            None => "No local objects.".to_string(),
        });
    }

    Ok(format_local_object_rows(
        &objects,
        limit,
        LocalObjectListFormat::Tool,
    ))
}

pub(crate) fn collect_local_object_rows(
    db: &ObjectDatabase,
    filter_type: Option<ObjectType>,
) -> Vec<LocalObjectRow> {
    let mut rows: Vec<_> = db
        .iter_objects()
        .filter(|(oid, _)| {
            filter_type
                .map(|ft| oid.object_type() == ft)
                .unwrap_or(true)
        })
        .map(|(oid, obj)| LocalObjectRow {
            object_type: oid.object_type(),
            instance: oid.instance_number(),
            name: obj.object_name().to_string(),
        })
        .collect();
    rows.sort_by_key(|row| (row.object_type.to_raw(), row.instance));
    rows
}

pub(crate) fn format_local_object_rows(
    objects: &[LocalObjectRow],
    limit: usize,
    format: LocalObjectListFormat,
) -> String {
    let shown = objects.len().min(limit);
    let omitted = objects.len().saturating_sub(shown);
    let mut result = if omitted > 0 {
        format!(
            "{} local object(s) (showing first {shown}):\n",
            objects.len()
        )
    } else {
        format!("{} local object(s):\n", objects.len())
    };
    for row in objects.iter().take(shown) {
        let bullet = match format {
            LocalObjectListFormat::Tool => "  - ",
            LocalObjectListFormat::StateResource => "  ",
        };
        result.push_str(&format!(
            "{bullet}{}:{} \"{}\"\n",
            object_type_name(row.object_type),
            row.instance,
            row.name,
        ));
    }
    if omitted > 0 {
        match format {
            LocalObjectListFormat::Tool => {
                result.push_str(&format!(
                    "  ... omitted {omitted} object(s); set limit up to {MAX_LIST_LOCAL_OBJECTS_LIMIT} to show more.\n"
                ));
            }
            LocalObjectListFormat::StateResource => {
                result.push_str(&format!(
                    "  ... omitted {omitted} object(s); use list_local_objects with limit up to {MAX_LIST_LOCAL_OBJECTS_LIMIT} for more.\n"
                ));
            }
        }
    }
    result
}

fn list_local_objects_limit(raw: Option<u32>) -> Result<usize, String> {
    let limit = raw.unwrap_or(DEFAULT_LIST_LOCAL_OBJECTS_LIMIT as u32);
    if limit == 0 || limit > MAX_LIST_LOCAL_OBJECTS_LIMIT as u32 {
        return Err(format!(
            "limit {limit} out of range; must be 1..={MAX_LIST_LOCAL_OBJECTS_LIMIT}"
        ));
    }
    Ok(limit as usize)
}

pub async fn read_local_property_impl(
    state: &GatewayState,
    params: ReadLocalPropertyParams,
) -> Result<String, String> {
    let obj_type = match parse_object_type(&params.object_type) {
        Ok(t) => t,
        Err(e) => return Err(e),
    };

    let property = match parse_property_name(&params.property) {
        Ok(p) => p,
        Err(e) => return Err(e),
    };

    let oid = match ObjectIdentifier::new(obj_type, params.object_instance) {
        Ok(o) => o,
        Err(e) => return Err(format!("{e}")),
    };

    let db = state.db.read().await;
    let obj = match db.get(&oid) {
        Some(o) => o,
        None => {
            return Err(format!(
                "Object {}:{} not found in local database.",
                params.object_type, params.object_instance
            ));
        }
    };

    match obj.read_property(property, None) {
        Ok(val) => {
            let json_val = property_value_to_json_with_context(&val, property);
            let display = match json_val.get("value") {
                Some(v) => format!("{v}"),
                None => format!("{json_val}"),
            };
            Ok(format!(
                "{}:{} {} = {}",
                object_type_name(obj_type),
                params.object_instance,
                property_name(property),
                display,
            ))
        }
        Err(e) => Err(format!("Error reading property: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
    use bacnet_objects::device::{DeviceConfig as BacnetDeviceConfig, DeviceObject};

    #[test]
    fn list_local_objects_params_default_limit_is_none() {
        let params: ListObjectsParams = serde_json::from_value(serde_json::json!({
            "object_type": null
        }))
        .unwrap();
        assert_eq!(params.limit, None);
    }

    #[test]
    fn list_local_objects_limit_rejects_invalid_values() {
        assert!(
            list_local_objects_limit(Some(0))
                .unwrap_err()
                .contains("out of range")
        );
        assert!(
            list_local_objects_limit(Some(MAX_LIST_LOCAL_OBJECTS_LIMIT as u32 + 1))
                .unwrap_err()
                .contains("out of range")
        );
    }

    #[tokio::test]
    async fn list_local_objects_applies_limit_and_reports_omissions() {
        let state = test_state();
        for instance in 1..=3 {
            create_local_object_impl(
                &state,
                CreateLocalObjectParams {
                    object_type: "analog-value".into(),
                    object_instance: instance,
                    object_name: format!("AV {instance}"),
                    number_of_states: None,
                },
            )
            .await
            .unwrap();
        }

        let out = list_local_objects_impl(
            &state,
            ListObjectsParams {
                object_type: None,
                limit: Some(2),
            },
        )
        .await
        .unwrap();

        assert!(out.contains("4 local object(s) (showing first 2)"));
        assert!(out.contains("analog-value:1"));
        assert!(out.contains("analog-value:2"));
        assert!(!out.contains("analog-value:3"));
        assert!(out.contains("omitted 2 object(s)"));
    }

    #[tokio::test]
    async fn local_object_rows_sort_by_type_and_instance() {
        let state = test_state();
        create_local_object_impl(
            &state,
            CreateLocalObjectParams {
                object_type: "binary-value".into(),
                object_instance: 2,
                object_name: "BV 2".into(),
                number_of_states: None,
            },
        )
        .await
        .unwrap();
        create_local_object_impl(
            &state,
            CreateLocalObjectParams {
                object_type: "analog-value".into(),
                object_instance: 1,
                object_name: "AV 1".into(),
                number_of_states: None,
            },
        )
        .await
        .unwrap();

        let db = state.db.read().await;
        let rows = collect_local_object_rows(&db, None);
        let rendered = format_local_object_rows(&rows, 3, LocalObjectListFormat::StateResource);

        let analog_pos = rendered.find("analog-value:1").unwrap();
        let binary_pos = rendered.find("binary-value:2").unwrap();
        assert!(analog_pos < binary_pos, "got: {rendered}");
    }

    #[test]
    fn state_resource_format_points_to_list_tool_for_more_rows() {
        let rows = vec![
            LocalObjectRow {
                object_type: ObjectType::ANALOG_VALUE,
                instance: 1,
                name: "AV 1".into(),
            },
            LocalObjectRow {
                object_type: ObjectType::ANALOG_VALUE,
                instance: 2,
                name: "AV 2".into(),
            },
        ];

        let out = format_local_object_rows(&rows, 1, LocalObjectListFormat::StateResource);

        assert!(out.contains("2 local object(s) (showing first 1)"));
        assert!(out.contains("use list_local_objects with limit up to"));
    }

    fn test_state() -> GatewayState {
        let cfg = GatewayConfig {
            mcp: McpConfig {
                read_only: false,
                ..McpConfig::default()
            },
            device: DeviceConfig {
                instance: 1234,
                name: "Test Gateway".to_string(),
                vendor_id: 999,
                description: "Test".to_string(),
            },
            transports: TransportsConfig::default(),
            bbmd: None,
            foreign_device: None,
            routes: vec![],
            objects: vec![],
        };
        let mut db = ObjectDatabase::new();
        let device = DeviceObject::new(BacnetDeviceConfig {
            instance: 1234,
            name: "Test Gateway".into(),
            vendor_id: 999,
            ..BacnetDeviceConfig::default()
        })
        .unwrap();
        db.add(Box::new(device)).unwrap();
        GatewayState::new(db, cfg)
    }
}

pub async fn write_local_property_impl(
    state: &GatewayState,
    params: WriteLocalPropertyParams,
) -> Result<String, String> {
    state.require_writable()?;

    let obj_type = parse_object_type(&params.object_type)?;
    let property = parse_property_name(&params.property)?;
    let oid =
        ObjectIdentifier::new(obj_type, params.object_instance).map_err(|e| format!("{e}"))?;
    let target_str = format!("{}:{}", object_type_name(obj_type), params.object_instance);

    // Local writes go through the same policy gate as remote writes — agents
    // shouldn't be able to bypass life-safety denials by targeting the
    // gateway's own DB. Local writes don't carry a priority (the local DB
    // doesn't model the priority array), so we evaluate with priority=None
    // which means the priority caps don't fire.
    if let PolicyDecision::Deny(reason) = state.flags.policy().evaluate(oid, None) {
        state.audit.append(AuditEntry::now(
            "write_local_property",
            Some(target_str),
            Some(property_name(property).to_string()),
            None,
            params.dry_run,
            "deny",
            reason.clone(),
        ));
        return Err(format!("Policy denied: {reason}"));
    }

    let value = crate::parse::json_to_property_value(&params.value)
        .map_err(|e| format!("Error parsing value: {e}"))?;

    if params.dry_run {
        state.audit.append(AuditEntry::now(
            "write_local_property",
            Some(target_str.clone()),
            Some(property_name(property).to_string()),
            None,
            true,
            "allow",
            String::new(),
        ));
        return Ok(format!(
            "[dry-run] Would write {} to local {} {}",
            params.value,
            target_str,
            property_name(property),
        ));
    }

    let mut db = state.db.write().await;
    let obj = match db.get_mut(&oid) {
        Some(o) => o,
        None => {
            return Err(format!(
                "Object {}:{} not found in local database.",
                params.object_type, params.object_instance
            ));
        }
    };

    match obj.write_property(property, None, value, None) {
        Ok(()) => {
            state.audit.append(AuditEntry::now(
                "write_local_property",
                Some(target_str.clone()),
                Some(property_name(property).to_string()),
                None,
                false,
                "allow",
                String::new(),
            ));
            Ok(format!(
                "Successfully wrote {} to local {} {}",
                params.value,
                target_str,
                property_name(property),
            ))
        }
        Err(e) => {
            let err_msg = format!("{e}");
            state.audit.append(AuditEntry::now(
                "write_local_property",
                Some(target_str),
                Some(property_name(property).to_string()),
                None,
                false,
                "error",
                err_msg.clone(),
            ));
            Err(format!("Error writing property: {err_msg}"))
        }
    }
}

/// Parameters for create_local_object tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateLocalObjectParams {
    /// Object type name.
    #[schemars(
        description = "Object type (e.g., 'analog-value', 'binary-input', 'multi-state-value')"
    )]
    pub object_type: String,
    /// Object instance number.
    #[schemars(description = "Object instance number")]
    pub object_instance: u32,
    /// Object name.
    #[schemars(description = "Human-readable object name")]
    pub object_name: String,
    /// Number of states for multi-state objects (default: 2).
    #[schemars(
        description = "Number of states for multi-state objects (default: 2, ignored for other types)"
    )]
    pub number_of_states: Option<u32>,
}

/// Parameters for delete_local_object tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteLocalObjectParams {
    /// Object type name.
    #[schemars(description = "Object type (e.g., 'analog-value')")]
    pub object_type: String,
    /// Object instance number.
    #[schemars(description = "Object instance number")]
    pub object_instance: u32,
}

pub async fn create_local_object_impl(
    state: &GatewayState,
    params: CreateLocalObjectParams,
) -> Result<String, String> {
    state.require_writable()?;
    let obj_type = match parse_object_type(&params.object_type) {
        Ok(t) => t,
        Err(e) => return Err(e),
    };

    let obj = match crate::parse::construct_object(
        obj_type,
        params.object_instance,
        &params.object_name,
        params.number_of_states,
    ) {
        Ok(o) => o,
        Err(e) => return Err(e),
    };

    let mut db = state.db.write().await;
    match db.add(obj) {
        Ok(()) => Ok(format!(
            "Created local object {}:{} \"{}\"",
            object_type_name(obj_type),
            params.object_instance,
            params.object_name,
        )),
        Err(e) => Err(format!("Error creating object: {e}")),
    }
}

pub async fn delete_local_object_impl(
    state: &GatewayState,
    params: DeleteLocalObjectParams,
) -> Result<String, String> {
    state.require_writable()?;
    let obj_type = match parse_object_type(&params.object_type) {
        Ok(t) => t,
        Err(e) => return Err(e),
    };

    let oid = match ObjectIdentifier::new(obj_type, params.object_instance) {
        Ok(o) => o,
        Err(e) => return Err(format!("{e}")),
    };

    if obj_type == bacnet_types::enums::ObjectType::DEVICE {
        return Err("Cannot delete the Device object.".to_string());
    }

    let mut db = state.db.write().await;
    match db.remove(&oid) {
        Some(_) => Ok(format!(
            "Deleted local object {}:{}",
            object_type_name(obj_type),
            params.object_instance,
        )),
        None => Err(format!(
            "Object {}:{} not found in local database.",
            params.object_type, params.object_instance,
        )),
    }
}
