//! MCP local object tools: list, read, write.

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_types::primitives::ObjectIdentifier;

use crate::audit::AuditEntry;
use crate::parse::{
    object_type_name, parse_object_type, parse_property_name, property_name,
    property_value_to_json_with_context,
};
use crate::safety::PolicyDecision;
use crate::state::GatewayState;

const DEFAULT_LIST_LOCAL_OBJECTS_LIMIT: usize = 500;
const MAX_LIST_LOCAL_OBJECTS_LIMIT: usize = 5000;

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
    let mut objects: Vec<_> = db
        .iter_objects()
        .filter(|(oid, _)| {
            filter_type
                .map(|ft| oid.object_type() == ft)
                .unwrap_or(true)
        })
        .collect();
    objects.sort_by_key(|(oid, _)| (oid.object_type().to_raw(), oid.instance_number()));

    if objects.is_empty() {
        return Ok(match &params.object_type {
            Some(t) => format!("No local objects of type '{t}'."),
            None => "No local objects.".to_string(),
        });
    }

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
    for (oid, obj) in objects.iter().take(shown) {
        result.push_str(&format!(
            "  - {}:{} \"{}\"\n",
            object_type_name(oid.object_type()),
            oid.instance_number(),
            obj.object_name(),
        ));
    }
    if omitted > 0 {
        result.push_str(&format!(
            "  ... omitted {omitted} object(s); set limit up to {MAX_LIST_LOCAL_OBJECTS_LIMIT} to show more.\n"
        ));
    }
    Ok(result)
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
    use bacnet_objects::database::ObjectDatabase;
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
