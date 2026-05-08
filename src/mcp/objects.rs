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

/// Parameters for list_local_objects tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListObjectsParams {
    /// Filter by object type (optional, e.g., "analog-value").
    #[schemars(
        description = "Filter by object type (optional, e.g., 'analog-value', 'binary-input')"
    )]
    pub object_type: Option<String>,
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
    let filter_type = match &params.object_type {
        Some(t) => match parse_object_type(t) {
            Ok(ot) => Some(ot),
            Err(e) => return Err(e),
        },
        None => None,
    };

    let db = state.db.read().await;
    let objects: Vec<_> = db
        .iter_objects()
        .filter(|(oid, _)| {
            filter_type
                .map(|ft| oid.object_type() == ft)
                .unwrap_or(true)
        })
        .collect();

    if objects.is_empty() {
        return Ok(match &params.object_type {
            Some(t) => format!("No local objects of type '{t}'."),
            None => "No local objects.".to_string(),
        });
    }

    let mut result = format!("{} local object(s):\n", objects.len());
    for (oid, obj) in &objects {
        result.push_str(&format!(
            "  - {}:{} \"{}\"\n",
            object_type_name(oid.object_type()),
            oid.instance_number(),
            obj.object_name(),
        ));
    }
    Ok(result)
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
