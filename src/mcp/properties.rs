//! MCP property tools: read_property, write_property, relinquish_at_priority.
//!
//! Every write tool here funnels through the same control-plane gate:
//!
//! 1. `state.require_writable()` — global read-only check.
//! 2. `state.flags.policy().evaluate(target, priority)` — layered policy
//!    (object-type allow/deny, per-object allow/deny, priority caps).
//! 3. `state.audit.append(...)` — record the decision **before** sending
//!    the BACnet APDU so a crash mid-flight still leaves a record of intent.
//! 4. `dry_run = true` short-circuits step 4 (no APDU is encoded) but still
//!    records an `allow`/`deny` audit entry — agents use this to pre-flight
//!    a write without affecting the device.

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_types::primitives::ObjectIdentifier;

use crate::audit::AuditEntry;
use crate::parse::{
    decode_raw_property_to_json_with_context, object_type_name, parse_object_type,
    parse_property_name, property_name,
};
use crate::safety::PolicyDecision;
use crate::state::GatewayState;

/// Parameters for read_property tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadPropertyParams {
    /// Device instance number of the target device.
    #[schemars(description = "Device instance number (e.g., 1234)")]
    pub device_instance: u32,
    /// Object type name (e.g., "analog-input", "binary-value").
    #[schemars(description = "Object type name (e.g., 'analog-input', 'binary-value', 'device')")]
    pub object_type: String,
    /// Object instance number.
    #[schemars(description = "Object instance number (e.g., 1)")]
    pub object_instance: u32,
    /// Property name (e.g., "present-value", "object-name").
    #[schemars(
        description = "Property name (e.g., 'present-value', 'object-name', 'status-flags')"
    )]
    pub property: String,
    /// Array index for array properties (optional).
    #[schemars(description = "Array index for array properties (optional)")]
    pub array_index: Option<u32>,
}

/// Parameters for write_property tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WritePropertyParams {
    /// Device instance number of the target device.
    #[schemars(description = "Device instance number (e.g., 1234)")]
    pub device_instance: u32,
    /// Object type name (e.g., "analog-output", "binary-value").
    #[schemars(description = "Object type name (e.g., 'analog-output', 'binary-value')")]
    pub object_type: String,
    /// Object instance number.
    #[schemars(description = "Object instance number (e.g., 1)")]
    pub object_instance: u32,
    /// Property name (e.g., "present-value").
    #[schemars(description = "Property name (e.g., 'present-value')")]
    pub property: String,
    /// Value to write (number, boolean, string, or null).
    #[schemars(
        description = "Value to write: number (72.5), boolean (true/false), string, or null"
    )]
    pub value: serde_json::Value,
    /// Command priority 1-16 (optional, for commandable properties).
    #[schemars(
        description = "Command priority 1-16 (optional, for commandable properties like present-value on outputs)"
    )]
    pub priority: Option<u8>,
    /// Dry-run mode. When true, runs all safety checks and records an audit
    /// entry but does not send the WriteProperty APDU.
    #[schemars(
        description = "If true, validate against policy + audit but do not actually send the WriteProperty (default false)"
    )]
    #[serde(default)]
    pub dry_run: bool,
}

/// Parameters for relinquish_at_priority tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RelinquishParams {
    /// Device instance number of the target device.
    #[schemars(description = "Device instance number (e.g., 1234)")]
    pub device_instance: u32,
    /// Object type name (must be a commandable type — analog/binary/multi-state output or value).
    #[schemars(description = "Object type (e.g., 'analog-output', 'binary-value')")]
    pub object_type: String,
    /// Object instance number.
    #[schemars(description = "Object instance number")]
    pub object_instance: u32,
    /// Property name (typically 'present-value').
    #[schemars(description = "Property name (typically 'present-value')")]
    #[serde(default = "default_present_value")]
    pub property: String,
    /// Priority slot to release (1-16). The slot is set to NULL on the wire,
    /// allowing lower-priority commands or relinquish-default to take effect.
    #[schemars(description = "Priority slot to release (1-16)")]
    pub priority: u8,
    /// Dry-run mode (see write_property).
    #[schemars(description = "If true, validate but do not actually send (default false)")]
    #[serde(default)]
    pub dry_run: bool,
}

fn default_present_value() -> String {
    "present-value".to_string()
}

pub async fn read_property_impl(
    state: &GatewayState,
    params: ReadPropertyParams,
) -> Result<String, String> {
    let client = match state.require_client() {
        Ok(c) => c,
        Err(msg) => return Err(msg),
    };

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

    let entry = match state.resolve_device(params.device_instance).await {
        Ok(e) => e,
        Err(msg) => return Err(msg),
    };

    match client
        .read_property(&entry.mac_address, oid, property, params.array_index)
        .await
    {
        Ok(ack) => {
            let val = decode_raw_property_to_json_with_context(&ack.property_value, property);
            let display = match val.get("value") {
                Some(v) => format!("{v}"),
                None => format!("{val}"),
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

pub async fn write_property_impl(
    state: &GatewayState,
    params: WritePropertyParams,
) -> Result<String, String> {
    state.require_writable()?;

    let obj_type = parse_object_type(&params.object_type)?;
    let property = parse_property_name(&params.property)?;
    let oid =
        ObjectIdentifier::new(obj_type, params.object_instance).map_err(|e| format!("{e}"))?;
    let target_str = format!("{}:{}", object_type_name(obj_type), params.object_instance);

    // Policy gate. Evaluated and audited regardless of dry_run.
    if let PolicyDecision::Deny(reason) = state.flags.policy().evaluate(oid, params.priority) {
        state.audit.append(AuditEntry::now(
            "write_property",
            Some(target_str),
            Some(property_name(property).to_string()),
            params.priority,
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
            "write_property",
            Some(target_str.clone()),
            Some(property_name(property).to_string()),
            params.priority,
            true,
            "allow",
            String::new(),
        ));
        return Ok(format!(
            "[dry-run] Would write {} to {} {} (priority {:?})",
            params.value,
            target_str,
            property_name(property),
            params.priority,
        ));
    }

    let client = state.require_client()?;
    let dev_entry = state.resolve_device(params.device_instance).await?;

    let mut buf = bytes::BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(&mut buf, &value)
        .map_err(|e| format!("Error encoding value: {e}"))?;

    match client
        .write_property(
            &dev_entry.mac_address,
            oid,
            property,
            None,
            buf.to_vec(),
            params.priority,
        )
        .await
    {
        Ok(()) => {
            state.audit.append(AuditEntry::now(
                "write_property",
                Some(target_str.clone()),
                Some(property_name(property).to_string()),
                params.priority,
                false,
                "allow",
                String::new(),
            ));
            Ok(format!(
                "Successfully wrote {} to {} {}",
                params.value,
                target_str,
                property_name(property),
            ))
        }
        Err(e) => {
            let err_msg = format!("{e}");
            state.audit.append(AuditEntry::now(
                "write_property",
                Some(target_str),
                Some(property_name(property).to_string()),
                params.priority,
                false,
                "error",
                err_msg.clone(),
            ));
            Err(format!("Error writing property: {err_msg}"))
        }
    }
}

/// Release a priority slot on a commandable BACnet object.
///
/// Encodes a NULL value at `params.priority`. The slot becomes inactive and
/// the device's commandable property falls back to the next-highest active
/// priority — or to `relinquish-default` if no other slots are taken.
///
/// Distinct from `write_property` because:
/// - The wire encoding is fixed (NULL), so callers can't accidentally write
///   a stale value while trying to release a priority.
/// - The audit log records the intent ("relinquish") separately from a
///   normal value write, which matters for forensic review.
pub async fn relinquish_at_priority_impl(
    state: &GatewayState,
    params: RelinquishParams,
) -> Result<String, String> {
    state.require_writable()?;

    let obj_type = parse_object_type(&params.object_type)?;
    let property = parse_property_name(&params.property)?;
    let oid =
        ObjectIdentifier::new(obj_type, params.object_instance).map_err(|e| format!("{e}"))?;
    let target_str = format!("{}:{}", object_type_name(obj_type), params.object_instance);

    // Policy gate — relinquish IS a write, so the same caps apply.
    if let PolicyDecision::Deny(reason) = state.flags.policy().evaluate(oid, Some(params.priority))
    {
        state.audit.append(AuditEntry::now(
            "relinquish_at_priority",
            Some(target_str),
            Some(property_name(property).to_string()),
            Some(params.priority),
            params.dry_run,
            "deny",
            reason.clone(),
        ));
        return Err(format!("Policy denied: {reason}"));
    }

    if params.dry_run {
        state.audit.append(AuditEntry::now(
            "relinquish_at_priority",
            Some(target_str.clone()),
            Some(property_name(property).to_string()),
            Some(params.priority),
            true,
            "allow",
            String::new(),
        ));
        return Ok(format!(
            "[dry-run] Would relinquish {} {} at priority {}",
            target_str,
            property_name(property),
            params.priority,
        ));
    }

    let client = state.require_client()?;
    let dev_entry = state.resolve_device(params.device_instance).await?;

    // BACnet "release" wire encoding: write NULL (one zero byte tag) at the
    // given priority slot. The encoding helper emits the application-tagged
    // NULL primitive used for command-priority release.
    let mut buf = bytes::BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(
        &mut buf,
        &bacnet_types::primitives::PropertyValue::Null,
    )
    .map_err(|e| format!("Error encoding NULL: {e}"))?;

    match client
        .write_property(
            &dev_entry.mac_address,
            oid,
            property,
            None,
            buf.to_vec(),
            Some(params.priority),
        )
        .await
    {
        Ok(()) => {
            state.audit.append(AuditEntry::now(
                "relinquish_at_priority",
                Some(target_str.clone()),
                Some(property_name(property).to_string()),
                Some(params.priority),
                false,
                "allow",
                String::new(),
            ));
            Ok(format!(
                "Released {} {} at priority {}",
                target_str,
                property_name(property),
                params.priority,
            ))
        }
        Err(e) => {
            let err_msg = format!("{e}");
            state.audit.append(AuditEntry::now(
                "relinquish_at_priority",
                Some(target_str),
                Some(property_name(property).to_string()),
                Some(params.priority),
                false,
                "error",
                err_msg.clone(),
            ));
            Err(format!("Error relinquishing: {err_msg}"))
        }
    }
}
