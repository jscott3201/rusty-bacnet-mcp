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

/// Per-call audit helper. Codex flagged two related issues in PR #3 review:
///
/// - **P1**: allowed writes were audited only AFTER the BACnet round-trip,
///   contradicting the docstring's "audit before round-trip so a crash
///   mid-flight still leaves a record of intent" claim.
/// - **P2**: early failures (`require_writable`, `require_client`, parse,
///   encode, `resolve_device`) returned without an audit entry, leaving
///   forensic gaps for common operational errors.
///
/// This helper threads the audit append through every error/early-out path.
/// `target` and `property` reflect whatever the caller passed — even on
/// pre-parse failures, the audit record names what the agent tried to do.
struct WriteAudit<'a> {
    state: &'a GatewayState,
    tool: &'static str,
    target: String,
    property: String,
    priority: Option<u8>,
    dry_run: bool,
}

impl<'a> WriteAudit<'a> {
    /// Record `deny` (policy or pre-flight validation refused the write) and
    /// return `reason` so the caller can `?` it back to the MCP client.
    fn deny(&self, reason: String) -> String {
        self.append("deny", reason)
    }

    /// Record `error` (validation passed but a downstream / network step
    /// failed). Returned for `?` by the caller.
    fn err(&self, reason: String) -> String {
        self.append("error", reason)
    }

    /// Record `allow` (intent). Called BEFORE the BACnet `await` for real
    /// writes so a crash between dispatch and response still leaves a trace.
    /// Also called for `dry_run = true` (the dry-run IS the intent).
    fn allow(&self) {
        self.append("allow", String::new());
    }

    fn append(&self, decision: &'static str, reason: String) -> String {
        self.state.audit.append(AuditEntry::now(
            self.tool,
            Some(self.target.clone()),
            Some(self.property.clone()),
            self.priority,
            self.dry_run,
            decision,
            reason.clone(),
        ));
        reason
    }
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
    let audit = WriteAudit {
        state,
        tool: "write_property",
        // Use raw user input so even pre-parse failures get a useful audit
        // record. Once parse succeeds we don't bother re-canonicalizing —
        // the public object-type vocabulary is kebab-case in both directions.
        target: format!("{}:{}", params.object_type, params.object_instance),
        property: params.property.clone(),
        priority: params.priority,
        dry_run: params.dry_run,
    };

    state.require_writable().map_err(|m| audit.deny(m))?;

    let obj_type = parse_object_type(&params.object_type).map_err(|m| audit.deny(m))?;
    let property = parse_property_name(&params.property).map_err(|m| audit.deny(m))?;
    let oid = ObjectIdentifier::new(obj_type, params.object_instance)
        .map_err(|e| audit.deny(format!("{e}")))?;

    // Policy gate. Evaluated and audited regardless of dry_run.
    if let PolicyDecision::Deny(reason) = state.flags.policy().evaluate(oid, params.priority) {
        return Err(format!("Policy denied: {}", audit.deny(reason)));
    }

    let value = crate::parse::json_to_property_value(&params.value)
        .map_err(|e| audit.err(format!("Error parsing value: {e}")))?;

    if params.dry_run {
        audit.allow();
        return Ok(format!(
            "[dry-run] Would write {} to {} {} (priority {:?})",
            params.value,
            audit.target,
            property_name(property),
            params.priority,
        ));
    }

    let client = state.require_client().map_err(|m| audit.err(m))?;
    let dev_entry = state
        .resolve_device(params.device_instance)
        .await
        .map_err(|m| audit.err(m))?;

    let mut buf = bytes::BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(&mut buf, &value)
        .map_err(|e| audit.err(format!("Error encoding value: {e}")))?;

    // Codex P1: audit BEFORE the round-trip so a crash mid-flight still
    // records intent. The post-await Err arm appends a second `error` entry
    // with the wire-level failure; success path is the implicit complement
    // of the pre-await `allow`.
    audit.allow();

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
        Ok(()) => Ok(format!(
            "Successfully wrote {} to {} {}",
            params.value,
            audit.target,
            property_name(property),
        )),
        Err(e) => {
            // Second entry — wire failure paired with the pre-await `allow`.
            // Forensic review sees both: intent recorded, then outcome.
            let err_msg = audit.err(format!("{e}"));
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
    let audit = WriteAudit {
        state,
        tool: "relinquish_at_priority",
        target: format!("{}:{}", params.object_type, params.object_instance),
        property: params.property.clone(),
        priority: Some(params.priority),
        dry_run: params.dry_run,
    };

    state.require_writable().map_err(|m| audit.deny(m))?;

    let obj_type = parse_object_type(&params.object_type).map_err(|m| audit.deny(m))?;
    let property = parse_property_name(&params.property).map_err(|m| audit.deny(m))?;
    let oid = ObjectIdentifier::new(obj_type, params.object_instance)
        .map_err(|e| audit.deny(format!("{e}")))?;

    // Policy gate — relinquish IS a write, so the same caps apply.
    if let PolicyDecision::Deny(reason) = state.flags.policy().evaluate(oid, Some(params.priority))
    {
        return Err(format!("Policy denied: {}", audit.deny(reason)));
    }

    if params.dry_run {
        audit.allow();
        return Ok(format!(
            "[dry-run] Would relinquish {} {} at priority {}",
            audit.target,
            property_name(property),
            params.priority,
        ));
    }

    let client = state.require_client().map_err(|m| audit.err(m))?;
    let dev_entry = state
        .resolve_device(params.device_instance)
        .await
        .map_err(|m| audit.err(m))?;

    // BACnet "release" wire encoding: write NULL (one zero byte tag) at the
    // given priority slot. The encoding helper emits the application-tagged
    // NULL primitive used for command-priority release.
    let mut buf = bytes::BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(
        &mut buf,
        &bacnet_types::primitives::PropertyValue::Null,
    )
    .map_err(|e| audit.err(format!("Error encoding NULL: {e}")))?;

    // Codex P1: pre-await intent record (matches write_property).
    audit.allow();

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
        Ok(()) => Ok(format!(
            "Released {} {} at priority {}",
            audit.target,
            property_name(property),
            params.priority,
        )),
        Err(e) => Err(format!(
            "Error relinquishing: {}",
            audit.err(format!("{e}"))
        )),
    }
}
