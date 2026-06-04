//! MCP COV tools.
//!
//! COV subscription is a read-side BACnet service with remote side effects:
//! the target device allocates a transient subscription and later sends
//! notifications. We therefore expose dry-run and audit records, but do not
//! require the gateway's write mode because no commandable value is changed.

use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::broadcast::error::TryRecvError;

use bacnet_services::cov::COVNotificationRequest;
use bacnet_types::primitives::ObjectIdentifier;

use crate::audit::AuditEntry;
use crate::parse::{
    decode_raw_property_to_json_with_context, object_type_name, parse_object_type, property_name,
};
use crate::state::GatewayState;

const DEFAULT_PROCESS_ID: u32 = 1;
const DEFAULT_LIFETIME_SECONDS: u32 = 300;
const MAX_LIFETIME_SECONDS: u32 = 86_400;
const DEFAULT_MAX_EVENTS: usize = 20;
const MAX_EVENTS: usize = 100;

/// Parameters for SubscribeCOV.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SubscribeCovParams {
    #[schemars(description = "Device instance number (must be in device table)")]
    pub device_instance: u32,
    #[schemars(description = "Object type (e.g., 'analog-input', 'binary-value')")]
    pub object_type: String,
    #[schemars(description = "Object instance number")]
    pub object_instance: u32,
    #[schemars(description = "Subscriber process id (default 1, must be non-zero)")]
    #[serde(default = "default_process_id")]
    pub subscriber_process_identifier: u32,
    #[schemars(description = "Request confirmed COV notifications (default false)")]
    #[serde(default)]
    pub confirmed: bool,
    #[schemars(description = "Subscription lifetime in seconds (default 300, max 86400)")]
    #[serde(default = "default_lifetime_seconds")]
    pub lifetime_seconds: u32,
    #[schemars(description = "Validate and audit without sending SubscribeCOV")]
    #[serde(default)]
    pub dry_run: bool,
}

/// Parameters for SubscribeCOV cancellation.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UnsubscribeCovParams {
    #[schemars(description = "Device instance number (must be in device table)")]
    pub device_instance: u32,
    #[schemars(description = "Object type (e.g., 'analog-input', 'binary-value')")]
    pub object_type: String,
    #[schemars(description = "Object instance number")]
    pub object_instance: u32,
    #[schemars(description = "Subscriber process id used for the subscription")]
    #[serde(default = "default_process_id")]
    pub subscriber_process_identifier: u32,
    #[schemars(description = "Validate and audit without sending cancellation")]
    #[serde(default)]
    pub dry_run: bool,
}

/// Parameters for draining queued COV notifications.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PollCovNotificationsParams {
    #[schemars(description = "Max notifications to return (default 20, max 100)")]
    pub max_events: Option<usize>,
}

pub async fn subscribe_cov_impl(
    state: &GatewayState,
    params: SubscribeCovParams,
) -> Result<String, String> {
    let target = format!("{}:{}", params.object_type, params.object_instance);
    let audit = CovAudit::new(
        state,
        "subscribe_cov",
        target.clone(),
        params.subscriber_process_identifier,
        params.dry_run,
    );
    let oid = validate_cov_target(
        &params.object_type,
        params.object_instance,
        params.subscriber_process_identifier,
        Some(params.lifetime_seconds),
        &audit,
    )?;

    if params.dry_run {
        audit.allow();
        return Ok(format!(
            "[dry-run] Would subscribe COV for {target} on device {} pid={} lifetime={}s confirmed={}",
            params.device_instance,
            params.subscriber_process_identifier,
            params.lifetime_seconds,
            params.confirmed,
        ));
    }

    let client = state.require_client().map_err(|m| audit.err(m))?;
    let entry = state
        .resolve_device(params.device_instance)
        .await
        .map_err(|m| audit.err(m))?;
    if entry.source_network.is_some() || entry.source_address.is_some() {
        return Err(audit.err("COV subscription for routed devices is not supported yet".into()));
    }

    audit.allow();
    client
        .subscribe_cov(
            &entry.mac_address,
            params.subscriber_process_identifier,
            oid,
            params.confirmed,
            Some(params.lifetime_seconds),
        )
        .await
        .map_err(|e| audit.err(format!("SubscribeCOV failed: {e}")))?;

    Ok(format!(
        "Subscribed COV for {target} on device {} pid={} lifetime={}s confirmed={}",
        params.device_instance,
        params.subscriber_process_identifier,
        params.lifetime_seconds,
        params.confirmed,
    ))
}

pub async fn unsubscribe_cov_impl(
    state: &GatewayState,
    params: UnsubscribeCovParams,
) -> Result<String, String> {
    let target = format!("{}:{}", params.object_type, params.object_instance);
    let audit = CovAudit::new(
        state,
        "unsubscribe_cov",
        target.clone(),
        params.subscriber_process_identifier,
        params.dry_run,
    );
    let oid = validate_cov_target(
        &params.object_type,
        params.object_instance,
        params.subscriber_process_identifier,
        None,
        &audit,
    )?;

    if params.dry_run {
        audit.allow();
        return Ok(format!(
            "[dry-run] Would cancel COV for {target} on device {} pid={}",
            params.device_instance, params.subscriber_process_identifier,
        ));
    }

    let client = state.require_client().map_err(|m| audit.err(m))?;
    let entry = state
        .resolve_device(params.device_instance)
        .await
        .map_err(|m| audit.err(m))?;
    if entry.source_network.is_some() || entry.source_address.is_some() {
        return Err(audit.err("COV cancellation for routed devices is not supported yet".into()));
    }

    audit.allow();
    client
        .unsubscribe_cov(
            &entry.mac_address,
            params.subscriber_process_identifier,
            oid,
        )
        .await
        .map_err(|e| audit.err(format!("UnsubscribeCOV failed: {e}")))?;

    Ok(format!(
        "Cancelled COV for {target} on device {} pid={}",
        params.device_instance, params.subscriber_process_identifier,
    ))
}

pub async fn poll_cov_notifications_impl(
    state: &GatewayState,
    params: PollCovNotificationsParams,
) -> Result<String, String> {
    let max_events = params.max_events.unwrap_or(DEFAULT_MAX_EVENTS);
    if max_events == 0 || max_events > MAX_EVENTS {
        return Err(format!(
            "max_events {max_events} out of range; must be 1..={MAX_EVENTS}"
        ));
    }

    let rx = state.require_cov_receiver()?;
    let mut rx = rx.lock().await;
    let mut events = Vec::new();
    let mut lagged = 0u64;

    while events.len() < max_events {
        match rx.try_recv() {
            Ok(notification) => events.push(notification),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Lagged(n)) => lagged = lagged.saturating_add(n),
            Err(TryRecvError::Closed) => return Err("COV notification channel closed".into()),
        }
    }

    Ok(format_cov_notifications(&events, lagged))
}

fn validate_cov_target(
    object_type: &str,
    object_instance: u32,
    process_id: u32,
    lifetime_seconds: Option<u32>,
    audit: &CovAudit<'_>,
) -> Result<ObjectIdentifier, String> {
    if process_id == 0 {
        return Err(audit.deny("subscriber_process_identifier must be non-zero".into()));
    }
    if let Some(lifetime) = lifetime_seconds
        && !(1..=MAX_LIFETIME_SECONDS).contains(&lifetime)
    {
        return Err(audit.deny(format!(
            "lifetime_seconds {lifetime} out of range; must be 1..={MAX_LIFETIME_SECONDS}"
        )));
    }

    let obj_type = parse_object_type(object_type).map_err(|m| audit.deny(m))?;
    ObjectIdentifier::new(obj_type, object_instance).map_err(|e| audit.deny(format!("{e}")))
}

fn format_cov_notifications(events: &[COVNotificationRequest], lagged: u64) -> String {
    if events.is_empty() {
        return if lagged == 0 {
            "No queued COV notifications.".into()
        } else {
            format!("No queued COV notifications; {lagged} older notification(s) were dropped.")
        };
    }

    let mut out = format!("{} COV notification(s):\n", events.len());
    if lagged > 0 {
        out.push_str(&format!("  dropped_before_poll={lagged}\n"));
    }
    for notification in events {
        out.push_str(&format!("  {}\n", format_cov_notification(notification)));
    }
    out
}

fn format_cov_notification(notification: &COVNotificationRequest) -> String {
    let device = notification.initiating_device_identifier.instance_number();
    let oid = notification.monitored_object_identifier;
    let target = format!(
        "{}:{}",
        object_type_name(oid.object_type()),
        oid.instance_number()
    );
    let mut parts = Vec::with_capacity(notification.list_of_values.len());
    for value in &notification.list_of_values {
        let idx = value
            .property_array_index
            .map(|i| format!("[{i}]"))
            .unwrap_or_default();
        let decoded =
            decode_raw_property_to_json_with_context(&value.value, value.property_identifier);
        let display = decoded
            .get("value")
            .map(|v| v.to_string())
            .unwrap_or_else(|| decoded.to_string());
        parts.push(format!(
            "{}{idx}={display}",
            property_name(value.property_identifier)
        ));
    }
    let prefix = format!(
        "pid={} device:{} {} time_remaining={}s {}",
        notification.subscriber_process_identifier,
        device,
        target,
        notification.time_remaining,
        parts.join(" "),
    );
    prefix.trim_end().to_string()
}

fn default_process_id() -> u32 {
    DEFAULT_PROCESS_ID
}

fn default_lifetime_seconds() -> u32 {
    DEFAULT_LIFETIME_SECONDS
}

struct CovAudit<'a> {
    state: &'a GatewayState,
    tool: &'static str,
    target: String,
    process_id: u32,
    dry_run: bool,
}

impl<'a> CovAudit<'a> {
    fn new(
        state: &'a GatewayState,
        tool: &'static str,
        target: String,
        process_id: u32,
        dry_run: bool,
    ) -> Self {
        Self {
            state,
            tool,
            target,
            process_id,
            dry_run,
        }
    }

    fn deny(&self, reason: String) -> String {
        self.append("deny", reason)
    }

    fn err(&self, reason: String) -> String {
        self.append("error", reason)
    }

    fn allow(&self) {
        self.append("allow", String::new());
    }

    fn append(&self, decision: &'static str, reason: String) -> String {
        self.state.audit.append(AuditEntry::now(
            self.tool,
            Some(self.target.clone()),
            Some("cov-subscription".into()),
            None,
            self.dry_run,
            decision,
            format!("pid={} {}", self.process_id, reason)
                .trim()
                .to_string(),
        ));
        reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_services::common::BACnetPropertyValue;
    use bacnet_types::enums::{ObjectType, PropertyIdentifier};

    #[test]
    fn subscribe_cov_params_default_to_safe_values() {
        let params: SubscribeCovParams = serde_json::from_value(serde_json::json!({
            "device_instance": 1234,
            "object_type": "analog-input",
            "object_instance": 1
        }))
        .unwrap();
        assert_eq!(params.subscriber_process_identifier, DEFAULT_PROCESS_ID);
        assert!(!params.confirmed);
        assert_eq!(params.lifetime_seconds, DEFAULT_LIFETIME_SECONDS);
        assert!(!params.dry_run);
    }

    #[test]
    fn poll_cov_params_accept_empty_shape() {
        let params: PollCovNotificationsParams =
            serde_json::from_value(serde_json::json!({})).expect("empty params accepted");
        assert_eq!(params.max_events, None);
    }

    #[test]
    fn format_cov_notifications_decodes_compact_values() {
        let notification = COVNotificationRequest {
            subscriber_process_identifier: 7,
            initiating_device_identifier: ObjectIdentifier::new(ObjectType::DEVICE, 1234).unwrap(),
            monitored_object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1)
                .unwrap(),
            time_remaining: 60,
            list_of_values: vec![
                BACnetPropertyValue {
                    property_identifier: PropertyIdentifier::PRESENT_VALUE,
                    property_array_index: None,
                    value: vec![0x44, 0x42, 0x90, 0x00, 0x00],
                    priority: None,
                },
                BACnetPropertyValue {
                    property_identifier: PropertyIdentifier::STATUS_FLAGS,
                    property_array_index: None,
                    value: vec![0x82, 0x04, 0x00],
                    priority: None,
                },
            ],
        };
        let out = format_cov_notifications(&[notification], 2);
        assert!(out.contains("1 COV notification(s)"));
        assert!(out.contains("dropped_before_poll=2"));
        assert!(out.contains("pid=7 device:1234 analog-input:1"));
        assert!(out.contains("time_remaining=60s"));
        assert!(out.contains("present-value="));
        assert!(out.contains("status-flags="));
    }

    #[test]
    fn format_cov_notifications_empty_mentions_lag() {
        assert_eq!(
            format_cov_notifications(&[], 0),
            "No queued COV notifications."
        );
        assert!(format_cov_notifications(&[], 3).contains("3 older"));
    }

    #[test]
    fn format_cov_notification_with_no_values_has_no_trailing_space() {
        let notification = COVNotificationRequest {
            subscriber_process_identifier: 7,
            initiating_device_identifier: ObjectIdentifier::new(ObjectType::DEVICE, 1234).unwrap(),
            monitored_object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1)
                .unwrap(),
            time_remaining: 60,
            list_of_values: vec![],
        };
        let out = format_cov_notification(&notification);
        assert_eq!(out, "pid=7 device:1234 analog-input:1 time_remaining=60s");
    }
}
