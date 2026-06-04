//! COV MCP tool tests (no live BACnet peer required).

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{BipConfig, DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
use bacnet_mcp::mcp::cov::{
    PollCovNotificationsParams, SubscribeCovParams, UnsubscribeCovParams,
    poll_cov_notifications_impl, subscribe_cov_impl, unsubscribe_cov_impl,
};
use bacnet_mcp::state::GatewayState;

use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig as BacnetDeviceConfig, DeviceObject};

fn test_config(read_only: bool) -> GatewayConfig {
    GatewayConfig {
        mcp: McpConfig {
            read_only,
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
    }
}

fn test_state(read_only: bool) -> GatewayState {
    let mut db = ObjectDatabase::new();
    let device = DeviceObject::new(BacnetDeviceConfig {
        instance: 1234,
        name: "Test Gateway".into(),
        vendor_id: 999,
        ..BacnetDeviceConfig::default()
    })
    .unwrap();
    db.add(Box::new(device)).unwrap();
    GatewayState::new(db, test_config(read_only))
}

fn subscribe_params(dry_run: bool) -> SubscribeCovParams {
    SubscribeCovParams {
        device_instance: 1234,
        object_type: "analog-input".into(),
        object_instance: 1,
        subscriber_process_identifier: 7,
        confirmed: false,
        lifetime_seconds: 300,
        dry_run,
    }
}

fn unsubscribe_params(dry_run: bool) -> UnsubscribeCovParams {
    UnsubscribeCovParams {
        device_instance: 1234,
        object_type: "analog-input".into(),
        object_instance: 1,
        subscriber_process_identifier: 7,
        dry_run,
    }
}

#[tokio::test]
async fn subscribe_cov_dry_run_allows_and_audits_without_client() {
    let state = test_state(false);
    let result = subscribe_cov_impl(&state, subscribe_params(true))
        .await
        .unwrap();
    assert!(result.contains("[dry-run]"), "got: {result}");
    assert!(result.contains("pid=7"), "got: {result}");
    assert!(result.contains("lifetime=300s"), "got: {result}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].tool, "subscribe_cov");
    assert_eq!(snap[0].decision, "allow");
    assert_eq!(snap[0].target.as_deref(), Some("analog-input:1"));
    assert_eq!(snap[0].property.as_deref(), Some("cov-subscription"));
    assert!(snap[0].dry_run);
    assert!(snap[0].reason.contains("pid=7"));
}

#[tokio::test]
async fn subscribe_cov_read_only_still_allows_dry_run() {
    let state = test_state(true);
    let result = subscribe_cov_impl(&state, subscribe_params(true))
        .await
        .unwrap();
    assert!(result.contains("[dry-run]"), "got: {result}");
    assert_eq!(state.audit.snapshot(0)[0].decision, "allow");
}

#[tokio::test]
async fn unsubscribe_cov_dry_run_allows_and_audits_without_client() {
    let state = test_state(false);
    let result = unsubscribe_cov_impl(&state, unsubscribe_params(true))
        .await
        .unwrap();
    assert!(result.contains("[dry-run]"), "got: {result}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].tool, "unsubscribe_cov");
    assert_eq!(snap[0].decision, "allow");
    assert!(snap[0].dry_run);
}

#[tokio::test]
async fn subscribe_cov_real_without_client_audits_error() {
    let state = test_state(false);
    let err = subscribe_cov_impl(&state, subscribe_params(false))
        .await
        .unwrap_err();
    assert!(err.contains("not started"), "got: {err}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "error");
    assert!(!snap[0].dry_run);
    assert!(snap[0].reason.contains("not started"));
}

#[tokio::test]
async fn unsubscribe_cov_real_without_client_audits_error() {
    let state = test_state(false);
    let err = unsubscribe_cov_impl(&state, unsubscribe_params(false))
        .await
        .unwrap_err();
    assert!(err.contains("not started"), "got: {err}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "error");
    assert!(snap[0].reason.contains("not started"));
}

#[tokio::test]
async fn subscribe_cov_rejects_zero_process_id_before_client() {
    let state = test_state(false);
    let mut params = subscribe_params(false);
    params.subscriber_process_identifier = 0;
    let err = subscribe_cov_impl(&state, params).await.unwrap_err();
    assert!(err.contains("non-zero"), "got: {err}");
    assert!(!err.contains("not started"));

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "deny");
}

#[tokio::test]
async fn subscribe_cov_rejects_lifetime_above_cap_before_client() {
    let state = test_state(false);
    let mut params = subscribe_params(false);
    params.lifetime_seconds = 86_401;
    let err = subscribe_cov_impl(&state, params).await.unwrap_err();
    assert!(err.contains("lifetime_seconds"), "got: {err}");
    assert!(err.contains("86400"), "got: {err}");
    assert!(!err.contains("not started"));

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "deny");
}

#[tokio::test]
async fn unsubscribe_cov_rejects_unknown_object_type_before_client() {
    let state = test_state(false);
    let mut params = unsubscribe_params(false);
    params.object_type = "not-a-real-type".into();
    let err = unsubscribe_cov_impl(&state, params).await.unwrap_err();
    assert!(err.contains("not-a-real-type"), "got: {err}");
    assert!(!err.contains("not started"));

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "deny");
}

#[tokio::test]
async fn poll_cov_notifications_no_client_errors_cleanly() {
    let state = test_state(false);
    let err = poll_cov_notifications_impl(&state, PollCovNotificationsParams { max_events: None })
        .await
        .unwrap_err();
    assert!(err.contains("not started"), "got: {err}");
    assert!(state.audit.snapshot(0).is_empty());
}

#[tokio::test]
async fn poll_cov_notifications_rejects_zero_max_before_client() {
    let state = test_state(false);
    let err = poll_cov_notifications_impl(
        &state,
        PollCovNotificationsParams {
            max_events: Some(0),
        },
    )
    .await
    .unwrap_err();
    assert!(err.contains("max_events"), "got: {err}");
    assert!(!err.contains("not started"));
}

#[tokio::test]
async fn poll_cov_notifications_rejects_above_cap_before_client() {
    let state = test_state(false);
    let err = poll_cov_notifications_impl(
        &state,
        PollCovNotificationsParams {
            max_events: Some(101),
        },
    )
    .await
    .unwrap_err();
    assert!(err.contains("1..=100"), "got: {err}");
    assert!(!err.contains("not started"));
}

#[tokio::test]
async fn poll_cov_notifications_started_client_empty_queue() {
    let built = build_ephemeral_gateway().await;
    let result = poll_cov_notifications_impl(
        &built.state,
        PollCovNotificationsParams {
            max_events: Some(10),
        },
    )
    .await
    .unwrap();
    assert_eq!(result, "No queued COV notifications.");
}

#[tokio::test]
async fn subscribe_cov_started_client_missing_device_audits_error() {
    let built = build_ephemeral_gateway().await;

    let err = subscribe_cov_impl(&built.state, subscribe_params(false))
        .await
        .unwrap_err();
    assert!(err.contains("not found"), "got: {err}");

    let snap = built.state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "error");
    assert!(snap[0].reason.contains("not found"));
}

async fn build_ephemeral_gateway() -> bacnet_mcp::builder::BuiltGateway {
    let config = GatewayConfig {
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
        transports: TransportsConfig {
            bip: Some(BipConfig {
                interface: "127.0.0.1".into(),
                port: 0,
                broadcast: "127.255.255.255".into(),
                network_number: 1,
            }),
            sc: None,
        },
        bbmd: None,
        foreign_device: None,
        routes: vec![],
        objects: vec![],
    };
    bacnet_mcp::builder::GatewayBuilder::new(config)
        .build()
        .await
        .expect("ephemeral gateway builds")
}
