//! Diagnostics MCP tool integration tests (no live BACnet stack).
//!
//! Mirrors the trend / schedule test pattern: a `test_state()` helper with
//! no client wired, plus pre-dispatch validation tests that anchor the
//! "agents get clear errors before we touch the wire" contract.

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
use bacnet_mcp::mcp::diagnostics::{PingDeviceParams, ping_device_impl};
use bacnet_mcp::state::GatewayState;

use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig as BacnetDeviceConfig, DeviceObject};

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

#[tokio::test]
async fn ping_device_no_client_errors_cleanly() {
    let state = test_state();
    let result = ping_device_impl(
        &state,
        PingDeviceParams {
            device_instance: 1234,
            count: None,
            timeout_seconds: None,
            interval_ms: None,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn ping_device_rejects_zero_count_pre_dispatch() {
    // Pre-dispatch validation: agent passing count=0 gets a range error, not
    // "client not started". Same ordering pattern as the trend / schedule
    // tools — clear input feedback before we reach for the wire.
    let state = test_state();
    let result = ping_device_impl(
        &state,
        PingDeviceParams {
            device_instance: 1234,
            count: Some(0),
            timeout_seconds: None,
            interval_ms: None,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(
        !err.contains("not started"),
        "validation must precede transport, got: {err}"
    );
    assert!(err.contains("count"));
    assert!(err.contains("range"));
}

#[tokio::test]
async fn ping_device_rejects_count_above_max_pre_dispatch() {
    let state = test_state();
    let result = ping_device_impl(
        &state,
        PingDeviceParams {
            device_instance: 1234,
            count: Some(11),
            timeout_seconds: None,
            interval_ms: None,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(!err.contains("not started"));
    assert!(err.contains("count"));
    assert!(err.contains("11"));
}

#[tokio::test]
async fn ping_device_rejects_zero_timeout_pre_dispatch() {
    let state = test_state();
    let result = ping_device_impl(
        &state,
        PingDeviceParams {
            device_instance: 1234,
            count: None,
            timeout_seconds: Some(0),
            interval_ms: None,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(!err.contains("not started"));
    assert!(err.contains("timeout_seconds"));
}

#[tokio::test]
async fn ping_device_rejects_timeout_above_max_pre_dispatch() {
    let state = test_state();
    let result = ping_device_impl(
        &state,
        PingDeviceParams {
            device_instance: 1234,
            count: None,
            timeout_seconds: Some(31),
            interval_ms: None,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(!err.contains("not started"));
    assert!(err.contains("timeout_seconds"));
}

#[tokio::test]
async fn ping_device_rejects_interval_above_max_pre_dispatch() {
    let state = test_state();
    let result = ping_device_impl(
        &state,
        PingDeviceParams {
            device_instance: 1234,
            count: None,
            timeout_seconds: None,
            interval_ms: Some(5001),
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(!err.contains("not started"));
    assert!(err.contains("interval_ms"));
}
