//! Trend-log MCP tool integration tests (no live BACnet stack).
//!
//! Split out of mcp_tests.rs to keep that file under the 700 LOC cap. Tests
//! exercise pre-dispatch validation order — agents must get parse errors
//! before generic "client not started" so they can self-correct without
//! reaching for the wire.

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
use bacnet_mcp::mcp::trend::{
    RangeMode, ReadTrendLogParams, TrendLogInfoParams, get_trend_log_info_impl, read_trend_log_impl,
};
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
async fn get_trend_log_info_no_client_errors_cleanly() {
    let state = test_state();
    let result = get_trend_log_info_impl(
        &state,
        TrendLogInfoParams {
            device_instance: 1234,
            trend_log_instance: 1,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn read_trend_log_no_client_errors_cleanly() {
    let state = test_state();
    let result = read_trend_log_impl(
        &state,
        ReadTrendLogParams {
            device_instance: 1234,
            trend_log_instance: 1,
            mode: RangeMode::ByPosition,
            reference: "1".into(),
            count: 50,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn read_trend_log_rejects_bad_datetime_pre_dispatch() {
    // Pre-dispatch validation: agents passing a malformed datetime get a
    // clear parse error, not a generic "client not started". Pattern
    // matches the bulk-read tools' validation-before-transport ordering.
    let state = test_state();
    let result = read_trend_log_impl(
        &state,
        ReadTrendLogParams {
            device_instance: 1234,
            trend_log_instance: 1,
            mode: RangeMode::ByTime,
            reference: "not-a-date".into(),
            count: 10,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(
        !err.contains("not started"),
        "validation must precede transport, got: {err}"
    );
    assert!(
        err.contains("date") || err.contains("datetime") || err.contains("garbage"),
        "expected datetime parse error, got: {err}"
    );
}
