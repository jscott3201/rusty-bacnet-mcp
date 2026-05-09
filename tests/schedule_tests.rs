//! Schedule MCP tool integration tests (no live BACnet stack).

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
use bacnet_mcp::mcp::schedules::{
    ReadScheduleExceptionsParams, ReadScheduleParams, ReadScheduleWeeklyParams,
    read_schedule_exceptions_impl, read_schedule_impl, read_schedule_weekly_impl,
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
async fn read_schedule_no_client_errors_cleanly() {
    let state = test_state();
    let result = read_schedule_impl(
        &state,
        ReadScheduleParams {
            device_instance: 1234,
            schedule_instance: 1,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn read_schedule_validates_oid_pre_dispatch() {
    // ObjectIdentifier::new rejects instance numbers above 4_194_303.
    // Pre-dispatch validation must precede transport — agents get a
    // clear error rather than a generic "client not started".
    let state = test_state();
    let result = read_schedule_impl(
        &state,
        ReadScheduleParams {
            device_instance: 1234,
            schedule_instance: 9_999_999,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(
        !err.contains("not started"),
        "OID validation must precede transport, got: {err}"
    );
}

// ─── read_schedule_weekly ───────────────────────────────────────────────────

#[tokio::test]
async fn read_schedule_weekly_no_client_errors_cleanly() {
    let state = test_state();
    let result = read_schedule_weekly_impl(
        &state,
        ReadScheduleWeeklyParams {
            device_instance: 1234,
            schedule_instance: 1,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn read_schedule_weekly_validates_oid_pre_dispatch() {
    let state = test_state();
    let result = read_schedule_weekly_impl(
        &state,
        ReadScheduleWeeklyParams {
            device_instance: 1234,
            schedule_instance: 9_999_999,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(
        !err.contains("not started"),
        "OID validation must precede transport, got: {err}"
    );
}

// ─── read_schedule_exceptions ───────────────────────────────────────────────

#[tokio::test]
async fn read_schedule_exceptions_no_client_errors_cleanly() {
    let state = test_state();
    let result = read_schedule_exceptions_impl(
        &state,
        ReadScheduleExceptionsParams {
            device_instance: 1234,
            schedule_instance: 1,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn read_schedule_exceptions_validates_oid_pre_dispatch() {
    let state = test_state();
    let result = read_schedule_exceptions_impl(
        &state,
        ReadScheduleExceptionsParams {
            device_instance: 1234,
            schedule_instance: 9_999_999,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(
        !err.contains("not started"),
        "OID validation must precede transport, got: {err}"
    );
}
