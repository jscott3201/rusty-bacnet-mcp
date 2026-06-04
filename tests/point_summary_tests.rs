//! Compact point-summary MCP tool tests (no live BACnet peer required).

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
use bacnet_mcp::mcp::points::{
    PointSummaryRequest, ReadPointSummaryParams, read_point_summary_impl,
};
use bacnet_mcp::state::GatewayState;

use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig as BacnetDeviceConfig, DeviceObject};

fn test_state() -> GatewayState {
    let mut db = ObjectDatabase::new();
    let device = DeviceObject::new(BacnetDeviceConfig {
        instance: 1234,
        name: "Test Gateway".into(),
        vendor_id: 999,
        ..BacnetDeviceConfig::default()
    })
    .unwrap();
    db.add(Box::new(device)).unwrap();
    GatewayState::new(db, test_config())
}

fn test_config() -> GatewayConfig {
    GatewayConfig {
        mcp: McpConfig::default(),
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

fn valid_params() -> ReadPointSummaryParams {
    ReadPointSummaryParams {
        device_instance: 1234,
        points: vec![PointSummaryRequest {
            object_type: "analog-input".into(),
            object_instance: 1,
        }],
        include_names: false,
        include_units: false,
    }
}

#[tokio::test]
async fn read_point_summary_empty_points_rejected_before_client() {
    let state = test_state();
    let mut params = valid_params();
    params.points.clear();

    let err = read_point_summary_impl(&state, params).await.unwrap_err();
    assert!(err.contains("at least one"), "got: {err}");
    assert!(!err.contains("not started"), "got: {err}");
}

#[tokio::test]
async fn read_point_summary_point_cap_rejected_before_client() {
    let state = test_state();
    let mut params = valid_params();
    params.points = (0..129)
        .map(|i| PointSummaryRequest {
            object_type: "analog-input".into(),
            object_instance: i,
        })
        .collect();

    let err = read_point_summary_impl(&state, params).await.unwrap_err();
    assert!(err.contains("exceeds max 128"), "got: {err}");
    assert!(!err.contains("not started"), "got: {err}");
}

#[tokio::test]
async fn read_point_summary_unknown_object_type_rejected_before_client() {
    let state = test_state();
    let mut params = valid_params();
    params.points[0].object_type = "not-a-type".into();

    let err = read_point_summary_impl(&state, params).await.unwrap_err();
    assert!(err.contains("not-a-type"), "got: {err}");
    assert!(!err.contains("not started"), "got: {err}");
}

#[tokio::test]
async fn read_point_summary_valid_request_requires_client_after_validation() {
    let state = test_state();
    let err = read_point_summary_impl(&state, valid_params())
        .await
        .unwrap_err();
    assert!(err.contains("not started"), "got: {err}");
}
