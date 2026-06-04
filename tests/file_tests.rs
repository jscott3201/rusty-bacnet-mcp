//! AtomicReadFile MCP tool tests (no live BACnet peer required).

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
use bacnet_mcp::mcp::files::{
    FileAccessMode, FilePayloadFormat, ReadFileChunkParams, read_file_chunk_impl,
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

fn valid_params() -> ReadFileChunkParams {
    ReadFileChunkParams {
        device_instance: 1234,
        file_instance: 7,
        mode: FileAccessMode::Stream,
        start: 0,
        count: Some(32),
        format: FilePayloadFormat::Auto,
    }
}

#[tokio::test]
async fn read_file_chunk_valid_request_requires_client_after_validation() {
    let state = test_state();
    let err = read_file_chunk_impl(&state, valid_params())
        .await
        .unwrap_err();
    assert!(err.contains("not started"), "got: {err}");
}

#[tokio::test]
async fn read_file_chunk_rejects_bad_file_instance_before_client() {
    let state = test_state();
    let mut params = valid_params();
    params.file_instance = 4_194_304;

    let err = read_file_chunk_impl(&state, params).await.unwrap_err();
    assert!(
        err.contains("ObjectIdentifier") || err.contains("instance"),
        "got: {err}"
    );
    assert!(!err.contains("not started"), "got: {err}");
}

#[tokio::test]
async fn read_file_chunk_rejects_negative_start_before_client() {
    let state = test_state();
    let mut params = valid_params();
    params.start = -1;

    let err = read_file_chunk_impl(&state, params).await.unwrap_err();
    assert!(err.contains("non-negative"), "got: {err}");
    assert!(!err.contains("not started"), "got: {err}");
}

#[tokio::test]
async fn read_file_chunk_rejects_zero_count_before_client() {
    let state = test_state();
    let mut params = valid_params();
    params.count = Some(0);

    let err = read_file_chunk_impl(&state, params).await.unwrap_err();
    assert!(err.contains("between 1"), "got: {err}");
    assert!(!err.contains("not started"), "got: {err}");
}

#[tokio::test]
async fn read_file_chunk_rejects_stream_count_cap_before_client() {
    let state = test_state();
    let mut params = valid_params();
    params.count = Some(2_049);

    let err = read_file_chunk_impl(&state, params).await.unwrap_err();
    assert!(err.contains("stream octet count"), "got: {err}");
    assert!(err.contains("exceeds max 2048"), "got: {err}");
    assert!(!err.contains("not started"), "got: {err}");
}

#[tokio::test]
async fn read_file_chunk_rejects_record_count_cap_before_client() {
    let state = test_state();
    let mut params = valid_params();
    params.mode = FileAccessMode::Record;
    params.count = Some(17);

    let err = read_file_chunk_impl(&state, params).await.unwrap_err();
    assert!(err.contains("record count"), "got: {err}");
    assert!(err.contains("exceeds max 16"), "got: {err}");
    assert!(!err.contains("not started"), "got: {err}");
}

#[test]
fn read_file_chunk_rejects_unknown_mode_during_deserialization() {
    let err = serde_json::from_value::<ReadFileChunkParams>(serde_json::json!({
        "device_instance": 1234,
        "file_instance": 7,
        "mode": "blocks"
    }))
    .unwrap_err();

    assert!(err.to_string().contains("unknown variant"), "got: {err}");
}
