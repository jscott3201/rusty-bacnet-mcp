//! Discovery tool integration tests with live transport clients.

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{BipConfig, DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
use bacnet_mcp::mcp::discovery;
use bacnet_mcp::state::GatewayState;
use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig as BacnetDeviceConfig, DeviceObject};

#[tokio::test]
async fn register_device_started_bip_accepts_ip_port_address() {
    let built = build_ephemeral_bip_gateway().await;

    let result = discovery::register_device_impl(
        &built.state,
        discovery::RegisterDeviceParams {
            device_instance: 44_001,
            address: "192.168.10.25:47808".into(),
        },
    )
    .await
    .unwrap();
    assert!(result.contains("Registered device 44001"));

    let devices = discovery::list_known_devices_impl(
        &built.state,
        discovery::ListKnownDevicesParams { limit: None },
    )
    .await
    .unwrap();
    assert!(devices.contains("Instance 44001"), "got: {devices}");
    assert!(devices.contains("c0, a8, 0a, 19, ba, c0"), "got: {devices}");
}

#[tokio::test]
async fn discover_devices_rejects_bad_limit_before_client() {
    let state = unstarted_state();
    let err = discovery::discover_devices_impl(
        &state,
        discovery::DiscoverParams {
            low_instance: None,
            high_instance: None,
            timeout_seconds: None,
            target: None,
            limit: Some(0),
        },
    )
    .await
    .unwrap_err();
    assert!(err.contains("limit 0 out of range"), "got: {err}");
}

#[tokio::test]
async fn list_known_devices_rejects_bad_limit_before_client() {
    let state = unstarted_state();
    let err = discovery::list_known_devices_impl(
        &state,
        discovery::ListKnownDevicesParams { limit: Some(0) },
    )
    .await
    .unwrap_err();
    assert!(err.contains("limit 0 out of range"), "got: {err}");
}

async fn build_ephemeral_bip_gateway() -> bacnet_mcp::builder::BuiltGateway {
    bacnet_mcp::builder::GatewayBuilder::new(base_config())
        .build()
        .await
        .expect("ephemeral B/IP gateway builds")
}

fn unstarted_state() -> GatewayState {
    let config = base_config();
    let mut db = ObjectDatabase::new();
    let device = DeviceObject::new(BacnetDeviceConfig {
        instance: config.device.instance,
        name: config.device.name.clone(),
        vendor_id: config.device.vendor_id,
        ..BacnetDeviceConfig::default()
    })
    .unwrap();
    db.add(Box::new(device)).unwrap();
    GatewayState::new(db, config)
}

fn base_config() -> GatewayConfig {
    GatewayConfig {
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
    }
}
