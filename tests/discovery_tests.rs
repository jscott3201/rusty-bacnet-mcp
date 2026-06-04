//! Discovery tool integration tests with live transport clients.

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{BipConfig, DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
use bacnet_mcp::mcp::discovery;

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

    let devices = discovery::list_known_devices_impl(&built.state)
        .await
        .unwrap();
    assert!(devices.contains("Instance 44001"), "got: {devices}");
    assert!(devices.contains("c0, a8, 0a, 19, ba, c0"), "got: {devices}");
}

async fn build_ephemeral_bip_gateway() -> bacnet_mcp::builder::BuiltGateway {
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
        .expect("ephemeral B/IP gateway builds")
}
