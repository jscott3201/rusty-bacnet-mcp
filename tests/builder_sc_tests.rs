#![cfg(feature = "sc")]

use bacnet_mcp::builder::GatewayBuilder;
use bacnet_mcp::config::GatewayConfig;

#[tokio::test]
async fn sc_runtime_build_requires_readable_client_certificate() {
    let config = GatewayConfig::from_json(include_str!("../examples/bacnet-mcp.sc.json")).unwrap();
    config.validate().unwrap();

    let err = match GatewayBuilder::new(config).build().await {
        Ok(_) => panic!("placeholder SC config must not build without certificate files"),
        Err(err) => err,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("failed to read SC client cert"),
        "unexpected error: {msg}"
    );
}
