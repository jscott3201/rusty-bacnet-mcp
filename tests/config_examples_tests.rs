use bacnet_mcp::config::GatewayConfig;

#[test]
fn starter_examples_parse_and_validate() {
    for (name, raw) in [
        (
            "bacnet-mcp.json",
            include_str!("../examples/bacnet-mcp.json"),
        ),
        (
            "bacnet-mcp.container.json",
            include_str!("../examples/bacnet-mcp.container.json"),
        ),
        (
            "bacnet-mcp.sc.json",
            include_str!("../examples/bacnet-mcp.sc.json"),
        ),
    ] {
        let config = GatewayConfig::from_json(raw)
            .unwrap_or_else(|err| panic!("{name} should parse as GatewayConfig: {err}"));
        config
            .validate()
            .unwrap_or_else(|err| panic!("{name} should validate: {err}"));
    }
}
