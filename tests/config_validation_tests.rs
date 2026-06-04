use bacnet_mcp::config::{GatewayConfig, parse_sc_vmac};

#[test]
fn parse_full_config() {
    let json = r#"{
        "mcp": {
            "api_key": "test-key",
            "read_only": false,
            "http": { "bind": "0.0.0.0:3000" }
        },
        "device": {
            "instance": 389001,
            "name": "Test Gateway",
            "vendor_id": 555
        },
        "transports": {
            "bip": {
                "interface": "0.0.0.0",
                "port": 47808,
                "broadcast": "192.168.1.255",
                "network_number": 1
            }
        },
        "routes": [
            { "network": 4, "via_transport": "bip", "next_hop": "192.168.1.100:47808" }
        ],
        "objects": [
            { "type": "analog-value", "instance": 1, "name": "Gateway Uptime", "units": "seconds" }
        ]
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    assert_eq!(config.mcp.api_key.as_deref(), Some("test-key"));
    assert!(!config.mcp.read_only);
    assert_eq!(
        config.mcp.http.as_ref().map(|h| h.bind.as_str()),
        Some("0.0.0.0:3000")
    );
    assert_eq!(config.device.instance, 389001);
    assert_eq!(config.device.name, "Test Gateway");
    assert_eq!(config.device.vendor_id, 555);
    assert!(config.transports.bip.is_some());
    assert!(config.transports.sc.is_none());
    assert_eq!(config.routes.len(), 1);
    assert_eq!(config.routes[0].network, 4);
    assert_eq!(config.objects.len(), 1);
    assert_eq!(config.objects[0].object_type, "analog-value");
    config.validate().unwrap();
}

#[test]
fn parse_minimal_config_is_read_only_but_runtime_transport_is_required() {
    let json = r#"{ "device": { "instance": 1234, "name": "Minimal" } }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    assert!(config.mcp.api_key.is_none());
    assert!(
        config.mcp.read_only,
        "default safety posture must be read-only"
    );
    assert!(config.mcp.http.is_none());
    assert!(config.transports.bip.is_none());
    assert!(config.routes.is_empty());
    assert!(config.objects.is_empty());
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("exactly one runtime transport"));
}

#[test]
fn validate_device_instance_too_large() {
    let json = r#"{ "device": { "instance": 4194303, "name": "Bad" } }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("4194303"));
}

#[test]
fn validate_bbmd_and_foreign_device_mutually_exclusive() {
    let json = r#"{
        "device": { "instance": 1, "name": "Test" },
        "transports": {
            "bip": { "broadcast": "192.168.1.255", "network_number": 1 }
        },
        "bbmd": { "enabled": true },
        "foreign_device": { "bbmd": "192.168.1.1:47808", "ttl": 300 }
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("mutually exclusive"));
}

#[test]
fn validate_bbmd_requires_bip() {
    let json = r#"{
        "device": { "instance": 1, "name": "Test" },
        "bbmd": { "enabled": true }
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("requires transports.bip"));
}

#[test]
fn validate_rejects_multiple_runtime_transports() {
    let json = r#"{
        "device": { "instance": 1, "name": "Test" },
        "transports": {
            "bip": { "broadcast": "192.168.1.255", "network_number": 1 },
            "sc": {
                "hub_uri": "wss://hub.example.com",
                "cert": "c.pem", "key": "k.pem",
                "client_vmac": "02:00:00:00:00:01",
                "server_vmac": "02:00:00:00:00:02",
                "network_number": 1
            }
        }
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("exactly one runtime transport"));
}

#[test]
fn validate_network_numbers_reject_reserved_values() {
    for (number, expected) in [(0, "reserved"), (65535, "reserved")] {
        let json = format!(
            r#"{{
                "device": {{ "instance": 1, "name": "Test" }},
                "transports": {{
                    "bip": {{ "broadcast": "192.168.1.255", "network_number": {number} }}
                }}
            }}"#
        );
        let config = GatewayConfig::from_json(&json).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.message.contains(expected));
    }
}

#[test]
fn validate_sc_requires_hub_uri() {
    let json = r#"{
        "device": { "instance": 1, "name": "Test" },
        "transports": {
            "sc": {
                "cert": "c.pem", "key": "k.pem",
                "client_vmac": "02:00:00:00:00:01",
                "server_vmac": "02:00:00:00:00:02",
                "network_number": 2
            }
        }
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("hub_uri"));
}

#[test]
fn validate_sc_embedded_hub_mode_accepted() {
    let json = r#"{
        "device": { "instance": 1, "name": "Test" },
        "transports": {
            "sc": {
                "listen": "127.0.0.1:8443",
                "cert": "c.pem", "key": "k.pem", "ca": "ca.pem",
                "hub_vmac": "02:00:00:00:00:ff",
                "client_vmac": "02:00:00:00:00:01",
                "server_vmac": "02:00:00:00:00:02",
                "network_number": 2
            }
        }
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    config.validate().unwrap();
}

#[test]
fn validate_sc_embedded_hub_requires_ca_for_mtls() {
    let json = r#"{
        "device": { "instance": 1, "name": "Test" },
        "transports": {
            "sc": {
                "listen": "127.0.0.1:8443",
                "cert": "c.pem", "key": "k.pem",
                "hub_vmac": "02:00:00:00:00:ff",
                "client_vmac": "02:00:00:00:00:01",
                "server_vmac": "02:00:00:00:00:02",
                "network_number": 2
            }
        }
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("ca") && err.message.contains("mTLS"));
}

#[test]
fn validate_sc_embedded_hub_requires_hub_vmac() {
    let json = r#"{
        "device": { "instance": 1, "name": "Test" },
        "transports": {
            "sc": {
                "listen": "127.0.0.1:8443",
                "cert": "c.pem", "key": "k.pem", "ca": "ca.pem",
                "client_vmac": "02:00:00:00:00:01",
                "server_vmac": "02:00:00:00:00:02",
                "network_number": 2
            }
        }
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("hub_vmac"));
}

#[test]
fn validate_sc_embedded_hub_rejects_duplicate_hub_vmac() {
    let json = r#"{
        "device": { "instance": 1, "name": "Test" },
        "transports": {
            "sc": {
                "listen": "127.0.0.1:8443",
                "cert": "c.pem", "key": "k.pem", "ca": "ca.pem",
                "hub_vmac": "02:00:00:00:00:01",
                "client_vmac": "02:00:00:00:00:01",
                "server_vmac": "02:00:00:00:00:02",
                "network_number": 2
            }
        }
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("hub_vmac") && err.message.contains("differ"));
}

#[test]
fn validate_sc_embedded_hub_wildcard_listen_requires_hub_uri() {
    let json = r#"{
        "device": { "instance": 1, "name": "Test" },
        "transports": {
            "sc": {
                "listen": "0.0.0.0:8443",
                "cert": "c.pem", "key": "k.pem", "ca": "ca.pem",
                "hub_vmac": "02:00:00:00:00:ff",
                "client_vmac": "02:00:00:00:00:01",
                "server_vmac": "02:00:00:00:00:02",
                "network_number": 2
            }
        }
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("hub_uri") && err.message.contains("wildcard"));
}

#[test]
fn validate_sc_node_mode_accepted() {
    let json = r#"{
        "device": { "instance": 1, "name": "SC Node Gateway" },
        "transports": {
            "sc": {
                "hub_uri": "wss://hub.example.com",
                "cert": "certs/node.pem", "key": "certs/node.key", "ca": "certs/ca.pem",
                "client_vmac": "02:00:00:00:00:01",
                "server_vmac": "020000000002",
                "network_number": 2
            }
        }
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    config.validate().unwrap();
}

#[test]
fn validate_sc_rejects_duplicate_vmacs() {
    let json = r#"{
        "device": { "instance": 1, "name": "SC Node Gateway" },
        "transports": {
            "sc": {
                "hub_uri": "wss://hub.example.com",
                "cert": "certs/node.pem", "key": "certs/node.key",
                "client_vmac": "02:00:00:00:00:01",
                "server_vmac": "020000000001",
                "network_number": 2
            }
        }
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("must differ"));
}

#[test]
fn parse_sc_vmac_rejects_reserved_values() {
    let err = parse_sc_vmac("00:00:00:00:00:00").unwrap_err();
    assert!(err.contains("reserved"));
    let err = parse_sc_vmac("ff:ff:ff:ff:ff:ff").unwrap_err();
    assert!(err.contains("reserved"));
}

#[test]
fn validate_unknown_route_transport_rejected() {
    let json = r#"{
        "device": { "instance": 1, "name": "Test" },
        "transports": {
            "bip": { "broadcast": "192.168.1.255", "network_number": 1 }
        },
        "routes": [ { "network": 5, "via_transport": "mstp" } ]
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("mstp") || err.message.contains("unknown"));
}

#[test]
fn validate_route_transport_must_be_active_transport() {
    let json = r#"{
        "device": { "instance": 1, "name": "Test" },
        "transports": {
            "bip": { "broadcast": "192.168.1.255", "network_number": 1 }
        },
        "routes": [ { "network": 5, "via_transport": "sc" } ]
    }"#;
    let config = GatewayConfig::from_json(json).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.message.contains("not configured"));
}
