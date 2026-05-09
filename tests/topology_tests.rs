//! Topology graph integration tests.
//!
//! Anchors the JSON shape and the always-stale-view contract: the graph
//! is built from in-memory state alone, no fresh wire calls, and the
//! `limitations` field is always present so agents know what isn't there.

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{
    BipConfig, DeviceConfig, GatewayConfig, McpConfig, RouteConfig, TransportsConfig,
};
use bacnet_mcp::mcp::topology::build_graph;
use bacnet_mcp::state::GatewayState;

use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig as BacnetDeviceConfig, DeviceObject};

fn test_state(routes: Vec<RouteConfig>) -> GatewayState {
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
        transports: TransportsConfig {
            bip: Some(BipConfig {
                interface: "127.0.0.1".to_string(),
                port: 47808,
                broadcast: "127.255.255.255".to_string(),
                network_number: 1,
            }),
            sc: None,
        },
        bbmd: None,
        foreign_device: None,
        routes,
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
async fn topology_graph_has_required_top_level_fields() {
    let state = test_state(vec![]);
    let graph = build_graph(&state).await;
    // Top-level shape is part of the contract — anchor every field so a
    // future refactor can't silently drop one.
    for field in [
        "local_device",
        "networks",
        "devices",
        "gateway_routes",
        "summary",
        "limitations",
    ] {
        assert!(
            graph.get(field).is_some(),
            "topology graph missing field: {field}\nfull graph: {graph}"
        );
    }
}

#[tokio::test]
async fn topology_graph_local_device_reflects_config() {
    let state = test_state(vec![]);
    let graph = build_graph(&state).await;
    let local = graph.get("local_device").unwrap();
    assert_eq!(local["instance"], 1234);
    assert_eq!(local["name"], "Test Gateway");
    assert_eq!(local["vendor_id"], 999);
}

#[tokio::test]
async fn topology_graph_includes_local_transport_network() {
    // The configured BIP network (1) must appear in the networks list with
    // is_local=true and transport=bip, even when no devices are discovered.
    // This is the "the graph is useful before any discovery happens" check.
    let state = test_state(vec![]);
    let graph = build_graph(&state).await;
    let networks = graph["networks"].as_array().unwrap();
    let local_net = networks
        .iter()
        .find(|n| n["number"] == 1)
        .expect("local BIP network 1 must appear in networks");
    assert_eq!(local_net["is_local"], true);
    assert_eq!(local_net["transport"], "bip");
    assert_eq!(local_net["device_count"], 0);
}

#[tokio::test]
async fn topology_graph_includes_configured_routes() {
    // Routes from config should appear in gateway_routes verbatim AND
    // their target networks should appear in the networks list (even if
    // no devices on those networks have been discovered yet).
    let routes = vec![
        RouteConfig {
            network: 5,
            via_transport: "bip".to_string(),
            next_hop: Some("192.168.1.50:47808".to_string()),
        },
        RouteConfig {
            network: 7,
            via_transport: "sc".to_string(),
            next_hop: None,
        },
    ];
    let state = test_state(routes);
    let graph = build_graph(&state).await;

    let gw_routes = graph["gateway_routes"].as_array().unwrap();
    assert_eq!(gw_routes.len(), 2);
    let route5 = gw_routes.iter().find(|r| r["network"] == 5).unwrap();
    assert_eq!(route5["via_transport"], "bip");
    assert_eq!(route5["next_hop"], "192.168.1.50:47808");
    let route7 = gw_routes.iter().find(|r| r["network"] == 7).unwrap();
    assert_eq!(route7["via_transport"], "sc");
    assert!(
        route7.get("next_hop").is_none(),
        "next_hop should be omitted when not configured"
    );

    let networks = graph["networks"].as_array().unwrap();
    for net in [5u64, 7] {
        let entry = networks
            .iter()
            .find(|n| n["number"] == net)
            .unwrap_or_else(|| panic!("network {net} from config.routes missing from networks"));
        assert_eq!(entry["is_local"], false);
    }
}

#[tokio::test]
async fn topology_graph_summary_counts_match_arrays() {
    let routes = vec![RouteConfig {
        network: 5,
        via_transport: "bip".to_string(),
        next_hop: None,
    }];
    let state = test_state(routes);
    let graph = build_graph(&state).await;
    let summary = &graph["summary"];
    let networks_len = graph["networks"].as_array().unwrap().len();
    let devices_len = graph["devices"].as_array().unwrap().len();
    let routes_len = graph["gateway_routes"].as_array().unwrap().len();
    assert_eq!(summary["total_networks"], networks_len);
    assert_eq!(summary["total_devices"], devices_len);
    assert_eq!(summary["total_gateway_routes"], routes_len);
}

#[tokio::test]
async fn topology_graph_limitations_array_is_non_empty() {
    // The limitations field is part of the v1 contract — agents read it
    // to understand what *isn't* in the graph. Dropping it would let
    // agents draw false conclusions from absence (e.g. "no router devices
    // listed → must be a flat network").
    let state = test_state(vec![]);
    let graph = build_graph(&state).await;
    let limits = graph["limitations"].as_array().unwrap();
    assert!(!limits.is_empty(), "limitations must list known v1 gaps");
    let joined: String = limits
        .iter()
        .map(|v| v.as_str().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ");
    // The two big v2 items from the design conversation must be called
    // out by name so an agent reading just this field knows what's
    // missing.
    assert!(
        joined.contains("BBMD"),
        "limitations should mention BBMD-peer gap"
    );
    assert!(
        joined.contains("router"),
        "limitations should mention I-Am-Router gap"
    );
}

#[tokio::test]
async fn topology_graph_no_panic_when_client_unstarted() {
    // No client started → discovered_devices() unreachable. The aggregator
    // must degrade gracefully, returning a config-only view rather than
    // panicking. This is the "useful before discovery" contract from the
    // module doc-comment.
    let state = test_state(vec![]);
    let graph = build_graph(&state).await;
    assert_eq!(graph["devices"].as_array().unwrap().len(), 0);
    assert_eq!(graph["summary"]["total_devices"], 0);
}
