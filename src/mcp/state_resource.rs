//! Live MCP state resource formatting.

use crate::config::describe_sc_runtime;
use crate::mcp::{discovery, objects, topology};
use crate::state::GatewayState;

const PCAP_CAPTURE_RESOURCE_ROWS: usize = 25;

pub async fn read_state_resource(state: &GatewayState, uri: &str) -> Option<String> {
    match uri {
        "bacnet://state/devices" => Some(read_devices_resource(state).await),
        "bacnet://state/local-objects" => Some(read_local_objects_resource(state).await),
        "bacnet://audit/recent" => Some(read_audit_resource(state)),
        "bacnet://state/config" => Some(read_config_resource(state)),
        "bacnet://state/pcap-captures" => Some(
            state
                .pcap_captures
                .format_list(true, PCAP_CAPTURE_RESOURCE_ROWS),
        ),
        "bacnet://topology/graph" => Some(read_topology_resource(state).await),
        _ => None,
    }
}

async fn read_devices_resource(state: &GatewayState) -> String {
    match state.require_client() {
        Ok(client) => {
            let devices = client.discovered_devices().await;
            if devices.is_empty() {
                "No discovered devices.".to_string()
            } else {
                discovery::format_device_list(
                    devices,
                    discovery::DEFAULT_DEVICE_LIST_LIMIT,
                    discovery::DeviceListFormat::StateResource,
                )
            }
        }
        Err(_) => "No devices (client not started).".to_string(),
    }
}

async fn read_local_objects_resource(state: &GatewayState) -> String {
    let db = state.db.read().await;
    let rows = objects::collect_local_object_rows(&db, None);
    objects::format_local_object_rows(
        &rows,
        objects::DEFAULT_LIST_LOCAL_OBJECTS_LIMIT,
        objects::LocalObjectListFormat::StateResource,
    )
}

fn read_audit_resource(state: &GatewayState) -> String {
    let entries = state.audit.snapshot(100);
    let mut out = format!(
        "{} audit entr{} (most recent last):\n",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }
    );
    for e in &entries {
        out.push_str(&format_audit_line(e));
    }
    out
}

fn read_config_resource(state: &GatewayState) -> String {
    let config = &state.config;
    let mut result = String::new();
    result.push_str(&format!(
        "Device: {} (instance {})\n",
        config.device.name, config.device.instance
    ));
    result.push_str(&format!(
        "Mode: {}\n",
        if state.is_read_only() {
            "read-only"
        } else {
            "writable"
        }
    ));
    if let Some(http) = &config.mcp.http {
        result.push_str(&format!("HTTP transport bind: {}\n", http.bind));
    }
    result.push_str(&format!(
        "Auth: {}\n",
        if config.mcp.api_key.is_some() {
            "enabled (bearer token)"
        } else {
            "disabled"
        }
    ));
    if let Some(bip) = &config.transports.bip {
        result.push_str(&format!(
            "Transport BIP: {}:{}, network {}\n",
            bip.interface, bip.port, bip.network_number
        ));
    }
    if let Some(sc) = &config.transports.sc {
        result.push_str(&format!(
            "Transport SC: {}, network {}\n",
            describe_sc_runtime(sc),
            sc.network_number
        ));
    }
    result
}

async fn read_topology_resource(state: &GatewayState) -> String {
    let graph = topology::build_graph(state).await;
    serde_json::to_string_pretty(&graph)
        .unwrap_or_else(|e| format!("{{\"error\": \"serialize topology: {e}\"}}"))
}

/// Render one audit entry as a single line for the `bacnet://audit/recent`
/// resource. Format is human-readable and stable enough to grep:
/// `<iso-timestamp> <decision> <tool> <target> <property> [pri=N] [dry-run] reason`
fn format_audit_line(e: &crate::audit::AuditEntry) -> String {
    let secs = (e.at_ms / 1000) as i64;
    let ms = (e.at_ms % 1000) as u32;
    let ts = format!("epoch+{secs}.{ms:03}");

    let target = e.target.as_deref().unwrap_or("-");
    let property = e.property.as_deref().unwrap_or("-");
    let pri = e.priority.map(|p| format!(" pri={p}")).unwrap_or_default();
    let dry = if e.dry_run { " dry-run" } else { "" };
    let reason = if e.reason.is_empty() {
        String::new()
    } else {
        format!(" — {}", e.reason)
    };
    format!(
        "  {ts} {decision:>5} {tool} {target} {property}{pri}{dry}{reason}\n",
        decision = e.decision,
        tool = e.tool,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
    use bacnet_objects::database::ObjectDatabase;

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

    #[tokio::test]
    async fn pcap_capture_resource_lists_empty_registry() {
        let state = GatewayState::new(ObjectDatabase::new(), test_config());

        let out = read_state_resource(&state, "bacnet://state/pcap-captures")
            .await
            .unwrap();

        assert!(out.contains("pcap capture sessions"));
        assert!(out.contains("showing 0/0"));
        assert!(out.contains("  -"));
    }

    #[tokio::test]
    async fn unknown_state_resource_returns_none() {
        let state = GatewayState::new(ObjectDatabase::new(), test_config());

        assert!(
            read_state_resource(&state, "bacnet://state/not-real")
                .await
                .is_none()
        );
    }
}
