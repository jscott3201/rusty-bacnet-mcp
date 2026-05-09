//! Topology graph aggregator — builds the `bacnet://topology/graph` resource.
//!
//! Returns a JSON view of the BACnet topology this gateway has observed.
//! v1 is **always-stale**: the graph is built at read-time from existing
//! in-memory state, with no fresh wire calls and no background polling task.
//!
//! What's surfaced:
//! - **local_device** — the gateway's own device identity from config.
//! - **networks** — the union of: the gateway's local transport networks
//!   (from `transports.bip`/`transports.sc`), every distinct `source_network`
//!   observed in the discovered-devices table, and every `network` listed
//!   in `config.routes`.
//! - **devices** — every entry in `client.discovered_devices()`, placed on
//!   its `source_network` (or the local transport network when
//!   `source_network` is `None`, meaning the IAm came from a directly-
//!   reachable peer).
//! - **gateway_routes** — `config.routes`, each saying "this gateway reaches
//!   network N via `via_transport` (and optionally `next_hop`)". These are
//!   *output* paths, not bidirectional bridges.
//!
//! What's deliberately **not** surfaced (v2 work):
//! - "Router device X bridges networks A↔B" — the non-router NetworkLayer
//!   in `bacnet-network` discards I-Am-Router-To-Network messages at the
//!   dispatch boundary (`layer.rs:86-92`), so a client-side observer needs
//!   an upstream hook before we can aggregate this signal.
//! - BBMD peer relationships and foreign-device registrations — `probe_bbmd`
//!   surfaces these on demand for one BBMD at a time, but caching them
//!   into the graph requires a probe-result store this module deliberately
//!   avoids in v1.
//!
//! Both gaps are reported back in the `limitations` field so agents reading
//! the graph know what *isn't* in it and don't draw false conclusions from
//! absence.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::state::GatewayState;

/// Build the topology graph from current in-memory state.
///
/// Async only because `client.discovered_devices()` is async; the call is a
/// lock-and-clone, not network I/O.
pub async fn build_graph(state: &GatewayState) -> Value {
    let config = state.config.as_ref();

    // Local transport networks: each configured transport advertises its
    // own network number. Used as the "fallback network" for devices whose
    // source_network is None (directly-reachable IAm).
    let mut local_networks: Vec<(u16, &str)> = Vec::new();
    if let Some(bip) = &config.transports.bip {
        local_networks.push((bip.network_number, "bip"));
    }
    if let Some(sc) = &config.transports.sc {
        local_networks.push((sc.network_number, "sc"));
    }
    let primary_local_network = local_networks.first().map(|(n, _)| *n);

    // Discovered devices — only available when the client has been started.
    // For the unstarted case (test fixtures, --print-config), build the
    // graph from config alone so the resource still has a useful shape.
    let discovered = match state.require_client() {
        Ok(client) => client.discovered_devices().await,
        Err(_) => Vec::new(),
    };

    // Aggregate device counts per network. BTreeMap so iteration order is
    // stable (network number ascending) — output JSON shouldn't shuffle
    // between reads.
    let mut network_devices: BTreeMap<u16, usize> = BTreeMap::new();
    for net in local_networks.iter().map(|(n, _)| *n) {
        network_devices.entry(net).or_insert(0);
    }
    for r in &config.routes {
        network_devices.entry(r.network).or_insert(0);
    }
    for d in &discovered {
        let net = d.source_network.or(primary_local_network).unwrap_or(0);
        *network_devices.entry(net).or_insert(0) += 1;
    }

    // Build the networks array. Mark each entry with its transport name
    // (when it's one of the gateway's local networks) and an `is_local`
    // flag so agents can quickly tell which networks are directly-attached
    // vs reached through a router.
    let networks_json: Vec<Value> = network_devices
        .iter()
        .map(|(net, count)| {
            let transport = local_networks
                .iter()
                .find(|(n, _)| n == net)
                .map(|(_, t)| *t);
            let mut obj = json!({
                "number": *net,
                "is_local": transport.is_some(),
                "device_count": *count,
            });
            if let Some(t) = transport {
                obj["transport"] = json!(t);
            }
            obj
        })
        .collect();

    let devices_json: Vec<Value> = discovered
        .iter()
        .map(|d| {
            let net = d.source_network.or(primary_local_network).unwrap_or(0);
            json!({
                "instance": d.object_identifier.instance_number(),
                "vendor_id": d.vendor_id,
                "mac": format_mac(d.mac_address.as_slice()),
                "network": net,
                "max_apdu": d.max_apdu_length,
            })
        })
        .collect();

    let routes_json: Vec<Value> = config
        .routes
        .iter()
        .map(|r| {
            let mut obj = json!({
                "network": r.network,
                "via_transport": r.via_transport,
            });
            if let Some(hop) = &r.next_hop {
                obj["next_hop"] = json!(hop);
            }
            obj
        })
        .collect();

    json!({
        "local_device": {
            "instance": config.device.instance,
            "name": config.device.name,
            "vendor_id": config.device.vendor_id,
        },
        "networks": networks_json,
        "devices": devices_json,
        "gateway_routes": routes_json,
        "summary": {
            "total_networks": networks_json.len(),
            "total_devices": devices_json.len(),
            "total_gateway_routes": routes_json.len(),
        },
        "limitations": [
            "BBMD peer relationships not included — call probe_bbmd to inspect a specific BBMD's BDT/FDT",
            "Inter-network router devices not identified — bacnet-network 0.9 discards I-Am-Router-To-Network messages on the client side, so the gateway can't aggregate them yet (v2 work)",
            "Devices with no IAm received are absent — call discover_devices to populate the table",
        ],
    })
}

/// Render a BACnet MAC address as colon-separated hex. Works for any
/// transport — BIP MACs are 6 bytes (4 IP + 2 port), MS/TP is 1 byte,
/// SC VMACs are 6 bytes. The agent reading the JSON gets a shape that
/// round-trips back through `parse::socket_addr_to_mac` for the BIP case.
fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_mac_renders_bip_address() {
        // BIP MAC = 4-byte IP + 2-byte port (big-endian).
        let mac = [0xc0, 0xa8, 0x01, 0x0a, 0xba, 0xc0];
        assert_eq!(format_mac(&mac), "c0:a8:01:0a:ba:c0");
    }

    #[test]
    fn format_mac_renders_mstp_address() {
        let mac = [0x05];
        assert_eq!(format_mac(&mac), "05");
    }

    #[test]
    fn format_mac_handles_empty_slice() {
        assert_eq!(format_mac(&[]), "");
    }
}
