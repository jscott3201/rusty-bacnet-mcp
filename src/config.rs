//! JSON configuration parsing and validation.
//!
//! The project uses JSON exclusively for application config — no TOML or YAML.
//! JSON is unambiguous, agent-friendly, and supported by every language without
//! external tooling. (Cargo.toml is the one TOML file in the repo, mandated by
//! the Rust ecosystem; that's outside this project's config surface.)

use serde::Deserialize;
use std::collections::HashSet;

/// Top-level gateway configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GatewayConfig {
    /// MCP server settings.
    #[serde(default)]
    pub mcp: McpConfig,
    /// Local BACnet device identity.
    pub device: DeviceConfig,
    /// Transport configurations.
    #[serde(default)]
    pub transports: TransportsConfig,
    /// BBMD configuration (mutually exclusive with foreign_device).
    #[serde(default)]
    pub bbmd: Option<BbmdConfig>,
    /// Foreign device registration (mutually exclusive with bbmd).
    #[serde(default)]
    pub foreign_device: Option<ForeignDeviceConfig>,
    /// Static routing table entries.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    /// Pre-populated local objects.
    #[serde(default)]
    pub objects: Vec<ObjectConfig>,
}

/// MCP server settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct McpConfig {
    /// Bearer-token API key. If omitted, no auth is applied to the streamable-HTTP
    /// transport. Stdio transport relies on transport-level identity, so auth is
    /// not enforced there regardless of this setting.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Read-only mode. When true, all write operations (write_property,
    /// create_object, delete_object, write_local_property) are rejected.
    /// Default is `true` — operators must explicitly opt in to writes.
    #[serde(default = "default_read_only")]
    pub read_only: bool,
    /// Optional streamable-HTTP transport configuration. Presence of this block
    /// is independent of the `--transport` CLI flag; when both `--transport http`
    /// and this block are missing a bind address, startup fails.
    #[serde(default)]
    pub http: Option<McpHttpConfig>,
    /// Layered safety policy for write operations. Missing block = conservative
    /// defaults (life-safety object types denied, priorities 1–8 reserved,
    /// `device:0` always denied). See `crate::safety::WritePolicy`.
    #[serde(default)]
    pub safety: Option<SafetyConfig>,
    /// Audit log configuration. Missing block = in-memory ring buffer only,
    /// surfaced via the `bacnet://audit/recent` MCP resource.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            read_only: default_read_only(),
            http: None,
            safety: None,
            audit: None,
        }
    }
}

/// Layered safety policy for write operations.
///
/// Every field is optional; missing fields fall back to the conservative
/// defaults baked into `WritePolicy::default_safe()`. Operators only override
/// what they want to relax — they never have to redeclare the safe baseline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct SafetyConfig {
    /// Object-type allowlist. When set, only writes targeting these types are
    /// permitted. Names are the kebab-case forms accepted by `parse_object_type`
    /// (e.g. `"analog-output"`, `"binary-value"`). Vendor types are written
    /// as `"vendor-N"` where N is the proprietary type id.
    #[serde(default)]
    pub allow_object_types: Option<Vec<String>>,
    /// Object-type denylist. Defaults to life-safety types
    /// (`life-safety-point`, `life-safety-zone`, `notification-class`).
    /// Setting this to an empty array (`[]`) explicitly disables type denial.
    #[serde(default)]
    pub deny_object_types: Option<Vec<String>>,
    /// Per-object allowlist. Each entry is a `"<type>:<instance>"` pair (e.g.
    /// `"analog-output:42"`).
    #[serde(default)]
    pub allow_objects: Option<Vec<String>>,
    /// Per-object denylist. `"device:0"` is always denied regardless of this
    /// field — it's an undefined target for WriteProperty.
    #[serde(default)]
    pub deny_objects: Option<Vec<String>>,
    /// Minimum BACnet command priority a write may target. Default `9` blocks
    /// priorities 1–8 (life-safety / manual-life-safety per ASHRAE 135-2020
    /// Table 19-1). Set to `1` to disable the floor entirely.
    #[serde(default)]
    pub min_priority: Option<u8>,
    /// Maximum priority. Default `16`. Operators rarely need to set this.
    #[serde(default)]
    pub max_priority: Option<u8>,
}

/// Audit log configuration.
///
/// The in-memory ring buffer is always present (it's the surface for the
/// `bacnet://audit/recent` MCP resource). The optional `path` mirrors every
/// entry to a JSON-Lines file so the log survives daemon restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct AuditConfig {
    /// Ring-buffer capacity. Default 5000 entries. Older entries evict on
    /// insert past the cap.
    #[serde(default)]
    pub capacity: Option<usize>,
    /// Optional path to a JSON-Lines file. The file is opened append-only on
    /// each write — no file handle is held across operations, so log rotation
    /// (e.g. via `logrotate`) works without the daemon noticing.
    #[serde(default)]
    pub path: Option<String>,
}

fn default_read_only() -> bool {
    true
}

/// Streamable-HTTP MCP transport configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct McpHttpConfig {
    /// Bind address for the HTTP listener.
    #[serde(default = "default_http_bind")]
    pub bind: String,
}

impl Default for McpHttpConfig {
    fn default() -> Self {
        Self {
            bind: default_http_bind(),
        }
    }
}

fn default_http_bind() -> String {
    "127.0.0.1:3000".to_string()
}

/// Local BACnet device identity.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceConfig {
    /// Device instance number (0–4194302).
    pub instance: u32,
    /// Device object name.
    pub name: String,
    /// Vendor identifier.
    #[serde(default = "default_vendor_id")]
    pub vendor_id: u16,
    /// Device description.
    #[serde(default)]
    pub description: String,
}

fn default_vendor_id() -> u16 {
    999
}

/// Transport configurations.
///
/// BACnet/IP and BACnet/SC are the supported transports. MS/TP support
/// was removed in 0.2.0 to focus the project on IP-based BACnet networks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct TransportsConfig {
    /// BACnet/IP transport.
    #[serde(default)]
    pub bip: Option<BipConfig>,
    /// BACnet/SC transport (Hub or Node).
    #[serde(default)]
    pub sc: Option<ScConfig>,
}

/// BACnet/IP transport configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BipConfig {
    /// Bind interface address.
    #[serde(default = "default_interface")]
    pub interface: String,
    /// UDP port.
    #[serde(default = "default_bip_port")]
    pub port: u16,
    /// Subnet broadcast address.
    pub broadcast: String,
    /// Network number for this transport.
    pub network_number: u16,
}

fn default_interface() -> String {
    "0.0.0.0".to_string()
}

fn default_bip_port() -> u16 {
    47808
}

/// BACnet/SC transport configuration.
///
/// SC supports two roles:
/// - **Node**: connects out to a remote hub (set `hub_uri`).
/// - **Hub**: listens for incoming SC node connections (set `listen` and omit `hub_uri`).
///
/// `listen` and `hub_uri` are mutually exclusive — a single SC transport
/// runs in exactly one role.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ScConfig {
    /// Node mode: WebSocket URI of the remote SC hub (e.g. `wss://hub.example.com:8443`).
    /// Omit for Hub mode.
    #[serde(default)]
    pub hub_uri: Option<String>,
    /// Hub mode: bind address for incoming WebSocket connections (e.g. `0.0.0.0:8443`).
    /// Omit for Node mode.
    #[serde(default)]
    pub listen: Option<String>,
    /// TLS client/server certificate path (PEM).
    pub cert: String,
    /// TLS private key path (PEM).
    pub key: String,
    /// CA bundle for peer verification (PEM).
    #[serde(default)]
    pub ca: Option<String>,
    /// Network number for this transport.
    pub network_number: u16,
}

/// BBMD configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BbmdConfig {
    /// Enable BBMD on the BIP transport.
    #[serde(default)]
    pub enabled: bool,
    /// Initial Broadcast Distribution Table entries (IP:port strings).
    #[serde(default)]
    pub bdt: Vec<String>,
}

/// Foreign device registration configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ForeignDeviceConfig {
    /// BBMD address to register with (IP:port).
    pub bbmd: String,
    /// Time-to-live in seconds.
    pub ttl: u16,
}

/// Static route entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RouteConfig {
    /// Destination network number.
    pub network: u16,
    /// Transport to route through (`"bip"` or `"sc"`).
    pub via_transport: String,
    /// Next hop address (optional, for routed networks).
    #[serde(default)]
    pub next_hop: Option<String>,
}

/// Pre-populated local object.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ObjectConfig {
    /// Object type name (e.g., "analog-value").
    #[serde(rename = "type")]
    pub object_type: String,
    /// Object instance number.
    pub instance: u32,
    /// Object name.
    pub name: String,
    /// Engineering units (optional).
    #[serde(default)]
    pub units: Option<String>,
    /// Number of states for multi-state objects (default: 2).
    #[serde(default)]
    pub number_of_states: Option<u32>,
}

/// Configuration validation error.
#[derive(Debug, Clone)]
pub struct ConfigError {
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "config error: {}", self.message)
    }
}

impl std::error::Error for ConfigError {}

impl GatewayConfig {
    /// Parse a JSON string into a GatewayConfig.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Device instance range
        if self.device.instance > 4_194_302 {
            return Err(ConfigError {
                message: format!(
                    "device instance {} exceeds maximum 4194302",
                    self.device.instance
                ),
            });
        }

        // BBMD and foreign_device are mutually exclusive
        if self.bbmd.is_some() && self.foreign_device.is_some() {
            return Err(ConfigError {
                message: "bbmd and foreign_device are mutually exclusive".to_string(),
            });
        }

        // BBMD requires BIP transport
        if let Some(bbmd) = &self.bbmd
            && bbmd.enabled
            && self.transports.bip.is_none()
        {
            return Err(ConfigError {
                message: "bbmd requires transports.bip to be configured".to_string(),
            });
        }

        // SC role: Hub vs Node — `listen` and `hub_uri` are mutually exclusive,
        // and exactly one must be set.
        if let Some(sc) = &self.transports.sc {
            match (sc.listen.as_ref(), sc.hub_uri.as_ref()) {
                (Some(_), Some(_)) => {
                    return Err(ConfigError {
                        message:
                            "transports.sc cannot set both `listen` (Hub) and `hub_uri` (Node)"
                                .to_string(),
                    });
                }
                (None, None) => {
                    return Err(ConfigError {
                        message: "transports.sc requires either `listen` (Hub mode) or `hub_uri` (Node mode)".to_string(),
                    });
                }
                _ => {}
            }
        }

        // Validate and check uniqueness of network numbers.
        let mut network_numbers = HashSet::new();
        let transport_networks: Vec<(u16, &str)> = [
            self.transports
                .bip
                .as_ref()
                .map(|t| (t.network_number, "bip")),
            self.transports
                .sc
                .as_ref()
                .map(|t| (t.network_number, "sc")),
        ]
        .into_iter()
        .flatten()
        .collect();

        for (num, name) in &transport_networks {
            if *num == 0 {
                return Err(ConfigError {
                    message: format!(
                        "{name} network_number 0 is reserved (local-only, no routing)"
                    ),
                });
            }
            if *num == 65535 {
                return Err(ConfigError {
                    message: format!("{name} network_number 65535 is reserved (broadcast)"),
                });
            }
            if !network_numbers.insert(*num) {
                return Err(ConfigError {
                    message: format!("duplicate network number {num}"),
                });
            }
        }

        // Safety policy validation. Catches malformed `mcp.safety` blocks at
        // config load instead of at the first MCP write call. This is also
        // the place that pins BACnet's 1–16 priority range — Codex P2 in
        // PR #3 review flagged that out-of-range values were silently
        // accepted before this check landed.
        if let Some(safety) = &self.mcp.safety {
            if let Some(min) = safety.min_priority
                && !(1..=16).contains(&min)
            {
                return Err(ConfigError {
                    message: format!("mcp.safety.min_priority {min} is out of BACnet range 1..=16"),
                });
            }
            if let Some(max) = safety.max_priority
                && !(1..=16).contains(&max)
            {
                return Err(ConfigError {
                    message: format!("mcp.safety.max_priority {max} is out of BACnet range 1..=16"),
                });
            }
            if let (Some(min), Some(max)) = (safety.min_priority, safety.max_priority)
                && min > max
            {
                return Err(ConfigError {
                    message: format!(
                        "mcp.safety.min_priority ({min}) must be ≤ max_priority ({max})"
                    ),
                });
            }
            // Build the policy once at validate-time so type/object name
            // parse errors fail loudly here rather than at hot-reload.
            crate::safety::WritePolicy::from_config(safety)
                .map_err(|message| ConfigError { message })?;
        }

        // Routes can only target known transports.
        for route in &self.routes {
            match route.via_transport.as_str() {
                "bip" | "sc" => {}
                other => {
                    return Err(ConfigError {
                        message: format!(
                            "route via_transport '{other}' is unknown (must be 'bip' or 'sc')"
                        ),
                    });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                },
                "sc": {
                    "hub_uri": "wss://hub.example.com",
                    "cert": "certs/client.pem",
                    "key": "certs/client.key",
                    "network_number": 2
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
        assert!(config.transports.sc.is_some());
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].network, 4);
        assert_eq!(config.objects.len(), 1);
        assert_eq!(config.objects[0].object_type, "analog-value");
        config.validate().unwrap();
    }

    #[test]
    fn parse_minimal_config_is_read_only_by_default() {
        let json = r#"{
            "device": { "instance": 1234, "name": "Minimal" }
        }"#;
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
        config.validate().unwrap();
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
    fn validate_duplicate_network_numbers() {
        let json = r#"{
            "device": { "instance": 1, "name": "Test" },
            "transports": {
                "bip": { "broadcast": "192.168.1.255", "network_number": 1 },
                "sc": {
                    "hub_uri": "wss://hub.example.com",
                    "cert": "c.pem", "key": "k.pem",
                    "network_number": 1
                }
            }
        }"#;
        let config = GatewayConfig::from_json(json).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("duplicate network number"));
    }

    #[test]
    fn validate_network_number_zero_rejected() {
        let json = r#"{
            "device": { "instance": 1, "name": "Test" },
            "transports": {
                "bip": { "broadcast": "192.168.1.255", "network_number": 0 }
            }
        }"#;
        let config = GatewayConfig::from_json(json).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("reserved"));
    }

    #[test]
    fn validate_network_number_broadcast_rejected() {
        let json = r#"{
            "device": { "instance": 1, "name": "Test" },
            "transports": {
                "bip": { "broadcast": "192.168.1.255", "network_number": 65535 }
            }
        }"#;
        let config = GatewayConfig::from_json(json).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("reserved"));
    }

    #[test]
    fn validate_sc_requires_hub_or_node_mode() {
        let json = r#"{
            "device": { "instance": 1, "name": "Test" },
            "transports": {
                "sc": { "cert": "c.pem", "key": "k.pem", "network_number": 2 }
            }
        }"#;
        let config = GatewayConfig::from_json(json).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("Hub mode") || err.message.contains("Node mode"));
    }

    #[test]
    fn validate_sc_hub_and_node_mutually_exclusive() {
        let json = r#"{
            "device": { "instance": 1, "name": "Test" },
            "transports": {
                "sc": {
                    "hub_uri": "wss://hub.example.com",
                    "listen": "0.0.0.0:8443",
                    "cert": "c.pem", "key": "k.pem",
                    "network_number": 2
                }
            }
        }"#;
        let config = GatewayConfig::from_json(json).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.message.contains("Hub") && err.message.contains("Node"));
    }

    #[test]
    fn validate_sc_hub_mode_accepted() {
        let json = r#"{
            "device": { "instance": 1, "name": "SC Hub Gateway" },
            "transports": {
                "sc": {
                    "listen": "0.0.0.0:8443",
                    "cert": "certs/hub.pem", "key": "certs/hub.key", "ca": "certs/ca.pem",
                    "network_number": 2
                }
            }
        }"#;
        let config = GatewayConfig::from_json(json).unwrap();
        config.validate().unwrap();
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
}
