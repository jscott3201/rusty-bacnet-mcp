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
/// The MCP gateway runs as a BACnet/SC node: its local client and local server
/// each connect to an SC hub over TLS WebSocket. `client_vmac` and
/// `server_vmac` must be distinct stable 6-byte VMACs so the hub can route
/// requests and notifications unambiguously.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ScConfig {
    /// WebSocket URI of the remote SC hub (e.g. `wss://hub.example.com:8443`).
    #[serde(default)]
    pub hub_uri: Option<String>,
    /// Reserved for a future embedded SC hub. Runtime transport support today
    /// requires `hub_uri`; validation rejects `listen` so configs cannot look
    /// like they started a local hub when they did not.
    #[serde(default)]
    pub listen: Option<String>,
    /// TLS client/server certificate path (PEM).
    pub cert: String,
    /// TLS private key path (PEM).
    pub key: String,
    /// CA bundle for peer verification (PEM).
    #[serde(default)]
    pub ca: Option<String>,
    /// VMAC used by the MCP client's SC node, formatted as
    /// `01:02:03:04:05:06` or `010203040506`.
    pub client_vmac: String,
    /// VMAC used by the local BACnet server's SC node, formatted as
    /// `01:02:03:04:05:06` or `010203040506`.
    pub server_vmac: String,
    /// Network number for this transport.
    pub network_number: u16,
}

/// Parse a BACnet/SC VMAC from colon-separated or compact hex.
pub fn parse_sc_vmac(raw: &str) -> Result<[u8; 6], String> {
    let compact = raw.replace([':', '-'], "");
    if compact.len() != 12 {
        return Err(format!(
            "SC VMAC '{raw}' must contain exactly 12 hex digits"
        ));
    }
    let mut vmac = [0u8; 6];
    for (idx, slot) in vmac.iter_mut().enumerate() {
        let start = idx * 2;
        let byte = u8::from_str_radix(&compact[start..start + 2], 16)
            .map_err(|e| format!("SC VMAC '{raw}' contains invalid hex: {e}"))?;
        *slot = byte;
    }
    if is_reserved_sc_vmac(&vmac) {
        return Err(format!(
            "SC VMAC '{raw}' is reserved; all-zero and all-ff VMACs are invalid"
        ));
    }
    Ok(vmac)
}

fn is_reserved_sc_vmac(vmac: &[u8; 6]) -> bool {
    *vmac == [0; 6] || *vmac == [0xff; 6]
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

        let has_bip = self.transports.bip.is_some();
        let has_sc = self.transports.sc.is_some();

        // BBMD requires BIP transport
        if let Some(bbmd) = &self.bbmd
            && bbmd.enabled
            && self.transports.bip.is_none()
        {
            return Err(ConfigError {
                message: "bbmd requires transports.bip to be configured".to_string(),
            });
        }

        match (has_bip, has_sc) {
            (true, true) => {
                return Err(ConfigError {
                    message:
                        "configure exactly one runtime transport: transports.bip or transports.sc"
                            .to_string(),
                });
            }
            (false, false) => {
                return Err(ConfigError {
                    message:
                        "configure exactly one runtime transport: transports.bip or transports.sc"
                            .to_string(),
                });
            }
            _ => {}
        }

        // SC runtime: node mode only today. Embedded hub support needs shared
        // local database/router wiring before it can be represented honestly.
        if let Some(sc) = &self.transports.sc {
            if sc.listen.is_some() {
                return Err(ConfigError {
                    message:
                        "transports.sc.listen is not a runtime transport yet; configure hub_uri to connect to an SC hub"
                            .to_string(),
                });
            }
            let hub_uri = sc.hub_uri.as_deref().ok_or_else(|| ConfigError {
                message: "transports.sc.hub_uri is required for BACnet/SC node mode".to_string(),
            })?;
            if !hub_uri.starts_with("wss://") {
                return Err(ConfigError {
                    message: "transports.sc.hub_uri must use wss://".to_string(),
                });
            }
            if sc.cert.trim().is_empty() {
                return Err(ConfigError {
                    message: "transports.sc.cert must not be empty".to_string(),
                });
            }
            if sc.key.trim().is_empty() {
                return Err(ConfigError {
                    message: "transports.sc.key must not be empty".to_string(),
                });
            }
            let client_vmac = parse_sc_vmac(&sc.client_vmac).map_err(|message| ConfigError {
                message: format!("transports.sc.client_vmac: {message}"),
            })?;
            let server_vmac = parse_sc_vmac(&sc.server_vmac).map_err(|message| ConfigError {
                message: format!("transports.sc.server_vmac: {message}"),
            })?;
            if client_vmac == server_vmac {
                return Err(ConfigError {
                    message: "transports.sc.client_vmac and server_vmac must differ".to_string(),
                });
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
                "bip" if has_bip => {}
                "sc" if has_sc => {}
                "bip" | "sc" => {
                    return Err(ConfigError {
                        message: format!(
                            "route via_transport '{}' is not configured as the active transport",
                            route.via_transport
                        ),
                    });
                }
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
