//! Gateway shared state.
//!
//! `GatewayState` is the single source of truth that every MCP tool (and the
//! TUI) calls into. It cleanly separates two kinds of runtime state:
//!
//! - **`config: Arc<GatewayConfig>`** — frozen at boot. Fields that drove
//!   transport construction, socket binding, or BACnet identity cannot change
//!   without rebuilding the stack. Read-only access only.
//! - **`flags: Arc<RuntimeFlags>`** — live-mutable. Fields read per-request by
//!   MCP tools (today: `read_only`; Phase 2 will add the safety control plane:
//!   write allow/deny lists, priority caps, audit log path).
//!
//! The TUI's hot-reload (`F9`) updates `flags` for hot-safe changes and warns
//! the operator about restart-required fields.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;

use bacnet_client::client::BACnetClient;
use bacnet_client::discovery::DiscoveredDevice;
use bacnet_objects::database::ObjectDatabase;
use bacnet_transport::bip::BipTransport;

use crate::config::GatewayConfig;

/// Live-mutable runtime flags.
///
/// Read by MCP tools on every request, so we use lock-free primitives. The
/// TUI's reload action calls `apply()` with a freshly-validated config.
///
/// Adding a new live-mutable field: add it as an atomic / `ArcSwap` here, mirror
/// it in `apply()`, and update the classifier in
/// `crate::tui::reload_safety_check` to mark its config-side counterpart as
/// `Applied` instead of `Stale`.
pub struct RuntimeFlags {
    read_only: AtomicBool,
}

impl RuntimeFlags {
    pub fn from_config(config: &GatewayConfig) -> Self {
        Self {
            read_only: AtomicBool::new(config.mcp.read_only),
        }
    }

    /// Hot-swap the live fields from a new config. Only fields classified as
    /// `Applied` by `reload_safety_check` are read here — everything else is
    /// frozen until the daemon restarts.
    pub fn apply(&self, config: &GatewayConfig) {
        self.read_only
            .store(config.mcp.read_only, Ordering::Relaxed);
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only.load(Ordering::Relaxed)
    }

    /// Direct setter (Operate-tab and tests). Bypasses the config snapshot —
    /// the operator opts in to writes for a single session without editing the
    /// JSON file.
    pub fn set_read_only(&self, value: bool) {
        self.read_only.store(value, Ordering::Relaxed);
    }
}

/// Shared state for the gateway, accessible by every MCP tool surface.
///
/// Cheaply cloneable (all fields are Arc-wrapped) and passed into MCP tool
/// handlers. The TUI clones it for its own reads; both views see the same
/// `RuntimeFlags` atomic so a TUI hot-reload immediately affects in-flight
/// MCP tool calls.
#[derive(Clone)]
pub struct GatewayState {
    /// Local BACnet object database (shared with the server).
    pub db: Arc<RwLock<ObjectDatabase>>,
    /// Frozen-at-startup configuration. Read-only.
    pub config: Arc<GatewayConfig>,
    /// Live-mutable runtime flags. Updated by the TUI's reload action.
    pub flags: Arc<RuntimeFlags>,
    /// BACnet client for remote device operations (None in test-only mode).
    client: Option<Arc<BACnetClient<BipTransport>>>,
}

impl GatewayState {
    /// Create a minimal GatewayState (for tests without a live BACnet stack).
    pub fn new(db: ObjectDatabase, config: GatewayConfig) -> Self {
        let flags = Arc::new(RuntimeFlags::from_config(&config));
        Self {
            db: Arc::new(RwLock::new(db)),
            config: Arc::new(config),
            flags,
            client: None,
        }
    }

    /// Create a GatewayState with the full BACnet stack.
    pub fn new_with_stack(
        db: Arc<RwLock<ObjectDatabase>>,
        config: Arc<GatewayConfig>,
        client: BACnetClient<BipTransport>,
    ) -> Self {
        let flags = Arc::new(RuntimeFlags::from_config(&config));
        Self {
            db,
            config,
            flags,
            client: Some(Arc::new(client)),
        }
    }

    /// Get a reference to the BACnet client (if started).
    pub fn client(&self) -> Option<&BACnetClient<BipTransport>> {
        self.client.as_deref()
    }

    /// Get the BACnet client, returning an error message if not started.
    pub fn require_client(&self) -> Result<&BACnetClient<BipTransport>, String> {
        self.client()
            .ok_or_else(|| "BACnet client not started".to_string())
    }

    /// Resolve a device instance number to a DiscoveredDevice entry.
    pub async fn resolve_device(&self, instance: u32) -> Result<DiscoveredDevice, String> {
        let client = self.require_client()?;
        client
            .get_device(instance)
            .await
            .ok_or_else(|| format!("Device {instance} not found. Use discover_devices first."))
    }

    /// Manually register a device in the client's device table.
    pub async fn add_device_manual(&self, instance: u32, address: &str) -> Result<(), String> {
        let client = self.require_client()?;
        let addr: std::net::SocketAddrV4 = address
            .parse()
            .map_err(|e| format!("invalid address '{address}': {e}"))?;
        let mac = crate::parse::socket_addr_to_mac(addr);
        client
            .add_device(instance, &mac)
            .await
            .map_err(|e| format!("{e}"))
    }

    /// Check if the gateway is in read-only mode. Reads the live atomic, so
    /// changes via `RuntimeFlags::apply()` or `set_read_only()` take effect
    /// on the next call.
    pub fn is_read_only(&self) -> bool {
        self.flags.is_read_only()
    }

    /// Return an error if write operations are disabled.
    pub fn require_writable(&self) -> Result<(), String> {
        if self.flags.is_read_only() {
            Err(
                "Gateway is in read-only mode. Set mcp.read_only = false in config and reload, \
                 pass --writes-enabled, or toggle from the TUI."
                    .to_string(),
            )
        } else {
            Ok(())
        }
    }
}
