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

use crate::audit::{AuditLog, build_audit_log};
use crate::config::GatewayConfig;
use crate::safety::{LivePolicy, WritePolicy, build_live_policy};

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
    /// Live-mutable write policy. F9 reload swaps this via `ArcSwap` — readers
    /// see the new value on their next `.load()` without locking.
    policy: Arc<LivePolicy>,
}

impl RuntimeFlags {
    pub fn from_config(config: &GatewayConfig) -> Result<Self, String> {
        let policy = build_live_policy(
            config
                .mcp
                .safety
                .as_ref()
                .unwrap_or(&crate::config::SafetyConfig::default()),
        )?;
        Ok(Self {
            read_only: AtomicBool::new(config.mcp.read_only),
            policy,
        })
    }

    /// Hot-swap the live fields from a new config. Only fields classified as
    /// `Applied` by `reload_safety_check` are read here — everything else is
    /// frozen until the daemon restarts.
    pub fn apply(&self, config: &GatewayConfig) -> Result<(), String> {
        self.read_only
            .store(config.mcp.read_only, Ordering::Relaxed);
        let safety_default = crate::config::SafetyConfig::default();
        let new_policy =
            WritePolicy::from_config(config.mcp.safety.as_ref().unwrap_or(&safety_default))?;
        self.policy.store(Arc::new(new_policy));
        Ok(())
    }

    /// Mirror the same set of fields that `apply()` reads from `src` into `dst`.
    /// The TUI calls this on `PartialApplied` reload outcomes so its in-memory
    /// view of `GatewayConfig` reflects exactly what's live, while
    /// restart-required fields keep showing the old (still-effective) values.
    ///
    /// **Invariant:** the field set mirrored here MUST match `apply()` exactly.
    /// Adding a hot-applied field requires updating both — and the classifier
    /// in `crate::tui::reload_safety_check`.
    pub fn mirror_applied_fields(src: &GatewayConfig, dst: &mut GatewayConfig) {
        dst.mcp.read_only = src.mcp.read_only;
        dst.mcp.safety = src.mcp.safety.clone();
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

    /// Snapshot the current write policy. RCU semantics — `ArcSwap::load_full`
    /// is wait-free and the returned `Arc<WritePolicy>` is immutable.
    pub fn policy(&self) -> Arc<WritePolicy> {
        self.policy.load_full()
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
    /// Append-only audit log of every write attempt (allow / deny / dry-run /
    /// error). Bounded ring buffer with optional JSON-Lines file mirror.
    /// File path is fixed at startup — the open path is stale-until-restart.
    pub audit: Arc<AuditLog>,
    /// BACnet client for remote device operations (None in test-only mode).
    client: Option<Arc<BACnetClient<BipTransport>>>,
}

impl GatewayState {
    /// Create a minimal GatewayState (for tests without a live BACnet stack).
    ///
    /// **Panics** if the bundled safety config fails validation. Tests pass
    /// either no safety block (defaults) or known-good values; production
    /// builds use `try_new` / `new_with_stack` paths that surface the error
    /// at boot, before any sockets bind.
    pub fn new(db: ObjectDatabase, config: GatewayConfig) -> Self {
        let flags =
            Arc::new(RuntimeFlags::from_config(&config).expect("safety config must validate"));
        let audit = build_audit_log(config.mcp.audit.as_ref());
        Self {
            db: Arc::new(RwLock::new(db)),
            config: Arc::new(config),
            flags,
            audit,
            client: None,
        }
    }

    /// Create a GatewayState with the full BACnet stack. Returns the parsed
    /// safety-config error verbatim so the binary can surface a clean message
    /// before any sockets are bound.
    pub fn try_new_with_stack(
        db: Arc<RwLock<ObjectDatabase>>,
        config: Arc<GatewayConfig>,
        client: BACnetClient<BipTransport>,
    ) -> Result<Self, String> {
        let flags = Arc::new(RuntimeFlags::from_config(&config)?);
        let audit = build_audit_log(config.mcp.audit.as_ref());
        Ok(Self {
            db,
            config,
            flags,
            audit,
            client: Some(Arc::new(client)),
        })
    }

    /// Backwards-compatible shim. New callers should use `try_new_with_stack`
    /// so config errors surface at boot. This wrapper panics so test fixtures
    /// keep working without changes.
    pub fn new_with_stack(
        db: Arc<RwLock<ObjectDatabase>>,
        config: Arc<GatewayConfig>,
        client: BACnetClient<BipTransport>,
    ) -> Self {
        Self::try_new_with_stack(db, config, client).expect("safety config must validate")
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
