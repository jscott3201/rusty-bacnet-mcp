//! Gateway builder for constructing the full BACnet stack.

use std::net::Ipv4Addr;
use std::sync::Arc;

use bacnet_client::client::BACnetClient;
use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig as BacnetDeviceConfig, DeviceObject};
use bacnet_server::server::BACnetServer;
use bacnet_transport::bip::BipTransport;
use bacnet_types::error::Error;

/// Builder error. We promote to a boxed `std::error::Error` here because
/// `bacnet_types::error::Error` has no free-form variant, and the gateway
/// build path needs to surface both BACnet errors and our own validation
/// errors (e.g. malformed `mcp.safety` config — Codex P1 in PR #3).
pub type BuildError = Box<dyn std::error::Error>;

#[cfg(feature = "sc")]
use crate::config::parse_sc_vmac;
use crate::config::{BipConfig, GatewayConfig, ScConfig};
use crate::parse::{construct_object, parse_object_type};
use crate::runtime::{GatewayClient, GatewayServer};
use crate::state::GatewayState;

/// Builder for constructing a fully wired Gateway.
pub struct GatewayBuilder {
    config: GatewayConfig,
}

impl GatewayBuilder {
    /// Create a new builder from config.
    pub fn new(config: GatewayConfig) -> Self {
        Self { config }
    }

    /// Build the gateway: create the active transport, start client/server,
    /// and return state.
    pub async fn build(self) -> Result<BuiltGateway, BuildError> {
        let db = build_object_database(&self.config)?;
        let (server, client) = match (
            self.config.transports.bip.as_ref(),
            self.config.transports.sc.as_ref(),
        ) {
            (Some(bip), None) => build_bip_stack(&self.config, db, bip).await?,
            (None, Some(sc)) => build_sc_stack(&self.config, db, sc).await?,
            (Some(_), Some(_)) => {
                return Err(
                    "configure exactly one runtime transport: transports.bip or transports.sc"
                        .into(),
                );
            }
            (None, None) => {
                return Err(
                    "configure exactly one runtime transport: transports.bip or transports.sc"
                        .into(),
                );
            }
        };

        let server_mac = server.local_mac().to_vec();
        let db = server.database().clone();

        // Use the fallible constructor so a malformed `mcp.safety` block
        // surfaces as a normal build error instead of a panic. Codex flagged
        // the prior `expect()` path as P1 in PR #3 review — config typos
        // should never abort the daemon abruptly. `validate()` already
        // pre-checks the safety block at config load, so this is defense
        // in depth.
        let state = GatewayState::try_new_with_stack(db, Arc::new(self.config), client)
            .map_err(|msg| -> BuildError { format!("safety config: {msg}").into() })?;

        Ok(BuiltGateway {
            state,
            server_mac,
            server,
        })
    }
}

fn build_object_database(config: &GatewayConfig) -> Result<ObjectDatabase, BuildError> {
    let mut db = ObjectDatabase::new();
    let device = DeviceObject::new(BacnetDeviceConfig {
        instance: config.device.instance,
        name: config.device.name.clone(),
        vendor_id: config.device.vendor_id,
        ..BacnetDeviceConfig::default()
    })?;
    db.add(Box::new(device))?;

    for obj_cfg in &config.objects {
        let obj_type = parse_object_type(&obj_cfg.object_type)
            .map_err(|e| Error::Encoding(format!("object config: {e}")))?;
        let obj = construct_object(
            obj_type,
            obj_cfg.instance,
            &obj_cfg.name,
            obj_cfg.number_of_states,
        )
        .map_err(|e| Error::Encoding(format!("object config: {e}")))?;
        db.add(obj)
            .map_err(|e| Error::Encoding(format!("object config: {e}")))?;
        tracing::info!(
            "Pre-populated object {}:{} ({})",
            obj_cfg.object_type,
            obj_cfg.instance,
            obj_cfg.name
        );
    }

    Ok(db)
}

async fn build_bip_stack(
    config: &GatewayConfig,
    db: ObjectDatabase,
    bip: &BipConfig,
) -> Result<(GatewayServer, GatewayClient), BuildError> {
    let interface: Ipv4Addr = bip
        .interface
        .parse()
        .map_err(|e| Error::Encoding(format!("invalid BIP interface: {e}")))?;
    let broadcast: Ipv4Addr = bip
        .broadcast
        .parse()
        .map_err(|e| Error::Encoding(format!("invalid BIP broadcast: {e}")))?;

    let fd_config = if let Some(fd) = &config.foreign_device {
        let addr: std::net::SocketAddrV4 = fd.bbmd.parse().map_err(|e| {
            Error::Encoding(format!("invalid foreign_device.bbmd '{}': {e}", fd.bbmd))
        })?;
        Some(bacnet_transport::bip::ForeignDeviceConfig {
            bbmd_ip: *addr.ip(),
            bbmd_port: addr.port(),
            ttl: fd.ttl,
        })
    } else {
        None
    };

    let mut server_transport = BipTransport::new(interface, bip.port, broadcast);

    if let Some(ref fdc) = fd_config {
        server_transport.register_as_foreign_device(fdc.clone());
        tracing::info!(
            "Registered as foreign device with BBMD {}:{}",
            fdc.bbmd_ip,
            fdc.bbmd_port
        );
    }

    if let Some(bbmd_cfg) = &config.bbmd
        && bbmd_cfg.enabled
    {
        let mut bdt_entries = Vec::new();
        for entry_str in &bbmd_cfg.bdt {
            let addr: std::net::SocketAddrV4 = entry_str
                .parse()
                .map_err(|e| Error::Encoding(format!("invalid BDT entry '{entry_str}': {e}")))?;
            bdt_entries.push(bacnet_transport::bbmd::BdtEntry {
                ip: addr.ip().octets(),
                port: addr.port(),
                broadcast_mask: [0xff, 0xff, 0xff, 0xff],
            });
        }
        server_transport.enable_bbmd(bdt_entries);
        tracing::info!("BBMD enabled with {} BDT entries", bbmd_cfg.bdt.len());
    }

    let server = BACnetServer::generic_builder()
        .transport(server_transport)
        .database(db)
        .vendor_id(config.device.vendor_id)
        .build()
        .await?;

    let mut client_transport = BipTransport::new(interface, bip.port, broadcast);
    if let Some(ref fdc) = fd_config {
        client_transport.register_as_foreign_device(fdc.clone());
    }

    let client = BACnetClient::generic_builder()
        .transport(client_transport)
        .apdu_timeout_ms(6000)
        .build()
        .await?;

    Ok((GatewayServer::Bip(server), GatewayClient::Bip(client)))
}

#[cfg(feature = "sc")]
async fn build_sc_stack(
    config: &GatewayConfig,
    db: ObjectDatabase,
    sc: &ScConfig,
) -> Result<(GatewayServer, GatewayClient), BuildError> {
    use bacnet_transport::sc::ScTransport;
    use bacnet_transport::sc_tls::TlsWebSocket;

    let hub_uri = sc
        .hub_uri
        .as_deref()
        .ok_or_else(|| Error::Encoding("transports.sc.hub_uri is required".into()))?;
    let client_vmac = parse_sc_vmac(&sc.client_vmac)
        .map_err(|e| Error::Encoding(format!("invalid SC client_vmac: {e}")))?;
    let server_vmac = parse_sc_vmac(&sc.server_vmac)
        .map_err(|e| Error::Encoding(format!("invalid SC server_vmac: {e}")))?;
    if client_vmac == server_vmac {
        return Err(Error::Encoding("SC client_vmac and server_vmac must differ".into()).into());
    }

    let tls_config = build_sc_client_tls_config(sc)?;

    let server_ws = TlsWebSocket::connect(hub_uri, tls_config.clone()).await?;
    let server_transport = ScTransport::new(server_ws, server_vmac);
    let server = BACnetServer::generic_builder()
        .transport(server_transport)
        .database(db)
        .vendor_id(config.device.vendor_id)
        .build()
        .await?;

    let client_ws = TlsWebSocket::connect(hub_uri, tls_config).await?;
    let client_transport = ScTransport::new(client_ws, client_vmac);
    let client = BACnetClient::generic_builder()
        .transport(client_transport)
        .apdu_timeout_ms(6000)
        .build()
        .await?;

    Ok((GatewayServer::Sc(server), GatewayClient::Sc(client)))
}

#[cfg(not(feature = "sc"))]
async fn build_sc_stack(
    _config: &GatewayConfig,
    _db: ObjectDatabase,
    _sc: &ScConfig,
) -> Result<(GatewayServer, GatewayClient), BuildError> {
    Err("BACnet/SC runtime requires building with --features sc".into())
}

#[cfg(feature = "sc")]
fn build_sc_client_tls_config(
    sc: &ScConfig,
) -> Result<Arc<tokio_rustls::rustls::ClientConfig>, BuildError> {
    use tokio_rustls::rustls;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let cert_data = std::fs::read(&sc.cert)
        .map_err(|e| format!("failed to read SC client cert '{}': {e}", sc.cert))?;
    let key_data = std::fs::read(&sc.key)
        .map_err(|e| format!("failed to read SC client key '{}': {e}", sc.key))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse SC client cert '{}': {e}", sc.cert))?;
    let key = PrivateKeyDer::from_pem_slice(&key_data)
        .map_err(|e| format!("failed to parse SC client key '{}': {e}", sc.key))?;

    let mut root_store = rustls::RootCertStore::empty();
    if let Some(ca_path) = sc.ca.as_deref() {
        let ca_data = std::fs::read(ca_path)
            .map_err(|e| format!("failed to read SC CA bundle '{ca_path}': {e}"))?;
        let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&ca_data)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("failed to parse SC CA bundle '{ca_path}': {e}"))?;
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| format!("failed to add SC CA certificate '{ca_path}': {e}"))?;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = root_store.add(cert);
        }
        if root_store.is_empty() {
            return Err(
                "no native CA certificates could be loaded; set transports.sc.ca explicitly".into(),
            );
        }
    }

    let tls = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .map_err(|e| format!("SC TLS client config error: {e}"))?;

    Ok(Arc::new(tls))
}

/// A fully constructed gateway with its state and metadata.
pub struct BuiltGateway {
    /// Shared state for API/MCP handlers.
    pub state: GatewayState,
    /// The server's active transport MAC address.
    pub server_mac: Vec<u8>,
    /// The BACnet server (kept alive; drop to stop).
    pub server: GatewayServer,
}
