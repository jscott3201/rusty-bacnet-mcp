//! Runtime BACnet transport handles.
//!
//! The MCP tools should not know whether the active data link is BACnet/IP or
//! BACnet/SC. This module owns that boundary while preserving transport-
//! specific operations such as BBMD management on B/IP.

use std::sync::Arc;

use bacnet_client::client::BACnetClient;
use bacnet_client::discovery::DiscoveredDevice;
use bacnet_objects::database::ObjectDatabase;
use bacnet_server::server::BACnetServer;
use bacnet_transport::bip::BipTransport;
use bacnet_types::enums::{ConfirmedServiceChoice, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;
use bytes::Bytes;
use tokio::sync::{RwLock, broadcast};

#[cfg(feature = "sc")]
pub type ScTlsTransport = bacnet_transport::sc::ScTransport<bacnet_transport::sc_tls::TlsWebSocket>;

#[cfg(feature = "sc")]
pub type GatewayScHub = bacnet_transport::sc_hub::ScHub;

#[cfg(not(feature = "sc"))]
pub struct GatewayScHub;

/// The active BACnet client.
pub enum GatewayClient {
    /// BACnet/IP over UDP.
    Bip(BACnetClient<BipTransport>),
    /// BACnet/SC over TLS WebSocket.
    #[cfg(feature = "sc")]
    Sc(BACnetClient<ScTlsTransport>),
}

impl GatewayClient {
    /// Human-readable transport name for status output.
    pub fn transport_name(&self) -> &'static str {
        match self {
            Self::Bip(_) => "bip",
            #[cfg(feature = "sc")]
            Self::Sc(_) => "sc",
        }
    }

    /// Get a receiver for inbound COV notifications.
    pub fn cov_notifications(
        &self,
    ) -> broadcast::Receiver<bacnet_services::cov::COVNotificationRequest> {
        match self {
            Self::Bip(client) => client.cov_notifications(),
            #[cfg(feature = "sc")]
            Self::Sc(client) => client.cov_notifications(),
        }
    }

    /// Send a global Who-Is on the active transport.
    pub async fn who_is(
        &self,
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    ) -> Result<(), Error> {
        match self {
            Self::Bip(client) => client.who_is(low_limit, high_limit).await,
            #[cfg(feature = "sc")]
            Self::Sc(client) => client.who_is(low_limit, high_limit).await,
        }
    }

    /// Send a directed Who-Is on the active transport.
    pub async fn who_is_directed(
        &self,
        destination_mac: &[u8],
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    ) -> Result<(), Error> {
        match self {
            Self::Bip(client) => {
                client
                    .who_is_directed(destination_mac, low_limit, high_limit)
                    .await
            }
            #[cfg(feature = "sc")]
            Self::Sc(client) => {
                client
                    .who_is_directed(destination_mac, low_limit, high_limit)
                    .await
            }
        }
    }

    /// Snapshot the active transport's discovered device table.
    pub async fn discovered_devices(&self) -> Vec<DiscoveredDevice> {
        match self {
            Self::Bip(client) => client.discovered_devices().await,
            #[cfg(feature = "sc")]
            Self::Sc(client) => client.discovered_devices().await,
        }
    }

    /// Resolve one device from the active transport's device table.
    pub async fn get_device(&self, instance: u32) -> Option<DiscoveredDevice> {
        match self {
            Self::Bip(client) => client.get_device(instance).await,
            #[cfg(feature = "sc")]
            Self::Sc(client) => client.get_device(instance).await,
        }
    }

    /// Parse a manual address for the active transport.
    ///
    /// BACnet/IP uses IPv4 socket addresses (`192.0.2.10:47808`). BACnet/SC
    /// uses 6-byte VMACs (`02:00:00:00:00:10` or `020000000010`).
    pub fn parse_manual_address(&self, address: &str) -> Result<Vec<u8>, String> {
        match self {
            Self::Bip(_) => {
                let addr: std::net::SocketAddrV4 = address.parse().map_err(|e| {
                    format!("invalid B/IP address '{address}' (expected ip:port): {e}")
                })?;
                Ok(crate::parse::socket_addr_to_mac(addr))
            }
            #[cfg(feature = "sc")]
            Self::Sc(_) => crate::config::parse_sc_vmac(address)
                .map(|vmac| vmac.to_vec())
                .map_err(|e| format!("invalid BACnet/SC VMAC address: {e}")),
        }
    }

    /// Manually add a BACnet device to the active transport's device table.
    pub async fn add_device(&self, instance: u32, mac: &[u8]) -> Result<(), Error> {
        match self {
            Self::Bip(client) => client.add_device(instance, mac).await,
            #[cfg(feature = "sc")]
            Self::Sc(client) => client.add_device(instance, mac).await,
        }
    }

    /// Send a raw confirmed request and return the service response payload.
    pub async fn confirmed_request(
        &self,
        destination_mac: &[u8],
        service_choice: ConfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<Bytes, Error> {
        match self {
            Self::Bip(client) => {
                client
                    .confirmed_request(destination_mac, service_choice, service_data)
                    .await
            }
            #[cfg(feature = "sc")]
            Self::Sc(client) => {
                client
                    .confirmed_request(destination_mac, service_choice, service_data)
                    .await
            }
        }
    }

    /// Read one property from a remote object.
    pub async fn read_property(
        &self,
        destination_mac: &[u8],
        object_identifier: ObjectIdentifier,
        property_identifier: PropertyIdentifier,
        property_array_index: Option<u32>,
    ) -> Result<bacnet_services::read_property::ReadPropertyACK, Error> {
        match self {
            Self::Bip(client) => {
                client
                    .read_property(
                        destination_mac,
                        object_identifier,
                        property_identifier,
                        property_array_index,
                    )
                    .await
            }
            #[cfg(feature = "sc")]
            Self::Sc(client) => {
                client
                    .read_property(
                        destination_mac,
                        object_identifier,
                        property_identifier,
                        property_array_index,
                    )
                    .await
            }
        }
    }

    /// Read multiple properties from a remote device.
    pub async fn read_property_multiple(
        &self,
        destination_mac: &[u8],
        specs: Vec<bacnet_services::rpm::ReadAccessSpecification>,
    ) -> Result<bacnet_services::rpm::ReadPropertyMultipleACK, Error> {
        match self {
            Self::Bip(client) => client.read_property_multiple(destination_mac, specs).await,
            #[cfg(feature = "sc")]
            Self::Sc(client) => client.read_property_multiple(destination_mac, specs).await,
        }
    }

    /// Write one property to a remote object.
    pub async fn write_property(
        &self,
        destination_mac: &[u8],
        object_identifier: ObjectIdentifier,
        property_identifier: PropertyIdentifier,
        property_array_index: Option<u32>,
        property_value: Vec<u8>,
        priority: Option<u8>,
    ) -> Result<(), Error> {
        match self {
            Self::Bip(client) => {
                client
                    .write_property(
                        destination_mac,
                        object_identifier,
                        property_identifier,
                        property_array_index,
                        property_value,
                        priority,
                    )
                    .await
            }
            #[cfg(feature = "sc")]
            Self::Sc(client) => {
                client
                    .write_property(
                        destination_mac,
                        object_identifier,
                        property_identifier,
                        property_array_index,
                        property_value,
                        priority,
                    )
                    .await
            }
        }
    }

    /// Write multiple properties to a discovered device.
    pub async fn write_property_multiple_to_device(
        &self,
        device_instance: u32,
        specs: Vec<bacnet_services::wpm::WriteAccessSpecification>,
    ) -> Result<(), Error> {
        match self {
            Self::Bip(client) => {
                client
                    .write_property_multiple_to_device(device_instance, specs)
                    .await
            }
            #[cfg(feature = "sc")]
            Self::Sc(client) => {
                client
                    .write_property_multiple_to_device(device_instance, specs)
                    .await
            }
        }
    }

    /// Subscribe to COV notifications on a remote device.
    pub async fn subscribe_cov(
        &self,
        destination_mac: &[u8],
        subscriber_process_identifier: u32,
        monitored_object_identifier: ObjectIdentifier,
        confirmed: bool,
        lifetime: Option<u32>,
    ) -> Result<(), Error> {
        match self {
            Self::Bip(client) => {
                client
                    .subscribe_cov(
                        destination_mac,
                        subscriber_process_identifier,
                        monitored_object_identifier,
                        confirmed,
                        lifetime,
                    )
                    .await
            }
            #[cfg(feature = "sc")]
            Self::Sc(client) => {
                client
                    .subscribe_cov(
                        destination_mac,
                        subscriber_process_identifier,
                        monitored_object_identifier,
                        confirmed,
                        lifetime,
                    )
                    .await
            }
        }
    }

    /// Cancel a COV subscription on a remote device.
    pub async fn unsubscribe_cov(
        &self,
        destination_mac: &[u8],
        subscriber_process_identifier: u32,
        monitored_object_identifier: ObjectIdentifier,
    ) -> Result<(), Error> {
        match self {
            Self::Bip(client) => {
                client
                    .unsubscribe_cov(
                        destination_mac,
                        subscriber_process_identifier,
                        monitored_object_identifier,
                    )
                    .await
            }
            #[cfg(feature = "sc")]
            Self::Sc(client) => {
                client
                    .unsubscribe_cov(
                        destination_mac,
                        subscriber_process_identifier,
                        monitored_object_identifier,
                    )
                    .await
            }
        }
    }

    /// Get event information from a remote device.
    pub async fn get_event_information(
        &self,
        destination_mac: &[u8],
        last_received_object_identifier: Option<ObjectIdentifier>,
    ) -> Result<Bytes, Error> {
        match self {
            Self::Bip(client) => {
                client
                    .get_event_information(destination_mac, last_received_object_identifier)
                    .await
            }
            #[cfg(feature = "sc")]
            Self::Sc(client) => {
                client
                    .get_event_information(destination_mac, last_received_object_identifier)
                    .await
            }
        }
    }

    /// Read a range from a list or log property.
    pub async fn read_range(
        &self,
        destination_mac: &[u8],
        object_identifier: ObjectIdentifier,
        property_identifier: PropertyIdentifier,
        property_array_index: Option<u32>,
        range: Option<bacnet_services::read_range::RangeSpec>,
    ) -> Result<bacnet_services::read_range::ReadRangeAck, Error> {
        match self {
            Self::Bip(client) => {
                client
                    .read_range(
                        destination_mac,
                        object_identifier,
                        property_identifier,
                        property_array_index,
                        range,
                    )
                    .await
            }
            #[cfg(feature = "sc")]
            Self::Sc(client) => {
                client
                    .read_range(
                        destination_mac,
                        object_identifier,
                        property_identifier,
                        property_array_index,
                        range,
                    )
                    .await
            }
        }
    }

    /// Read file object bytes/records from a remote device.
    pub async fn atomic_read_file(
        &self,
        destination_mac: &[u8],
        file_identifier: ObjectIdentifier,
        access: bacnet_services::file::FileAccessMethod,
    ) -> Result<Bytes, Error> {
        match self {
            Self::Bip(client) => {
                client
                    .atomic_read_file(destination_mac, file_identifier, access)
                    .await
            }
            #[cfg(feature = "sc")]
            Self::Sc(client) => {
                client
                    .atomic_read_file(destination_mac, file_identifier, access)
                    .await
            }
        }
    }

    /// Read a B/IP BBMD Broadcast Distribution Table.
    pub async fn read_bdt(
        &self,
        target: &[u8],
    ) -> Result<Vec<bacnet_transport::bbmd::BdtEntry>, Error> {
        match self {
            Self::Bip(client) => client.read_bdt(target).await,
            #[cfg(feature = "sc")]
            Self::Sc(_) => Err(Error::Encoding(
                "probe_bbmd requires the B/IP transport; BACnet/SC has no BBMD tables".into(),
            )),
        }
    }

    /// Read a B/IP BBMD Foreign Device Table.
    pub async fn read_fdt(
        &self,
        target: &[u8],
    ) -> Result<Vec<bacnet_transport::bbmd::FdtEntryWire>, Error> {
        match self {
            Self::Bip(client) => client.read_fdt(target).await,
            #[cfg(feature = "sc")]
            Self::Sc(_) => Err(Error::Encoding(
                "probe_bbmd requires the B/IP transport; BACnet/SC has no foreign-device table"
                    .into(),
            )),
        }
    }
}

/// The active BACnet server, kept alive for the process lifetime.
pub enum GatewayServer {
    /// BACnet/IP over UDP.
    Bip(BACnetServer<BipTransport>),
    /// BACnet/SC over TLS WebSocket.
    #[cfg(feature = "sc")]
    Sc(BACnetServer<ScTlsTransport>),
}

impl GatewayServer {
    /// Local data-link MAC for logging/status.
    pub fn local_mac(&self) -> &[u8] {
        match self {
            Self::Bip(server) => server.local_mac(),
            #[cfg(feature = "sc")]
            Self::Sc(server) => server.local_mac(),
        }
    }

    /// Shared object database owned by the active server.
    pub fn database(&self) -> &Arc<RwLock<ObjectDatabase>> {
        match self {
            Self::Bip(server) => server.database(),
            #[cfg(feature = "sc")]
            Self::Sc(server) => server.database(),
        }
    }
}
