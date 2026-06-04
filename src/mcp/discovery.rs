//! MCP discovery tools: discover_devices, list_known_devices, get_device_info.

use schemars::JsonSchema;
use serde::Deserialize;

use bacnet_client::discovery::DiscoveredDevice;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::ObjectIdentifier;

use crate::parse::{decode_raw_property_to_json, property_name};
use crate::state::GatewayState;

pub(crate) const DEFAULT_DEVICE_LIST_LIMIT: usize = 500;
const MAX_DEVICE_LIST_LIMIT: usize = 5000;

/// Parameters for discover_devices tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiscoverParams {
    /// Minimum device instance number to discover (optional).
    #[schemars(description = "Minimum device instance number to search for (optional, 0-4194302)")]
    pub low_instance: Option<u32>,
    /// Maximum device instance number to discover (optional).
    #[schemars(description = "Maximum device instance number to search for (optional, 0-4194302)")]
    pub high_instance: Option<u32>,
    /// How long to wait for responses in seconds (default: 3, max: 30).
    #[schemars(description = "Seconds to wait for IAm responses (default: 3, max: 30)")]
    pub timeout_seconds: Option<u64>,
    /// Target address for unicast discovery on the active transport. B/IP
    /// expects `ip:port`; BACnet/SC expects a 6-byte VMAC. If omitted, sends a
    /// global WhoIs on the active transport.
    #[schemars(
        description = "Target address for directed WhoIs: B/IP ip:port or BACnet/SC VMAC. Omit for global WhoIs."
    )]
    pub target: Option<String>,
    /// Maximum device rows to return in the text response.
    #[schemars(description = "Max devices to return (default 500, hard cap 5000)")]
    pub limit: Option<u32>,
}

/// Parameters for list_known_devices tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListKnownDevicesParams {
    /// Maximum device rows to return in the text response.
    #[schemars(description = "Max devices to return (default 500, hard cap 5000)")]
    pub limit: Option<u32>,
}

/// Parameters for get_device_info tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeviceInfoParams {
    /// The device instance number to query.
    #[schemars(
        description = "Device instance number (must be in the device table from a prior discover)"
    )]
    pub device_instance: u32,
}

/// Parameters for register_device tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RegisterDeviceParams {
    /// Device instance number.
    #[schemars(description = "Device instance number")]
    pub device_instance: u32,
    /// Device address on the active transport. B/IP expects `ip:port`;
    /// BACnet/SC expects a 6-byte VMAC.
    #[schemars(description = "Device address: B/IP ip:port or BACnet/SC VMAC")]
    pub address: String,
}

pub async fn register_device_impl(
    state: &GatewayState,
    params: RegisterDeviceParams,
) -> Result<String, String> {
    state
        .add_device_manual(params.device_instance, &params.address)
        .await?;
    Ok(format!(
        "Registered device {} at {}",
        params.device_instance, params.address
    ))
}

pub async fn discover_devices_impl(
    state: &GatewayState,
    params: DiscoverParams,
) -> Result<String, String> {
    let limit = device_list_limit(params.limit)?;
    let client = match state.require_client() {
        Ok(c) => c,
        Err(msg) => return Err(msg),
    };

    const MAX_DISCOVER_TIMEOUT_SECS: u64 = 30;
    let timeout = params
        .timeout_seconds
        .unwrap_or(3)
        .min(MAX_DISCOVER_TIMEOUT_SECS);

    match &params.target {
        Some(target) => {
            let mac = client.parse_manual_address(target)?;
            if let Err(e) = client
                .who_is_directed(&mac, params.low_instance, params.high_instance)
                .await
            {
                return Err(format!("Error sending directed WhoIs: {e}"));
            }
        }
        None => {
            if let Err(e) = client
                .who_is(params.low_instance, params.high_instance)
                .await
            {
                return Err(format!("Error sending WhoIs: {e}"));
            }
        }
    }

    tokio::time::sleep(std::time::Duration::from_secs(timeout)).await;

    let devices = client.discovered_devices().await;
    if devices.is_empty() {
        return Ok("No devices discovered.".to_string());
    }

    Ok(format_device_list(
        devices,
        limit,
        DeviceListFormat::Discovered,
    ))
}

pub async fn list_known_devices_impl(
    state: &GatewayState,
    params: ListKnownDevicesParams,
) -> Result<String, String> {
    let limit = device_list_limit(params.limit)?;
    let client = match state.require_client() {
        Ok(c) => c,
        Err(msg) => return Err(msg),
    };

    let devices = client.discovered_devices().await;
    if devices.is_empty() {
        return Ok("No devices in the device table. Use discover_devices first.".to_string());
    }

    Ok(format_device_list(devices, limit, DeviceListFormat::Known))
}

#[derive(Clone, Copy)]
pub(crate) enum DeviceListFormat {
    Discovered,
    Known,
    StateResource,
}

pub(crate) fn format_device_list(
    mut devices: Vec<DiscoveredDevice>,
    limit: usize,
    format: DeviceListFormat,
) -> String {
    devices.sort_by_key(|dev| dev.object_identifier.instance_number());
    let shown = devices.len().min(limit);
    let omitted = devices.len().saturating_sub(shown);
    let mut out = format.header(devices.len(), shown, omitted);
    for dev in devices.iter().take(shown) {
        out.push_str(&format.line(dev));
    }
    if omitted > 0 {
        out.push_str(&format.omission_line(omitted));
    }
    out
}

pub(crate) fn device_list_limit(raw: Option<u32>) -> Result<usize, String> {
    let limit = raw.unwrap_or(DEFAULT_DEVICE_LIST_LIMIT as u32);
    if limit == 0 || limit > MAX_DEVICE_LIST_LIMIT as u32 {
        return Err(format!(
            "limit {limit} out of range; must be 1..={MAX_DEVICE_LIST_LIMIT}"
        ));
    }
    Ok(limit as usize)
}

impl DeviceListFormat {
    fn header(self, total: usize, shown: usize, omitted: usize) -> String {
        let suffix = if omitted > 0 {
            format!(" (showing first {shown})")
        } else {
            String::new()
        };
        match self {
            Self::Discovered => format!("Discovered {total} device(s){suffix}:\n"),
            Self::Known => format!("{total} known device(s){suffix}:\n"),
            Self::StateResource => format!("{total} discovered device(s){suffix}:\n"),
        }
    }

    fn line(self, dev: &DiscoveredDevice) -> String {
        let mut line = match self {
            Self::Discovered => format!(
                "  - Instance {}, vendor ID {}, max APDU {}, MAC {:02x?}",
                dev.object_identifier.instance_number(),
                dev.vendor_id,
                dev.max_apdu_length,
                dev.mac_address.as_slice(),
            ),
            Self::Known => format!(
                "  - Instance {}, vendor ID {}, MAC {:02x?}",
                dev.object_identifier.instance_number(),
                dev.vendor_id,
                dev.mac_address.as_slice(),
            ),
            Self::StateResource => format!(
                "  Instance {}, vendor {}, MAC {:02x?}",
                dev.object_identifier.instance_number(),
                dev.vendor_id,
                dev.mac_address.as_slice(),
            ),
        };
        if matches!(self, Self::Discovered | Self::Known)
            && let Some(net) = dev.source_network
        {
            line.push_str(&format!(", network {net}"));
        }
        line.push('\n');
        line
    }

    fn omission_line(self, omitted: usize) -> String {
        match self {
            Self::Discovered | Self::Known => {
                format!(
                    "  ... omitted {omitted} device(s); set limit up to {MAX_DEVICE_LIST_LIMIT} to show more.\n"
                )
            }
            Self::StateResource => {
                format!(
                    "  ... omitted {omitted} device(s); use list_known_devices with limit up to {MAX_DEVICE_LIST_LIMIT} for more.\n"
                )
            }
        }
    }
}

pub async fn get_device_info_impl(
    state: &GatewayState,
    params: DeviceInfoParams,
) -> Result<String, String> {
    let client = match state.require_client() {
        Ok(c) => c,
        Err(msg) => return Err(msg),
    };

    let entry = match state.resolve_device(params.device_instance).await {
        Ok(e) => e,
        Err(msg) => return Err(msg),
    };

    let device_oid = match ObjectIdentifier::new(ObjectType::DEVICE, params.device_instance) {
        Ok(oid) => oid,
        Err(e) => return Err(format!("Invalid device instance: {e}")),
    };

    let mut result = format!("Device {} info:\n", params.device_instance);
    result.push_str(&format!("  MAC: {:02x?}\n", entry.mac_address.as_slice()));
    result.push_str(&format!("  Vendor ID: {}\n", entry.vendor_id));
    result.push_str(&format!("  Max APDU: {}\n", entry.max_apdu_length));

    let props = [
        PropertyIdentifier::OBJECT_NAME,
        PropertyIdentifier::VENDOR_NAME,
        PropertyIdentifier::MODEL_NAME,
        PropertyIdentifier::FIRMWARE_REVISION,
        PropertyIdentifier::APPLICATION_SOFTWARE_VERSION,
        PropertyIdentifier::PROTOCOL_VERSION,
        PropertyIdentifier::PROTOCOL_REVISION,
        PropertyIdentifier::DESCRIPTION,
    ];

    for prop in props {
        if let Ok(ack) = client
            .read_property(&entry.mac_address, device_oid, prop, None)
            .await
        {
            let val = decode_raw_property_to_json(&ack.property_value);
            let display = match val.get("value") {
                Some(v) => format!("{v}"),
                None => format!("{val}"),
            };
            result.push_str(&format!("  {}: {}\n", property_name(prop), display));
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    use bacnet_types::MacAddr;
    use bacnet_types::enums::Segmentation;

    #[test]
    fn discover_params_default_limit_is_none() {
        let params: DiscoverParams = serde_json::from_value(serde_json::json!({
            "low_instance": null,
            "high_instance": null,
            "timeout_seconds": 1,
            "target": null
        }))
        .unwrap();
        assert_eq!(params.limit, None);
    }

    #[test]
    fn list_known_devices_params_default_limit_is_none() {
        let params: ListKnownDevicesParams = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(params.limit, None);
    }

    #[test]
    fn device_list_limit_rejects_invalid_values() {
        assert!(
            device_list_limit(Some(0))
                .unwrap_err()
                .contains("out of range")
        );
        assert!(
            device_list_limit(Some(MAX_DEVICE_LIST_LIMIT as u32 + 1))
                .unwrap_err()
                .contains("out of range")
        );
    }

    #[test]
    fn format_known_devices_sorts_limits_and_reports_omissions() {
        let out = format_device_list(
            vec![device(10), device(8), device(9)],
            2,
            DeviceListFormat::Known,
        );

        assert!(out.contains("3 known device(s) (showing first 2)"));
        assert!(out.contains("Instance 8"));
        assert!(out.contains("Instance 9"));
        assert!(!out.contains("Instance 10"));
        assert!(out.contains("omitted 1 device(s)"));
    }

    #[test]
    fn format_state_resource_points_to_list_known_devices_for_more_rows() {
        let out = format_device_list(
            vec![device(1), device(2)],
            1,
            DeviceListFormat::StateResource,
        );

        assert!(out.contains("2 discovered device(s) (showing first 1)"));
        assert!(out.contains("use list_known_devices with limit up to"));
    }

    fn device(instance: u32) -> DiscoveredDevice {
        let last_octet = instance as u8;
        DiscoveredDevice {
            object_identifier: ObjectIdentifier::new(ObjectType::DEVICE, instance).unwrap(),
            mac_address: MacAddr::from_slice(&[192, 168, 1, last_octet, 0xba, 0xc0]),
            max_apdu_length: 1476,
            segmentation_supported: Segmentation::NONE,
            max_segments_accepted: None,
            vendor_id: 999,
            last_seen: Instant::now(),
            source_network: Some(1),
            source_address: None,
        }
    }
}
