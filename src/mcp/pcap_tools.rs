//! Feature-gated pcap MCP tools.
//!
//! The MCP tool is always present so the tool schema stays stable. Builds
//! without the `pcap` feature return a clear runtime error; pcap-enabled builds
//! list capture interfaces so operators can plan BACnet/IP captures before
//! opening live sessions.

use schemars::JsonSchema;
use serde::Deserialize;

#[cfg(any(feature = "pcap", test))]
const DEFAULT_INTERFACE_LIMIT: usize = 100;
#[cfg(any(feature = "pcap", test))]
const MAX_INTERFACE_LIMIT: usize = 500;
#[cfg(any(feature = "pcap", test))]
const MAX_ADDRS_PER_INTERFACE: usize = 8;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListPcapInterfacesParams {
    #[schemars(description = "Max interfaces to return (default 100, hard cap 500)")]
    pub limit: Option<u32>,
    #[schemars(description = "Include interface IP address rows (default true)")]
    pub include_addresses: Option<bool>,
}

#[cfg(feature = "pcap")]
pub fn list_pcap_interfaces_impl(params: ListPcapInterfacesParams) -> Result<String, String> {
    let limit = interface_limit(params.limit)?;
    let include_addresses = params.include_addresses.unwrap_or(true);
    let devices =
        pcap::Device::list().map_err(|e| format!("cannot list pcap capture interfaces: {e}"))?;
    let rows: Vec<InterfaceRow> = devices.into_iter().map(InterfaceRow::from).collect();
    Ok(format_interface_rows(&rows, limit, include_addresses))
}

#[cfg(not(feature = "pcap"))]
pub fn list_pcap_interfaces_impl(params: ListPcapInterfacesParams) -> Result<String, String> {
    let _ = params;
    Err("pcap support is not enabled in this build; rebuild with feature `pcap`".to_string())
}

#[cfg(any(feature = "pcap", test))]
fn interface_limit(raw: Option<u32>) -> Result<usize, String> {
    let limit = raw.unwrap_or(DEFAULT_INTERFACE_LIMIT as u32);
    if limit == 0 || limit as usize > MAX_INTERFACE_LIMIT {
        return Err(format!(
            "limit {limit} out of range; must be 1..={MAX_INTERFACE_LIMIT}"
        ));
    }
    Ok(limit as usize)
}

#[cfg(any(feature = "pcap", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct InterfaceRow {
    name: String,
    desc: Option<String>,
    addresses: Vec<String>,
}

#[cfg(feature = "pcap")]
impl From<pcap::Device> for InterfaceRow {
    fn from(device: pcap::Device) -> Self {
        Self {
            name: compact_text(&device.name),
            desc: device.desc.as_deref().map(compact_text),
            addresses: device.addresses.iter().map(format_address).collect(),
        }
    }
}

#[cfg(feature = "pcap")]
fn format_address(addr: &pcap::Address) -> String {
    let mut parts = vec![addr.addr.to_string()];
    if let Some(netmask) = addr.netmask {
        parts.push(format!("netmask={netmask}"));
    }
    if let Some(broadcast) = addr.broadcast_addr {
        parts.push(format!("broadcast={broadcast}"));
    }
    if let Some(dst) = addr.dst_addr {
        parts.push(format!("dst={dst}"));
    }
    parts.join(" ")
}

#[cfg(any(feature = "pcap", test))]
fn compact_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(any(feature = "pcap", test))]
fn format_interface_rows(rows: &[InterfaceRow], limit: usize, include_addresses: bool) -> String {
    if rows.is_empty() {
        return "No pcap capture interfaces found.".to_string();
    }

    let mut sorted: Vec<&InterfaceRow> = rows.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let shown = sorted.len().min(limit);
    let mut out = format!(
        "pcap capture interfaces (showing {shown}/{}):\n",
        sorted.len()
    );
    for row in sorted.into_iter().take(shown) {
        out.push_str("  ");
        out.push_str(&row.name);
        if let Some(desc) = &row.desc
            && !desc.is_empty()
        {
            out.push_str(" desc=\"");
            out.push_str(desc);
            out.push('"');
        }
        if include_addresses {
            let addr_count = row.addresses.len();
            if addr_count == 0 {
                out.push_str(" addrs=-");
            } else {
                let emitted = addr_count.min(MAX_ADDRS_PER_INTERFACE);
                out.push_str(" addrs=");
                out.push_str(&row.addresses[..emitted].join(","));
                if addr_count > emitted {
                    out.push_str(&format!(" (+{} more)", addr_count - emitted));
                }
            }
        } else {
            out.push_str(" addrs=omitted");
        }
        out.push('\n');
    }
    if rows.len() > shown {
        out.push_str(&format!(
            "... {} interface(s) omitted; raise limit up to {MAX_INTERFACE_LIMIT}\n",
            rows.len() - shown
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, desc: Option<&str>, addresses: &[&str]) -> InterfaceRow {
        InterfaceRow {
            name: name.to_string(),
            desc: desc.map(str::to_string),
            addresses: addresses.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn interface_limit_defaults_and_rejects_bad_values() {
        assert_eq!(interface_limit(None).unwrap(), DEFAULT_INTERFACE_LIMIT);
        assert_eq!(interface_limit(Some(1)).unwrap(), 1);
        assert!(
            interface_limit(Some(0))
                .unwrap_err()
                .contains("out of range")
        );
        assert!(
            interface_limit(Some((MAX_INTERFACE_LIMIT + 1) as u32))
                .unwrap_err()
                .contains("out of range")
        );
    }

    #[test]
    fn format_interface_rows_sorts_omits_and_caps_addresses() {
        let mut addrs = vec![
            "192.168.1.10".to_string(),
            "fe80::1".to_string(),
            "10.0.0.1".to_string(),
            "10.0.0.2".to_string(),
            "10.0.0.3".to_string(),
            "10.0.0.4".to_string(),
            "10.0.0.5".to_string(),
            "10.0.0.6".to_string(),
            "10.0.0.7".to_string(),
        ];
        let rows = vec![
            row("utun0", None, &[]),
            InterfaceRow {
                name: "en0".to_string(),
                desc: Some("Wi-Fi".to_string()),
                addresses: std::mem::take(&mut addrs),
            },
        ];

        let out = format_interface_rows(&rows, 1, true);

        assert!(out.starts_with("pcap capture interfaces (showing 1/2):"));
        assert!(out.contains("en0 desc=\"Wi-Fi\""));
        assert!(out.contains("(+1 more)"));
        assert!(out.contains("1 interface(s) omitted"));
        assert!(!out.contains("utun0 addrs=-"));
    }

    #[test]
    fn format_interface_rows_can_omit_addresses() {
        let rows = vec![row("en0", Some("main interface"), &["192.168.1.10"])];

        let out = format_interface_rows(&rows, 10, false);

        assert!(out.contains("en0 desc=\"main interface\" addrs=omitted"));
        assert!(!out.contains("192.168.1.10"));
    }

    #[test]
    fn compact_text_collapses_whitespace() {
        assert_eq!(compact_text("a\n b\t c"), "a b c");
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn list_interfaces_reports_disabled_feature_without_pcap() {
        let err = list_pcap_interfaces_impl(ListPcapInterfacesParams {
            limit: None,
            include_addresses: None,
        })
        .unwrap_err();

        assert!(err.contains("rebuild with feature `pcap`"));
    }
}
