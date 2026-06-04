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

#[test]
fn pcap_limits_default_and_reject_bad_values() {
    assert_eq!(packet_limit(None).unwrap(), DEFAULT_PCAP_PACKET_LIMIT);
    assert_eq!(row_limit(None).unwrap(), DEFAULT_PCAP_ROW_LIMIT);
    assert_eq!(packet_limit(Some(1)).unwrap(), 1);
    assert_eq!(row_limit(Some(1)).unwrap(), 1);
    assert!(
        packet_limit(Some(0))
            .unwrap_err()
            .contains("max_packets 0 out of range")
    );
    assert!(
        packet_limit(Some((MAX_PCAP_PACKET_LIMIT + 1) as u32))
            .unwrap_err()
            .contains("out of range")
    );
    assert!(
        row_limit(Some((MAX_PCAP_ROW_LIMIT + 1) as u32))
            .unwrap_err()
            .contains("out of range")
    );
}

#[cfg(feature = "pcap")]
fn who_is_bvlc() -> Vec<u8> {
    vec![0x81, 0x0B, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08]
}

#[cfg(feature = "pcap")]
fn ipv4_udp(payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&[192, 168, 1, 10]);
    pkt[16..20].copy_from_slice(&[192, 168, 1, 255]);
    pkt[20..22].copy_from_slice(&47808u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&47808u16.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

#[cfg(feature = "pcap")]
fn ethernet_frame(payload: &[u8]) -> Vec<u8> {
    let ipv4 = ipv4_udp(payload);
    let mut frame = vec![0u8; 14];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ipv4);
    frame
}

#[cfg(feature = "pcap")]
fn non_udp_ethernet_frame() -> Vec<u8> {
    let mut frame = ethernet_frame(&who_is_bvlc());
    frame[23] = 6;
    frame
}

#[cfg(feature = "pcap")]
fn unique_pcap_path(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bacnet-mcp-{name}-{}-{nanos}.pcap",
        std::process::id()
    ))
}

#[cfg(feature = "pcap")]
fn write_pcap(path: &std::path::Path, datalink: u32, packets: &[Vec<u8>]) {
    let mut bytes = Vec::new();
    push_u32_le(&mut bytes, 0xA1B2C3D4);
    push_u16_le(&mut bytes, 2);
    push_u16_le(&mut bytes, 4);
    push_u32_le(&mut bytes, 0);
    push_u32_le(&mut bytes, 0);
    push_u32_le(&mut bytes, 65_535);
    push_u32_le(&mut bytes, datalink);
    for (idx, packet) in packets.iter().enumerate() {
        push_u32_le(&mut bytes, idx as u32);
        push_u32_le(&mut bytes, 0);
        push_u32_le(&mut bytes, packet.len() as u32);
        push_u32_le(&mut bytes, packet.len() as u32);
        bytes.extend_from_slice(packet);
    }
    std::fs::write(path, bytes).unwrap();
}

#[cfg(feature = "pcap")]
fn push_u16_le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "pcap")]
fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "pcap")]
#[test]
fn analyze_pcap_file_decodes_ethernet_capture() {
    let path = unique_pcap_path("ethernet");
    write_pcap(
        &path,
        pcap::Linktype::ETHERNET.0 as u32,
        &[ethernet_frame(&who_is_bvlc()), non_udp_ethernet_frame()],
    );

    let out = analyze_pcap_file_impl(AnalyzePcapFileParams {
        path: path.display().to_string(),
        max_packets: None,
        max_rows: Some(5),
        include_errors: None,
    })
    .unwrap();
    let _ = std::fs::remove_file(path);

    assert!(out.contains("datalink: ETHERNET(1) input=ethernet"));
    assert!(out.contains("scanned: 2 limit=5000 decoded=1 errors=1 truncated=0"));
    assert!(out.contains("ORIGINAL_BROADCAST_NPDU / WHO_IS"));
    assert!(out.contains("WHO_IS: 1"));
    assert!(out.contains("192.168.1.10:47808 -> 192.168.1.255:47808"));
    assert!(out.contains("ipv4 protocol 6 is not UDP"));
}

#[cfg(feature = "pcap")]
#[test]
fn analyze_pcap_file_honors_packet_and_row_limits() {
    let path = unique_pcap_path("limits");
    write_pcap(
        &path,
        pcap::Linktype::ETHERNET.0 as u32,
        &[
            ethernet_frame(&who_is_bvlc()),
            ethernet_frame(&who_is_bvlc()),
            ethernet_frame(&who_is_bvlc()),
        ],
    );

    let out = analyze_pcap_file_impl(AnalyzePcapFileParams {
        path: path.display().to_string(),
        max_packets: Some(2),
        max_rows: Some(1),
        include_errors: Some(false),
    })
    .unwrap();
    let _ = std::fs::remove_file(path);

    assert!(out.contains("scanned: 2 limit=2 decoded=2 errors=0 truncated=0"));
    assert!(out.contains("WHO_IS: 2"));
    assert!(out.contains("1 decoded packet(s) omitted"));
    assert!(!out.contains("decode_errors:"));
}

#[cfg(feature = "pcap")]
#[test]
fn analyze_pcap_file_rejects_unsupported_datalink() {
    let path = unique_pcap_path("unsupported");
    write_pcap(&path, pcap::Linktype::IEEE802_11_RADIOTAP.0 as u32, &[]);

    let err = analyze_pcap_file_impl(AnalyzePcapFileParams {
        path: path.display().to_string(),
        max_packets: None,
        max_rows: None,
        include_errors: None,
    })
    .unwrap_err();
    let _ = std::fs::remove_file(path);

    assert!(err.contains("unsupported pcap datalink DLT(127)"));
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

#[cfg(not(feature = "pcap"))]
#[test]
fn analyze_pcap_file_reports_disabled_feature_without_pcap() {
    let err = analyze_pcap_file_impl(AnalyzePcapFileParams {
        path: "capture.pcap".to_string(),
        max_packets: None,
        max_rows: None,
        include_errors: None,
    })
    .unwrap_err();

    assert!(err.contains("rebuild with feature `pcap`"));
}
