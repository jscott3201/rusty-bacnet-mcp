#![cfg(feature = "mcp")]

use bacnet_encoding::apdu::{self, Apdu, ConfirmedRequest, UnconfirmedRequest};
use bacnet_encoding::npdu::{self, Npdu};
use bacnet_mcp::mcp::wire::{
    AnalyzeBacnetIpPacketParams, WireInputKind, WireResponseMode, analyze_bacnet_ip_packet_impl,
};
use bacnet_transport::bvll;
use bacnet_types::enums::{
    BvlcFunction, ConfirmedServiceChoice, NetworkPriority, UnconfirmedServiceChoice,
};
use bytes::{Bytes, BytesMut};

fn packet_params(bytes: Vec<u8>, input: WireInputKind) -> AnalyzeBacnetIpPacketParams {
    AnalyzeBacnetIpPacketParams {
        bytes_hex: hex(&bytes),
        input,
        response_mode: WireResponseMode::Compact,
        max_detail_lines: None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn simple_npdu() -> Npdu {
    Npdu {
        is_network_message: false,
        expecting_reply: false,
        priority: NetworkPriority::NORMAL,
        destination: None,
        source: None,
        hop_count: 255,
        message_type: None,
        vendor_id: None,
        payload: Bytes::new(),
    }
}

fn build_bvlc_packet(function: BvlcFunction, npdu: &Npdu, apdu: Option<&Apdu>) -> Vec<u8> {
    let mut apdu_buf = BytesMut::new();
    if let Some(apdu) = apdu {
        apdu::encode_apdu(&mut apdu_buf, apdu).unwrap();
    }
    let mut npdu_with_payload = npdu.clone();
    npdu_with_payload.payload = Bytes::from(apdu_buf.to_vec());

    let mut npdu_buf = BytesMut::new();
    npdu::encode_npdu(&mut npdu_buf, &npdu_with_payload).unwrap();

    let mut bvlc_buf = BytesMut::new();
    bvll::encode_bvll(&mut bvlc_buf, function, &npdu_buf).unwrap();
    bvlc_buf.to_vec()
}

fn who_is_bvlc() -> Vec<u8> {
    let apdu = Apdu::UnconfirmedRequest(UnconfirmedRequest {
        service_choice: UnconfirmedServiceChoice::WHO_IS,
        service_request: Bytes::new(),
    });
    build_bvlc_packet(
        BvlcFunction::ORIGINAL_BROADCAST_NPDU,
        &simple_npdu(),
        Some(&apdu),
    )
}

fn read_property_bvlc() -> Vec<u8> {
    let apdu = Apdu::ConfirmedRequest(ConfirmedRequest {
        segmented: false,
        more_follows: false,
        segmented_response_accepted: true,
        max_segments: None,
        max_apdu_length: 1476,
        invoke_id: 7,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: ConfirmedServiceChoice::READ_PROPERTY,
        service_request: Bytes::from_static(&[0x0C, 0, 0, 0, 1, 0x19, 0x55]),
    });
    build_bvlc_packet(
        BvlcFunction::ORIGINAL_UNICAST_NPDU,
        &Npdu {
            expecting_reply: true,
            ..simple_npdu()
        },
        Some(&apdu),
    )
}

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

fn ethernet_frame(payload: &[u8]) -> Vec<u8> {
    let ipv4 = ipv4_udp(payload);
    let mut frame = vec![0u8; 14];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ipv4);
    frame
}

#[test]
fn compact_bvlc_payload_reports_service_summary() {
    let out =
        analyze_bacnet_ip_packet_impl(packet_params(who_is_bvlc(), WireInputKind::Bvlc)).unwrap();

    assert!(out.contains("input: bvlc"));
    assert!(out.contains("summary: ORIGINAL_BROADCAST_NPDU / WHO_IS"));
    assert!(!out.contains("APDU:"));
}

#[test]
fn detailed_bvlc_payload_reports_layers_and_bounds_detail_lines() {
    let mut params = packet_params(read_property_bvlc(), WireInputKind::Bvlc);
    params.response_mode = WireResponseMode::Detailed;
    params.max_detail_lines = Some(2);
    let out = analyze_bacnet_ip_packet_impl(params).unwrap();

    assert!(out.contains("summary: ORIGINAL_UNICAST_NPDU / READ_PROPERTY"));
    assert!(out.contains("BVLC: ORIGINAL_UNICAST_NPDU"));
    assert!(out.contains("NPDU: version=1"));
    assert!(out.contains("detail line(s) omitted"));
    assert!(!out.contains("Service: READ_PROPERTY"));
}

#[test]
fn ethernet_frame_reports_udp_flow() {
    let frame = ethernet_frame(&who_is_bvlc());
    let out = analyze_bacnet_ip_packet_impl(packet_params(frame, WireInputKind::Ethernet)).unwrap();

    assert!(out.contains("input: ethernet"));
    assert!(out.contains("udp: 192.168.1.10:47808 -> 192.168.1.255:47808"));
    assert!(out.contains("WHO_IS"));
}

#[test]
fn vlan_tagged_ethernet_frame_is_supported() {
    let ipv4 = ipv4_udp(&who_is_bvlc());
    let mut frame = vec![0u8; 18];
    frame[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ipv4);

    let out = analyze_bacnet_ip_packet_impl(packet_params(frame, WireInputKind::Ethernet)).unwrap();
    assert!(out.contains("summary: ORIGINAL_BROADCAST_NPDU / WHO_IS"));
}

#[test]
fn raw_ipv4_bsd_null_and_linux_sll_inputs_share_parser() {
    let ipv4 = ipv4_udp(&who_is_bvlc());
    assert!(
        analyze_bacnet_ip_packet_impl(packet_params(ipv4.clone(), WireInputKind::Ipv4))
            .unwrap()
            .contains("WHO_IS")
    );

    let mut bsd = 2u32.to_le_bytes().to_vec();
    bsd.extend_from_slice(&ipv4);
    assert!(
        analyze_bacnet_ip_packet_impl(packet_params(bsd, WireInputKind::BsdNull))
            .unwrap()
            .contains("WHO_IS")
    );

    let mut sll = vec![0u8; 16];
    sll[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
    sll.extend_from_slice(&ipv4);
    assert!(
        analyze_bacnet_ip_packet_impl(packet_params(sll, WireInputKind::LinuxSll))
            .unwrap()
            .contains("WHO_IS")
    );
}

#[test]
fn forwarded_npdu_reports_originating_ip_in_detail() {
    let npdu = simple_npdu();
    let mut npdu_buf = BytesMut::new();
    npdu::encode_npdu(&mut npdu_buf, &npdu).unwrap();
    let mut bvlc = BytesMut::new();
    bvll::encode_bvll_forwarded(&mut bvlc, [10, 0, 0, 44], 47808, &npdu_buf).unwrap();

    let mut params = packet_params(bvlc.to_vec(), WireInputKind::Bvlc);
    params.response_mode = WireResponseMode::Detailed;
    let out = analyze_bacnet_ip_packet_impl(params).unwrap();

    assert!(out.contains("summary: FORWARDED_NPDU / NPDU"));
    assert!(out.contains("Forwarded-from: 10.0.0.44:47808"));
}

#[test]
fn parser_accepts_spaced_prefixed_and_colon_hex() {
    let bytes = who_is_bvlc();
    let text = bytes
        .iter()
        .map(|b| format!("0x{b:02X}"))
        .collect::<Vec<_>>()
        .join(": ");
    let out = analyze_bacnet_ip_packet_impl(AnalyzeBacnetIpPacketParams {
        bytes_hex: text,
        input: WireInputKind::Bvlc,
        response_mode: WireResponseMode::Compact,
        max_detail_lines: None,
    })
    .unwrap();

    assert!(out.contains("WHO_IS"));
}

#[test]
fn rejects_non_udp_ipv4_before_bvlc_decode() {
    let mut ipv4 = ipv4_udp(&who_is_bvlc());
    ipv4[9] = 6;

    let err = analyze_bacnet_ip_packet_impl(packet_params(ipv4, WireInputKind::Ipv4)).unwrap_err();
    assert!(err.contains("is not UDP"));
}

#[test]
fn rejects_invalid_bvlc_payload() {
    let err = analyze_bacnet_ip_packet_impl(AnalyzeBacnetIpPacketParams {
        bytes_hex: "01020304".to_string(),
        input: WireInputKind::Bvlc,
        response_mode: WireResponseMode::Compact,
        max_detail_lines: None,
    })
    .unwrap_err();

    assert!(err.contains("BVLC decode error"));
}

#[test]
fn rejects_out_of_range_detail_limit() {
    let mut params = packet_params(who_is_bvlc(), WireInputKind::Bvlc);
    params.response_mode = WireResponseMode::Detailed;
    params.max_detail_lines = Some(0);

    let err = analyze_bacnet_ip_packet_impl(params).unwrap_err();
    assert!(err.contains("max_detail_lines 0 out of range"));
}

#[test]
fn rejects_oversized_hex_before_decoding_full_payload() {
    let oversized = vec![0x81; 8193];
    let err = analyze_bacnet_ip_packet_impl(AnalyzeBacnetIpPacketParams {
        bytes_hex: hex(&oversized),
        input: WireInputKind::Bvlc,
        response_mode: WireResponseMode::Compact,
        max_detail_lines: None,
    })
    .unwrap_err();

    assert!(err.contains("max decoded size of 8192 bytes"));
}
