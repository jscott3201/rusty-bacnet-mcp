//! Alarm + event MCP tool integration tests (no live BACnet stack).
//!
//! Pre-dispatch validation order matters here: agents passing garbage to
//! acknowledge_alarm must get a clear policy/parse error rather than a
//! generic "BACnet client not started", and every write attempt — allow,
//! deny, dry-run, error — must produce an audit entry.

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
use bacnet_mcp::mcp::alarms::{
    AcknowledgeAlarmParams, AlarmSummaryParams, EventInformationParams, acknowledge_alarm_impl,
    get_alarm_summary_impl, get_event_information_impl,
};
use bacnet_mcp::state::GatewayState;

use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig as BacnetDeviceConfig, DeviceObject};

fn test_state(read_only: bool) -> GatewayState {
    let cfg = GatewayConfig {
        mcp: McpConfig {
            read_only,
            ..McpConfig::default()
        },
        device: DeviceConfig {
            instance: 1234,
            name: "Test Gateway".to_string(),
            vendor_id: 999,
            description: "Test".to_string(),
        },
        transports: TransportsConfig::default(),
        bbmd: None,
        foreign_device: None,
        routes: vec![],
        objects: vec![],
    };
    let mut db = ObjectDatabase::new();
    let device = DeviceObject::new(BacnetDeviceConfig {
        instance: 1234,
        name: "Test Gateway".into(),
        vendor_id: 999,
        ..BacnetDeviceConfig::default()
    })
    .unwrap();
    db.add(Box::new(device)).unwrap();
    GatewayState::new(db, cfg)
}

#[tokio::test]
async fn alarm_summary_no_client_errors_cleanly() {
    let state = test_state(false);
    let result = get_alarm_summary_impl(
        &state,
        AlarmSummaryParams {
            device_instance: 1234,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn event_information_no_client_errors_cleanly() {
    let state = test_state(false);
    let result = get_event_information_impl(
        &state,
        EventInformationParams {
            device_instance: 1234,
            after: None,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn event_information_rejects_bad_after_pre_dispatch() {
    let state = test_state(false);
    let result = get_event_information_impl(
        &state,
        EventInformationParams {
            device_instance: 1234,
            after: Some("garbage".into()),
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(
        !err.contains("not started"),
        "validation must precede transport, got: {err}"
    );
}

#[tokio::test]
async fn acknowledge_alarm_dry_run_records_audit_and_skips_send() {
    let state = test_state(false);
    let result = acknowledge_alarm_impl(
        &state,
        AcknowledgeAlarmParams {
            device_instance: 1234,
            object_type: "analog-input".into(),
            object_instance: 1,
            event_state_acknowledged: 2,
            acknowledgment_source: "operator-test".into(),
            acknowledging_process_identifier: 1,
            transition_timestamp: None,
            dry_run: true,
        },
    )
    .await
    .unwrap();
    assert!(result.contains("[dry-run]"), "got: {result}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].tool, "acknowledge_alarm");
    assert_eq!(snap[0].decision, "allow");
    assert!(snap[0].dry_run);
}

#[tokio::test]
async fn acknowledge_alarm_read_only_mode_audits_deny() {
    // Pin: require_writable failure in read-only mode produces a deny audit
    // entry, matching write_property's behaviour from PR #3.
    let state = test_state(true); // read_only = true (production default)
    let result = acknowledge_alarm_impl(
        &state,
        AcknowledgeAlarmParams {
            device_instance: 1234,
            object_type: "analog-input".into(),
            object_instance: 1,
            event_state_acknowledged: 2,
            acknowledgment_source: "operator-test".into(),
            acknowledging_process_identifier: 1,
            transition_timestamp: None,
            dry_run: false,
        },
    )
    .await;
    assert!(
        result.unwrap_err().to_lowercase().contains("read-only"),
        "expected read-only refusal"
    );

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "deny");
}

#[tokio::test]
async fn acknowledge_alarm_rejects_invalid_event_state() {
    // Codex P2 (PR #5): event_state_acknowledged > 15 must fail local
    // validation rather than be dispatched to the device. The check fires
    // through the audit deny path so forensic review still records intent.
    let state = test_state(false);
    let result = acknowledge_alarm_impl(
        &state,
        AcknowledgeAlarmParams {
            device_instance: 1234,
            object_type: "analog-input".into(),
            object_instance: 1,
            event_state_acknowledged: 99,
            acknowledgment_source: "operator-test".into(),
            acknowledging_process_identifier: 1,
            transition_timestamp: None,
            dry_run: true,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(
        err.contains("EventState") || err.contains("event_state_acknowledged"),
        "got: {err}"
    );

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "deny");
}

#[tokio::test]
async fn acknowledge_alarm_accepts_transition_timestamp() {
    // Codex P1 (PR #5): a caller can now pass the original event's
    // transition timestamp (sequence number form) so strict devices can
    // match the ack against the pending transition.
    let state = test_state(false);
    let result = acknowledge_alarm_impl(
        &state,
        AcknowledgeAlarmParams {
            device_instance: 1234,
            object_type: "analog-input".into(),
            object_instance: 1,
            event_state_acknowledged: 2,
            acknowledgment_source: "operator-test".into(),
            acknowledging_process_identifier: 1,
            transition_timestamp: Some("seq#42".into()),
            dry_run: true,
        },
    )
    .await
    .unwrap();
    assert!(result.contains("[dry-run]"), "got: {result}");
    assert!(
        result.contains("seq#42"),
        "ts must be echoed in dry-run: {result}"
    );
}

#[tokio::test]
async fn acknowledge_alarm_rejects_bad_transition_timestamp() {
    let state = test_state(false);
    let result = acknowledge_alarm_impl(
        &state,
        AcknowledgeAlarmParams {
            device_instance: 1234,
            object_type: "analog-input".into(),
            object_instance: 1,
            event_state_acknowledged: 2,
            acknowledgment_source: "operator-test".into(),
            acknowledging_process_identifier: 1,
            transition_timestamp: Some("not-a-thing".into()),
            dry_run: true,
        },
    )
    .await;
    assert!(result.is_err());
    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "deny");
}

#[tokio::test]
async fn acknowledge_alarm_no_client_audits_then_errors() {
    // Pin: even after policy passes, transport prerequisite failures must
    // produce an `error` audit entry — same Codex P2 fix that landed for
    // write_property and relinquish_at_priority in PR #3.
    let state = test_state(false);
    let result = acknowledge_alarm_impl(
        &state,
        AcknowledgeAlarmParams {
            device_instance: 1234,
            object_type: "analog-input".into(),
            object_instance: 1,
            event_state_acknowledged: 2,
            acknowledgment_source: "operator-test".into(),
            acknowledging_process_identifier: 1,
            transition_timestamp: None,
            dry_run: false,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "error");
}
