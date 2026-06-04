//! MCP server integration tests.
//! Requires: `cargo test -p bacnet-mcp --features mcp`

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
use bacnet_mcp::mcp::GatewayMcp;
use bacnet_mcp::mcp::bulk;
use bacnet_mcp::mcp::discovery;
use bacnet_mcp::mcp::objects;
use bacnet_mcp::mcp::reference;
use bacnet_mcp::state::GatewayState;

use bacnet_objects::analog::AnalogValueObject;
use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig as BacnetDeviceConfig, DeviceObject};

use rmcp::ServerHandler;

fn test_config() -> GatewayConfig {
    GatewayConfig {
        mcp: McpConfig {
            // Tests need writes enabled — the production default is read-only.
            read_only: false,
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
    }
}

fn test_state() -> GatewayState {
    let mut db = ObjectDatabase::new();
    let device = DeviceObject::new(BacnetDeviceConfig {
        instance: 1234,
        name: "Test Gateway".into(),
        vendor_id: 999,
        ..BacnetDeviceConfig::default()
    })
    .unwrap();
    db.add(Box::new(device)).unwrap();
    let av = AnalogValueObject::new(1, "Test AV", 95).unwrap();
    db.add(Box::new(av)).unwrap();
    GatewayState::new(db, test_config())
}

#[test]
fn mcp_server_has_tool_capabilities() {
    let state = test_state();
    let mcp = GatewayMcp::new(state);
    let info = mcp.get_info();
    assert!(info.capabilities.tools.is_some());
}

#[tokio::test]
async fn mcp_list_local_objects() {
    let state = test_state();
    let result = objects::list_local_objects_impl(
        &state,
        objects::ListObjectsParams {
            object_type: None,
            limit: None,
        },
    )
    .await;

    let result = result.unwrap();
    assert!(result.contains("2 local object(s)"));
    assert!(result.contains("device:1234"));
    assert!(result.contains("analog-value:1"));
}

#[tokio::test]
async fn mcp_list_local_objects_filtered() {
    let state = test_state();
    let result = objects::list_local_objects_impl(
        &state,
        objects::ListObjectsParams {
            object_type: Some("analog-value".to_string()),
            limit: None,
        },
    )
    .await;

    let result = result.unwrap();
    assert!(result.contains("1 local object(s)"));
    assert!(result.contains("analog-value:1"));
    assert!(!result.contains("device:1234"));
}

#[tokio::test]
async fn mcp_read_local_property() {
    let state = test_state();
    let result = objects::read_local_property_impl(
        &state,
        objects::ReadLocalPropertyParams {
            object_type: "analog-value".to_string(),
            object_instance: 1,
            property: "object-name".to_string(),
        },
    )
    .await;

    assert!(result.unwrap().contains("Test AV"));
}

#[tokio::test]
async fn mcp_write_and_read_local_property() {
    let state = test_state();

    let result = objects::write_local_property_impl(
        &state,
        objects::WriteLocalPropertyParams {
            object_type: "analog-value".to_string(),
            object_instance: 1,
            property: "present-value".to_string(),
            value: serde_json::json!(42.0),
            dry_run: false,
        },
    )
    .await;

    assert!(result.unwrap().contains("Successfully wrote"));

    let result = objects::read_local_property_impl(
        &state,
        objects::ReadLocalPropertyParams {
            object_type: "analog-value".to_string(),
            object_instance: 1,
            property: "present-value".to_string(),
        },
    )
    .await;

    assert!(result.unwrap().contains("42"));
}

#[tokio::test]
async fn mcp_read_nonexistent_object() {
    let state = test_state();
    let result = objects::read_local_property_impl(
        &state,
        objects::ReadLocalPropertyParams {
            object_type: "analog-input".to_string(),
            object_instance: 999,
            property: "present-value".to_string(),
        },
    )
    .await;

    assert!(result.unwrap_err().contains("not found"));
}

#[tokio::test]
async fn mcp_list_known_devices_no_client() {
    let state = test_state();
    let result = discovery::list_known_devices_impl(
        &state,
        discovery::ListKnownDevicesParams { limit: None },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn mcp_discover_devices_no_client() {
    let state = test_state();
    let result = discovery::discover_devices_impl(
        &state,
        discovery::DiscoverParams {
            low_instance: None,
            high_instance: None,
            timeout_seconds: Some(1),
            target: None,
            limit: None,
        },
    )
    .await;

    assert!(result.unwrap_err().contains("not started"));
}

// --- Bulk read tools (RPM-backed) ---

#[tokio::test]
async fn rpm_empty_objects_rejected_pre_dispatch() {
    // Empty `objects` is a parameter error; we must not even attempt to
    // contact the (absent) BACnet client.
    let state = test_state();
    let result = bulk::read_property_multiple_impl(
        &state,
        bulk::ReadPropertyMultipleParams {
            device_instance: 1234,
            objects: vec![],
            response_mode: bulk::RpmResponseMode::Compact,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(
        err.contains("at least one"),
        "expected pre-dispatch validation error, got: {err}"
    );
    assert!(
        !err.contains("client not started"),
        "validation must precede client check, got: {err}"
    );
}

#[tokio::test]
async fn rpm_no_client_after_validation() {
    let state = test_state();
    let result = bulk::read_property_multiple_impl(
        &state,
        bulk::ReadPropertyMultipleParams {
            device_instance: 1234,
            objects: vec![bulk::ObjectRequest {
                object_type: "analog-input".into(),
                object_instance: 1,
                properties: vec![bulk::PropertyRequest {
                    property: bulk::PropertyId::Name("present-value".into()),
                    array_index: None,
                }],
            }],
            response_mode: bulk::RpmResponseMode::Compact,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn read_priority_array_no_client() {
    let state = test_state();
    let result = bulk::read_priority_array_impl(
        &state,
        bulk::ReadPriorityArrayParams {
            device_instance: 1234,
            object_type: "analog-output".into(),
            object_instance: 1,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn enumerate_objects_no_client() {
    let state = test_state();
    let result = bulk::enumerate_objects_impl(
        &state,
        bulk::EnumerateObjectsParams {
            device_instance: 1234,
            limit: None,
            include_names: false,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn get_device_capabilities_no_client() {
    let state = test_state();
    let result = bulk::get_device_capabilities_impl(
        &state,
        bulk::DeviceCapabilitiesParams {
            device_instance: 1234,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

// --- Create/Delete local objects ---

#[tokio::test]
async fn mcp_create_local_object() {
    let state = test_state();
    let result = objects::create_local_object_impl(
        &state,
        objects::CreateLocalObjectParams {
            object_type: "multi-state-value".to_string(),
            object_instance: 1,
            object_name: "Test MSV".to_string(),
            number_of_states: Some(4),
        },
    )
    .await;

    let result = result.unwrap();
    assert!(result.contains("Created"));
    assert!(result.contains("multi-state-value:1"));

    // Verify it exists.
    let list = objects::list_local_objects_impl(
        &state,
        objects::ListObjectsParams {
            object_type: Some("multi-state-value".to_string()),
            limit: None,
        },
    )
    .await;
    assert!(list.unwrap().contains("Test MSV"));
}

#[tokio::test]
async fn mcp_create_integer_value() {
    let state = test_state();
    let result = objects::create_local_object_impl(
        &state,
        objects::CreateLocalObjectParams {
            object_type: "integer-value".to_string(),
            object_instance: 1,
            object_name: "Test IV".to_string(),
            number_of_states: None,
        },
    )
    .await;

    assert!(result.unwrap().contains("Created"));
}

#[tokio::test]
async fn mcp_delete_local_object() {
    let state = test_state();
    let result = objects::delete_local_object_impl(
        &state,
        objects::DeleteLocalObjectParams {
            object_type: "analog-value".to_string(),
            object_instance: 1,
        },
    )
    .await;

    assert!(result.unwrap().contains("Deleted"));

    // Verify it's gone.
    let read = objects::read_local_property_impl(
        &state,
        objects::ReadLocalPropertyParams {
            object_type: "analog-value".to_string(),
            object_instance: 1,
            property: "present-value".to_string(),
        },
    )
    .await;
    assert!(read.unwrap_err().contains("not found"));
}

#[tokio::test]
async fn mcp_delete_device_object_rejected() {
    let state = test_state();
    let result = objects::delete_local_object_impl(
        &state,
        objects::DeleteLocalObjectParams {
            object_type: "device".to_string(),
            object_instance: 1234,
        },
    )
    .await;

    assert!(result.unwrap_err().to_lowercase().contains("cannot delete"));
}

// --- Safety control plane + audit log ---

#[tokio::test]
async fn local_write_dry_run_records_allow_audit_and_skips_db_mutation() {
    let state = test_state();

    // Read the original value first.
    let before = objects::read_local_property_impl(
        &state,
        objects::ReadLocalPropertyParams {
            object_type: "analog-value".to_string(),
            object_instance: 1,
            property: "present-value".to_string(),
        },
    )
    .await
    .unwrap();

    // Dry-run write — must report allow + audit, but DB stays untouched.
    let result = objects::write_local_property_impl(
        &state,
        objects::WriteLocalPropertyParams {
            object_type: "analog-value".to_string(),
            object_instance: 1,
            property: "present-value".to_string(),
            value: serde_json::json!(123.0),
            dry_run: true,
        },
    )
    .await
    .unwrap();
    assert!(result.contains("[dry-run]"), "got: {result}");

    // DB unchanged.
    let after = objects::read_local_property_impl(
        &state,
        objects::ReadLocalPropertyParams {
            object_type: "analog-value".to_string(),
            object_instance: 1,
            property: "present-value".to_string(),
        },
    )
    .await
    .unwrap();
    assert_eq!(before, after, "dry-run must not mutate the local DB");

    // Audit entry recorded with allow + dry_run flags.
    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "allow");
    assert!(snap[0].dry_run);
    assert_eq!(snap[0].tool, "write_local_property");
}

#[tokio::test]
async fn write_to_life_safety_type_is_denied_and_audited() {
    use bacnet_mcp::config::SafetyConfig;

    // Build a config with the default safety policy (life-safety types denied).
    // Test the local-write path because it doesn't need a network client.
    let mut cfg = test_config();
    cfg.mcp.safety = Some(SafetyConfig::default());

    let mut db = bacnet_objects::database::ObjectDatabase::new();
    let device = bacnet_objects::device::DeviceObject::new(bacnet_objects::device::DeviceConfig {
        instance: 1234,
        name: "Test Gateway".into(),
        vendor_id: 999,
        ..bacnet_objects::device::DeviceConfig::default()
    })
    .unwrap();
    db.add(Box::new(device)).unwrap();

    let state = bacnet_mcp::state::GatewayState::new(db, cfg);

    let result = objects::write_local_property_impl(
        &state,
        objects::WriteLocalPropertyParams {
            object_type: "notification-class".to_string(),
            object_instance: 1,
            property: "priority".to_string(),
            value: serde_json::json!(5),
            dry_run: false,
        },
    )
    .await;

    let err = result.unwrap_err();
    assert!(err.contains("Policy denied"), "got: {err}");
    assert!(
        err.to_lowercase().contains("notification-class"),
        "got: {err}"
    );

    // The denial is recorded in the audit log.
    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "deny");
    assert!(!snap[0].dry_run);
}

#[tokio::test]
async fn relinquish_no_client_audits_then_errors() {
    // This test pins Codex's PR #3 P2 fix: pre-send transport failures
    // (require_client / resolve_device) MUST record an audit entry. Before
    // the fix, the early `?` returned without auditing, leaving forensic
    // gaps on the most common operational failure (BACnet client not yet
    // started by the daemon).
    use bacnet_mcp::mcp::properties::{RelinquishParams, relinquish_at_priority_impl};

    let state = test_state();

    let result = relinquish_at_priority_impl(
        &state,
        RelinquishParams {
            device_instance: 1234,
            object_type: "analog-output".into(),
            object_instance: 1,
            property: "present-value".into(),
            priority: 10,
            dry_run: false,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(err.contains("not started"), "got: {err}");

    // The fix: an `error` audit entry must exist for the no-client failure.
    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1, "no-client failure must audit; got: {snap:?}");
    assert_eq!(snap[0].tool, "relinquish_at_priority");
    assert_eq!(snap[0].decision, "error");
    assert!(snap[0].reason.contains("not started"));
}

#[tokio::test]
async fn write_property_no_client_audits_pre_send_failure() {
    // Pins Codex P2: write_property with no client must audit the early
    // failure, not silently `?` past the audit append.
    use bacnet_mcp::mcp::properties::{WritePropertyParams, write_property_impl};

    let state = test_state();
    let result = write_property_impl(
        &state,
        WritePropertyParams {
            device_instance: 1234,
            object_type: "analog-output".into(),
            object_instance: 1,
            property: "present-value".into(),
            value: serde_json::json!(72.5),
            priority: Some(10),
            dry_run: false,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(err.contains("not started"), "got: {err}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1, "no-client failure must audit; got: {snap:?}");
    assert_eq!(snap[0].tool, "write_property");
    assert_eq!(snap[0].decision, "error");
    assert_eq!(snap[0].priority, Some(10));
}

#[tokio::test]
async fn write_property_read_only_mode_audits_deny() {
    // Pins Codex P2: require_writable failure (read-only daemon) must
    // record an audit entry.
    use bacnet_mcp::config::McpConfig;
    use bacnet_mcp::mcp::properties::{WritePropertyParams, write_property_impl};

    // Build a state with read_only=true (the production default).
    let mut cfg = test_config();
    cfg.mcp = McpConfig {
        read_only: true,
        ..McpConfig::default()
    };
    let mut db = bacnet_objects::database::ObjectDatabase::new();
    let device = bacnet_objects::device::DeviceObject::new(bacnet_objects::device::DeviceConfig {
        instance: 1234,
        name: "Test".into(),
        vendor_id: 999,
        ..bacnet_objects::device::DeviceConfig::default()
    })
    .unwrap();
    db.add(Box::new(device)).unwrap();
    let state = bacnet_mcp::state::GatewayState::new(db, cfg);

    let result = write_property_impl(
        &state,
        WritePropertyParams {
            device_instance: 1234,
            object_type: "analog-output".into(),
            object_instance: 1,
            property: "present-value".into(),
            value: serde_json::json!(1.0),
            priority: Some(10),
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
    assert!(snap[0].reason.to_lowercase().contains("read-only"));
}

#[tokio::test]
async fn relinquish_dry_run_records_allow_audit() {
    use bacnet_mcp::mcp::properties::{RelinquishParams, relinquish_at_priority_impl};

    let state = test_state();
    let result = relinquish_at_priority_impl(
        &state,
        RelinquishParams {
            device_instance: 1234,
            object_type: "analog-output".into(),
            object_instance: 1,
            property: "present-value".into(),
            priority: 10,
            dry_run: true,
        },
    )
    .await
    .unwrap();
    assert!(result.contains("[dry-run]"), "got: {result}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].tool, "relinquish_at_priority");
    assert_eq!(snap[0].decision, "allow");
    assert!(snap[0].dry_run);
    assert_eq!(snap[0].priority, Some(10));
}

#[tokio::test]
async fn relinquish_below_priority_floor_is_denied() {
    use bacnet_mcp::mcp::properties::{RelinquishParams, relinquish_at_priority_impl};

    let state = test_state();
    // Default min_priority = 9. Priority 5 should be denied.
    let result = relinquish_at_priority_impl(
        &state,
        RelinquishParams {
            device_instance: 1234,
            object_type: "analog-output".into(),
            object_instance: 1,
            property: "present-value".into(),
            priority: 5,
            dry_run: true,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(err.contains("Policy denied"), "got: {err}");
    assert!(err.contains("floor"), "got: {err}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "deny");
}

#[tokio::test]
async fn allow_object_types_overrides_default_allow_list() {
    use bacnet_mcp::config::SafetyConfig;

    let mut cfg = test_config();
    cfg.mcp.safety = Some(SafetyConfig {
        allow_object_types: Some(vec!["analog-value".into()]),
        ..SafetyConfig::default()
    });

    let mut db = bacnet_objects::database::ObjectDatabase::new();
    let device = bacnet_objects::device::DeviceObject::new(bacnet_objects::device::DeviceConfig {
        instance: 1234,
        name: "Test Gateway".into(),
        vendor_id: 999,
        ..bacnet_objects::device::DeviceConfig::default()
    })
    .unwrap();
    db.add(Box::new(device)).unwrap();
    let av = AnalogValueObject::new(1, "Test AV", 95).unwrap();
    db.add(Box::new(av)).unwrap();
    let state = bacnet_mcp::state::GatewayState::new(db, cfg);

    // Allowed type → write succeeds.
    let ok = objects::write_local_property_impl(
        &state,
        objects::WriteLocalPropertyParams {
            object_type: "analog-value".into(),
            object_instance: 1,
            property: "present-value".into(),
            value: serde_json::json!(7.0),
            dry_run: true,
        },
    )
    .await;
    assert!(ok.is_ok(), "got: {ok:?}");

    // Not on the allow list → denied.
    let denied = objects::write_local_property_impl(
        &state,
        objects::WriteLocalPropertyParams {
            object_type: "binary-value".into(),
            object_instance: 1,
            property: "present-value".into(),
            value: serde_json::json!(true),
            dry_run: true,
        },
    )
    .await;
    let err = denied.unwrap_err();
    assert!(err.contains("Policy denied"), "got: {err}");
    assert!(err.contains("type allowlist"), "got: {err}");
}

// --- Trend logs (moved to tests/trend_tests.rs to fit the 700 LOC cap) ---

// --- Reference resources ---

#[test]
fn reference_resources_list() {
    let resources = reference::reference_resources();
    assert_eq!(resources.len(), 11);
    for r in &resources {
        assert!(
            r.uri.starts_with("bacnet://reference/"),
            "bad URI: {}",
            r.uri
        );
    }
}

#[test]
fn state_resources_list() {
    let resources = reference::state_resources();
    assert_eq!(resources.len(), 5);
    let prefixes: Vec<&str> = resources
        .iter()
        .map(|r| {
            if r.uri.starts_with("bacnet://state/") {
                "state"
            } else if r.uri.starts_with("bacnet://audit/") {
                "audit"
            } else if r.uri.starts_with("bacnet://topology/") {
                "topology"
            } else {
                "other"
            }
        })
        .collect();
    assert!(prefixes.iter().filter(|p| **p == "state").count() == 3);
    assert!(prefixes.iter().filter(|p| **p == "audit").count() == 1);
    assert!(prefixes.iter().filter(|p| **p == "topology").count() == 1);
    assert!(!prefixes.contains(&"other"));
}

#[test]
fn reference_templates_list() {
    let templates = reference::reference_templates();
    assert_eq!(templates.len(), 1);
    assert!(templates[0].uri_template.contains("{type}"));
}

#[test]
fn reference_read_tool_guide() {
    let content = reference::read_reference("bacnet://reference/tool-guide").unwrap();
    assert!(content.contains("Token-efficient usage"));
    assert!(content.contains("read_point_summary"));
    assert!(content.contains("read_property_multiple"));
    assert!(content.contains("dry_run"));
}

#[test]
fn reference_read_object_types_index() {
    let content = reference::read_reference("bacnet://reference/object-types").unwrap();
    assert!(content.contains("analog-input"));
    assert!(content.contains("device"));
    assert!(content.contains("binary-value"));
}

#[test]
fn reference_read_properties() {
    let content = reference::read_reference("bacnet://reference/properties").unwrap();
    assert!(content.contains("present-value"));
    assert!(content.contains("status-flags"));
}

#[test]
fn reference_read_networking() {
    let content = reference::read_reference("bacnet://reference/networking").unwrap();
    assert!(content.contains("BBMD"));
    assert!(content.contains("router"));
}

#[test]
fn reference_read_object_type_detail_analog_input() {
    let content =
        reference::read_reference("bacnet://reference/object-types/analog-input").unwrap();
    assert!(content.contains("Sensor"));
    assert!(content.contains("present-value"));
    assert!(content.contains("cov-increment"));
}

#[test]
fn reference_read_object_type_detail_device() {
    let content = reference::read_reference("bacnet://reference/object-types/device").unwrap();
    assert!(content.contains("vendor-name"));
    assert!(content.contains("object-list"));
}

#[test]
fn reference_read_bibbs() {
    let content = reference::read_reference("bacnet://reference/bibbs").unwrap();
    // Naming convention is the load-bearing teaching for any BIBB consumer —
    // an agent that doesn't internalize A=initiator / B=executor will reason
    // wrong about which side a device fulfills.
    assert!(content.contains("A-side") || content.contains("A = initiator"));
    assert!(content.contains("B-side") || content.contains("B = executor"));
    // Anchor a couple of the load-bearing BIBBs and a profile so a future
    // refactor can't silently drop them.
    assert!(content.contains("DS-RP"));
    assert!(content.contains("DM-DDB"));
    assert!(content.contains("B-OWS"));
    assert!(content.contains("protocol-services-supported"));
}

#[test]
fn reference_read_unknown_returns_none() {
    assert!(reference::read_reference("bacnet://reference/nonexistent").is_none());
}

#[test]
fn reference_server_has_resource_capabilities() {
    let state = test_state();
    let mcp = GatewayMcp::new(state);
    let info = mcp.get_info();
    assert!(info.capabilities.resources.is_some());
}
