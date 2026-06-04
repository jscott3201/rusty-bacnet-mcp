//! WritePropertyMultiple MCP tests.
//! Requires: `cargo test -p bacnet-mcp --features mcp`

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{BipConfig, DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
use bacnet_mcp::mcp::properties::{
    WritePropertyMultipleObjectParams, WritePropertyMultipleParams,
    WritePropertyMultipleValueParams, write_property_multiple_impl,
};
use bacnet_mcp::state::GatewayState;

use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig as BacnetDeviceConfig, DeviceObject};

fn test_config(read_only: bool) -> GatewayConfig {
    GatewayConfig {
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
    }
}

fn test_state(read_only: bool) -> GatewayState {
    let mut db = ObjectDatabase::new();
    let device = DeviceObject::new(BacnetDeviceConfig {
        instance: 1234,
        name: "Test Gateway".into(),
        vendor_id: 999,
        ..BacnetDeviceConfig::default()
    })
    .unwrap();
    db.add(Box::new(device)).unwrap();
    GatewayState::new(db, test_config(read_only))
}

fn value(
    property: &str,
    json: serde_json::Value,
    priority: Option<u8>,
) -> WritePropertyMultipleValueParams {
    WritePropertyMultipleValueParams {
        property: property.to_string(),
        value: json,
        array_index: None,
        priority,
    }
}

fn one_value_batch(dry_run: bool, priority: Option<u8>) -> WritePropertyMultipleParams {
    WritePropertyMultipleParams {
        device_instance: 1234,
        objects: vec![WritePropertyMultipleObjectParams {
            object_type: "analog-output".to_string(),
            object_instance: 1,
            properties: vec![value("present-value", serde_json::json!(72.5), priority)],
        }],
        dry_run,
    }
}

#[tokio::test]
async fn wpm_dry_run_allows_and_audits_each_property_without_client() {
    let state = test_state(false);
    let params = WritePropertyMultipleParams {
        device_instance: 1234,
        objects: vec![
            WritePropertyMultipleObjectParams {
                object_type: "analog-output".into(),
                object_instance: 1,
                properties: vec![
                    value("present-value", serde_json::json!(72.5), Some(10)),
                    value("out-of-service", serde_json::json!(true), None),
                ],
            },
            WritePropertyMultipleObjectParams {
                object_type: "binary-output".into(),
                object_instance: 2,
                properties: vec![value("present-value", serde_json::json!(true), Some(12))],
            },
        ],
        dry_run: true,
    };

    let result = write_property_multiple_impl(&state, params).await.unwrap();
    assert!(result.contains("[dry-run]"), "got: {result}");
    assert!(result.contains("3 properties"), "got: {result}");
    assert!(result.contains("2 objects"), "got: {result}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 3);
    assert!(snap.iter().all(|e| e.tool == "write_property_multiple"));
    assert!(snap.iter().all(|e| e.decision == "allow"));
    assert!(snap.iter().all(|e| e.dry_run));
    assert_eq!(snap[0].target.as_deref(), Some("analog-output:1"));
    assert_eq!(snap[0].property.as_deref(), Some("present-value"));
    assert_eq!(snap[0].priority, Some(10));
    assert_eq!(snap[1].property.as_deref(), Some("out-of-service"));
    assert_eq!(snap[1].priority, None);
    assert_eq!(snap[2].target.as_deref(), Some("binary-output:2"));
}

#[tokio::test]
async fn wpm_real_write_without_client_audits_error_for_each_property() {
    let state = test_state(false);
    let result = write_property_multiple_impl(&state, one_value_batch(false, Some(10))).await;
    let err = result.unwrap_err();
    assert!(err.contains("not started"), "got: {err}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].tool, "write_property_multiple");
    assert_eq!(snap[0].decision, "error");
    assert!(!snap[0].dry_run);
    assert!(snap[0].reason.contains("not started"));
}

#[tokio::test]
async fn wpm_read_only_mode_denies_and_audits_all_requested_properties() {
    let state = test_state(true);
    let params = WritePropertyMultipleParams {
        device_instance: 1234,
        objects: vec![WritePropertyMultipleObjectParams {
            object_type: "analog-output".into(),
            object_instance: 1,
            properties: vec![
                value("present-value", serde_json::json!(72.5), Some(10)),
                value("out-of-service", serde_json::json!(false), None),
            ],
        }],
        dry_run: false,
    };

    let err = write_property_multiple_impl(&state, params)
        .await
        .unwrap_err();
    assert!(err.to_lowercase().contains("read-only"), "got: {err}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 2);
    assert!(snap.iter().all(|e| e.decision == "deny"));
    assert!(
        snap.iter()
            .all(|e| e.reason.to_lowercase().contains("read-only"))
    );
}

#[tokio::test]
async fn wpm_priority_floor_denies_before_any_batch_dispatch() {
    let state = test_state(false);
    let result = write_property_multiple_impl(&state, one_value_batch(true, Some(5))).await;
    let err = result.unwrap_err();
    assert!(err.contains("Policy denied"), "got: {err}");
    assert!(err.contains("floor"), "got: {err}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "deny");
    assert_eq!(snap[0].priority, Some(5));
}

#[tokio::test]
async fn wpm_rejects_priority_outside_bacnet_range_and_audits() {
    let state = test_state(false);
    let result = write_property_multiple_impl(&state, one_value_batch(true, Some(17))).await;
    let err = result.unwrap_err();
    assert!(err.contains("1..=16"), "got: {err}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "deny");
    assert_eq!(snap[0].priority, Some(17));
}

#[tokio::test]
async fn wpm_invalid_value_shape_audits_error() {
    let state = test_state(false);
    let params = WritePropertyMultipleParams {
        device_instance: 1234,
        objects: vec![WritePropertyMultipleObjectParams {
            object_type: "analog-output".into(),
            object_instance: 1,
            properties: vec![value(
                "present-value",
                serde_json::json!({ "bad": "shape" }),
                Some(10),
            )],
        }],
        dry_run: true,
    };

    let err = write_property_multiple_impl(&state, params)
        .await
        .unwrap_err();
    assert!(err.contains("Error parsing value"), "got: {err}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "error");
    assert!(snap[0].reason.contains("Error parsing value"));
}

#[tokio::test]
async fn wpm_unknown_property_audits_deny() {
    let state = test_state(false);
    let params = WritePropertyMultipleParams {
        device_instance: 1234,
        objects: vec![WritePropertyMultipleObjectParams {
            object_type: "analog-output".into(),
            object_instance: 1,
            properties: vec![value(
                "definitely-not-a-property",
                serde_json::json!(1.0),
                Some(10),
            )],
        }],
        dry_run: true,
    };

    let err = write_property_multiple_impl(&state, params)
        .await
        .unwrap_err();
    assert!(err.contains("unknown property"), "got: {err}");

    let snap = state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "deny");
    assert_eq!(
        snap[0].property.as_deref(),
        Some("definitely-not-a-property")
    );
}

#[tokio::test]
async fn wpm_empty_objects_rejected_before_audit_or_client() {
    let state = test_state(false);
    let params = WritePropertyMultipleParams {
        device_instance: 1234,
        objects: vec![],
        dry_run: false,
    };
    let err = write_property_multiple_impl(&state, params)
        .await
        .unwrap_err();
    assert!(err.contains("at least one"), "got: {err}");
    assert!(state.audit.snapshot(0).is_empty());
}

#[tokio::test]
async fn wpm_empty_properties_rejected_before_audit_or_client() {
    let state = test_state(false);
    let params = WritePropertyMultipleParams {
        device_instance: 1234,
        objects: vec![WritePropertyMultipleObjectParams {
            object_type: "analog-output".into(),
            object_instance: 1,
            properties: vec![],
        }],
        dry_run: false,
    };
    let err = write_property_multiple_impl(&state, params)
        .await
        .unwrap_err();
    assert!(err.contains("no properties"), "got: {err}");
    assert!(state.audit.snapshot(0).is_empty());
}

#[tokio::test]
async fn wpm_object_count_cap_rejected_before_audit_or_client() {
    let state = test_state(false);
    let objects = (0..33)
        .map(|i| WritePropertyMultipleObjectParams {
            object_type: "analog-output".into(),
            object_instance: i,
            properties: vec![value("present-value", serde_json::json!(1.0), Some(10))],
        })
        .collect();
    let params = WritePropertyMultipleParams {
        device_instance: 1234,
        objects,
        dry_run: false,
    };
    let err = write_property_multiple_impl(&state, params)
        .await
        .unwrap_err();
    assert!(err.contains("max is 32"), "got: {err}");
    assert!(state.audit.snapshot(0).is_empty());
}

#[tokio::test]
async fn wpm_property_count_cap_rejected_before_audit_or_client() {
    let state = test_state(false);
    let properties = (0..129)
        .map(|_| value("present-value", serde_json::json!(1.0), Some(10)))
        .collect();
    let params = WritePropertyMultipleParams {
        device_instance: 1234,
        objects: vec![WritePropertyMultipleObjectParams {
            object_type: "analog-output".into(),
            object_instance: 1,
            properties,
        }],
        dry_run: false,
    };
    let err = write_property_multiple_impl(&state, params)
        .await
        .unwrap_err();
    assert!(err.contains("max is 128"), "got: {err}");
    assert!(state.audit.snapshot(0).is_empty());
}

#[tokio::test]
async fn wpm_started_client_missing_device_audits_error() {
    let config = GatewayConfig {
        mcp: McpConfig {
            read_only: false,
            ..McpConfig::default()
        },
        device: DeviceConfig {
            instance: 1234,
            name: "Test Gateway".to_string(),
            vendor_id: 999,
            description: "Test".to_string(),
        },
        transports: TransportsConfig {
            bip: Some(BipConfig {
                interface: "127.0.0.1".into(),
                port: 0,
                broadcast: "127.255.255.255".into(),
                network_number: 1,
            }),
            sc: None,
        },
        bbmd: None,
        foreign_device: None,
        routes: vec![],
        objects: vec![],
    };
    let built = bacnet_mcp::builder::GatewayBuilder::new(config)
        .build()
        .await
        .expect("ephemeral gateway builds");

    let err = write_property_multiple_impl(&built.state, one_value_batch(false, Some(10)))
        .await
        .unwrap_err();
    assert!(err.contains("not found"), "got: {err}");

    let snap = built.state.audit.snapshot(0);
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].decision, "error");
    assert!(snap[0].reason.contains("not found"));
}
