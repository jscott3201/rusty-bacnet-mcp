//! Schedule MCP tool integration tests (no live BACnet stack).

#![cfg(feature = "mcp")]

use bacnet_mcp::config::{DeviceConfig, GatewayConfig, McpConfig, TransportsConfig};
use bacnet_mcp::mcp::schedule_write::{
    ExceptionInput, PeriodInput, ScheduleValueInput, TimeValueInput, WriteScheduleExceptionsParams,
    WriteScheduleWeeklyParams, write_schedule_exceptions_impl, write_schedule_weekly_impl,
};
use bacnet_mcp::mcp::schedules::{
    ReadScheduleExceptionsParams, ReadScheduleParams, ReadScheduleWeeklyParams,
    read_schedule_exceptions_impl, read_schedule_impl, read_schedule_weekly_impl,
};
use bacnet_mcp::state::GatewayState;

use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig as BacnetDeviceConfig, DeviceObject};

fn test_state() -> GatewayState {
    let cfg = GatewayConfig {
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
async fn read_schedule_no_client_errors_cleanly() {
    let state = test_state();
    let result = read_schedule_impl(
        &state,
        ReadScheduleParams {
            device_instance: 1234,
            schedule_instance: 1,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn read_schedule_validates_oid_pre_dispatch() {
    // ObjectIdentifier::new rejects instance numbers above 4_194_303.
    // Pre-dispatch validation must precede transport — agents get a
    // clear error rather than a generic "client not started".
    let state = test_state();
    let result = read_schedule_impl(
        &state,
        ReadScheduleParams {
            device_instance: 1234,
            schedule_instance: 9_999_999,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(
        !err.contains("not started"),
        "OID validation must precede transport, got: {err}"
    );
}

// ─── read_schedule_weekly ───────────────────────────────────────────────────

#[tokio::test]
async fn read_schedule_weekly_no_client_errors_cleanly() {
    let state = test_state();
    let result = read_schedule_weekly_impl(
        &state,
        ReadScheduleWeeklyParams {
            device_instance: 1234,
            schedule_instance: 1,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn read_schedule_weekly_validates_oid_pre_dispatch() {
    let state = test_state();
    let result = read_schedule_weekly_impl(
        &state,
        ReadScheduleWeeklyParams {
            device_instance: 1234,
            schedule_instance: 9_999_999,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(
        !err.contains("not started"),
        "OID validation must precede transport, got: {err}"
    );
}

// ─── read_schedule_exceptions ───────────────────────────────────────────────

#[tokio::test]
async fn read_schedule_exceptions_no_client_errors_cleanly() {
    let state = test_state();
    let result = read_schedule_exceptions_impl(
        &state,
        ReadScheduleExceptionsParams {
            device_instance: 1234,
            schedule_instance: 1,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
}

#[tokio::test]
async fn read_schedule_exceptions_validates_oid_pre_dispatch() {
    let state = test_state();
    let result = read_schedule_exceptions_impl(
        &state,
        ReadScheduleExceptionsParams {
            device_instance: 1234,
            schedule_instance: 9_999_999,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(
        !err.contains("not started"),
        "OID validation must precede transport, got: {err}"
    );
}

// ─── write_schedule_weekly ──────────────────────────────────────────────────

fn empty_week() -> Vec<Vec<TimeValueInput>> {
    (0..7).map(|_| Vec::new()).collect()
}

#[tokio::test]
async fn write_schedule_weekly_dry_run_passes_without_client() {
    // dry_run short-circuits before require_client / resolve_device, so an
    // unstarted client must produce a dry-run report rather than an error.
    let state = test_state();
    let result = write_schedule_weekly_impl(
        &state,
        WriteScheduleWeeklyParams {
            device_instance: 1234,
            schedule_instance: 1,
            days: empty_week(),
            dry_run: true,
        },
    )
    .await;
    let out = result.expect("dry-run should succeed before require_client");
    assert!(out.starts_with("[dry-run]"));
}

#[tokio::test]
async fn write_schedule_weekly_rejects_wrong_day_count() {
    // 6 days instead of 7 — must fail pre-dispatch with a clear message.
    let state = test_state();
    let mut days = empty_week();
    days.pop();
    let result = write_schedule_weekly_impl(
        &state,
        WriteScheduleWeeklyParams {
            device_instance: 1234,
            schedule_instance: 1,
            days,
            dry_run: true,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(err.contains("7"), "want 7-day error, got: {err}");
}

#[tokio::test]
async fn write_schedule_weekly_rejects_bad_time() {
    let state = test_state();
    let mut days = empty_week();
    days[0].push(TimeValueInput {
        time: "not-a-time".into(),
        value: ScheduleValueInput::Real(72.0),
    });
    let result = write_schedule_weekly_impl(
        &state,
        WriteScheduleWeeklyParams {
            device_instance: 1234,
            schedule_instance: 1,
            days,
            dry_run: true,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(err.contains("time"), "want time error, got: {err}");
}

#[tokio::test]
async fn write_schedule_weekly_dry_run_records_allow_audit() {
    let state = test_state();
    let _ = write_schedule_weekly_impl(
        &state,
        WriteScheduleWeeklyParams {
            device_instance: 1234,
            schedule_instance: 1,
            days: empty_week(),
            dry_run: true,
        },
    )
    .await
    .unwrap();
    let entries = state.audit.snapshot(0);
    assert!(
        entries
            .iter()
            .any(|e| e.tool == "write_schedule_weekly" && e.decision == "allow" && e.dry_run),
        "expected an allow+dry-run audit entry; got: {entries:?}"
    );
}

#[tokio::test]
async fn write_schedule_weekly_real_write_no_client_audits_pre_send_failure() {
    // Real write (dry_run = false), no client → require_client fails AFTER
    // policy gate passes. Expect (a) no deny (policy passed), (b) an err
    // entry from require_client failure.
    let state = test_state();
    let result = write_schedule_weekly_impl(
        &state,
        WriteScheduleWeeklyParams {
            device_instance: 1234,
            schedule_instance: 1,
            days: empty_week(),
            dry_run: false,
        },
    )
    .await;
    assert!(result.unwrap_err().contains("not started"));
    let entries = state.audit.snapshot(0);
    let our: Vec<_> = entries
        .iter()
        .filter(|e| e.tool == "write_schedule_weekly")
        .collect();
    assert!(
        our.iter().any(|e| e.decision == "error"),
        "expected an error audit entry; got: {our:?}"
    );
}

// ─── write_schedule_exceptions ──────────────────────────────────────────────

#[tokio::test]
async fn write_schedule_exceptions_dry_run_with_concrete_date() {
    let state = test_state();
    let events = vec![ExceptionInput {
        period: PeriodInput::Date("2026-12-25".into()),
        time_values: vec![TimeValueInput {
            time: "00:00".into(),
            value: ScheduleValueInput::Real(60.0),
        }],
        priority: 8,
    }];
    let result = write_schedule_exceptions_impl(
        &state,
        WriteScheduleExceptionsParams {
            device_instance: 1234,
            schedule_instance: 1,
            events,
            dry_run: true,
        },
    )
    .await;
    let out = result.expect("dry-run with valid concrete date should pass");
    assert!(out.contains("[dry-run]"));
    assert!(out.contains("1 exception events"));
}

#[tokio::test]
async fn write_schedule_exceptions_dry_run_with_week_n_day_pattern() {
    let state = test_state();
    let events = vec![ExceptionInput {
        period: PeriodInput::WeekNDay("*/1/Mon".into()),
        time_values: vec![TimeValueInput {
            time: "08:00".into(),
            value: ScheduleValueInput::Real(70.0),
        }],
        priority: 10,
    }];
    let result = write_schedule_exceptions_impl(
        &state,
        WriteScheduleExceptionsParams {
            device_instance: 1234,
            schedule_instance: 1,
            events,
            dry_run: true,
        },
    )
    .await;
    let out = result.unwrap();
    assert!(out.contains("[dry-run]"));
}

#[tokio::test]
async fn write_schedule_exceptions_rejects_priority_out_of_range() {
    let state = test_state();
    let events = vec![ExceptionInput {
        period: PeriodInput::Date("2026-12-25".into()),
        time_values: vec![],
        priority: 17,
    }];
    let result = write_schedule_exceptions_impl(
        &state,
        WriteScheduleExceptionsParams {
            device_instance: 1234,
            schedule_instance: 1,
            events,
            dry_run: true,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(err.contains("priority"));
    assert!(err.contains("17"));
}

#[tokio::test]
async fn write_schedule_exceptions_rejects_bad_period_string() {
    let state = test_state();
    let events = vec![ExceptionInput {
        period: PeriodInput::Date("not-a-date".into()),
        time_values: vec![],
        priority: 8,
    }];
    let result = write_schedule_exceptions_impl(
        &state,
        WriteScheduleExceptionsParams {
            device_instance: 1234,
            schedule_instance: 1,
            events,
            dry_run: true,
        },
    )
    .await;
    let err = result.unwrap_err();
    assert!(err.contains("date"));
}
