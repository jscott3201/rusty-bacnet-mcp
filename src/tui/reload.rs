//! Hot-reload classification + apply path.
//!
//! Split out from `tui/mod.rs` because it's a self-contained domain:
//! `reload_safety_check` partitions a proposed config change into
//! `Applied` / `PartialApplied` / `Refused`; `do_save_and_reload` is the
//! F9 handler that runs the classifier, writes the new file to disk, and
//! atomically swaps the live runtime flags (when safe). The whole module
//! is unit-tested without a live BACnet stack — the tests live below.

use std::time::Instant;

use crate::config::GatewayConfig;
use crate::tui::app::App;
use crate::tui::event::StatusKind;

/// Classification of a config change as it relates to hot-reload.
///
/// - `Applied`: every changed field is hot-swap safe; live state has been updated.
/// - `PartialApplied`: some fields applied immediately, others need a daemon restart.
/// - `Refused`: at least one change would corrupt running state — nothing was touched.
#[derive(Debug, Clone)]
pub enum ReloadOutcome {
    Applied {
        changed: Vec<&'static str>,
    },
    PartialApplied {
        applied: Vec<&'static str>,
        stale: Vec<&'static str>,
    },
    Refused {
        reason: String,
    },
}

/// Classify a proposed config change.
///
/// **Bucketing rationale:**
/// - `Applied` — fields that `RuntimeFlags::apply()` knows how to swap atomically.
///   Today: `mcp.read_only`. Phase 2 will add the safety control plane fields.
/// - `Refused` — changes that would corrupt the BACnet wire protocol or running peers.
///   Today: `device.instance` (already-discovered peers cache I-Am responses; a
///   mid-flight change creates two devices claiming the same instance number).
/// - `Stale` (still allowed) — restart-required but harmless to write to disk.
///   The operator gets a precise list of what won't take effect until restart.
pub fn reload_safety_check(old: &GatewayConfig, new: &GatewayConfig) -> ReloadOutcome {
    // ── Refused ──────────────────────────────────────────────────────────
    if old.device.instance != new.device.instance {
        return ReloadOutcome::Refused {
            reason: format!(
                "device.instance change ({} → {}) requires daemon restart — \
                 already-discovered peers cached the old I-Am and a live swap \
                 would create conflicting identities on the BACnet network",
                old.device.instance, new.device.instance,
            ),
        };
    }

    let mut applied: Vec<&'static str> = Vec::new();
    let mut stale: Vec<&'static str> = Vec::new();

    // ── Hot-swap safe (covered by RuntimeFlags::apply) ──────────────────
    if old.mcp.read_only != new.mcp.read_only {
        applied.push("mcp.read_only");
    }
    if old.mcp.safety != new.mcp.safety {
        // Whole `safety` block is hot-swappable via ArcSwap. Tracking
        // sub-fields individually doesn't add value — the block deserializes
        // to a single `WritePolicy` that gets atomically replaced.
        applied.push("mcp.safety");
    }

    // ── Stale until restart ─────────────────────────────────────────────
    if old.mcp.api_key != new.mcp.api_key {
        stale.push("mcp.api_key (HTTP auth middleware bound at startup)");
    }
    if old.mcp.http != new.mcp.http {
        stale.push("mcp.http (TCP listener already bound)");
    }
    if old.device.name != new.device.name {
        stale.push("device.name (Device object held in DB)");
    }
    if old.device.vendor_id != new.device.vendor_id {
        stale.push("device.vendor_id (Device object held in DB)");
    }
    if old.device.description != new.device.description {
        stale.push("device.description (Device object held in DB)");
    }
    if old.transports.bip != new.transports.bip {
        stale.push("transports.bip (UDP socket already bound)");
    }
    if old.transports.sc != new.transports.sc {
        stale.push("transports.sc (transport already established)");
    }
    if old.bbmd != new.bbmd {
        stale.push("bbmd (BDT registered with peers)");
    }
    if old.foreign_device != new.foreign_device {
        stale.push("foreign_device (BBMD registration TTL active)");
    }
    if old.routes != new.routes {
        stale.push("routes (NPDU routing table built at boot)");
    }
    if old.objects != new.objects {
        stale.push("objects (local DB pre-populated at boot)");
    }
    if old.mcp.audit != new.mcp.audit {
        // Audit log is a per-startup file handle. Path / capacity changes
        // require a restart to take effect — the in-memory ring buffer would
        // otherwise have to be drained-and-reopened mid-flight, which loses
        // entries.
        stale.push("mcp.audit (audit log file/capacity bound at startup)");
    }

    if stale.is_empty() {
        ReloadOutcome::Applied { changed: applied }
    } else {
        ReloadOutcome::PartialApplied { applied, stale }
    }
}

pub(super) async fn do_save_and_reload(app: &mut App) {
    // 1. Parse + validate the editor buffer.
    let parsed = match app.configure.validate() {
        Ok(p) => p,
        Err(msg) => {
            app.configure.record_error(msg.clone());
            app.toast = Some((Instant::now(), StatusKind::Err, msg));
            return;
        }
    };

    // 2. Classify the change. Refused changes never touch disk or live state.
    let outcome = reload_safety_check(&app.config, &parsed);
    if let ReloadOutcome::Refused { reason } = &outcome {
        app.configure.record_error(reason.clone());
        app.toast = Some((
            Instant::now(),
            StatusKind::Err,
            format!("Refused: {}", first_line(reason)),
        ));
        tracing::warn!("Reload refused: {reason}");
        return;
    }

    // 3. Write to disk. We persist the new config even when fields are stale
    //    so the next daemon restart picks them up. Write with a trailing
    //    newline (POSIX convention); the dirty-check normalizes both sides.
    let mut text = app.configure.editor.lines().join("\n");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    if let Err(e) = std::fs::write(&app.config_path, &text) {
        let msg = format!("write {}: {}", app.config_path, e);
        app.configure.record_error(msg.clone());
        app.toast = Some((Instant::now(), StatusKind::Err, msg));
        return;
    }
    app.configure.disk_text = text;

    // 4. Apply hot-safe live changes. The atomic swap happens here; in-flight
    //    MCP tool calls see the new value on their next read. If the safety
    //    block is malformed, surface the error and skip the apply — the file
    //    has already been written so the next restart picks it up, but live
    //    state stays on the previous policy.
    if let Err(e) = app.gateway.flags.apply(&parsed) {
        let msg = format!("safety policy invalid (live state unchanged): {e}");
        app.configure.record_error(msg.clone());
        app.toast = Some((Instant::now(), StatusKind::Err, msg));
        return;
    }

    // 5. Update the TUI's runtime view so it reflects what's actually live.
    //
    //    On `Applied`, every change is hot-safe → mirror the whole parsed
    //    config so future reload-checks compare against the new baseline.
    //
    //    On `PartialApplied`, restart-required fields are NOT live yet — the
    //    Observe tab and `bacnet://state/config` resource must keep showing
    //    the old (still-effective) values. We only mirror the fields that
    //    actually applied; the new file lives on disk and takes effect at
    //    next daemon start.
    match &outcome {
        ReloadOutcome::Applied { .. } => {
            app.config = parsed;
        }
        ReloadOutcome::PartialApplied { .. } => {
            crate::state::RuntimeFlags::mirror_applied_fields(&parsed, &mut app.config);
        }
        ReloadOutcome::Refused { .. } => unreachable!("handled at step 2"),
    }
    app.configure.mark_saved();

    // 6. Toast the operator about what actually applied vs. what's stale.
    let (kind, msg) = format_reload_toast(&outcome);
    tracing::info!(
        "Config reload: {} (file: {})",
        format_reload_log(&outcome),
        app.config_path,
    );
    app.toast = Some((Instant::now(), kind, msg));
}

fn format_reload_toast(outcome: &ReloadOutcome) -> (StatusKind, String) {
    match outcome {
        ReloadOutcome::Applied { changed } if changed.is_empty() => (
            StatusKind::Info,
            "Saved (no live-config changes detected)".into(),
        ),
        ReloadOutcome::Applied { changed } => {
            (StatusKind::Ok, format!("Applied: {}", changed.join(", ")))
        }
        ReloadOutcome::PartialApplied { applied, stale } => {
            let prefix = if applied.is_empty() {
                String::new()
            } else {
                format!("Applied: {}.  ", applied.join(", "))
            };
            (
                StatusKind::Warn,
                format!(
                    "{prefix}Restart required for {} field(s) — see logs.",
                    stale.len()
                ),
            )
        }
        ReloadOutcome::Refused { reason } => (StatusKind::Err, format!("Refused: {reason}")),
    }
}

fn format_reload_log(outcome: &ReloadOutcome) -> String {
    match outcome {
        ReloadOutcome::Applied { changed } if changed.is_empty() => "no-op".into(),
        ReloadOutcome::Applied { changed } => format!("applied [{}]", changed.join(", ")),
        ReloadOutcome::PartialApplied { applied, stale } => format!(
            "applied [{}], stale [{}]",
            applied.join(", "),
            stale.join(", "),
        ),
        ReloadOutcome::Refused { reason } => format!("refused: {reason}"),
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

#[cfg(test)]
mod reload_tests {
    use super::*;
    use crate::config::{BipConfig, DeviceConfig, McpConfig, McpHttpConfig, TransportsConfig};

    fn baseline() -> GatewayConfig {
        GatewayConfig {
            mcp: McpConfig {
                api_key: Some("token-A".into()),
                read_only: true,
                http: Some(McpHttpConfig {
                    bind: "127.0.0.1:3000".into(),
                }),
                safety: None,
                audit: None,
            },
            device: DeviceConfig {
                instance: 389001,
                name: "Test Gateway".into(),
                vendor_id: 999,
                description: "test".into(),
            },
            transports: TransportsConfig {
                bip: Some(BipConfig {
                    interface: "0.0.0.0".into(),
                    port: 47808,
                    broadcast: "192.168.1.255".into(),
                    network_number: 1,
                }),
                sc: None,
            },
            bbmd: None,
            foreign_device: None,
            routes: vec![],
            objects: vec![],
        }
    }

    #[test]
    fn no_change_is_noop_applied() {
        let outcome = reload_safety_check(&baseline(), &baseline());
        match outcome {
            ReloadOutcome::Applied { changed } => assert!(changed.is_empty()),
            other => panic!("expected Applied{{}} no-op, got {other:?}"),
        }
    }

    #[test]
    fn read_only_toggle_is_hot_applied() {
        let old = baseline();
        let mut new = baseline();
        new.mcp.read_only = false;
        match reload_safety_check(&old, &new) {
            ReloadOutcome::Applied { changed } => assert_eq!(changed, vec!["mcp.read_only"]),
            other => panic!("expected Applied with mcp.read_only, got {other:?}"),
        }
    }

    #[test]
    fn device_instance_change_is_refused() {
        let old = baseline();
        let mut new = baseline();
        new.device.instance = 999_999;
        match reload_safety_check(&old, &new) {
            ReloadOutcome::Refused { reason } => {
                assert!(reason.contains("device.instance"), "reason: {reason}");
                assert!(reason.contains("389001"), "reason: {reason}");
                assert!(reason.contains("999999"), "reason: {reason}");
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn api_key_rotation_is_stale_until_restart() {
        let old = baseline();
        let mut new = baseline();
        new.mcp.api_key = Some("token-B".into());
        match reload_safety_check(&old, &new) {
            ReloadOutcome::PartialApplied { applied, stale } => {
                assert!(applied.is_empty());
                assert!(stale.iter().any(|s| s.contains("mcp.api_key")));
            }
            other => panic!("expected PartialApplied, got {other:?}"),
        }
    }

    #[test]
    fn read_only_plus_api_key_is_partial_applied() {
        let old = baseline();
        let mut new = baseline();
        new.mcp.read_only = false;
        new.mcp.api_key = Some("token-B".into());
        match reload_safety_check(&old, &new) {
            ReloadOutcome::PartialApplied { applied, stale } => {
                assert_eq!(applied, vec!["mcp.read_only"]);
                assert!(stale.iter().any(|s| s.contains("mcp.api_key")));
            }
            other => panic!("expected PartialApplied with mixed bucket, got {other:?}"),
        }
    }

    #[test]
    fn http_bind_change_is_stale() {
        let old = baseline();
        let mut new = baseline();
        new.mcp.http = Some(McpHttpConfig {
            bind: "0.0.0.0:8080".into(),
        });
        match reload_safety_check(&old, &new) {
            ReloadOutcome::PartialApplied { applied, stale } => {
                assert!(applied.is_empty());
                assert!(stale.iter().any(|s| s.contains("mcp.http")));
            }
            other => panic!("expected PartialApplied for mcp.http change, got {other:?}"),
        }
    }

    #[test]
    fn transport_change_is_stale() {
        let old = baseline();
        let mut new = baseline();
        if let Some(bip) = &mut new.transports.bip {
            bip.broadcast = "10.0.0.255".into();
        }
        match reload_safety_check(&old, &new) {
            ReloadOutcome::PartialApplied { applied, stale } => {
                assert!(applied.is_empty());
                assert!(stale.iter().any(|s| s.contains("transports.bip")));
            }
            other => panic!("expected PartialApplied for transport change, got {other:?}"),
        }
    }

    #[test]
    fn refused_takes_precedence_over_other_changes() {
        // Even if we'd apply read_only, the device.instance change should
        // still refuse — the operator gets a clear "no" instead of partial work.
        let old = baseline();
        let mut new = baseline();
        new.mcp.read_only = false;
        new.device.instance = 999_999;
        match reload_safety_check(&old, &new) {
            ReloadOutcome::Refused { .. } => {}
            other => {
                panic!("expected Refused even with hot-safe edits also present, got {other:?}")
            }
        }
    }

    #[test]
    fn runtime_flags_apply_swaps_atomically() {
        // Sanity check that RuntimeFlags::apply actually mirrors what the
        // classifier promised. If the bucketing diverges from apply's behavior,
        // this test catches it.
        let config = baseline();
        let flags = crate::state::RuntimeFlags::from_config(&config).unwrap();
        assert!(flags.is_read_only());

        let mut next = baseline();
        next.mcp.read_only = false;
        flags.apply(&next).unwrap();
        assert!(!flags.is_read_only());
    }

    #[test]
    fn runtime_flags_apply_is_atomic_on_safety_parse_failure() {
        // Codex P1 (PR #3 review): a malformed `mcp.safety` block must NOT
        // mutate `read_only` mid-reload. Before the fix, `apply` stored the
        // new `read_only` first and only then tried to parse the policy —
        // a parse error returned `Err` with `read_only` already flipped.
        let config = baseline(); // read_only = true
        let flags = crate::state::RuntimeFlags::from_config(&config).unwrap();
        assert!(flags.is_read_only());
        let policy_before = std::sync::Arc::as_ptr(&flags.policy());

        // Construct a config that flips read_only AND has an invalid
        // safety block. Both fields are classified as Applied; before the
        // fix, read_only would commit before the policy parse fails.
        let mut bad = baseline();
        bad.mcp.read_only = false;
        bad.mcp.safety = Some(crate::config::SafetyConfig {
            min_priority: Some(99), // out of BACnet 1..=16 range
            ..crate::config::SafetyConfig::default()
        });

        let err = flags.apply(&bad).unwrap_err();
        assert!(
            err.contains("min_priority") || err.contains("99"),
            "expected priority-range error, got: {err}"
        );
        // read_only must still be true (its pre-apply value).
        assert!(
            flags.is_read_only(),
            "read_only must not flip when safety parse fails"
        );
        // policy must be the same Arc instance (unchanged).
        let policy_after = std::sync::Arc::as_ptr(&flags.policy());
        assert_eq!(
            policy_before, policy_after,
            "policy Arc must not swap when parse fails"
        );
    }

    #[test]
    fn mirror_applied_fields_only_updates_hot_safe_bits() {
        // The TUI calls mirror_applied_fields on PartialApplied so the runtime
        // view shows new values for applied fields while keeping old values for
        // restart-required fields. This test pins that contract: after mirror,
        // mcp.read_only matches the new config but mcp.api_key (stale) does not.
        let mut runtime_view = baseline();
        let mut new_file = baseline();
        new_file.mcp.read_only = false;
        new_file.mcp.api_key = Some("rotated-token".into());
        new_file.mcp.http = Some(crate::config::McpHttpConfig {
            bind: "0.0.0.0:9999".into(),
        });

        crate::state::RuntimeFlags::mirror_applied_fields(&new_file, &mut runtime_view);

        // Applied → mirrored.
        assert!(!runtime_view.mcp.read_only);
        // Stale → unchanged from baseline.
        assert_eq!(runtime_view.mcp.api_key.as_deref(), Some("token-A"));
        assert_eq!(
            runtime_view.mcp.http.as_ref().map(|h| h.bind.as_str()),
            Some("127.0.0.1:3000")
        );
    }
}
