//! Layered safety control plane for write operations.
//!
//! Every write tool consults `WritePolicy::evaluate()` before encoding the
//! BACnet APDU. The policy enforces:
//!
//! - **Object-type denylist** — life-safety types are denied by default to
//!   prevent agent writes to fire/sprinkler/access-control infrastructure.
//! - **Object-type allowlist** — when set, only these types are writable.
//! - **Per-object denylist** — `device:0` is implicitly denied (writing to a
//!   device's own Device object via WriteProperty is undefined behavior).
//! - **Per-object allowlist** — restrict writes to a specific roster.
//! - **Priority caps** — bound the BACnet 16-level command priority writes
//!   can target. `min_priority = 9` (the default) blocks priorities 1–8 which
//!   are reserved for life-safety / manual-life-safety / safety equipment
//!   (ASHRAE 135-2020 Table 19-1).
//!
//! The policy is stored in `RuntimeFlags` behind an `ArcSwap` so the TUI's F9
//! reload swaps it without restarting the daemon. Audit log entries record
//! every write attempt — allowed, denied, or dry-run — so post-incident review
//! always has a record of what an agent tried to do.

use std::sync::Arc;

use arc_swap::ArcSwap;
use bacnet_types::enums::ObjectType;
use bacnet_types::primitives::ObjectIdentifier;

use crate::config::SafetyConfig;

/// Per-write decision returned by `WritePolicy::evaluate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The write is allowed — proceed with encoding and dispatch.
    Allow,
    /// The write is denied. The reason is suitable for surfacing to the
    /// caller (MCP error message + audit log entry).
    Deny(String),
}

/// Live-mutable safety policy for write operations.
///
/// All fields are populated from `[mcp.safety]` in the JSON config (see
/// `SafetyConfig`). Defaults are conservative: life-safety types are denied,
/// `device:0` is implicitly denied, priority writes are capped at 9–16.
#[derive(Debug, Clone)]
pub struct WritePolicy {
    pub allow_object_types: Option<Vec<ObjectType>>,
    pub deny_object_types: Vec<ObjectType>,
    pub allow_objects: Option<Vec<ObjectIdentifier>>,
    pub deny_objects: Vec<ObjectIdentifier>,
    pub min_priority: Option<u8>,
    pub max_priority: Option<u8>,
}

impl WritePolicy {
    /// Conservative default: life-safety types denied, priority floor at 9
    /// (agents can't take 1–8). `device:0` is denied implicitly via
    /// `evaluate()`; we don't list it here because it isn't a fixed instance.
    pub fn default_safe() -> Self {
        Self {
            allow_object_types: None,
            deny_object_types: vec![
                ObjectType::LIFE_SAFETY_POINT,
                ObjectType::LIFE_SAFETY_ZONE,
                ObjectType::NOTIFICATION_CLASS,
            ],
            allow_objects: None,
            deny_objects: Vec::new(),
            min_priority: Some(9),
            max_priority: Some(16),
        }
    }

    /// Build a `WritePolicy` from a `SafetyConfig`. Missing config blocks fall
    /// back to `default_safe()` field by field — operators opt in to looser
    /// policy explicitly, never accidentally.
    pub fn from_config(cfg: &SafetyConfig) -> Result<Self, String> {
        let defaults = Self::default_safe();
        let allow_object_types = cfg
            .allow_object_types
            .as_ref()
            .map(|names| {
                names
                    .iter()
                    .map(|n| crate::parse::parse_object_type(n))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let deny_object_types = if let Some(names) = &cfg.deny_object_types {
            names
                .iter()
                .map(|n| crate::parse::parse_object_type(n))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            defaults.deny_object_types
        };
        let allow_objects = cfg
            .allow_objects
            .as_ref()
            .map(|v| parse_object_specs(v))
            .transpose()?;
        let deny_objects = cfg
            .deny_objects
            .as_ref()
            .map(|v| parse_object_specs(v))
            .transpose()?
            .unwrap_or(defaults.deny_objects);
        // Codex flagged out-of-range priorities (PR #3 review, P2). BACnet
        // command priorities are 1..=16; anything outside is a config typo,
        // not a permissive intent. We validate here as well as in
        // `GatewayConfig::validate` so direct callers of `from_config` (e.g.
        // tests, custom embeddings) get the same guarantee.
        let min_priority = cfg.min_priority.or(defaults.min_priority);
        let max_priority = cfg.max_priority.or(defaults.max_priority);
        if let Some(p) = min_priority {
            if !(1..=16).contains(&p) {
                return Err(format!("min_priority {p} is out of BACnet range 1..=16"));
            }
        }
        if let Some(p) = max_priority {
            if !(1..=16).contains(&p) {
                return Err(format!("max_priority {p} is out of BACnet range 1..=16"));
            }
        }
        if let (Some(min), Some(max)) = (min_priority, max_priority) {
            if min > max {
                return Err(format!(
                    "min_priority ({min}) must be ≤ max_priority ({max})"
                ));
            }
        }
        Ok(Self {
            allow_object_types,
            deny_object_types,
            allow_objects,
            deny_objects,
            min_priority,
            max_priority,
        })
    }

    /// Evaluate a proposed write against the policy.
    ///
    /// `priority` is the BACnet command priority (1–16) the caller wants to
    /// write at, or `None` if the write doesn't use the priority array
    /// (non-commandable properties).
    pub fn evaluate(&self, target: ObjectIdentifier, priority: Option<u8>) -> PolicyDecision {
        // device:0 is reserved/undefined — never allowed.
        if target.object_type() == ObjectType::DEVICE && target.instance_number() == 0 {
            return PolicyDecision::Deny(
                "writes to device:0 are not allowed (reserved instance)".into(),
            );
        }

        // Per-object denylist (always enforced).
        if self.deny_objects.contains(&target) {
            return PolicyDecision::Deny(format!(
                "{}:{} is on the per-object denylist",
                crate::parse::object_type_name(target.object_type()),
                target.instance_number(),
            ));
        }

        // Per-object allowlist (if set, target must be on it).
        if let Some(allow) = &self.allow_objects {
            if !allow.contains(&target) {
                return PolicyDecision::Deny(format!(
                    "{}:{} is not on the per-object allowlist",
                    crate::parse::object_type_name(target.object_type()),
                    target.instance_number(),
                ));
            }
        }

        // Object-type denylist.
        if self
            .deny_object_types
            .iter()
            .any(|t| *t == target.object_type())
        {
            return PolicyDecision::Deny(format!(
                "object type '{}' is on the type denylist",
                crate::parse::object_type_name(target.object_type()),
            ));
        }

        // Object-type allowlist.
        if let Some(allow) = &self.allow_object_types {
            if !allow.iter().any(|t| *t == target.object_type()) {
                return PolicyDecision::Deny(format!(
                    "object type '{}' is not on the type allowlist",
                    crate::parse::object_type_name(target.object_type()),
                ));
            }
        }

        // Priority caps. Only enforced when the write specifies a priority —
        // non-commandable properties (e.g. config setpoints on AV) write
        // without one and aren't priority-gated.
        if let Some(p) = priority {
            if let Some(min) = self.min_priority {
                if p < min {
                    return PolicyDecision::Deny(format!(
                        "priority {p} is below the configured floor (min_priority = {min}; \
                         priorities 1–8 are reserved for life-safety per ASHRAE 135-2020)"
                    ));
                }
            }
            if let Some(max) = self.max_priority {
                if p > max {
                    return PolicyDecision::Deny(format!(
                        "priority {p} is above the configured ceiling (max_priority = {max})"
                    ));
                }
            }
        }

        PolicyDecision::Allow
    }
}

impl Default for WritePolicy {
    fn default() -> Self {
        Self::default_safe()
    }
}

fn parse_object_specs(specs: &[String]) -> Result<Vec<ObjectIdentifier>, String> {
    specs
        .iter()
        .map(|s| {
            let (ot, inst) = crate::parse::parse_object_specifier(s)?;
            ObjectIdentifier::new(ot, inst).map_err(|e| format!("invalid object identifier: {e}"))
        })
        .collect()
}

/// Hot-swappable policy. The TUI's F9 reload calls `store(new)` to replace
/// the policy; in-flight write requests see the new value on their next
/// `load()` (RCU semantics — no locking on the read path).
pub type LivePolicy = ArcSwap<WritePolicy>;

/// Build the live policy handle from the safety config block.
pub fn build_live_policy(cfg: &SafetyConfig) -> Result<Arc<LivePolicy>, String> {
    let policy = WritePolicy::from_config(cfg)?;
    Ok(Arc::new(ArcSwap::new(Arc::new(policy))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(t: ObjectType, i: u32) -> ObjectIdentifier {
        ObjectIdentifier::new(t, i).unwrap()
    }

    #[test]
    fn defaults_deny_life_safety_types() {
        let p = WritePolicy::default_safe();
        assert!(matches!(
            p.evaluate(oid(ObjectType::LIFE_SAFETY_POINT, 1), Some(10)),
            PolicyDecision::Deny(_)
        ));
        assert!(matches!(
            p.evaluate(oid(ObjectType::LIFE_SAFETY_ZONE, 1), Some(10)),
            PolicyDecision::Deny(_)
        ));
        assert!(matches!(
            p.evaluate(oid(ObjectType::NOTIFICATION_CLASS, 1), Some(10)),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn defaults_allow_normal_writable_types() {
        let p = WritePolicy::default_safe();
        assert_eq!(
            p.evaluate(oid(ObjectType::ANALOG_OUTPUT, 1), Some(10)),
            PolicyDecision::Allow
        );
        assert_eq!(
            p.evaluate(oid(ObjectType::BINARY_VALUE, 5), Some(16)),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn device_zero_always_denied() {
        let p = WritePolicy::default_safe();
        let d = p.evaluate(oid(ObjectType::DEVICE, 0), None);
        let msg = match d {
            PolicyDecision::Deny(m) => m,
            _ => panic!("expected deny for device:0"),
        };
        assert!(msg.contains("device:0"));
        assert!(msg.contains("reserved"));
    }

    #[test]
    fn priority_floor_blocks_life_safety_priorities() {
        let p = WritePolicy::default_safe();
        // 1-8 are reserved by default (min_priority = 9).
        for prio in 1..=8 {
            let d = p.evaluate(oid(ObjectType::ANALOG_OUTPUT, 1), Some(prio));
            assert!(
                matches!(d, PolicyDecision::Deny(ref msg) if msg.contains("floor")),
                "priority {prio} should be blocked, got {d:?}"
            );
        }
        // 9-16 allowed.
        for prio in 9..=16 {
            assert_eq!(
                p.evaluate(oid(ObjectType::ANALOG_OUTPUT, 1), Some(prio)),
                PolicyDecision::Allow,
            );
        }
    }

    #[test]
    fn priority_caps_can_be_disabled() {
        let mut p = WritePolicy::default_safe();
        p.min_priority = None;
        p.max_priority = None;
        // With no caps, priority 1 is allowed (operator opted in).
        assert_eq!(
            p.evaluate(oid(ObjectType::ANALOG_OUTPUT, 1), Some(1)),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn type_allowlist_overrides_default_allow() {
        let mut p = WritePolicy::default_safe();
        p.allow_object_types = Some(vec![ObjectType::ANALOG_VALUE]);
        // AO not on allowlist → deny.
        assert!(matches!(
            p.evaluate(oid(ObjectType::ANALOG_OUTPUT, 1), Some(10)),
            PolicyDecision::Deny(_)
        ));
        // AV on allowlist → allow.
        assert_eq!(
            p.evaluate(oid(ObjectType::ANALOG_VALUE, 1), Some(10)),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn per_object_denylist_takes_precedence_over_type() {
        let mut p = WritePolicy::default_safe();
        p.deny_objects = vec![oid(ObjectType::ANALOG_OUTPUT, 99)];
        // Different instance allowed.
        assert_eq!(
            p.evaluate(oid(ObjectType::ANALOG_OUTPUT, 1), Some(10)),
            PolicyDecision::Allow
        );
        // Specific instance denied.
        assert!(matches!(
            p.evaluate(oid(ObjectType::ANALOG_OUTPUT, 99), Some(10)),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn write_without_priority_skips_priority_check() {
        // Non-commandable writes (no priority specified) bypass the cap.
        let p = WritePolicy::default_safe();
        assert_eq!(
            p.evaluate(oid(ObjectType::ANALOG_VALUE, 1), None),
            PolicyDecision::Allow
        );
    }
}
