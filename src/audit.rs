//! Append-only audit log for write operations.
//!
//! Every write tool — allowed, denied, or dry-run — emits one `AuditEntry`.
//! The log is in-memory by default (a bounded `VecDeque` ring buffer surfaced
//! via the `bacnet://audit/recent` MCP resource) and optionally mirrors to a
//! JSON-Lines file so post-incident review survives a daemon restart.
//!
//! The log is append-only and lock-protected. A write tool obtains the lock,
//! pushes one entry, drops the lock, then encodes/sends. We deliberately do
//! the audit write *before* the BACnet round-trip so a crash mid-flight still
//! leaves a record of intent.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::Serialize;

use crate::config::AuditConfig;

/// Default ring-buffer capacity. Surfaced via the MCP resource; bounded so a
/// runaway agent can't blow out memory by hammering a denied-write loop.
const DEFAULT_CAPACITY: usize = 5_000;

/// One audit log entry. Serialized to JSON Lines when a file path is set.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    /// Unix epoch milliseconds (UTC). Easier to ingest than RFC3339 from
    /// downstream tooling, and serialization stays one number.
    pub at_ms: u64,
    /// Tool name (e.g. `"write_property"`, `"write_local_property"`).
    pub tool: &'static str,
    /// Target object as `"<type>:<instance>"`. `None` for tools that don't
    /// target a single object (none today; reserved for future expansion).
    pub target: Option<String>,
    /// Property name written, if applicable.
    pub property: Option<String>,
    /// BACnet command priority, if specified.
    pub priority: Option<u8>,
    /// Dry-run flag — when true, the call did not encode/send a BACnet APDU.
    pub dry_run: bool,
    /// Per-write decision: `"allow"`, `"deny"`, or `"error"` (allowed but the
    /// network layer failed). Allow + dry_run is recorded as `"allow"`.
    pub decision: &'static str,
    /// Free-text reason. For deny: the policy reason. For error: the BACnet
    /// error message. For allow: empty.
    pub reason: String,
}

impl AuditEntry {
    pub fn now(
        tool: &'static str,
        target: Option<String>,
        property: Option<String>,
        priority: Option<u8>,
        dry_run: bool,
        decision: &'static str,
        reason: String,
    ) -> Self {
        let at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            at_ms,
            tool,
            target,
            property,
            priority,
            dry_run,
            decision,
            reason,
        }
    }
}

/// Bounded ring buffer of audit entries with optional JSON-Lines file mirror.
///
/// Reads (`snapshot`) and writes (`append`) take a short mutex; this is a
/// write-rare hot path (one entry per MCP write call), so contention is
/// negligible compared to the BACnet round-trip the entry describes.
pub struct AuditLog {
    inner: Mutex<Inner>,
}

struct Inner {
    entries: VecDeque<AuditEntry>,
    capacity: usize,
    file_path: Option<PathBuf>,
}

impl AuditLog {
    pub fn new(capacity: usize, file_path: Option<PathBuf>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: VecDeque::with_capacity(capacity.min(64)),
                capacity,
                file_path,
            }),
        }
    }

    /// Build from `AuditConfig`. Missing config = in-memory ring buffer at the
    /// default capacity, no file mirror.
    pub fn from_config(cfg: Option<&AuditConfig>) -> Self {
        let (capacity, file_path) = match cfg {
            Some(c) => (
                c.capacity.unwrap_or(DEFAULT_CAPACITY),
                c.path.as_ref().map(PathBuf::from),
            ),
            None => (DEFAULT_CAPACITY, None),
        };
        Self::new(capacity, file_path)
    }

    /// Append one entry. Trims the oldest entries past `capacity`. If a file
    /// path is configured, also appends a JSON-Lines record — file write
    /// errors are logged via `tracing::warn!` and the in-memory buffer still
    /// gets the entry, because the file is best-effort and the in-memory
    /// resource is the agent-facing surface.
    pub fn append(&self, entry: AuditEntry) {
        let mut inner = self.inner.lock();
        // File mirror runs first and is independent of in-memory capacity —
        // operators may want disk-only auditing (capacity=0) without losing
        // any records. JSON-Lines format means downstream tooling reads the
        // file directly.
        if let Some(path) = inner.file_path.clone() {
            if let Err(e) = append_jsonl(&path, &entry) {
                tracing::warn!("audit file append failed ({}): {}", path.display(), e);
            }
        }
        // Codex P2 (PR #3 review): a misconfigured `mcp.audit.capacity = 0`
        // previously hit the `len == capacity` check only when full and then
        // pushed unconditionally, growing the buffer unbounded. Treat 0 as
        // "in-memory ring disabled"; rely on the file mirror for forensic
        // record (or accept the loss if no path is set — operator opted in).
        if inner.capacity == 0 {
            return;
        }
        // `>= capacity` not `==` so a capacity that shrinks at hot-reload
        // (rare but possible if we add resizing later) doesn't grow past
        // the current limit.
        while inner.entries.len() >= inner.capacity {
            inner.entries.pop_front();
        }
        inner.entries.push_back(entry);
    }

    /// Snapshot the most recent `n` entries, newest last. `n = 0` returns
    /// every entry currently in the buffer.
    pub fn snapshot(&self, n: usize) -> Vec<AuditEntry> {
        let inner = self.inner.lock();
        let len = inner.entries.len();
        let take = if n == 0 { len } else { n.min(len) };
        inner.entries.iter().skip(len - take).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn append_jsonl(path: &Path, entry: &AuditEntry) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let mut line = serde_json::to_string(entry)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    f.write_all(line.as_bytes())
}

/// Build the audit log handle from the audit config block.
pub fn build_audit_log(cfg: Option<&AuditConfig>) -> Arc<AuditLog> {
    Arc::new(AuditLog::from_config(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tool: &'static str, decision: &'static str) -> AuditEntry {
        AuditEntry::now(
            tool,
            Some("analog-output:1".into()),
            Some("present-value".into()),
            Some(10),
            false,
            decision,
            String::new(),
        )
    }

    #[test]
    fn append_and_snapshot_roundtrip() {
        let log = AuditLog::new(4, None);
        log.append(entry("write_property", "allow"));
        log.append(entry("write_property", "deny"));
        let snap = log.snapshot(0);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].decision, "allow");
        assert_eq!(snap[1].decision, "deny");
    }

    #[test]
    fn ring_buffer_evicts_oldest() {
        let log = AuditLog::new(2, None);
        log.append(entry("a", "allow"));
        log.append(entry("b", "allow"));
        log.append(entry("c", "allow"));
        let snap = log.snapshot(0);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].tool, "b");
        assert_eq!(snap[1].tool, "c");
    }

    #[test]
    fn snapshot_n_returns_tail() {
        let log = AuditLog::new(10, None);
        for _ in 0..5 {
            log.append(entry("write_property", "allow"));
        }
        log.append(entry("relinquish", "allow"));
        let snap = log.snapshot(2);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[1].tool, "relinquish");
    }

    #[test]
    fn file_mirror_writes_jsonl() {
        let tmp =
            std::env::temp_dir().join(format!("bacnet-mcp-audit-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let log = AuditLog::new(10, Some(tmp.clone()));
        log.append(entry("write_property", "allow"));
        log.append(entry("write_property", "deny"));
        let body = std::fs::read_to_string(&tmp).expect("read audit file");
        let lines: Vec<_> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line is valid JSON with the expected keys.
        let v0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v0["tool"], "write_property");
        assert_eq!(v0["decision"], "allow");
        let _ = std::fs::remove_file(&tmp);
    }
}
