# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] — Phase 2: trend-log tools (ReadRange-backed)

Adds two MCP tools for working with BACnet TrendLog objects. Together they answer the agentic question "what is this trend logging, how much data does it have, and can I read a specific window?" without round-tripping through the lower-level read tools.

### Added — 2 new MCP tools

- **`get_trend_log_info`** — One RPM round-trip for TrendLog metadata: `object-name`, `description`, `log-enable`, `log-interval`, `buffer-size`, `record-count`, `total-record-count`, `log-device-object-property` (the data source the trend is sampling), `start-time`, `stop-time`, `logging-type`, `status-flags`, `event-state`. The first call an agent should make before reading records — answers "is this trend running and how many records exist?"
- **`read_trend_log`** — Windowed read of a TrendLog's `log-buffer` via the BACnet **ReadRange** service (ASHRAE 135-2020 Clause 15.8). Three range modes: `by_position` (1-based array index), `by_sequence` (sequence number), `by_time` (`"YYYY-MM-DD HH:MM:SS"`). `count` is signed — positive reads forward, negative reads backward. Returns one decoded line per record: timestamp + value + optional status flags.

Both tools are read-only. Like the bulk-read tools added in 0.4.0, they don't consult `WritePolicy` or append audit entries.

### Added — LogRecord stream decoder

`bacnet-services 0.8` returns ReadRange's `item_data` as raw bytes — there's no upstream decoder for the stream-of-LogRecord shape that `log-buffer` produces. `src/mcp/trend.rs` implements one: parses each `BACnetLogRecord` (timestamp envelope, log-datum CHOICE, optional StatusFlags) and surfaces a domain-specific `DecodedLogRecord` shape covering the 11 LogDatum variants (real, unsigned, signed, enum, boolean, bitstring, null, log-status, time-change, failure, plus a fallback for vendor-extended any-value).

### Added — pre-dispatch validation

`read_trend_log` parses both the object identifier and the range spec (including the datetime string for `by_time`) BEFORE touching the BACnet client. Same pattern as `read_property_multiple` — agents passing a malformed datetime get a clear "datetime missing time part" error rather than a generic "BACnet client not started".

### Added — tests

12 new tests bring the total to 100 passing:
- 9 unit tests in `src/mcp/trend.rs` covering single-record decode, multi-record decode, status-flag attachment, ISO datetime parsing (full, T-separator, garbage rejection), and `RangeSpec` builder for all three modes.
- 3 integration tests in `tests/trend_tests.rs` covering the no-client paths and the validation-precedes-transport ordering for malformed datetimes.

### Changed

- **`tests/mcp_tests.rs` split** — moved trend integration tests to `tests/trend_tests.rs` to keep the file under the 700 LOC cap. Future PRs that grow integration coverage should split by domain (each `tests/*.rs` is a separate cargo test crate).

### Notes

- BACnet TrendLog objects in real devices vary on which optional properties they expose. `get_trend_log_info` requests all 13 properties unconditionally; properties the device doesn't implement come back as `<error class=PROPERTY code=UNKNOWN_PROPERTY>` lines, which is exactly the signal an agent needs to know what's available.
- This PR makes no changes to `WritePolicy`, the audit log, or any write tool — those landed in 0.5.0 and are unchanged here.

## [0.5.0] — Phase 2: layered safety control plane + audit log + relinquish

This release lands the **write-side safety control plane** that Phase 2 was waiting on. Every write tool now consults a hot-swappable `WritePolicy` before encoding a BACnet APDU and emits one append-only `AuditEntry` (allow / deny / dry-run / error) regardless of outcome. A `dry_run` parameter lets agents pre-flight a write through the full policy + audit pipeline without touching the wire.

### Added — safety control plane

- **`src/safety.rs`** — `WritePolicy` with object-type allow/deny lists, per-object allow/deny lists, and BACnet command-priority caps. Conservative defaults: `LIFE_SAFETY_POINT` / `LIFE_SAFETY_ZONE` / `NOTIFICATION_CLASS` denied; `device:0` always denied (reserved per ASHRAE 135-2020); `min_priority = 9` so priorities 1–8 (life-safety / manual-life-safety / safety equipment) can never be taken by an agent.
- **`mcp.safety` config block** — `allow_object_types`, `deny_object_types`, `allow_objects`, `deny_objects`, `min_priority`, `max_priority`. Every field optional; missing fields fall back to `default_safe()` field-by-field. Operators only override what they want to relax.
- **Hot-swap via `ArcSwap`** — `LivePolicy = ArcSwap<WritePolicy>` lives in `RuntimeFlags`. F9 reload replaces the policy atomically; in-flight writes see the new value on their next `.load_full()`. The TUI's reload classifier marks `mcp.safety` as `Applied` (no restart needed).

### Added — audit log

- **`src/audit.rs`** — `AuditLog` is a bounded ring buffer (default 5000 entries, configurable via `mcp.audit.capacity`) with optional JSON-Lines file mirror (`mcp.audit.path`). The audit write happens **before** the BACnet round-trip so a crash mid-flight still leaves a record of intent.
- **`bacnet://audit/recent`** MCP resource — surfaces the last 100 audit entries to agents and operators in human-readable form. Format is grep-friendly: `epoch+SECS.MMM <decision> <tool> <target> <property> [pri=N] [dry-run] reason`.
- File path / capacity is restart-required (the file handle and buffer cap are bound at startup); the TUI classifier marks `mcp.audit` as `Stale`.

### Added — write tools

- **`dry_run` parameter** on `write_property` and `write_local_property`. When true, the call runs the full policy gate and writes an audit entry but never encodes a WriteProperty APDU. Agents use this to validate intent before taking real action.
- **`relinquish_at_priority`** tool — releases a priority slot on a commandable BACnet object by writing NULL at that priority. The object falls back to the next-highest active priority (or to `relinquish-default`). Distinct from `write_property` because the wire encoding is fixed (NULL), so agents can't accidentally write a stale value while trying to release a priority. Subject to the same safety policy.

### Added — tests

15 new tests bring the total to 85 passing:
- `src/safety.rs` — 8 unit tests covering defaults, device:0 hard-block, priority floor, allow/deny precedence, and disabled-cap modes.
- `src/audit.rs` — 4 unit tests covering ring-buffer eviction, snapshot windows, and JSON-Lines file append.
- `tests/mcp_tests.rs` — 6 integration tests covering the dry-run path (records audit, skips DB), life-safety denial (records audit, errors), `relinquish_at_priority` allow + deny + dry-run, and the type-allowlist override.

### Changed

- **`RuntimeFlags::from_config` / `apply` now return `Result<_, String>`** — a malformed `mcp.safety` block fails loudly at boot or hot-reload instead of silently dropping back to defaults. The TUI reload path surfaces the error and leaves live state untouched.
- **`GatewayState` gains `audit: Arc<AuditLog>`** field. New `try_new_with_stack(...)` returns `Result<Self, String>` so binaries surface safety-config errors before any sockets bind; the existing `new_with_stack` wraps it with `expect()` for backward compatibility with test fixtures.
- **`parking_lot` promoted to a base dep** (was `tui`-only). The audit log uses `parking_lot::Mutex`; the dep is small and avoids gating the audit module behind `tui`.

### Notes

- `write_property_multiple` (full WPM service) is intentionally deferred to a follow-up PR — it shares the same control-plane gate, so landing the gate first means WPM is a small, focused change against an already-validated foundation.
- File-size cap (700 LOC non-comment / non-empty per file) verified clean. New files: `safety.rs` and `audit.rs`. Touched files: `config.rs`, `state.rs`, `lib.rs`, `mcp/properties.rs`, `mcp/objects.rs`, `mcp/mod.rs`, `mcp/reference/mod.rs`, `tui/mod.rs`.

## [0.4.0] — Phase 2 begins: bulk-read tools (RPM-backed)

First slice of Phase 2 (MCP feature expansion). Lands ReadPropertyMultiple as foundational infrastructure plus three convenience tools that share it. Together these unlock the **override audit lighthouse demo** ("find all overridden points across N devices, group by source priority").

### Added — 4 new MCP tools (read-only)

- **`read_property_multiple`** — Generic N-objects × M-properties read in one round-trip via the BACnet ReadPropertyMultiple service. Cuts latency 5–10× over sequential `read_property` calls and is the primary tool for bulk reads. Supports per-property `array_index` for array properties; supports `all` / `required` / `optional` aggregate property identifiers.
- **`read_priority_array`** — Returns the 16-slot priority array, present-value, and relinquish-default for a commandable object in one RPM round-trip. Identifies the highest active priority slot — answers the central agentic question "who is overriding this point?"
- **`enumerate_objects`** — Lists every object on a remote device with its identifier and `object-name`, by reading `Device.object_list` then chunked object-name reads (32 per RPM). Default cap 500 objects, hard cap 5000. Tolerates per-chunk failures so partial results land even on flaky devices.
- **`get_device_capabilities`** — One RPM round-trip for the device profile: vendor info, firmware/protocol revisions, max APDU, segmentation support, services-supported bitstring, object-types-supported bitstring. Lets an agent reason about callable services before it tries them.

All four are gated by the existing `read_only` flag the same as other reads (no change to safety surface). The Phase 2 safety control plane (write policy, dry-run, audit log) lands in the next PR alongside priority writes.

### Added — tests

11 new tests: 6 unit tests for the RPM spec builder + JSON object-id parser, 5 integration tests exercising the no-client / parameter-validation paths. Total: 60 tests passing.

### Notes
- Module structure: new `src/mcp/bulk.rs` (~430 LOC) groups the four tools and their shared helpers (`format_result_element`, `prop_ref`, `parse_object_id_from_json`).
- No safety-plane changes; all four tools wrap the existing `read_property_multiple` upstream API. The wire-protocol layer is unchanged.

## [0.3.0] — Operator console (TUI) + reload safety layer

The 0.3.0 release adds an interactive ratatui-based operator console, a layered hot-reload safety story with an explicit type-system split between frozen config and live-mutable runtime flags, and modernized CI patterns adopted from the selene-db reference repo.

### Added
- **`--mode tui` operator console.** Three tabs: **Configure** (live JSON editor with validation and partial hot-reload), **Observe** (device table, transport status panel, in-memory log tail), **Operate** (manual WhoIs / ReadProperty / WriteProperty forms with recent-action history). Auto-refresh, mouse capture toggle, F1 help popup, Ctrl-M / Ctrl-C shutdown, terminal restore on panic.
- **`RuntimeFlags` + `reload_safety_check`.** Architectural split: `GatewayState.config: Arc<GatewayConfig>` is frozen at boot; live-mutable flags (today `read_only` as `AtomicBool`) live in `GatewayState.flags: Arc<RuntimeFlags>`. F9 in the Configure tab classifies changes as `Applied`, `PartialApplied { applied, stale }`, or `Refused { reason }`. `device.instance` changes are refused (would corrupt I-Am cache on the wire). Applied fields take effect on the next MCP request without restart; stale fields persist to disk for the next boot.
- **`tui` cargo feature.** Pulls in ratatui 0.29 + crossterm 0.28 + tui-widgets + tui-textarea + parking_lot. Custom in-memory `LogLayer` (no tui-logger dep) feeds tracing events into the Observe tab.
- **`--writes-enabled` CLI flag.** Force writes on for a single session without editing config.
- **`--no-http` CLI flag.** TUI mode without an HTTP MCP surface (fully air-gapped operator console).
- **CI: 700 LOC file-size cap.** `.github/scripts/check-file-size.sh` enforces a 700-LOC cap (non-empty, non-comment) on every tracked `.rs` file. Adopted from selene-db.
- **CI: no-secret scan.** `.github/scripts/check-no-secrets.sh` greps for AWS keys, private key blocks, Slack tokens, GitHub tokens, `sk-` API tokens.
- **CI: cargo-audit job** for advisory database checks.

### Changed
- **CI workflow rewritten** to selene-db patterns: PR-driven trigger with `workflow_dispatch`, draft-PR skip, Cargo.lock guards on `cargo deny` and `cargo audit`, `--locked` flags everywhere, `permissions: contents: read`, `concurrency: cancel-in-progress`, stable Rust toolchain (was pinned 1.93). Multi-OS test matrix retained because BACnet UDP socket behavior differs across platforms.
- `src/mcp/reference/content.rs` split into `content.rs` (index strings) + `details.rs` (per-object-type drill-downs) to fit the 700 LOC cap.
- `GatewayState::is_read_only()` and `require_writable()` now read from `RuntimeFlags` atomic instead of frozen config — visible to the TUI's hot-toggle and any future runtime control surface.
- `Cargo.toml` package version bumped to **0.3.0**.

### Notes
- Phase 2 (MCP feature expansion: ReadPropertyMultiple, priority array, trends, alarms, schedules, full safety control plane) remains the next milestone. The `RuntimeFlags` plumbing landed in 0.3.0 specifically to give Phase 2 a place to add its live-mutable safety state without another refactor.
- BACnet/SC transport wiring (Phase 4) still pending — config schema accepts both Hub and Node modes; `builder.rs` wires only BIP today.

## [0.2.0] — MCP-only refocus

The project's identity tightened to a **dedicated MCP server** for agentic interaction with BACnet networks. The HTTP REST surface and MS/TP transport were removed to focus the codebase on IP-based BACnet (BIP and SC).

### Removed (breaking)
- **HTTP REST API** under `/api/v1/`. All operations are now MCP tools. Programmatic clients should use an MCP client SDK or speak JSON-RPC over the streamable-HTTP transport at `/mcp`.
- **MS/TP transport** (`transports.mstp` config block, `Rs485Config`, `serial` feature flag). The project now supports BACnet/IP and BACnet/SC only.
- **TOML config support**. The config file is now JSON. The default config filename is `bacnet-mcp.json` (was `gateway.toml`).
- `bacnet-gateway` binary name. The binary and package are now `bacnet-mcp`.
- `--no-api`, `--no-mcp`, `--bind` (renamed/removed) CLI flags.

### Changed
- **rmcp upgraded 1.2 → 1.6** — picks up `transport-streamable-http-server-session` (resumable sessions), `tower` middleware, schemars 1.0, edition 2024.
- **Edition bumped to 2024**, MSRV 1.85.
- **Default safety posture is read-only.** `mcp.read_only` defaults to `true`. Writes require explicit opt-in via config (`"read_only": false`) or `--writes-enabled`.
- **Auth feature gating relocated** — the `auth/` module is now under `mcp` (was `http`); library consumers selecting `--features mcp` get the bearer-token middleware automatically. Closes a previously-known gap.
- **Stdio MCP transport added.** `--transport stdio` (default) speaks JSON-RPC over stdin/stdout for Claude Desktop / Claude Code child-process integration.
- **Streamable-HTTP MCP transport** retained at `/mcp` via `--transport http`.
- **Both transports concurrently** via `--transport both`.
- BACnet/SC config now supports both **Hub** mode (`listen` field) and **Node** mode (`hub_uri` field), with mutual-exclusion validation. Wiring through to the builder is still pending.

### Added
- `examples/bacnet-mcp.json` starter config.
- Validation: SC role (Hub / Node) mutual-exclusion checks; route `via_transport` allowlist (`bip` | `sc`).

### Notes
- Phase 2 (MCP feature expansion) and Phase 3 (TUI) follow this release. See [CLAUDE.md](CLAUDE.md) for the roadmap.

## [0.1.0] — Standalone release

Extracted from the [`rusty-bacnet`](https://github.com/jscott3201/rusty-bacnet) workspace.
At extraction time the gateway was at parent version 0.8.1; functionality was unchanged from
that release.

### Surface
- HTTP REST API (Axum) under `/api/v1/` for device discovery, property read/write, local object CRUD.
- MCP (Model Context Protocol) server at `/mcp` exposing 10 tools and a built-in BACnet reference knowledge base.
- Bearer-token authentication, read-only mode, TOML-based configuration.
- Single binary (`bacnet-gateway`) with `--features bin`.
