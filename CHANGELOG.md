# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
