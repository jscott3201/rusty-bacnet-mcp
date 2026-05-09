# CLAUDE.md

Project guidance for Claude Code in this repository.

## Project Overview

Dedicated **MCP (Model Context Protocol) server** for agentic interaction with BACnet building automation networks. Wraps the [`rusty-bacnet`](https://github.com/jscott3201/rusty-bacnet) protocol stack and exposes device discovery, remote property read/write, local-object management, and a BACnet reference knowledge base to LLM agents over MCP.

The 0.1.x line shipped a combined HTTP REST API + MCP gateway. **0.2.0 dropped the HTTP REST surface entirely** — this is now MCP-only, with both stdio and streamable-HTTP transports. Configuration is JSON.

Consumes the `bacnet-*` library crates from crates.io.

## Common Commands

```bash
# Build (default features = mcp)
cargo build

# Build the binary CLI
cargo build --features bin

# Run with stdio transport (default — for Claude Desktop / Claude Code)
./target/debug/bacnet-mcp --config bacnet-mcp.json

# Run with streamable-HTTP transport
./target/debug/bacnet-mcp --config bacnet-mcp.json --transport http --bind 127.0.0.1:3000

# Run both transports concurrently
./target/debug/bacnet-mcp --config bacnet-mcp.json --transport both --bind 127.0.0.1:3000

# Tests
cargo test --features bin

# Lint (CI enforces zero warnings via RUSTFLAGS="-Dwarnings")
RUSTFLAGS="-Dwarnings" cargo clippy --all-targets --features bin

# Format check
cargo fmt --all --check

# Advisory + license check
cargo deny check
```

## Architecture

```
src/
  lib.rs       Module surface, feature-gated re-exports
  main.rs      CLI entry point (clap, gated by `bin` feature) — manages stdio
               and streamable-HTTP MCP transports concurrently
  config.rs    JSON schema + validation
  state.rs     GatewayState — Arc-cloneable shared state for MCP tools
  builder.rs   Wires the BACnet stack (BIP transport today; SC pending)
  parse.rs     Value/specifier parsing (JSON <-> BACnet types)
  auth/        Bearer-token authentication for the streamable-HTTP transport
               (constant-time compare via `subtle`)
  mcp/         MCP server (rmcp 1.6, gated by `mcp` feature)
    discovery.rs      device discovery tools
    objects.rs        local-object CRUD tools
    properties.rs     remote read/write tools
    reference/        BACnet reference knowledge base
      content.rs      static reference text (object types, properties, units, errors,
                      reliability, priority array, networking, services, troubleshooting)
      mod.rs          resource list + URI dispatch
    mod.rs            GatewayMcp, ServerHandler impl, #[tool] decls
tests/
  mcp_tests.rs   MCP integration tests (no live BACnet stack)
```

## Feature Flags

- `default = ["mcp"]` — library + tests work out of the box.
- `mcp` — rmcp-based MCP server (`mcp/`) plus auth middleware.
- `bin` — pulls in `mcp` plus clap + tracing-subscriber + tokio-util to compile the `bacnet-mcp` binary.
- `sc` — propagates BACnet/SC support to the underlying transport (currently unused; see Known Gaps).

Library consumers wanting config-only with no MCP/web deps: `default-features = false`.

## CLI Surface

```
bacnet-mcp [OPTIONS]
  -c, --config <PATH>          JSON config file (default: bacnet-mcp.json)
  -t, --transport <MODE>       stdio | http | both (default: stdio)
      --bind <ADDR>            HTTP transport bind override
  -k, --api-key <KEY>          Bearer token for HTTP auth (or BACNET_MCP_API_KEY env)
  -r, --read-only              Force read-only (writes rejected)
      --writes-enabled         Force writes on (overrides config; mutually exclusive with -r)
  -v, --verbose                Increase log level (-v info, -vv debug, -vvv trace)
  -q, --quiet                  Errors only
      --log-file <PATH>        Log file (required for stdio transport — stdout is JSON-RPC)
      --print-config           Print resolved config and exit
```

## Transport Selection

- **stdio** — JSON-RPC over stdin/stdout. Default. Right for local agentic clients (Claude Desktop, Claude Code) that spawn the server as a child process. Logs **must not** go to stdout — `--log-file` writes to a configured path or `$TMPDIR/bacnet-mcp-<pid>.log`.
- **http** — Streamable HTTP at `/mcp`. Right for remote / multi-client deployments. Bearer-token auth available via `mcp.api_key`.
- **both** — Both transports concurrently (e.g. local-stdio + ops dashboard via HTTP).

## Architectural Invariants

- **GatewayState is the single source of truth.** Every MCP tool calls methods on `GatewayState` — no duplicated BACnet logic. When adding new tools, extend `GatewayState`.
- **Frozen config vs. live flags.** `GatewayState.config: Arc<GatewayConfig>` is frozen at boot — fields that drove transport / socket / BACnet identity construction CANNOT change without rebuilding the stack. Hot-mutable runtime flags (today: `read_only`; Phase 2: write policy, audit log path) live in `GatewayState.flags: Arc<RuntimeFlags>` as atomics. The TUI's `reload_safety_check` enforces the split.
- **MCP reference data is compiled in.** All BACnet reference text lives in `src/mcp/reference/content.rs` (index strings) and `src/mcp/reference/details.rs` (per-object-type drill-downs) as `pub const ... : &str` and `pub fn`. No JSON files, no `include_str!`, no build.rs. Adding a new reference resource = add a `const`, register in `reference/mod.rs::RESOURCES`, expose in `mcp::list_resources`.
- **Bearer-token auth is constant-time.** `auth/bearer.rs` uses `subtle::ConstantTimeEq`. Don't replace with `==`.
- **Config validation is fail-fast at boot.** `config.rs::GatewayConfig::validate()` runs before any sockets open. Surface new validation rules there, not at request time.
- **Default safety posture is read-only.** `mcp.read_only` defaults to `true` — operators must explicitly enable writes via config or `--writes-enabled`. Phase 2 will expand this into a layered safety control plane (allow/deny lists, dry-run mediation, audit log) that plugs into the same `RuntimeFlags`.
- **Stdio owns stdout.** When stdio transport runs, `tracing` must be writer-redirected to a file (`with_writer(file).with_ansi(false)`). `init_tracing()` in `main.rs` handles this. The TUI mode forces stdio MCP off and routes `tracing` through both a file layer and the in-memory `LogBuffer` that the Observe tab reads.
- **Configuration is JSON only.** No TOML, no YAML, anywhere in the project's runtime config surface. (Cargo.toml is a Rust ecosystem requirement, not project config.)
- **Files are capped at 700 LOC** (non-empty, non-comment lines). CI runs `.github/scripts/check-file-size.sh` to enforce this. When a file approaches the cap, split by domain (e.g. `reference/content.rs` ↔ `reference/details.rs`).

## Known Gaps (file as GitHub issues)

1. **SC transport not wired.** `builder.rs` accepts `transports.sc` config blocks (Hub or Node mode) but currently only constructs the BIP transport. Multi-transport router is the unfinished work referenced at `builder.rs:30-31`.
2. **No starter `bacnet-mcp.json` ships in `examples/`** — write one for the install-and-run-fast workflow.
3. **No Docker image** for the MCP server. Add once SC wiring lands.
4. **Phase 2 features pending**: ReadPropertyMultiple, priority-array operations, trend-log windowed reads, alarm summary, schedule introspection, layered safety control plane (dry-run, audit log, policy allow/deny). Tracked in roadmap.
5. **Phase 3 (TUI) pending**: A separate `bacnet-mcp-tui` binary speaking to the daemon over a local control surface (Configure / Observe / Operate views via ratatui).

## Upstream Coupling

Imports from the `bacnet-*` library crates on crates.io, pinned to `^0.8`:
- `bacnet-types`, `bacnet-encoding`, `bacnet-services`
- `bacnet-transport` — including `bbmd::BdtEntry` and `bip::ForeignDeviceConfig` constructed by literal field assignment in `builder.rs`. Those structs must remain public-with-public-fields upstream; rebuild if they change.
- `bacnet-network`, `bacnet-client`, `bacnet-objects`, `bacnet-server`

## CI

Three-OS test matrix (Linux full feature set; macOS + Windows core). cargo-deny against advisory + license. Zero clippy warnings via `RUSTFLAGS="-Dwarnings"`. MSRV: 1.93 (edition 2024) — bumped from 1.85 alongside the bacnet-* 0.9 upgrade, which requires 1.93.

## License

MIT.
