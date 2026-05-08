# CLAUDE.md

Project guidance for Claude Code in this repository.

## Project Overview

Standalone HTTP REST API + MCP (Model Context Protocol) server gateway for the [`rusty-bacnet`](https://github.com/jscott3201/rusty-bacnet) BACnet protocol stack. Exposes device discovery, property read/write, and local object management to programmatic clients (REST) and AI agents (MCP).

Extracted from `jscott3201/rusty-bacnet`; consumes the `bacnet-*` library crates from crates.io.

## Common Commands

```bash
# Build (default features = http + mcp)
cargo build

# Build with the binary CLI
cargo build --features bin

# Run the gateway
./target/debug/bacnet-gateway --config gateway.toml

# Tests (default features include http + mcp, so plain cargo test works)
cargo test

# Lint (CI enforces zero warnings via RUSTFLAGS="-Dwarnings")
RUSTFLAGS="-Dwarnings" cargo clippy --all-targets

# Format check
cargo fmt --all --check

# Advisory + license check
cargo deny check
```

## Architecture

```
src/
  lib.rs       Module surface, feature-gated re-exports
  main.rs      CLI entry point (clap, gated by `bin` feature)
  config.rs    TOML schema + validation
  state.rs     GatewayState — Arc-cloneable shared state for REST + MCP
  builder.rs   Wires the BACnet stack (BIP transport, server, client)
  parse.rs     Value/specifier parsing (JSON <-> BACnet types)
  auth/        Bearer-token authentication (gated by `http`)
  api/         REST handlers (gated by `http`)
    devices.rs        /api/v1/devices/*
    objects.rs        /api/v1/objects (local DB CRUD)
    properties.rs     /api/v1/devices/{instance}/objects/.../properties/{prop}
    diagnostics.rs    /api/v1/health
    types.rs          shared API types + JSON helpers
    mod.rs            api_router, /api/v1 nesting, auth middleware
  mcp/         MCP server (gated by `mcp`)
    discovery.rs      device discovery tools
    objects.rs        local-object CRUD tools
    properties.rs     remote read/write tools
    reference/        BACnet reference knowledge base
      content.rs      static reference text (object types, properties, units, errors,
                      reliability, priority array, networking, services, troubleshooting)
      mod.rs          resource list + URI dispatch
    mod.rs            GatewayMcp, ServerHandler impl, 10 #[tool] decls
tests/
  api_tests.rs   REST integration tests
  mcp_tests.rs   MCP integration tests
```

## Feature Flags

- `default = ["http", "mcp"]` — library + tests work out of the box.
- `http` — Axum-based REST API (`api/`, `auth/`).
- `mcp` — rmcp-based MCP server (`mcp/`).
- `bin` — pulls in `http` + `mcp` + clap + tracing-subscriber + tokio-util to compile the `bacnet-gateway` binary.
- `sc-tls` — propagates BACnet/SC support to the underlying transport (currently unused; see Known Gaps).
- `serial` — propagates MS/TP support (currently unused; see Known Gaps).

Library consumers wanting config-only with no web deps: `default-features = false`.

## Architectural Invariants

- **GatewayState is the single source of truth.** REST handlers and MCP tools both call methods on `GatewayState` — no duplicated BACnet logic. When adding new functionality, extend `GatewayState` and call from both surfaces.
- **MCP reference data is compiled in.** All BACnet reference text lives in `src/mcp/reference/content.rs` as `pub const ... : &str`. No JSON files, no `include_str!`, no build.rs. Adding a new reference resource = add a `const`, register in `reference/mod.rs::RESOURCES`, expose in `mcp::list_resources`.
- **Bearer-token auth is constant-time.** `auth/bearer.rs` uses `subtle::ConstantTimeEq` to prevent timing side channels. Don't replace with `==`.
- **Config validation is fail-fast at boot.** `config.rs::GatewayConfig::validate()` runs before any sockets open. Surface new validation rules there, not at request time.

## Known Gaps (file as GitHub issues)

1. **SC + MS/TP transports**: `builder.rs` accepts SC and MS/TP config blocks via TOML but currently only constructs the BIP transport. Multi-transport router-centric model is the unfinished work referenced in `builder.rs:30-31`. SC/MS/TP configs parse silently but aren't used.
2. **`auth/` module gating**: `auth/` is gated by `http` even though the `bin` target applies bearer auth to MCP at runtime. Library consumers selecting `--features mcp` only (without `http`) get unauthenticated MCP unless they wire their own middleware. Consider widening the gate or pulling auth in via `mcp`.
3. **No starter `gateway.toml` ships in `examples/`** — the 9 inline configurations in `docs/gateway.md` should be promoted to real `examples/*.toml` files for the install-and-run-fast workflow.
4. **No Docker image** for the gateway. Add once SC/MS/TP wiring lands.

## Upstream Coupling

Imports from the `bacnet-*` library crates on crates.io, pinned to `^0.8`:
- `bacnet-types`, `bacnet-encoding`, `bacnet-services`
- `bacnet-transport` — including `bbmd::BdtEntry` and `bip::ForeignDeviceConfig` constructed by literal field assignment in `builder.rs`. Those structs must remain public-with-public-fields upstream; rebuild if they change.
- `bacnet-network`, `bacnet-client`, `bacnet-objects`, `bacnet-server`

## CI

Three-OS test matrix (Linux full feature set; macOS + Windows core). cargo-deny against advisory + license. Zero clippy warnings via `RUSTFLAGS="-Dwarnings"`. Same MSRV pin as upstream (1.93).

## License

MIT.
