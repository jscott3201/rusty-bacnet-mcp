# rusty-bacnet-mcp

HTTP REST API + MCP (Model Context Protocol) server gateway for BACnet networks. Lets programmatic clients and AI agents discover devices, read sensor values, write setpoints, and manage local objects on the [`rusty-bacnet`](https://github.com/jscott3201/rusty-bacnet) protocol stack.

[![CI](https://github.com/jscott3201/rusty-bacnet-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/jscott3201/rusty-bacnet-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What you get

- **REST API** at `/api/v1/` — device discovery, remote property read/write, local object CRUD, health.
- **MCP Server** at `/mcp` — 10 tools (`discover_devices`, `read_property`, `write_property`, `list_local_objects`, etc.) plus a built-in BACnet reference knowledge base. An LLM connected via MCP can troubleshoot devices, diagnose alarms, and read sensors with **zero prior BACnet knowledge** — the reference resources are compiled in.
- **Bearer-token authentication** with constant-time comparison.
- **Read-only mode** for safe production deployments.
- **TOML configuration** with full validation at boot.
- **Single static binary** (`bacnet-gateway`) — no runtime dependencies beyond a TOML config.

## Install

The crate is not published to crates.io. Install via `cargo install --git`:

```bash
cargo install --git https://github.com/jscott3201/rusty-bacnet-mcp bacnet-gateway --features bin
```

Or build from source:

```bash
git clone https://github.com/jscott3201/rusty-bacnet-mcp
cd rusty-bacnet-mcp
cargo build --release --features bin
# Binary at target/release/bacnet-gateway
```

## Quick Start

`gateway.toml`:

```toml
[server]
bind = "0.0.0.0:3000"
api_key = "your-secret-key"

[device]
instance = 389001
name = "BACnet Gateway"

[transports.bip]
interface = "0.0.0.0"
port = 47808
broadcast = "192.168.1.255"
network_number = 1
```

Run it:

```bash
bacnet-gateway --config gateway.toml
# Listening on 0.0.0.0:3000  (REST: /api/v1, MCP: /mcp)
```

Discover devices:

```bash
curl -H "Authorization: Bearer your-secret-key" \
  -X POST http://localhost:3000/api/v1/devices/discover
```

Connect an MCP client (Claude Desktop, etc.) to `http://localhost:3000/mcp`. The 10 tools and BACnet reference resources are immediately available.

## REST API (selected)

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/devices/discover` | Broadcast `WhoIs`, return discovered devices |
| `GET  /api/v1/devices/{instance}` | Read device properties (name, vendor, model, firmware) |
| `GET  /api/v1/devices/{instance}/objects/{type}:{id}/properties/{prop}` | Read remote property |
| `PUT  /api/v1/devices/{instance}/objects/{type}:{id}/properties/{prop}` | Write remote property |
| `GET/POST/DELETE /api/v1/objects` | Local object database CRUD |
| `GET  /api/v1/health` | Liveness check |

Full reference: [docs/gateway.md](docs/gateway.md).

## MCP Tools

```
discover_devices, list_known_devices, get_device_info,
read_property, write_property,
list_local_objects, read_local_property, write_local_property,
create_local_object, delete_local_object
```

Plus reference resources:
- `bacnet://reference/{object-types,properties,units,errors,reliability,priority-array,networking,services,troubleshooting}`
- `bacnet://reference/object-types/{type}` — per-object-type drill-down
- `bacnet://state/{devices,local-objects,config}` — live state snapshots

## Authentication

Bearer-token via `Authorization: Bearer <key>`. Configure in `gateway.toml` `[server].api_key`, override on the CLI with `--api-key`, or set `BACNET_GATEWAY_API_KEY` env var. Comparison is constant-time (subtle crate).

## Read-Only Mode

```bash
bacnet-gateway --config gateway.toml --read-only
```

Blocks all write paths (`PUT`/`DELETE` REST, write-flavored MCP tools). Returns `403` / MCP error.

## Documentation

- [docs/gateway.md](docs/gateway.md) — full REST endpoint reference, MCP tool catalog, TOML schema, 9 example configurations, authentication details.
- [CLAUDE.md](CLAUDE.md) — architectural notes for code contributors.
- [CHANGELOG.md](CHANGELOG.md) — release notes.

## Built On

This gateway consumes the [`rusty-bacnet`](https://github.com/jscott3201/rusty-bacnet) library crates from crates.io:

- `bacnet-types`, `bacnet-encoding`, `bacnet-services`
- `bacnet-transport`, `bacnet-network`
- `bacnet-client`, `bacnet-objects`, `bacnet-server`

Pinned to `^0.8`. cargo-deny runs against the advisory database in CI on every push.

## Known Gaps

See [CLAUDE.md](CLAUDE.md) for the up-to-date list. At extraction time:

1. SC and MS/TP transports parse from TOML but only BIP is wired (`builder.rs`).
2. Auth module gated by `http` — `--features mcp`-only consumers need to wire their own middleware.
3. Starter `gateway.toml` examples are inline in `docs/gateway.md`, not yet promoted to `examples/`.

## License

MIT — see [LICENSE](LICENSE).
