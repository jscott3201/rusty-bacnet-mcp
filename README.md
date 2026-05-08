# rusty-bacnet-mcp

Dedicated **MCP (Model Context Protocol) server** for agentic interaction with BACnet building automation networks. Lets LLM agents discover devices, read sensor values, write setpoints, and manage local objects on the [`rusty-bacnet`](https://github.com/jscott3201/rusty-bacnet) protocol stack — over MCP, via stdio (Claude Desktop / Claude Code) or streamable-HTTP (remote / multi-client).

[![CI](https://github.com/jscott3201/rusty-bacnet-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/jscott3201/rusty-bacnet-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What you get

- **MCP server** with both **stdio** and **streamable-HTTP** transports — pick one or run both.
- **BACnet tools** — `discover_devices`, `read_property`, `write_property`, local-object CRUD, plus more landing in 0.3 (ReadPropertyMultiple, priority array, trends, alarms, schedules).
- **Built-in BACnet reference resources** — an LLM connected via MCP can troubleshoot devices, diagnose alarms, and read sensors with **zero prior BACnet knowledge**. Reference content is compiled into the binary.
- **Bearer-token auth** on the HTTP transport with constant-time comparison.
- **Read-only by default** — operators must explicitly opt in to writes via config or `--writes-enabled`.
- **JSON configuration** with full validation at boot.
- **Single static binary** (`bacnet-mcp`) — no runtime deps beyond the JSON config.

## Status

Version 0.2.0 dropped the legacy HTTP REST API and MS/TP transport to focus the project on MCP-only agentic access over IP-based BACnet (BIP + SC).

Coming next:
- Phase 2 — feature expansion (RPM, priority array, trends, alarms, schedules, layered safety)
- Phase 3 — `bacnet-mcp-tui` operator console (ratatui)
- Phase 4 — BACnet/SC Hub + Node transport wiring

## Install

The crate is not published to crates.io yet. Build from source:

```bash
git clone https://github.com/jscott3201/rusty-bacnet-mcp
cd rusty-bacnet-mcp
cargo build --release --features bin
# Binary at target/release/bacnet-mcp
```

Or via `cargo install --git`:

```bash
cargo install --git https://github.com/jscott3201/rusty-bacnet-mcp bacnet-mcp --features bin
```

## Quick Start

Copy the starter config:

```bash
cp examples/bacnet-mcp.json ./bacnet-mcp.json
# Edit transports.bip.broadcast to match your subnet
```

### Stdio (for Claude Desktop / Claude Code)

```bash
bacnet-mcp --config bacnet-mcp.json
```

Stdio is the default. Logs go to `$TMPDIR/bacnet-mcp-<pid>.log` (override with `--log-file`); stdout is reserved for JSON-RPC.

In Claude Desktop / Claude Code MCP config, add:

```json
{
  "mcpServers": {
    "bacnet": {
      "command": "/absolute/path/to/bacnet-mcp",
      "args": ["--config", "/absolute/path/to/bacnet-mcp.json"]
    }
  }
}
```

### Streamable-HTTP (remote / multi-client)

```bash
bacnet-mcp --config bacnet-mcp.json --transport http --bind 127.0.0.1:3000
```

Endpoint: `http://127.0.0.1:3000/mcp`. Set `mcp.api_key` in the config (or `--api-key` / `BACNET_MCP_API_KEY`) to require bearer-token auth.

### Both transports concurrently

```bash
bacnet-mcp --config bacnet-mcp.json --transport both --bind 127.0.0.1:3000
```

## MCP Surface

**Tools** (10 today; expanding in 0.3):

```
discover_devices, list_known_devices, get_device_info, register_device,
read_property, write_property,
list_local_objects, read_local_property, write_local_property,
create_local_object, delete_local_object
```

**Resources**:

- `bacnet://reference/{object-types,properties,units,errors,reliability,priority-array,networking,services,troubleshooting}` — compiled-in reference text.
- `bacnet://reference/object-types/{type}` — per-type drill-down.
- `bacnet://state/{devices,local-objects,config}` — live state snapshots.

## Configuration (JSON)

```json
{
  "mcp": {
    "read_only": true,
    "api_key": "your-secret-key",
    "http": { "bind": "127.0.0.1:3000" }
  },
  "device": {
    "instance": 389001,
    "name": "BACnet MCP Gateway",
    "vendor_id": 999
  },
  "transports": {
    "bip": {
      "interface": "0.0.0.0",
      "port": 47808,
      "broadcast": "192.168.1.255",
      "network_number": 1
    }
  }
}
```

Full schema: see [src/config.rs](src/config.rs). Starter file: [examples/bacnet-mcp.json](examples/bacnet-mcp.json).

## CLI

```
bacnet-mcp [OPTIONS]
  -c, --config <PATH>          JSON config file (default: bacnet-mcp.json)
  -t, --transport <MODE>       stdio | http | both (default: stdio)
      --bind <ADDR>            HTTP transport bind override
  -k, --api-key <KEY>          Bearer token (or BACNET_MCP_API_KEY env)
  -r, --read-only              Force read-only
      --writes-enabled         Force writes on (overrides config)
  -v, --verbose                -v info, -vv debug, -vvv trace
  -q, --quiet                  Errors only
      --log-file <PATH>        Log file (auto $TMPDIR/bacnet-mcp-<pid>.log for stdio)
      --print-config           Print resolved config and exit
```

## Safety

`mcp.read_only` defaults to `true` — out of the box, every write tool returns `Gateway is in read-only mode`. To enable writes, set `"read_only": false` in JSON config or pass `--writes-enabled`. Phase 2 will add a layered safety control plane: per-tool dry-run, write allow/deny lists, priority-range caps, and an append-only audit log exposed as `bacnet://audit/recent`.

## Built On

Consumes the [`rusty-bacnet`](https://github.com/jscott3201/rusty-bacnet) library crates (`^0.8`):

- `bacnet-types`, `bacnet-encoding`, `bacnet-services`
- `bacnet-transport`, `bacnet-network`
- `bacnet-client`, `bacnet-objects`, `bacnet-server`

cargo-deny runs against the advisory database in CI on every push.

## Documentation

- [CLAUDE.md](CLAUDE.md) — architectural notes for contributors.
- [CHANGELOG.md](CHANGELOG.md) — release notes.

## License

MIT — see [LICENSE](LICENSE).
