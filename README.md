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
- Phase 4 — route-aware multi-transport composition

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

## Docker

Build the deployment image with BACnet/IP and BACnet/SC runtime support
compiled in:

```bash
scripts/docker-build.sh
# or override:
BACNET_MCP_DOCKER_TAG=bacnet-mcp:dev \
BACNET_MCP_DOCKER_TARGET=runtime \
BACNET_MCP_DOCKER_FEATURES=bin,sc \
  scripts/docker-build.sh
```

The Dockerfile follows the same shape as the other Rust protocol drivers:
Alpine musl builder, Alpine runtime target, and distroless static runtime
target. `scripts/docker-build.sh` defaults to the `distroless` target and
compiles with `bin,sc`. The Alpine target runs as `bacnet`; the distroless
target runs as non-root UID/GID `65532:65532`.

Both runtime targets include a CA bundle for TLS, expose MCP HTTP on
`3000/tcp`, BACnet/IP on `47808/udp`, and BACnet/SC embedded hub traffic on
`8443/tcp`. The default container config is B/IP-only, read-only, and binds MCP
HTTP to `0.0.0.0:3000`.

For BACnet/IP broadcast discovery, host networking is usually the least
surprising container mode:

```bash
docker run --rm --network host \
  -v "$PWD/examples/bacnet-mcp.container.json:/etc/bacnet-mcp/bacnet-mcp.json:ro" \
  bacnet-mcp:local
```

For routed/unicast deployments, explicit port publishing can work:

```bash
docker run --rm \
  -p 3000:3000/tcp \
  -p 47808:47808/udp \
  -v "$PWD/examples/bacnet-mcp.container.json:/etc/bacnet-mcp/bacnet-mcp.json:ro" \
  bacnet-mcp:local
```

`scripts/docker-ci.sh` builds and smokes both runtime targets. `scripts/docker-smoke.sh`
verifies the binary/config entry points and checks the runtime user contract
for the selected target.

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

### Operator TUI

```bash
bacnet-mcp --mode tui --config bacnet-mcp.json
```

TUI mode owns the terminal, so stdio MCP is disabled. If the config has an
HTTP MCP listener, it can run alongside the operator console. The Shell tab is
a read-oriented command REPL for quick checks:

```text
status
devices
whois [low] [high] [timeout_seconds]
read <device> <object-type> <object-instance> <property>
```

## MCP Surface

**Tools** include:

```
Discovery: register_device, discover_devices, list_known_devices, get_device_info
Remote reads: read_property, read_property_multiple, read_point_summary, read_priority_array,
  read_file_chunk, enumerate_objects, get_device_capabilities
Remote writes: write_property, write_property_multiple, relinquish_at_priority
Alarms/events: get_alarm_summary, get_event_information, acknowledge_alarm
COV: subscribe_cov, unsubscribe_cov, poll_cov_notifications
Schedules: read_schedule, read_schedule_weekly, read_schedule_exceptions,
  write_schedule_weekly, write_schedule_exceptions
Trends: get_trend_log_info, read_trend_log
Diagnostics: ping_device, probe_bbmd
Local objects: list_local_objects, read_local_property, write_local_property,
  create_local_object, delete_local_object
```

`register_device` and directed `discover_devices` targets use the active BACnet
transport address format: `ip:port` for B/IP, or a 6-byte VMAC such as
`02:00:00:00:00:10` for BACnet/SC.

`read_property_multiple` defaults to compact output with one line per object,
bounded scalar rendering, and value/error/missing counts. Set
`response_mode: "detailed"` only when full decoded property lines are needed.
`read_property` also defaults to compact output for large arrays/strings; set
`response_mode: "detailed"` when the full decoded value is required.
`list_local_objects` defaults to the first 500 gateway-local objects and reports
omissions; set `limit` up to 5000 for larger local databases.

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

Configure exactly one BACnet runtime transport. For BACnet/SC, build with
`--features bin,sc`. External-hub node mode needs a hub URI, client
certificate material, and distinct stable VMACs:

```json
{
  "device": {
    "instance": 389001,
    "name": "BACnet MCP SC Gateway",
    "vendor_id": 999
  },
  "transports": {
    "sc": {
      "hub_uri": "wss://hub.example.com:8443",
      "cert": "/etc/bacnet-mcp/certs/node.pem",
      "key": "/etc/bacnet-mcp/certs/node.key",
      "ca": "/etc/bacnet-mcp/certs/ca.pem",
      "client_vmac": "02:00:00:00:00:01",
      "server_vmac": "02:00:00:00:00:02",
      "network_number": 2
    }
  }
}
```

Embedded-hub mode starts a local BACnet/SC hub and connects the gateway's
client/server nodes through it. Provide `listen`, `hub_vmac`, and `ca` for
mTLS. If `listen` is a wildcard address, also provide `hub_uri` so local nodes
know which TLS name/address to use.

```json
{
  "device": {
    "instance": 389001,
    "name": "BACnet MCP SC Embedded Hub",
    "vendor_id": 999
  },
  "transports": {
    "sc": {
      "listen": "127.0.0.1:8443",
      "hub_uri": "wss://127.0.0.1:8443",
      "cert": "/etc/bacnet-mcp/certs/node.pem",
      "key": "/etc/bacnet-mcp/certs/node.key",
      "ca": "/etc/bacnet-mcp/certs/ca.pem",
      "hub_vmac": "02:00:00:00:00:ff",
      "client_vmac": "02:00:00:00:00:01",
      "server_vmac": "02:00:00:00:00:02",
      "network_number": 2
    }
  }
}
```

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
