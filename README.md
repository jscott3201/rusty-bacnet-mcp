# rusty-bacnet-mcp

Dedicated MCP server for BACnet building automation networks, built on the
[`rusty-bacnet`](https://github.com/jscott3201/rusty-bacnet) protocol stack.

`bacnet-mcp` exposes BACnet discovery, reads, writes, diagnostics, local object
management, and reference knowledge to MCP clients over stdio or streamable
HTTP. It also includes an operator TUI for local supervision, config reloads,
and quick read-oriented shell commands.

[![CI](https://github.com/jscott3201/rusty-bacnet-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/jscott3201/rusty-bacnet-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Current Status

- MCP-first gateway. The legacy REST/API direction is gone; the supported
  external control plane is MCP.
- BACnet/IP runtime support is available in the default binary build.
- BACnet/SC runtime support is available with the `sc` feature, including
  external hub node mode and embedded local hub mode.
- Daemon mode supports stdio, streamable HTTP, or both concurrently.
- TUI mode owns the terminal and can run alongside HTTP MCP for external
  clients.
- The MCP surface includes discovery, compact reads, RPM, point summaries,
  file chunks, priority arrays, writes, WPM, relinquish, alarms/events, COV,
  schedules, trends, diagnostics, local objects, state resources, and embedded
  BACnet reference resources.
- Outputs are designed for agent context efficiency: compact defaults, bounded
  list resources, omission markers, and detailed modes only where needed.
- Writes are read-only by default and guarded by runtime safety policy plus an
  audit resource.
- Container deployment is supported through Alpine and distroless runtime
  targets.

Development work lands on `development`; release promotion is reserved for
`main`.

## Install

The crate is not published to crates.io. Build from source:

```bash
git clone https://github.com/jscott3201/rusty-bacnet-mcp
cd rusty-bacnet-mcp
cargo build --release --features bin,sc
```

The binary is written to `target/release/bacnet-mcp`.

For a B/IP-only build:

```bash
cargo build --release --features bin
```

Install directly from Git:

```bash
cargo install --git https://github.com/jscott3201/rusty-bacnet-mcp bacnet-mcp --features bin,sc
```

## Quick Start

Copy and edit the starter config:

```bash
cp examples/bacnet-mcp.json ./bacnet-mcp.json
# Edit transports.bip.broadcast and device.instance for your site.
```

Run as a stdio MCP server:

```bash
bacnet-mcp --config bacnet-mcp.json
```

Run streamable HTTP:

```bash
bacnet-mcp --config bacnet-mcp.json --transport http --bind 127.0.0.1:3000
```

Endpoint:

```text
http://127.0.0.1:3000/mcp
```

Run both stdio and HTTP:

```bash
bacnet-mcp --config bacnet-mcp.json --transport both --bind 127.0.0.1:3000
```

Run the operator TUI:

```bash
bacnet-mcp --mode tui --config bacnet-mcp.json
```

In TUI mode stdio MCP is disabled because the terminal owns stdout. HTTP MCP
can still run unless `--no-http` is passed. Press `F12` to detach the TUI and
leave the BACnet stack plus HTTP MCP server running.

## MCP Client Config

For a local stdio client:

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

For streamable HTTP clients, connect to `/mcp`. If `mcp.api_key`,
`--api-key`, or `BACNET_MCP_API_KEY` is set, send it as a bearer token.

## Tools And Resources

Core tool groups:

- Discovery: `register_device`, `discover_devices`, `list_known_devices`,
  `get_device_info`
- Reads: `read_property`, `read_property_multiple`, `read_point_summary`,
  `read_priority_array`, `read_file_chunk`, `enumerate_objects`,
  `get_device_capabilities`
- Writes: `write_property`, `write_property_multiple`,
  `relinquish_at_priority`
- Alarms and events: `get_alarm_summary`, `get_event_information`,
  `acknowledge_alarm`
- COV: `subscribe_cov`, `unsubscribe_cov`, `poll_cov_notifications`
- Schedules: `read_schedule`, `read_schedule_weekly`,
  `read_schedule_exceptions`, `write_schedule_weekly`,
  `write_schedule_exceptions`
- Trends: `get_trend_log_info`, `read_trend_log`
- Diagnostics: `ping_device`, `probe_bbmd`
- Local objects: `list_local_objects`, `read_local_property`,
  `write_local_property`, `create_local_object`, `delete_local_object`

Compiled-in reference resources:

- `bacnet://reference/tool-guide`
- `bacnet://reference/object-types`
- `bacnet://reference/object-types/{type}`
- `bacnet://reference/properties`
- `bacnet://reference/units`
- `bacnet://reference/errors`
- `bacnet://reference/reliability`
- `bacnet://reference/priority-array`
- `bacnet://reference/networking`
- `bacnet://reference/services`
- `bacnet://reference/troubleshooting`
- `bacnet://reference/bibbs`

Live state and audit resources:

- `bacnet://state/devices`
- `bacnet://state/local-objects`
- `bacnet://state/config`
- `bacnet://audit/recent`
- `bacnet://topology/graph`

See [docs/mcp-surface.md](docs/mcp-surface.md) for tool usage, output budgets,
and safety notes.

## Configuration

Configuration is JSON-only:

```json
{
  "mcp": {
    "read_only": true,
    "http": {
      "bind": "127.0.0.1:3000"
    }
  },
  "device": {
    "instance": 389001,
    "name": "BACnet MCP Gateway",
    "vendor_id": 999,
    "description": "Agentic MCP gateway for BACnet networks"
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

Configure exactly one active BACnet runtime transport: `transports.bip` or
`transports.sc`. Starter examples live in `examples/`:

- `examples/bacnet-mcp.json`
- `examples/bacnet-mcp.sc.json`
- `examples/bacnet-mcp.sc-embedded.json`
- `examples/bacnet-mcp.container.json`

See [docs/configuration.md](docs/configuration.md) for B/IP, BACnet/SC,
read-only, safety, audit, and TUI reload details.

## Docker

Build the default distroless image with B/IP and SC support:

```bash
scripts/docker-build.sh
```

Override tag, target, or features:

```bash
BACNET_MCP_DOCKER_TAG=bacnet-mcp:dev \
BACNET_MCP_DOCKER_TARGET=runtime \
BACNET_MCP_DOCKER_FEATURES=bin,sc \
  scripts/docker-build.sh
```

Run with host networking for B/IP broadcast discovery:

```bash
docker run --rm --network host \
  -v "$PWD/examples/bacnet-mcp.container.json:/etc/bacnet-mcp/bacnet-mcp.json:ro" \
  bacnet-mcp:local
```

See [docs/deployment.md](docs/deployment.md) for Docker targets, ports,
BACnet/SC deployment notes, CI behavior, and TUI operations.

## CLI

```text
bacnet-mcp [OPTIONS]

  -m, --mode <MODE>            daemon | tui (default: daemon)
  -c, --config <PATH>          JSON config file (default: bacnet-mcp.json)
  -t, --transport <MODE>       stdio | http | both (default: stdio)
      --bind <ADDR>            HTTP bind override
  -k, --api-key <KEY>          HTTP bearer token, or BACNET_MCP_API_KEY
  -r, --read-only              Force read-only mode
      --writes-enabled         Force writes enabled
  -v, --verbose                -v info, -vv debug, -vvv trace
  -q, --quiet                  Errors only in daemon mode
      --log-file <PATH>        Log file path
      --no-http                TUI mode only: disable HTTP MCP
      --print-config           Print resolved config and exit
```

## Development

Useful local gates:

```bash
cargo fmt --all --check
cargo check --all-targets --features bin,sc --locked
cargo test --features bin,sc --locked
cargo clippy --all-targets --features bin,sc --locked -- -D warnings
cargo clippy --all-targets --features bin --locked -- -D warnings
cargo doc --workspace --no-deps --features bin,sc --locked
bash .github/scripts/check-file-size.sh
bash .github/scripts/check-no-secrets.sh
```

Dev CI is intentionally lean: formatting, linting, dependency checks, file-size
cap, and secret scan run on PRs. Heavy OS matrix tests, release builds, and
Docker builds are reserved for main/manual paths.

## Built On

- `bacnet-types`, `bacnet-encoding`, `bacnet-services`
- `bacnet-transport`, `bacnet-network`
- `bacnet-client`, `bacnet-objects`, `bacnet-server`
- `rmcp` for MCP server transports
- `ratatui` for the operator console

## License

MIT, see [LICENSE](LICENSE).
