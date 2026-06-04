# Deployment And Operations

`bacnet-mcp` can run as a local stdio child process, a remote streamable-HTTP
daemon, a TUI-backed operator console, or a containerized gateway.

## Daemon Modes

Stdio MCP:

```bash
bacnet-mcp --config bacnet-mcp.json
```

Streamable HTTP:

```bash
bacnet-mcp --config bacnet-mcp.json --transport http --bind 127.0.0.1:3000
```

Both:

```bash
bacnet-mcp --config bacnet-mcp.json --transport both --bind 127.0.0.1:3000
```

When stdio is active, logs are written to a file so stdout remains valid
JSON-RPC framing. Use `--log-file` to choose the path.

## Operator TUI

```bash
bacnet-mcp --mode tui --config bacnet-mcp.json
```

TUI mode disables stdio MCP because the terminal owns stdout. HTTP MCP can run
alongside the TUI unless `--no-http` is passed.

Important keys:

- `Tab` / `Shift-Tab`: move between tabs.
- `F5`: validate config in the Configure tab.
- `F9`: save and hot-reload config in the Configure tab.
- `F12`: detach the TUI and keep the daemon plus HTTP MCP running.
- `q`: quit when outside the Shell tab.

The Shell tab is read-oriented:

```text
status
devices
whois [low] [high] [timeout_seconds]
read <device> <object-type> <object-instance> <property>
```

The Configure tab uses the same JSON parser and validator as startup. Hot-safe
changes are applied immediately; restart-required changes are saved but remain
stale in the live view until restart.

## Docker

Build the default distroless runtime:

```bash
scripts/docker-build.sh
```

Build specific targets:

```bash
BACNET_MCP_DOCKER_TARGET=runtime scripts/docker-build.sh
BACNET_MCP_DOCKER_TARGET=distroless scripts/docker-build.sh
```

The Dockerfile builds with Alpine/musl and supports:

- `runtime`: Alpine runtime, non-root `bacnet` user.
- `distroless`: static distroless runtime, non-root UID/GID `65532:65532`.

The default feature set is `bin,sc`, so both BACnet/IP and BACnet/SC runtime
support are compiled in.

Runtime ports:

- `3000/tcp`: MCP streamable HTTP.
- `47808/udp`: BACnet/IP.
- `8443/tcp`: BACnet/SC embedded hub, when configured.

For BACnet/IP broadcast discovery, prefer host networking:

```bash
docker run --rm --network host \
  -v "$PWD/examples/bacnet-mcp.container.json:/etc/bacnet-mcp/bacnet-mcp.json:ro" \
  bacnet-mcp:local
```

For routed or unicast deployments:

```bash
docker run --rm \
  -p 3000:3000/tcp \
  -p 47808:47808/udp \
  -v "$PWD/examples/bacnet-mcp.container.json:/etc/bacnet-mcp/bacnet-mcp.json:ro" \
  bacnet-mcp:local
```

Mount SC certificate material read-only and reference it from the JSON config.

## CI Shape

Development PR CI is lean:

- format check
- clippy with `bin,sc`
- dependency deny/audit
- tracked Rust file-size cap
- no-secret scan

Release-heavy jobs are intentionally reserved for main/manual paths:

- OS matrix tests
- release binary build
- Docker build

Local full validation should still run before PRs:

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

