# Configuration

`bacnet-mcp` uses JSON configuration only. The config is parsed and validated at
startup, and the TUI Configure tab uses the same parser and validator before
saving reloads.

## Minimal B/IP Config

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

`transports.bip.broadcast` should match the BACnet/IP subnet. Container
deployments often use `255.255.255.255` in the container config and host
networking for broadcast discovery.

## BACnet/SC Node Mode

Build with the `sc` feature:

```bash
cargo build --release --features bin,sc
```

Use node mode when the gateway connects to an external BACnet/SC hub:

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

`client_vmac` and `server_vmac` must be distinct stable six-byte VMACs. Manual
device registration and directed discovery use VMAC addresses on SC, for
example `02:00:00:00:00:10`.

## BACnet/SC Embedded Hub Mode

Embedded hub mode starts a local BACnet/SC hub and connects the gateway client
and server nodes through it:

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

When `listen` is a wildcard bind address, provide `hub_uri` so the local nodes
know the concrete URI and TLS name to connect to. `hub_vmac`, `client_vmac`,
and `server_vmac` must all be distinct.

## MCP HTTP And Auth

HTTP is configured through `mcp.http.bind` or `--bind`:

```json
{
  "mcp": {
    "http": {
      "bind": "0.0.0.0:3000"
    },
    "api_key": "replace-me"
  }
}
```

The API key is only used by the streamable-HTTP transport. Stdio relies on the
parent process and transport-level identity. CLI/env overrides are available:

```bash
BACNET_MCP_API_KEY=replace-me bacnet-mcp --transport http --config bacnet-mcp.json
bacnet-mcp --transport http --api-key replace-me --config bacnet-mcp.json
```

## Read-Only, Safety, And Audit

`mcp.read_only` defaults to `true`. Write tools return an MCP error unless the
config sets `"read_only": false` or the process is started with
`--writes-enabled`.

The safety policy is layered. Missing fields keep conservative defaults:

```json
{
  "mcp": {
    "read_only": false,
    "safety": {
      "allow_object_types": ["analog-output", "analog-value"],
      "deny_object_types": ["life-safety-point", "life-safety-zone", "notification-class"],
      "deny_objects": ["device:0"],
      "min_priority": 9,
      "max_priority": 16
    },
    "audit": {
      "capacity": 5000,
      "path": "/var/log/bacnet-mcp/audit.jsonl"
    }
  }
}
```

The in-memory audit ring is always available through `bacnet://audit/recent`.
`mcp.audit.path` mirrors entries to JSON Lines for persistence.

## TUI Reload Rules

The TUI Configure tab can validate with `F5` and save/reload with `F9`.
Reloads are classified:

- Applied: hot-safe changes took effect immediately.
- Partial applied: hot-safe fields changed, restart-required fields were saved
  to disk but remain stale in the live runtime.
- Refused: unsafe runtime identity changes were rejected and not written.

Hot-safe fields include `mcp.read_only` and `mcp.safety`. Fields such as
`mcp.http`, `mcp.api_key`, transport config, device identity, routes, and audit
file/capacity require a restart.

