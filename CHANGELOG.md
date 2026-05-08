# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — Standalone release

Extracted from the [`rusty-bacnet`](https://github.com/jscott3201/rusty-bacnet) workspace.
At extraction time the gateway was at parent version 0.8.1; functionality is unchanged from
that release. This repository tracks `bacnet-*` library versions on crates.io and bumps
its own patch line as needed.

### Surface
- HTTP REST API (Axum) under `/api/v1/` for device discovery, property read/write, local object CRUD.
- MCP (Model Context Protocol) server at `/mcp` exposing 10 tools and a built-in BACnet reference knowledge base (9 reference resources + per-object-type drill-down + 3 live state resources).
- Bearer-token authentication, read-only mode, TOML-based configuration.
- Single binary (`bacnet-gateway`) with `--features bin` (which pulls in `http` + `mcp`).

### Changed from parent
- `default-features` flipped from `[]` to `["http", "mcp"]` — library is the binary's natural shape and tests now compile under plain `cargo test`. Library consumers who want config-only can opt out via `default-features = false`.
- This crate is `publish = false` — distribute via `cargo install --git`.

### Notes
- See [docs/gateway.md](docs/gateway.md) for the full configuration, REST endpoint, and MCP tool reference.
- Known gaps: SC and MS/TP transport configs parse but are not yet wired in `builder.rs` (only BIP transport is constructed). Tracked as a GitHub issue.
