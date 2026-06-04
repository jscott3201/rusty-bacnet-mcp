//! Dedicated MCP (Model Context Protocol) server for BACnet networks.
//!
//! Wraps the rusty-bacnet stack and exposes device discovery, property
//! read/write, local-object management, and a BACnet reference knowledge
//! base to LLM agents over MCP.
//!
//! # Feature flags
//!
//! - `mcp` — MCP server module (`mcp`) plus auth middleware. Default.
//! - `bin` — pulls in `mcp` plus the `bacnet-mcp` CLI binary entry point.
//! - `sc` — enables BACnet/SC TLS WebSocket runtime support.
//! - `pcap` — enables BACnet/IP packet capture discovery/analysis helpers.
//!
//! # Always available (no MCP/web dependencies)
//!
//! - `config` — TOML configuration parsing and validation
//! - `state` — shared gateway state (wraps BACnet client/server)
//! - `builder` — constructs the BACnet stack from config
//! - `parse` — BACnet value parsing and formatting utilities

pub mod audit;
#[cfg(feature = "mcp")]
pub mod auth;
pub mod builder;
pub mod config;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod parse;
pub mod pcap_state;
pub mod runtime;
pub mod safety;
pub mod state;
#[cfg(feature = "tui")]
pub mod tui;
