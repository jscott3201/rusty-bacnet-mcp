//! BACnet MCP server binary entry point.
//!
//! Two run modes:
//! - **daemon** (default): Loads JSON config, starts the BACnet stack, serves
//!   MCP over stdio, streamable-HTTP, or both. Headless.
//! - **tui**: Same BACnet stack, but a ratatui operator console replaces stdio.
//!   Stdio MCP is unavailable in TUI mode (terminal owns stdout); HTTP MCP can
//!   still run alongside the TUI for outside agentic clients.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use clap::{Parser, ValueEnum};
use rmcp::ServiceExt;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use bacnet_mcp::auth::Authenticator;
use bacnet_mcp::auth::bearer::BearerTokenAuth;
use bacnet_mcp::builder::GatewayBuilder;
use bacnet_mcp::config::GatewayConfig;
use bacnet_mcp::mcp::GatewayMcp;

/// How the binary should run.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum RunMode {
    /// Headless daemon. Serves MCP over stdio and/or streamable-HTTP.
    Daemon,
    /// Interactive TUI operator console. Stdio MCP is unavailable; HTTP MCP
    /// can still run alongside the TUI when configured.
    Tui,
}

/// Which MCP transport(s) to expose in daemon mode.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum TransportMode {
    /// Stdio only — JSON-RPC over stdin/stdout. Right for local agentic clients
    /// (Claude Desktop, Claude Code) that spawn the server as a child process.
    Stdio,
    /// Streamable-HTTP only. Right for remote / multi-client deployments.
    Http,
    /// Both stdio and HTTP concurrently.
    Both,
}

impl TransportMode {
    fn includes_stdio(self) -> bool {
        matches!(self, Self::Stdio | Self::Both)
    }
    fn includes_http(self) -> bool {
        matches!(self, Self::Http | Self::Both)
    }
}

/// Dedicated MCP server for BACnet building automation networks.
#[derive(Parser)]
#[command(name = "bacnet-mcp", version, about, long_about = None)]
struct Cli {
    /// Run mode. `daemon` is headless; `tui` opens an interactive operator console.
    #[arg(short = 'm', long, value_enum, default_value_t = RunMode::Daemon)]
    mode: RunMode,

    /// Config file path (JSON).
    #[arg(short, long, default_value = "bacnet-mcp.json")]
    config: String,

    /// MCP transport mode (daemon mode only — ignored when --mode tui).
    #[arg(short, long, value_enum, default_value_t = TransportMode::Stdio)]
    transport: TransportMode,

    /// Override HTTP transport bind address (only valid for http/both transports
    /// in daemon mode, or always in tui mode if HTTP is configured).
    #[arg(long)]
    bind: Option<String>,

    /// API key for bearer-token auth on the HTTP transport.
    /// Falls back to BACNET_MCP_API_KEY env var. No effect on stdio transport.
    #[arg(short = 'k', long)]
    api_key: Option<String>,

    /// Force read-only mode regardless of config.
    #[arg(short, long, conflicts_with = "writes_enabled")]
    read_only: bool,

    /// Force write operations enabled regardless of config. Use with care —
    /// writes to building systems can affect occupants.
    #[arg(long)]
    writes_enabled: bool,

    /// Increase log verbosity (-v info, -vv debug, -vvv trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress all output except errors. Daemon mode only — TUI mode always
    /// captures logs into the in-app log pane regardless.
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,

    /// Log file path. Required when transport includes stdio so logs don't
    /// collide with JSON-RPC framing on stdout. Defaults to stderr otherwise,
    /// or `$TMPDIR/bacnet-mcp-<pid>.log` in tui mode.
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Disable HTTP MCP transport in tui mode (the TUI runs alone with no
    /// outside agentic surface). Ignored in daemon mode.
    #[arg(long)]
    no_http: bool,

    /// Print resolved config and exit.
    #[arg(long)]
    print_config: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let mut config = load_config(&cli.config)?;
    apply_cli_overrides(&mut config, &cli);

    config.validate().map_err(|e| {
        eprintln!("Config validation error: {e}");
        e
    })?;

    if cli.print_config {
        println!("{config:#?}");
        return Ok(());
    }

    match cli.mode {
        RunMode::Daemon => run_daemon(cli, config).await,
        RunMode::Tui => run_tui(cli, config).await,
    }
}

// ─── daemon mode ────────────────────────────────────────────────────────────

async fn run_daemon(cli: Cli, config: GatewayConfig) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing_daemon(&cli)?;

    if cli.transport.includes_http() && resolved_http_bind(&config, &cli).is_none() {
        eprintln!(
            "Error: --transport {:?} requires either --bind or [mcp.http] in config.",
            cli.transport
        );
        std::process::exit(2);
    }

    tracing::info!("Starting bacnet-mcp (daemon mode)");

    let built = GatewayBuilder::new(config.clone())
        .build()
        .await
        .map_err(|e| {
            eprintln!("Failed to build BACnet stack: {e}");
            e
        })?;
    tracing::info!("BACnet server started on MAC {:02x?}", built.server_mac);

    let shutdown = CancellationToken::new();
    // stdio-alone: the daemon was spawned as a child by an MCP client and
    // should exit on stdin close. With HTTP also running, a stdio disconnect
    // must not cascade — HTTP clients keep going.
    let cancel_stdio_on_disconnect = !cli.transport.includes_http();
    let stdio_handle = if cli.transport.includes_stdio() {
        Some(spawn_stdio_server(
            built.state.clone(),
            shutdown.clone(),
            cancel_stdio_on_disconnect,
        ))
    } else {
        None
    };

    let http_handle = if cli.transport.includes_http() {
        let bind = resolved_http_bind(&config, &cli).expect("validated above");
        Some(spawn_http_server(
            built.state.clone(),
            config.mcp.api_key.clone(),
            bind,
            shutdown.clone(),
        )?)
    } else {
        None
    };

    wait_for_shutdown(shutdown.clone()).await;
    tracing::info!("Received shutdown signal — stopping MCP transports");

    if let Some(handle) = stdio_handle {
        let _ = handle.await;
    }
    if let Some(handle) = http_handle {
        let _ = handle.await;
    }

    drop(built);
    Ok(())
}

fn init_tracing_daemon(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let level = log_level(cli);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    if cli.transport.includes_stdio() {
        let path = resolve_log_path(cli);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(file)
            .with_ansi(false)
            .init();
        eprintln!("bacnet-mcp: logging to {}", path.display());
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }
    Ok(())
}

// ─── tui mode ───────────────────────────────────────────────────────────────

async fn run_tui(cli: Cli, mut config: GatewayConfig) -> Result<(), Box<dyn std::error::Error>> {
    // TUI mode forces HTTP-only (or no MCP). Stdio is impossible because the
    // terminal owns stdout. If the user explicitly disabled HTTP, the TUI runs
    // alone with no outside MCP surface.
    let want_http = !cli.no_http;
    if want_http {
        // Reconcile the in-memory config with whatever bind we'll actually
        // listen on (CLI > config > default), so the Observe tab's status
        // panel and `bacnet://state/config` resource report the truth instead
        // of saying HTTP is "not configured" while it's actively listening.
        let bind = resolved_http_bind(&config, &cli).unwrap_or_else(default_http_bind_string);
        config.mcp.http = Some(bacnet_mcp::config::McpHttpConfig { bind });
    } else {
        // Strip mcp.http from the live view so status display matches the
        // operator's `--no-http` intent even if the file still has the block.
        config.mcp.http = None;
    }

    let log_buffer = bacnet_mcp::tui::LogBuffer::default();
    init_tracing_tui(&cli, log_buffer.clone())?;

    let built = GatewayBuilder::new(config.clone())
        .build()
        .await
        .map_err(|e| {
            eprintln!("Failed to build BACnet stack: {e}");
            e
        })?;
    tracing::info!("BACnet server started on MAC {:02x?}", built.server_mac);

    let shutdown = CancellationToken::new();

    let http_handle = if want_http {
        let bind = resolved_http_bind(&config, &cli).expect("set above");
        Some(spawn_http_server(
            built.state.clone(),
            config.mcp.api_key.clone(),
            bind,
            shutdown.clone(),
        )?)
    } else {
        None
    };

    let result = bacnet_mcp::tui::run(
        built.state.clone(),
        config.clone(),
        cli.config.clone(),
        log_buffer,
        want_http,
        shutdown.clone(),
    )
    .await;

    // On detach (F12) the TUI tore down the render loop but left `shutdown`
    // alive so the HTTP MCP server keeps serving. Announce on stderr — now
    // safe because the alternate screen has been left — and wait for an
    // external signal (Ctrl-C / SIGTERM) before joining the HTTP task.
    if matches!(result, Ok(bacnet_mcp::tui::TuiExit::Detached)) {
        announce_detach(&config, &cli);
        wait_for_shutdown(shutdown.clone()).await;
    }

    if let Some(handle) = http_handle {
        let _ = handle.await;
    }
    drop(built);
    result
        .map(|_| ())
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })
}

/// Print the post-detach announcement to stderr. The TUI's alternate screen
/// has just been left, so this lands directly in the operator's shell.
///
/// Includes the PID (for `kill <pid>` later) and the HTTP bind (so it's
/// obvious what's still being served), plus a one-line tmux/disown hint —
/// the original detach plan called out that the operator backgrounds the
/// shell job manually since Option A doesn't double-fork.
fn announce_detach(config: &GatewayConfig, cli: &Cli) {
    let pid = std::process::id();
    let bind = resolved_http_bind(config, cli).unwrap_or_else(default_http_bind_string);
    eprintln!();
    eprintln!("─────────────────────────────────────────────────────────");
    eprintln!(" bacnet-mcp: TUI detached. Daemon still running.");
    eprintln!("   PID:       {pid}");
    eprintln!("   MCP HTTP:  http://{bind}/mcp");
    eprintln!("   Stop:      kill {pid}   (or Ctrl-C in this shell)");
    eprintln!("   Background:  Ctrl-Z; bg; disown");
    eprintln!("─────────────────────────────────────────────────────────");
}

fn init_tracing_tui(
    cli: &Cli,
    log_buffer: bacnet_mcp::tui::LogBuffer,
) -> Result<(), Box<dyn std::error::Error>> {
    // Two destinations:
    //   1. file (with_ansi(false)) for persistence after the TUI exits
    //   2. our LogLayer pushing into the in-memory buffer the Observe tab reads
    let path = resolve_log_path(cli);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file)
        .with_ansi(false);

    let level = log_level(cli);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(bacnet_mcp::tui::LogLayer::new(log_buffer))
        .init();
    Ok(())
}

// ─── shared helpers ─────────────────────────────────────────────────────────

fn log_level(cli: &Cli) -> &'static str {
    if cli.quiet {
        "error"
    } else {
        match cli.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    }
}

fn resolve_log_path(cli: &Cli) -> PathBuf {
    cli.log_file.clone().unwrap_or_else(|| {
        std::env::temp_dir().join(format!("bacnet-mcp-{}.log", std::process::id()))
    })
}

fn load_config(path: &str) -> Result<GatewayConfig, Box<dyn std::error::Error>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("Config file '{path}' not found.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error reading config file '{path}': {e}");
            std::process::exit(1);
        }
    };
    Ok(GatewayConfig::from_json(&text)?)
}

fn apply_cli_overrides(config: &mut GatewayConfig, cli: &Cli) {
    if let Some(bind) = &cli.bind {
        let http = config.mcp.http.get_or_insert_with(Default::default);
        http.bind = bind.clone();
    }
    if let Some(key) = &cli.api_key {
        config.mcp.api_key = Some(key.clone());
    }
    if config.mcp.api_key.is_none()
        && let Ok(key) = std::env::var("BACNET_MCP_API_KEY")
    {
        config.mcp.api_key = Some(key);
    }
    if cli.read_only {
        config.mcp.read_only = true;
    } else if cli.writes_enabled {
        config.mcp.read_only = false;
    }
}

fn resolved_http_bind(config: &GatewayConfig, cli: &Cli) -> Option<String> {
    cli.bind
        .clone()
        .or_else(|| config.mcp.http.as_ref().map(|h| h.bind.clone()))
}

fn default_http_bind_string() -> String {
    bacnet_mcp::config::McpHttpConfig::default().bind
}

/// Spawn the stdio MCP transport.
///
/// `cancel_on_disconnect` controls whether the global shutdown is triggered
/// when the stdio peer disconnects. For `--transport stdio` (alone) this is
/// `true` — the daemon was spawned by a parent process and should exit when
/// stdin closes. For `--transport both` it's `false` — a transient stdio peer
/// disconnect must not tear down the HTTP transport that other clients use.
/// Startup errors always cascade.
fn spawn_stdio_server(
    state: bacnet_mcp::state::GatewayState,
    shutdown: CancellationToken,
    cancel_on_disconnect: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("MCP stdio transport: ready");
        match GatewayMcp::new(state)
            .serve(rmcp::transport::io::stdio())
            .await
        {
            Ok(server) => {
                tokio::select! {
                    _ = server.waiting() => {
                        tracing::info!("MCP stdio peer disconnected");
                        if cancel_on_disconnect {
                            shutdown.cancel();
                        }
                    }
                    _ = shutdown.cancelled() => {
                        tracing::info!("MCP stdio: shutdown requested");
                    }
                }
            }
            Err(e) => {
                tracing::error!("MCP stdio failed to start: {e}");
                // Startup failure always cascades — the daemon can't run as
                // configured and should exit so the operator notices.
                shutdown.cancel();
            }
        }
    })
}

fn spawn_http_server(
    state: bacnet_mcp::state::GatewayState,
    api_key: Option<String>,
    bind: String,
    shutdown: CancellationToken,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let bind_addr: SocketAddr = bind
        .parse()
        .map_err(|e| format!("invalid HTTP bind '{bind}': {e}"))?;

    let mcp_state = state.clone();
    let svc = StreamableHttpService::new(
        move || Ok(GatewayMcp::new(mcp_state.clone())),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    );

    let mut router = Router::new().nest_service("/mcp", svc);
    if let Some(key) = api_key {
        let auth = Arc::new(BearerTokenAuth::new(key));
        router = router.layer(middleware::from_fn(move |req: Request, next: Next| {
            let auth = auth.clone();
            async move {
                match auth.authenticate(req.headers()) {
                    Ok(()) => next.run(req).await,
                    Err(e) => (
                        e.status,
                        axum::Json(serde_json::json!({ "error": e.message })),
                    )
                        .into_response(),
                }
            }
        }));
    }

    let shutdown_for_serve = shutdown.clone();
    Ok(tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("MCP HTTP failed to bind {bind_addr}: {e}");
                shutdown_for_serve.cancel();
                return;
            }
        };
        tracing::info!("MCP streamable-HTTP transport: listening on {bind_addr}/mcp");
        let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
            shutdown_for_serve.cancelled().await;
        });
        if let Err(e) = serve.await {
            tracing::error!("MCP HTTP serve error: {e}");
        }
        shutdown.cancel();
    }))
}

async fn wait_for_shutdown(shutdown: CancellationToken) {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
            _ = shutdown.cancelled() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = ctrl_c => {},
            _ = shutdown.cancelled() => {},
        }
    }
    shutdown.cancel();
}
