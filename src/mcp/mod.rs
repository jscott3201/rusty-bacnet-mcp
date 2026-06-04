//! MCP (Model Context Protocol) server implementation.
//!
//! Exposes BACnet operations as MCP tools and network state as MCP resources.

pub mod alarms;
pub mod bulk;
pub mod cov;
pub mod diagnostics;
pub mod discovery;
pub mod files;
pub mod objects;
pub mod pcap_tools;
pub mod points;
pub mod properties;
pub mod reference;
pub mod schedule_write;
pub mod schedules;
pub mod topology;
pub mod trend;
pub(crate) mod value_format;
pub mod wire;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::ErrorData as McpError;
use rmcp::model::ResourceContents;
use rmcp::model::{
    ListResourceTemplatesResult, ListResourcesResult, PaginatedRequestParams,
    ReadResourceRequestParams, ReadResourceResult, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler, tool, tool_handler, tool_router};

use crate::config::describe_sc_runtime;
use crate::state::GatewayState;

/// MCP server handler for the BACnet gateway.
#[derive(Clone)]
pub struct GatewayMcp {
    pub state: GatewayState,
    // Used internally by the rmcp-generated `#[tool_handler]` impl; the
    // dead-code analyzer can't trace through the macro expansion.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl GatewayMcp {
    pub fn new(state: GatewayState) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    // --- Discovery tools ---

    #[tool(description = "Manually add a BACnet device by B/IP ip:port or BACnet/SC VMAC.")]
    async fn register_device(
        &self,
        params: Parameters<discovery::RegisterDeviceParams>,
    ) -> Result<String, String> {
        discovery::register_device_impl(&self.state, params.0).await
    }

    #[tool(description = "Broadcast WhoIs and return bounded IAm device results.")]
    async fn discover_devices(
        &self,
        params: Parameters<discovery::DiscoverParams>,
    ) -> Result<String, String> {
        discovery::discover_devices_impl(&self.state, params.0).await
    }

    #[tool(description = "List bounded cached devices without network traffic.")]
    async fn list_known_devices(
        &self,
        params: Parameters<discovery::ListKnownDevicesParams>,
    ) -> Result<String, String> {
        discovery::list_known_devices_impl(&self.state, params.0).await
    }

    #[tool(description = "Read common Device object identity properties for one device.")]
    async fn get_device_info(
        &self,
        params: Parameters<discovery::DeviceInfoParams>,
    ) -> Result<String, String> {
        discovery::get_device_info_impl(&self.state, params.0).await
    }

    // --- Property tools ---

    #[tool(description = "Read one compact property value from a discovered remote device.")]
    async fn read_property(
        &self,
        params: Parameters<properties::ReadPropertyParams>,
    ) -> Result<String, String> {
        properties::read_property_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Safety-gated remote WriteProperty; use dry_run to validate and audit only."
    )]
    async fn write_property(
        &self,
        params: Parameters<properties::WritePropertyParams>,
    ) -> Result<String, String> {
        properties::write_property_impl(&self.state, params.0).await
    }

    #[tool(description = "Safety-gated remote WritePropertyMultiple batch; use dry_run first.")]
    async fn write_property_multiple(
        &self,
        params: Parameters<properties::WritePropertyMultipleParams>,
    ) -> Result<String, String> {
        properties::write_property_multiple_impl(&self.state, params.0).await
    }

    #[tool(description = "Safety-gated write of NULL to release one command priority slot.")]
    async fn relinquish_at_priority(
        &self,
        params: Parameters<properties::RelinquishParams>,
    ) -> Result<String, String> {
        properties::relinquish_at_priority_impl(&self.state, params.0).await
    }

    // --- Bulk read tools (RPM-backed) ---

    #[tool(
        description = "Read many properties in one compact RPM request; detailed mode available."
    )]
    async fn read_property_multiple(
        &self,
        params: Parameters<bulk::ReadPropertyMultipleParams>,
    ) -> Result<String, String> {
        bulk::read_property_multiple_impl(&self.state, params.0).await
    }

    #[tool(description = "Read compact value and health lines for selected points.")]
    async fn read_point_summary(
        &self,
        params: Parameters<points::ReadPointSummaryParams>,
    ) -> Result<String, String> {
        points::read_point_summary_impl(&self.state, params.0).await
    }

    #[tool(description = "Read a bounded chunk from a remote File object.")]
    async fn read_file_chunk(
        &self,
        params: Parameters<files::ReadFileChunkParams>,
    ) -> Result<String, String> {
        files::read_file_chunk_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Read present-value, priority-array, and relinquish-default for one object."
    )]
    async fn read_priority_array(
        &self,
        params: Parameters<bulk::ReadPriorityArrayParams>,
    ) -> Result<String, String> {
        bulk::read_priority_array_impl(&self.state, params.0).await
    }

    #[tool(description = "List grouped object identifiers; optionally fetch object names.")]
    async fn enumerate_objects(
        &self,
        params: Parameters<bulk::EnumerateObjectsParams>,
    ) -> Result<String, String> {
        bulk::enumerate_objects_impl(&self.state, params.0).await
    }

    #[tool(description = "Read a remote device capability profile for service planning.")]
    async fn get_device_capabilities(
        &self,
        params: Parameters<bulk::DeviceCapabilitiesParams>,
    ) -> Result<String, String> {
        bulk::get_device_capabilities_impl(&self.state, params.0).await
    }

    // --- COV tools ---

    #[tool(description = "Subscribe to COV updates; dry-run audits without subscribing.")]
    async fn subscribe_cov(
        &self,
        params: Parameters<cov::SubscribeCovParams>,
    ) -> Result<String, String> {
        cov::subscribe_cov_impl(&self.state, params.0).await
    }

    #[tool(description = "Cancel a COV subscription by object and process id.")]
    async fn unsubscribe_cov(
        &self,
        params: Parameters<cov::UnsubscribeCovParams>,
    ) -> Result<String, String> {
        cov::unsubscribe_cov_impl(&self.state, params.0).await
    }

    #[tool(description = "Drain queued COV notifications with a bounded result size.")]
    async fn poll_cov_notifications(
        &self,
        params: Parameters<cov::PollCovNotificationsParams>,
    ) -> Result<String, String> {
        cov::poll_cov_notifications_impl(&self.state, params.0).await
    }

    // --- Alarm + event tools ---

    #[tool(description = "List active alarms with object, state, and acked transitions.")]
    async fn get_alarm_summary(
        &self,
        params: Parameters<alarms::AlarmSummaryParams>,
    ) -> Result<String, String> {
        alarms::get_alarm_summary_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Read active event metadata, transition times, priorities, and paging state."
    )]
    async fn get_event_information(
        &self,
        params: Parameters<alarms::EventInformationParams>,
    ) -> Result<String, String> {
        alarms::get_event_information_impl(&self.state, params.0).await
    }

    #[tool(description = "Safety-gated alarm/event acknowledgement; use dry_run to validate.")]
    async fn acknowledge_alarm(
        &self,
        params: Parameters<alarms::AcknowledgeAlarmParams>,
    ) -> Result<String, String> {
        alarms::acknowledge_alarm_impl(&self.state, params.0).await
    }

    // --- Schedule tools ---

    #[tool(description = "Read scalar metadata from one Schedule object.")]
    async fn read_schedule(
        &self,
        params: Parameters<schedules::ReadScheduleParams>,
    ) -> Result<String, String> {
        schedules::read_schedule_impl(&self.state, params.0).await
    }

    #[tool(description = "Read a Schedule weekly-schedule array as decoded time/value entries.")]
    async fn read_schedule_weekly(
        &self,
        params: Parameters<schedules::ReadScheduleWeeklyParams>,
    ) -> Result<String, String> {
        schedules::read_schedule_weekly_impl(&self.state, params.0).await
    }

    #[tool(description = "Read a Schedule exception-schedule list as decoded special events.")]
    async fn read_schedule_exceptions(
        &self,
        params: Parameters<schedules::ReadScheduleExceptionsParams>,
    ) -> Result<String, String> {
        schedules::read_schedule_exceptions_impl(&self.state, params.0).await
    }

    #[tool(description = "Safety-gated whole-array replacement for a Schedule weekly-schedule.")]
    async fn write_schedule_weekly(
        &self,
        params: Parameters<schedule_write::WriteScheduleWeeklyParams>,
    ) -> Result<String, String> {
        schedule_write::write_schedule_weekly_impl(&self.state, params.0).await
    }

    #[tool(description = "Safety-gated whole-list replacement for a Schedule exception-schedule.")]
    async fn write_schedule_exceptions(
        &self,
        params: Parameters<schedule_write::WriteScheduleExceptionsParams>,
    ) -> Result<String, String> {
        schedule_write::write_schedule_exceptions_impl(&self.state, params.0).await
    }

    // --- Trend log tools (ReadRange-backed) ---

    #[tool(description = "Read TrendLog metadata needed before choosing a log-buffer window.")]
    async fn get_trend_log_info(
        &self,
        params: Parameters<trend::TrendLogInfoParams>,
    ) -> Result<String, String> {
        trend::get_trend_log_info_impl(&self.state, params.0).await
    }

    #[tool(description = "Read a TrendLog log-buffer window by position, sequence, or time.")]
    async fn read_trend_log(
        &self,
        params: Parameters<trend::ReadTrendLogParams>,
    ) -> Result<String, String> {
        trend::read_trend_log_impl(&self.state, params.0).await
    }

    // --- Diagnostic tools ---

    #[tool(description = "Measure BACnet round-trip reachability with Device.system-status reads.")]
    async fn ping_device(
        &self,
        params: Parameters<diagnostics::PingDeviceParams>,
    ) -> Result<String, String> {
        diagnostics::ping_device_impl(&self.state, params.0).await
    }

    #[tool(description = "Read a BACnet/IP BBMD's BDT and FDT tables by IP:port.")]
    async fn probe_bbmd(
        &self,
        params: Parameters<diagnostics::ProbeBbmdParams>,
    ) -> Result<String, String> {
        diagnostics::probe_bbmd_impl(&self.state, params.0).await
    }

    #[tool(description = "Decode one BACnet/IP payload or pcap frame into compact wire layers.")]
    async fn analyze_bacnet_ip_packet(
        &self,
        params: Parameters<wire::AnalyzeBacnetIpPacketParams>,
    ) -> Result<String, String> {
        wire::analyze_bacnet_ip_packet_impl(params.0)
    }

    #[tool(description = "List pcap capture interfaces if feature enabled.")]
    async fn list_pcap_interfaces(
        &self,
        params: Parameters<pcap_tools::ListPcapInterfacesParams>,
    ) -> Result<String, String> {
        pcap_tools::list_pcap_interfaces_impl(params.0)
    }

    #[tool(description = "Analyze an offline pcap file for BACnet/IP traffic.")]
    async fn analyze_pcap_file(
        &self,
        params: Parameters<pcap_tools::AnalyzePcapFileParams>,
    ) -> Result<String, String> {
        pcap_tools::analyze_pcap_file_impl(params.0)
    }

    // --- Local object tools ---

    #[tool(description = "List bounded gateway-local BACnet objects, optionally filtered by type.")]
    async fn list_local_objects(
        &self,
        params: Parameters<objects::ListObjectsParams>,
    ) -> Result<String, String> {
        objects::list_local_objects_impl(&self.state, params.0).await
    }

    #[tool(description = "Read one property from a gateway-local object.")]
    async fn read_local_property(
        &self,
        params: Parameters<objects::ReadLocalPropertyParams>,
    ) -> Result<String, String> {
        objects::read_local_property_impl(&self.state, params.0).await
    }

    #[tool(description = "Safety-gated write to a gateway-local object property.")]
    async fn write_local_property(
        &self,
        params: Parameters<objects::WriteLocalPropertyParams>,
    ) -> Result<String, String> {
        objects::write_local_property_impl(&self.state, params.0).await
    }

    #[tool(description = "Create an analog, binary, multi-state, or value object locally.")]
    async fn create_local_object(
        &self,
        params: Parameters<objects::CreateLocalObjectParams>,
    ) -> Result<String, String> {
        objects::create_local_object_impl(&self.state, params.0).await
    }

    #[tool(description = "Delete a gateway-local object; the Device object is protected.")]
    async fn delete_local_object(
        &self,
        params: Parameters<objects::DeleteLocalObjectParams>,
    ) -> Result<String, String> {
        objects::delete_local_object_impl(&self.state, params.0).await
    }
}

impl GatewayMcp {
    async fn read_state_resource(&self, uri: &str) -> Option<String> {
        match uri {
            "bacnet://state/devices" => {
                let text = match self.state.require_client() {
                    Ok(client) => {
                        let devices = client.discovered_devices().await;
                        if devices.is_empty() {
                            "No discovered devices.".to_string()
                        } else {
                            discovery::format_device_list(
                                devices,
                                discovery::DEFAULT_DEVICE_LIST_LIMIT,
                                discovery::DeviceListFormat::StateResource,
                            )
                        }
                    }
                    Err(_) => "No devices (client not started).".to_string(),
                };
                Some(text)
            }
            "bacnet://state/local-objects" => {
                let db = self.state.db.read().await;
                let rows = objects::collect_local_object_rows(&db, None);
                Some(objects::format_local_object_rows(
                    &rows,
                    objects::DEFAULT_LIST_LOCAL_OBJECTS_LIMIT,
                    objects::LocalObjectListFormat::StateResource,
                ))
            }
            "bacnet://audit/recent" => {
                // Last 100 entries by default. Truncate to keep the resource
                // readable; bigger windows fetch via the JSON-Lines file
                // (mcp.audit.path) once the operator wires one up.
                let entries = self.state.audit.snapshot(100);
                let mut out = format!(
                    "{} audit entr{} (most recent last):\n",
                    entries.len(),
                    if entries.len() == 1 { "y" } else { "ies" }
                );
                for e in &entries {
                    out.push_str(&format_audit_line(e));
                }
                Some(out)
            }
            "bacnet://state/config" => {
                let config = &self.state.config;
                let mut result = String::new();
                result.push_str(&format!(
                    "Device: {} (instance {})\n",
                    config.device.name, config.device.instance
                ));
                // Read mode from the live RuntimeFlags atomic, not the frozen
                // startup config — TUI hot-reload of mcp.read_only is reflected
                // here so MCP clients can trust this resource for safety state.
                result.push_str(&format!(
                    "Mode: {}\n",
                    if self.state.is_read_only() {
                        "read-only"
                    } else {
                        "writable"
                    }
                ));
                if let Some(http) = &config.mcp.http {
                    result.push_str(&format!("HTTP transport bind: {}\n", http.bind));
                }
                result.push_str(&format!(
                    "Auth: {}\n",
                    if config.mcp.api_key.is_some() {
                        "enabled (bearer token)"
                    } else {
                        "disabled"
                    }
                ));
                if let Some(bip) = &config.transports.bip {
                    result.push_str(&format!(
                        "Transport BIP: {}:{}, network {}\n",
                        bip.interface, bip.port, bip.network_number
                    ));
                }
                if let Some(sc) = &config.transports.sc {
                    result.push_str(&format!(
                        "Transport SC: {}, network {}\n",
                        describe_sc_runtime(sc),
                        sc.network_number
                    ));
                }
                Some(result)
            }
            "bacnet://topology/graph" => {
                let graph = topology::build_graph(&self.state).await;
                // serde_json::to_string_pretty so a human reading the
                // resource directly (TUI, curl, debug) sees readable
                // structure. Agents using a JSON parser don't care about
                // whitespace; pretty-printing is universally OK here.
                Some(
                    serde_json::to_string_pretty(&graph)
                        .unwrap_or_else(|e| format!("{{\"error\": \"serialize topology: {e}\"}}")),
                )
            }
            _ => None,
        }
    }
}

#[tool_handler]
impl ServerHandler for GatewayMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_instructions(
            "BACnet gateway MCP server. Use tools to discover devices, read/write properties, \
             and manage the local object database. Read reference resources \
             (bacnet://reference/*) to learn about BACnet object types, properties, \
             networking, and troubleshooting."
                .to_string(),
        )
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, McpError>> + Send + '_ {
        let mut resources = reference::reference_resources();
        resources.extend(reference::state_resources());
        std::future::ready(Ok(ListResourcesResult {
            resources,
            next_cursor: None,
            meta: None,
        }))
    }

    fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourceTemplatesResult, McpError>> + Send + '_
    {
        let templates = reference::reference_templates();
        std::future::ready(Ok(ListResourceTemplatesResult {
            resource_templates: templates,
            next_cursor: None,
            meta: None,
        }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResult, McpError>> + Send + '_ {
        let uri = request.uri;
        async move {
            // Try static reference resources first.
            if let Some(text) = reference::read_reference(&uri) {
                return Ok(ReadResourceResult::new(vec![ResourceContents::text(
                    text,
                    uri.clone(),
                )]));
            }

            // Try live state resources (async — may read from client/db).
            if let Some(text) = self.read_state_resource(&uri).await {
                return Ok(ReadResourceResult::new(vec![ResourceContents::text(
                    text,
                    uri.clone(),
                )]));
            }

            Err(McpError::resource_not_found(
                "resource not found",
                Some(serde_json::json!({ "uri": uri })),
            ))
        }
    }
}

/// Render one audit entry as a single line for the `bacnet://audit/recent`
/// resource. Format is human-readable and stable enough to grep:
/// `<iso-timestamp> <decision> <tool> <target> <property> [pri=N] [dry-run] reason`
fn format_audit_line(e: &crate::audit::AuditEntry) -> String {
    let secs = (e.at_ms / 1000) as i64;
    let ms = (e.at_ms % 1000) as u32;
    // Best-effort RFC3339-ish stamp without pulling chrono in. The number is
    // already epoch-millis so anyone who needs a real timestamp can reparse.
    let ts = format!("epoch+{secs}.{ms:03}");

    let target = e.target.as_deref().unwrap_or("-");
    let property = e.property.as_deref().unwrap_or("-");
    let pri = e.priority.map(|p| format!(" pri={p}")).unwrap_or_default();
    let dry = if e.dry_run { " dry-run" } else { "" };
    let reason = if e.reason.is_empty() {
        String::new()
    } else {
        format!(" — {}", e.reason)
    };
    format!(
        "  {ts} {decision:>5} {tool} {target} {property}{pri}{dry}{reason}\n",
        decision = e.decision,
        tool = e.tool,
    )
}
