//! MCP (Model Context Protocol) server implementation.
//!
//! Exposes BACnet operations as MCP tools and network state as MCP resources.

pub mod alarms;
pub mod bulk;
pub mod diagnostics;
pub mod discovery;
pub mod objects;
pub mod properties;
pub mod reference;
pub mod schedule_write;
pub mod schedules;
pub mod topology;
pub mod trend;

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

    #[tool(
        description = "Manually register a remote BACnet device by instance and IP:port address, without requiring WhoIs/IAm discovery."
    )]
    async fn register_device(
        &self,
        params: Parameters<discovery::RegisterDeviceParams>,
    ) -> Result<String, String> {
        discovery::register_device_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Discover BACnet devices on the network by sending a WhoIs broadcast. Returns a list of devices that respond with IAm."
    )]
    async fn discover_devices(
        &self,
        params: Parameters<discovery::DiscoverParams>,
    ) -> Result<String, String> {
        discovery::discover_devices_impl(&self.state, params.0).await
    }

    #[tool(
        description = "List all previously discovered BACnet devices from the device table. No network traffic is generated."
    )]
    async fn list_known_devices(&self) -> Result<String, String> {
        discovery::list_known_devices_impl(&self.state).await
    }

    #[tool(
        description = "Get detailed information about a specific BACnet device by reading its Device object properties (name, vendor, model, firmware, etc.)."
    )]
    async fn get_device_info(
        &self,
        params: Parameters<discovery::DeviceInfoParams>,
    ) -> Result<String, String> {
        discovery::get_device_info_impl(&self.state, params.0).await
    }

    // --- Property tools ---

    #[tool(
        description = "Read a property from a remote BACnet device. Specify the device instance, object type and instance, and property name."
    )]
    async fn read_property(
        &self,
        params: Parameters<properties::ReadPropertyParams>,
    ) -> Result<String, String> {
        properties::read_property_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Write a value to a property on a remote BACnet device. Pass `dry_run: true` to validate against the gateway's safety policy and write an audit entry without sending the WriteProperty APDU. The layered policy enforces object-type allow/deny lists, per-object lists, and a priority floor (default 9 — priorities 1–8 are reserved for life-safety per ASHRAE 135-2020)."
    )]
    async fn write_property(
        &self,
        params: Parameters<properties::WritePropertyParams>,
    ) -> Result<String, String> {
        properties::write_property_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Release a priority slot on a commandable BACnet object by writing NULL at that priority. The object falls back to the next-highest active priority — or to relinquish-default if no other slots are taken. Subject to the same safety policy as write_property."
    )]
    async fn relinquish_at_priority(
        &self,
        params: Parameters<properties::RelinquishParams>,
    ) -> Result<String, String> {
        properties::relinquish_at_priority_impl(&self.state, params.0).await
    }

    // --- Bulk read tools (RPM-backed) ---

    #[tool(
        description = "Read multiple properties from one or more objects on a remote BACnet device in a single round-trip via ReadPropertyMultiple. Cuts latency 5–10× over sequential read_property calls and is the primary tool for bulk discovery, override audits, and rich object snapshots. Use 'all' / 'required' / 'optional' as the property name to fetch every property the device exposes for that object."
    )]
    async fn read_property_multiple(
        &self,
        params: Parameters<bulk::ReadPropertyMultipleParams>,
    ) -> Result<String, String> {
        bulk::read_property_multiple_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Read the 16-slot priority array, present-value, and relinquish-default for a commandable BACnet object in one round-trip. Identifies the highest active priority slot — answers 'who is overriding this point?' which is the central question for override audits and remediation workflows."
    )]
    async fn read_priority_array(
        &self,
        params: Parameters<bulk::ReadPriorityArrayParams>,
    ) -> Result<String, String> {
        bulk::read_priority_array_impl(&self.state, params.0).await
    }

    #[tool(
        description = "List every BACnet object on a remote device with its identifier and object-name, by reading Device.object_list and then chunked object-name reads via RPM. Returns up to `limit` objects (default 500, hard cap 5000). Useful as the first step in any whole-device audit or schema-aware tool flow."
    )]
    async fn enumerate_objects(
        &self,
        params: Parameters<bulk::EnumerateObjectsParams>,
    ) -> Result<String, String> {
        bulk::enumerate_objects_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Read a remote device's capability profile in one RPM round-trip: vendor info, firmware/protocol revisions, max APDU, segmentation support, services-supported bitstring, object-types-supported bitstring. Lets an agent reason about which BACnet services and object types are actually available before it tries to call them."
    )]
    async fn get_device_capabilities(
        &self,
        params: Parameters<bulk::DeviceCapabilitiesParams>,
    ) -> Result<String, String> {
        bulk::get_device_capabilities_impl(&self.state, params.0).await
    }

    // --- Alarm + event tools ---

    #[tool(
        description = "List active alarms on a remote device via the BACnet GetAlarmSummary service (ASHRAE 135-2020 Clause 13.7). Returns one line per alarm: object identifier, alarm state, and which transitions have already been acknowledged. Read-only. Use this as the cheap first call when triaging incidents; switch to get_event_information for richer per-event metadata."
    )]
    async fn get_alarm_summary(
        &self,
        params: Parameters<alarms::AlarmSummaryParams>,
    ) -> Result<String, String> {
        alarms::get_alarm_summary_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Read active events on a remote device via GetEventInformation (Clause 13.10). Modern replacement for GetAlarmSummary — returns timestamps for each transition (off-normal, fault, normal), notify type, event-enable bits, per-transition priorities, and notification class. Pass `after: 'type:instance'` to page when the device's response sets more_events. Read-only."
    )]
    async fn get_event_information(
        &self,
        params: Parameters<alarms::EventInformationParams>,
    ) -> Result<String, String> {
        alarms::get_event_information_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Acknowledge a pending event transition on a remote device (Clause 13.6). Pass the event's object identifier, the EventState being acked (raw enumerated: 0=normal, 1=fault, 2=offnormal, ...), and a free-text source identifier. Goes through the gateway's safety policy and audit log the same way write_property does. Pass `dry_run: true` to validate without sending the APDU."
    )]
    async fn acknowledge_alarm(
        &self,
        params: Parameters<alarms::AcknowledgeAlarmParams>,
    ) -> Result<String, String> {
        alarms::acknowledge_alarm_impl(&self.state, params.0).await
    }

    // --- Schedule tools ---

    #[tool(
        description = "Read scalar metadata from a BACnet Schedule object in one RPM round-trip: object-name, present-value, schedule-default, effective-period, list-of-object-property-references (what this schedule writes to), status flags, reliability. Read-only. Use read_schedule_weekly and read_schedule_exceptions for the weekly-schedule and exception-schedule arrays — those are kept off this RPM so a populated array can't blow Max-APDU on small devices and take down the scalar fetch."
    )]
    async fn read_schedule(
        &self,
        params: Parameters<schedules::ReadScheduleParams>,
    ) -> Result<String, String> {
        schedules::read_schedule_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Read the weekly-schedule property of a BACnet Schedule object — a 7-element array (Mon..Sun) of (time, value) pairs that fire each day. Single ReadProperty so a populated array can't take down a bundled scalar fetch. Values are decoded via bacnet-services 0.9 codecs; the polymorphic value field of each time-value pair is rendered through the same decoder used for scalar property values."
    )]
    async fn read_schedule_weekly(
        &self,
        params: Parameters<schedules::ReadScheduleWeeklyParams>,
    ) -> Result<String, String> {
        schedules::read_schedule_weekly_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Read the exception-schedule property of a BACnet Schedule object — a list of special events, each defining a period (specific date, date range, week-and-day pattern, or calendar-object reference), its own (time, value) entries, and a priority for conflict resolution against the weekly schedule. Single ReadProperty. Decoded via bacnet-services 0.9 codecs."
    )]
    async fn read_schedule_exceptions(
        &self,
        params: Parameters<schedules::ReadScheduleExceptionsParams>,
    ) -> Result<String, String> {
        schedules::read_schedule_exceptions_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Replace the entire weekly-schedule of a BACnet Schedule object atomically. Takes 7 lists (Mon..Sun) of (time, value) entries. Values use tagged JSON: {\"real\": 72.0}, {\"boolean\": true}, {\"unsigned\": 3}, or {\"null\": null}. Times are 'HH:MM' or 'HH:MM:SS'. Whole-array replacement matches the WriteProperty semantics for this property — there's no per-element write in the spec. Routes through the same safety policy + audit log as write_property. Pass dry_run: true to validate without sending. v1 limitation: only Real / Boolean / Unsigned / Null value types (other primitives v2)."
    )]
    async fn write_schedule_weekly(
        &self,
        params: Parameters<schedule_write::WriteScheduleWeeklyParams>,
    ) -> Result<String, String> {
        schedule_write::write_schedule_weekly_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Replace the entire exception-schedule of a BACnet Schedule object atomically. Each event has a period (tagged: {\"date\": \"YYYY-MM-DD\"} optionally with '-Mon..-Sun' suffix, or {\"week_n_day\": \"month/week/dow\"} pattern matching format_week_n_day output), a list of time-values, and a priority 1..=16 for conflict resolution against the weekly schedule. Whole-list replacement (WriteProperty semantics). Routes through write_property's safety policy + audit log. Pass dry_run: true to validate without sending. v1 limitations: only Date and WeekNDay periods (DateRange / CalendarReference v2); only Real / Boolean / Unsigned / Null value types; only concrete dates (sentinel month/day patterns v2)."
    )]
    async fn write_schedule_exceptions(
        &self,
        params: Parameters<schedule_write::WriteScheduleExceptionsParams>,
    ) -> Result<String, String> {
        schedule_write::write_schedule_exceptions_impl(&self.state, params.0).await
    }

    // --- Trend log tools (ReadRange-backed) ---

    #[tool(
        description = "Read TrendLog metadata in one RPM round-trip: object-name, log-enable, log-interval, buffer-size, record-count, total-record-count, log-device-object-property (the source the trend is sampling), start/stop time, logging-type, status flags, event state. Use this before calling read_trend_log to know how many records exist and how to range-select them."
    )]
    async fn get_trend_log_info(
        &self,
        params: Parameters<trend::TrendLogInfoParams>,
    ) -> Result<String, String> {
        trend::get_trend_log_info_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Read a window of records from a TrendLog's log-buffer via the BACnet ReadRange service. Three range modes per ASHRAE 135-2020 Clause 15.8: 'by_position' (1-based array index), 'by_sequence' (sequence number), 'by_time' ('YYYY-MM-DD HH:MM:SS'). `count` is signed — positive reads forward, negative reads backward. Records are decoded into timestamp + value + optional status flags."
    )]
    async fn read_trend_log(
        &self,
        params: Parameters<trend::ReadTrendLogParams>,
    ) -> Result<String, String> {
        trend::read_trend_log_impl(&self.state, params.0).await
    }

    // --- Diagnostic tools ---

    #[tool(
        description = "Ping a remote BACnet device by issuing one or more confirmed ReadProperty(Device, system-status) round-trips and reporting per-attempt latency plus min/avg/max/loss summary. The BACnet equivalent of ping(8): exercises the full TSM + transport path so a successful response confirms the device is reachable as a BACnet peer, not just IP-reachable. Read-only. count default 1, max 10; timeout_seconds default uses the client's apdu_timeout, max 30; interval_ms default 0, max 5000."
    )]
    async fn ping_device(
        &self,
        params: Parameters<diagnostics::PingDeviceParams>,
    ) -> Result<String, String> {
        diagnostics::ping_device_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Probe a BACnet/IP BBMD by reading its Broadcast Distribution Table and Foreign Device Table (Annex J). Returns the BDT (peer BBMDs this BBMD forwards broadcasts to, with broadcast masks) and the FDT (foreign devices registered with this BBMD, with TTL and remaining lifetime). The two reads run concurrently. Read-only. Target is `ip:port` since BBMDs are routing infrastructure addressed by IP, not BACnet device instance. timeout_seconds default uses the transport's internal value, max 30."
    )]
    async fn probe_bbmd(
        &self,
        params: Parameters<diagnostics::ProbeBbmdParams>,
    ) -> Result<String, String> {
        diagnostics::probe_bbmd_impl(&self.state, params.0).await
    }

    // --- Local object tools ---

    #[tool(
        description = "List objects in the gateway's local BACnet object database. Optionally filter by object type."
    )]
    async fn list_local_objects(
        &self,
        params: Parameters<objects::ListObjectsParams>,
    ) -> Result<String, String> {
        objects::list_local_objects_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Read a property from the gateway's local object database. No network traffic."
    )]
    async fn read_local_property(
        &self,
        params: Parameters<objects::ReadLocalPropertyParams>,
    ) -> Result<String, String> {
        objects::read_local_property_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Write a value to a property in the gateway's local object database. No network traffic."
    )]
    async fn write_local_property(
        &self,
        params: Parameters<objects::WriteLocalPropertyParams>,
    ) -> Result<String, String> {
        objects::write_local_property_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Create a new object in the gateway's local BACnet database. Supports analog, binary, multi-state, and value types."
    )]
    async fn create_local_object(
        &self,
        params: Parameters<objects::CreateLocalObjectParams>,
    ) -> Result<String, String> {
        objects::create_local_object_impl(&self.state, params.0).await
    }

    #[tool(
        description = "Delete an object from the gateway's local BACnet database. Cannot delete the Device object."
    )]
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
                            let mut result = format!("{} discovered device(s):\n", devices.len());
                            for dev in &devices {
                                result.push_str(&format!(
                                    "  Instance {}, vendor {}, MAC {:02x?}\n",
                                    dev.object_identifier.instance_number(),
                                    dev.vendor_id,
                                    dev.mac_address.as_slice(),
                                ));
                            }
                            result
                        }
                    }
                    Err(_) => "No devices (client not started).".to_string(),
                };
                Some(text)
            }
            "bacnet://state/local-objects" => {
                let db = self.state.db.read().await;
                let mut result = format!("{} local object(s):\n", db.len());
                for (oid, obj) in db.iter_objects() {
                    result.push_str(&format!(
                        "  {}:{} \"{}\"\n",
                        crate::parse::object_type_name(oid.object_type()),
                        oid.instance_number(),
                        obj.object_name(),
                    ));
                }
                Some(result)
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
                    let role = match (sc.listen.as_deref(), sc.hub_uri.as_deref()) {
                        (Some(addr), _) => format!("Hub listening on {addr}"),
                        (_, Some(uri)) => format!("Node connected to {uri}"),
                        _ => "(unconfigured)".to_string(),
                    };
                    result.push_str(&format!(
                        "Transport SC: {}, network {}\n",
                        role, sc.network_number
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
