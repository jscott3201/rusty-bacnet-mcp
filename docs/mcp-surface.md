# MCP Surface

`bacnet-mcp` exposes BACnet operations as MCP tools plus state/reference data as
MCP resources. The surface is optimized for agents: tools validate early,
outputs default compact, list-like responses are bounded, and resources include
BACnet reference material so callers do not need prior protocol context.

## Recommended Flow

1. Read `bacnet://reference/tool-guide`.
2. Discover or register a device.
3. Read `get_device_capabilities` before broad reads on unknown devices.
4. Prefer `read_point_summary` or `read_property_multiple` for snapshots.
5. Use `read_property` for one-off detail.
6. Use `response_mode: "detailed"` only when compact output hides data you need.

## Discovery

- `register_device`: manually add a known device.
- `discover_devices`: send WhoIs and return bounded IAm rows.
- `list_known_devices`: read the cached device table without network traffic.
- `get_device_info`: read common Device object identity properties.

Address format depends on the active BACnet transport:

- B/IP: `192.168.1.20:47808`
- BACnet/SC: `02:00:00:00:00:10`

`discover_devices` and `list_known_devices` default to the first 500 rows and
accept `limit` up to 5000. Omission markers report when rows were skipped.

## Reads

- `read_property`: one compact property value.
- `read_property_multiple`: many object/property pairs through RPM.
- `read_point_summary`: compact value/health lines for selected points.
- `read_priority_array`: command priority array inspection.
- `read_file_chunk`: bounded AtomicReadFile stream or record chunks.
- `enumerate_objects`: object-list enumeration with compact type/range output.
- `get_device_capabilities`: common Device profile fields.

Compact read defaults:

- `read_property` compacts large arrays and strings.
- `read_property_multiple` emits one compact line per object with value, error,
  and missing counts.
- `enumerate_objects` omits object names by default.
- `read_file_chunk` caps payload display bytes and provides continuation hints.

Use detailed modes only for troubleshooting or when the raw decoded shape is
needed.

## Writes

- `write_property`
- `write_property_multiple`
- `relinquish_at_priority`
- `write_schedule_weekly`
- `write_schedule_exceptions`
- `write_local_property`
- `create_local_object`
- `delete_local_object`

Writes are read-only by default. When enabled, writes still pass through the
safety policy and append audit entries. Many write tools support dry-run style
validation so operators can inspect what would happen before mutating a device
or local object.

## Alarms, Events, COV, Schedules, Trends

- Alarms/events: `get_alarm_summary`, `get_event_information`,
  `acknowledge_alarm`
- COV: `subscribe_cov`, `unsubscribe_cov`, `poll_cov_notifications`
- Schedules: `read_schedule`, `read_schedule_weekly`,
  `read_schedule_exceptions`, `write_schedule_weekly`,
  `write_schedule_exceptions`
- Trends: `get_trend_log_info`, `read_trend_log`

Schedule and trend readers avoid broad unbounded reads where BACnet devices
commonly exceed APDU limits. COV polling is bounded by `max_events`.

## Diagnostics

- `ping_device`: repeated reads of a small Device property with latency/loss
  summary.
- `probe_bbmd`: B/IP-only BBMD BDT/FDT inspection.
- `analyze_bacnet_ip_packet`: decode one BACnet/IP BVLC payload or captured
  frame into compact BVLC/NPDU/APDU layers.
- `list_pcap_interfaces`: list host capture interfaces when the `pcap` feature
  is enabled.
- `analyze_pcap_file`: read an offline pcap file and summarize BACnet/IP
  services, BVLC functions, peers, decoded samples, and decode errors.
- `start_pcap_capture`, `stop_pcap_capture`, `list_pcap_captures`,
  `read_pcap_capture`: manage bounded live BACnet/IP capture sessions.

`probe_bbmd` is intentionally unavailable on BACnet/SC because SC has no BBMD
tables.

`analyze_bacnet_ip_packet` is read-only and does not touch the active BACnet
runtime. It accepts hex bytes for `input` shapes `bvlc`, `ipv4`, `ethernet`,
`bsd_null`, and `linux_sll`; the frame inputs are the datalink shapes expected
from pcap capture handles. Compact mode returns a UDP flow and service summary.
Detailed mode adds bounded layer lines with `max_detail_lines`.

`list_pcap_interfaces` is feature-gated because libpcap is a platform-level
dependency. It returns bounded, sorted interface rows and can omit addresses
for a shorter listing.

`analyze_pcap_file` is also feature-gated. It opens local pcap files with
Ethernet, BSD null, raw IPv4, or Linux SLL datalinks and scans a bounded packet
count. The report is deterministic and row-capped for MCP use.

Live pcap capture is feature-gated and requires host capture permissions. The
default BPF is `udp port 47808`; callers can override it when inspecting BBMD,
foreign-device, or routed BACnet/IP traffic. Sessions auto-stop at `max_packets`
and retain a bounded recent-packet ring plus aggregate service, BVLC, peer, and
decode-error counts.

## Local Objects

- `list_local_objects`
- `read_local_property`
- `write_local_property`
- `create_local_object`
- `delete_local_object`

`list_local_objects` defaults to the first 500 local objects and accepts
`limit` up to 5000. The Device object is protected from deletion.

## Resources

Reference resources:

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

State resources:

- `bacnet://state/devices`: bounded discovered-device table.
- `bacnet://state/local-objects`: bounded local object list.
- `bacnet://state/config`: sanitized live runtime config.
- `bacnet://audit/recent`: bounded write audit tail.
- `bacnet://topology/graph`: JSON topology snapshot.

The state config resource reflects live runtime state, not simply the last file
contents. TUI partial reloads preserve stale restart-required fields in this
resource until the daemon restarts.
