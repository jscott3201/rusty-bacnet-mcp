//! Static BACnet reference content compiled into the binary.
//!
//! All content is original reference material (not spec text). Per-object-type
//! detail blocks live in `super::details` to keep this file under the project's
//! 700 LOC cap.

pub const OBJECT_TYPES_INDEX: &str = "\
BACnet Object Types — 65 standard types defined in ASHRAE 135-2020.

Input Objects (physical sensors/contacts):
  analog-input     — Analog sensor (temperature, pressure, humidity, CO2, etc.)
  binary-input     — Digital contact (switch, relay status, occupancy sensor)
  multi-state-input — Multi-position sensor (fan speed selector, damper position)

Output Objects (physical actuators):
  analog-output    — Analog actuator (valve, damper, VFD speed)
  binary-output    — Digital actuator (relay, contactor, on/off valve)
  multi-state-output — Multi-position actuator (fan speed command)

Value Objects (software points, no physical I/O):
  analog-value     — Floating-point setpoint or calculation result
  binary-value     — Boolean flag or mode switch
  multi-state-value — Enumerated mode or state
  integer-value    — Integer setpoint or counter
  large-analog-value — Double-precision floating point
  positive-integer-value — Unsigned integer value
  datetime-value   — Date/time value
  characterstring-value — Text string value
  octetstring-value — Raw byte string value
  bitstring-value  — Bit field value
  time-value       — Time-of-day value
  date-value       — Date value
  datepattern-value — Date pattern for scheduling
  timepattern-value — Time pattern for scheduling
  datetimepattern-value — Combined date+time pattern for scheduling

Device & Infrastructure:
  device           — Represents the BACnet device itself (required in every device)
  network-port     — Network interface configuration (BIP port, MS/TP port, etc.)

Scheduling:
  schedule         — Weekly schedule with exception dates
  calendar         — List of date patterns for holidays/exceptions

Trending:
  trend-log        — Historical data logging (samples at intervals or on COV)
  trend-log-multiple — Multi-object trend logging

Alarming & Events:
  notification-class — Alarm routing configuration (who gets notified)
  event-enrollment — Event detection rules (out-of-range, change-of-state, etc.)
  event-log        — Historical event/alarm log
  notification-forwarder — Forwards alarm notifications between networks

File & Data:
  file             — File transfer object (firmware upload, config backup)
  pulse-converter  — Converts pulse count input to analog value
  accumulator      — Pulse counter with prescale
  averaging        — Statistical averaging over time period

Advanced:
  loop             — PID control loop
  program          — Programmable logic program
  command          — Macro command (write multiple values atomically)
  group            — Object grouping for bulk reads
  structured-view  — Hierarchical organization of objects
  global-group     — Cross-device object grouping
  access-door      — Door access control
  access-point     — Access control point
  access-zone      — Access control zone
  access-credential — Access credential
  credential-data-input — Access control credential reader
  access-rights    — Access rights definition
  access-user      — Access control user
  life-safety-point — Life safety input (smoke, fire, sprinkler)
  life-safety-zone — Life safety zone grouping
  load-control     — Demand response / load shedding
  lighting-output  — Lighting control with dimming
  binary-lighting-output — On/off lighting control
  channel          — Lighting channel grouping
  color            — Color control (RGB/CIE)
  color-temperature — Color temperature control
  elevator-group   — Elevator bank grouping
  escalator        — Escalator monitoring
  lift             — Elevator/lift monitoring
  staging          — Multi-stage equipment sequencing
  timer            — Countdown/countup timer
  audit-log        — Security audit trail
  audit-reporter   — Audit event reporter
  alert-enrollment — Alert detection enrollment
  network-security — Network security configuration

Use bacnet://reference/object-types/{type-name} to get detailed info on any type.
";

pub const TOOL_GUIDE: &str = "\
BACnet MCP Tool Guide - compact routing and workflow guide.

Default workflow:
  1. discover_devices or register_device.
  2. get_device_capabilities before broad reads on an unknown device.
  3. enumerate_objects to discover object identifiers; set include_names for labels.
  4. read_property_multiple for snapshots; read_property for one-off scalar reads.
  5. Use write tools only after reading state and checking policy/audit posture.

Token-efficient usage:
  - Prefer read_property_multiple over many read_property calls.
  - Prefer read_point_summary for compact value/health snapshots of known points.
  - Prefer read_file_chunk for bounded File object reads; page with next_start/next_record.
  - Prefer read_schedule before schedule array reads so you know the target refs.
  - Prefer get_trend_log_info before read_trend_log so you can choose a bounded range.
  - Prefer write_property_multiple for coordinated batch writes after dry-run.
  - Prefer COV subscriptions over repeated polling for changing values.
  - Fetch detailed reference resources only when a workflow needs the background.

Tool families:
  discovery:
    discover_devices broadcasts WhoIs and fills the device table.
    register_device adds a known device without broadcast: B/IP uses IP:port, BACnet/SC uses VMAC.
    list_known_devices reads the cached table without wire traffic.
    get_device_info reads common Device object identity fields.

  remote reads:
    read_property reads one property from one object.
    read_property_multiple reads many object/property pairs in one RPM request.
    read_point_summary returns one compact value/health line per selected point.
    read_file_chunk reads a bounded File object stream or record chunk.
    read_priority_array reads present-value, priority-array, and relinquish-default.
    enumerate_objects groups Device.object-list; include_names fetches labels.
    get_device_capabilities reads vendor/protocol/service capability fields.

  remote writes:
    write_property writes one property value.
    write_property_multiple writes multiple values in one WPM request.
    relinquish_at_priority releases one command priority slot by writing NULL.

  change-of-value:
    subscribe_cov starts a transient notification subscription; dry-run first.
    poll_cov_notifications drains queued notifications with a bounded limit.
    unsubscribe_cov cancels by object and subscriber process id.

  alarms and events:
    get_alarm_summary is the cheap active-alarm triage call.
    get_event_information returns richer event details and supports paging.
    acknowledge_alarm is a safety-gated write path; use dry_run first.

  schedules:
    read_schedule reads scalar metadata and target references.
    read_schedule_weekly reads the weekly-schedule array.
    read_schedule_exceptions reads exception-schedule entries.
    write_schedule_weekly and write_schedule_exceptions replace whole arrays/lists.

  trends:
    get_trend_log_info reads buffer counters and source metadata.
    read_trend_log reads a bounded ReadRange window by position, sequence, or time.

  diagnostics:
    ping_device confirms BACnet APDU reachability, not just IP reachability.
    probe_bbmd reads BBMD BDT/FDT tables by IP:port.

  local objects:
    list_local_objects, read_local_property, write_local_property,
    create_local_object, and delete_local_object operate on the gateway database.

Safety posture:
  - The gateway is read-only by default.
  - Remote and local writes flow through the same policy and audit log.
  - Use dry_run where available to validate and record intent without sending APDUs.
  - Priorities 1-8 are reserved by the default policy; release overrides with
    relinquish_at_priority rather than writing a competing lower-priority value.
  - For batch writes, one denied entry prevents dispatch of the whole WPM APDU.
  - Review bacnet://audit/recent after any denied, dry-run, or failed write path.

Reference resources:
  - bacnet://reference/services explains service choice tradeoffs.
  - bacnet://reference/priority-array explains command priority semantics.
  - bacnet://reference/errors maps protocol errors to likely next steps.
  - bacnet://reference/object-types/{type} gives object-specific guidance.
";

pub const PROPERTIES: &str = "\
BACnet Properties — Common properties found on most object types.

present-value: The current value of the object. For inputs, this is the sensor reading. \
For outputs, this is the commanded value. For values, this is the software point value. \
Type depends on the object: Real for analog, Enumerated for binary (0=inactive, 1=active), \
Unsigned for multi-state.

object-name: Human-readable name string. Must be unique within a device. \
Used for discovery (WhoHas service).

object-type: Enumerated value identifying the type (0=analog-input, 1=analog-output, etc.).

object-identifier: Combination of object-type and instance-number. Globally unique within a device.

status-flags: 4-bit field indicating object state:
  Bit 0 — IN_ALARM: an alarm condition is active
  Bit 1 — FAULT: a fault has been detected (see reliability property)
  Bit 2 — OVERRIDDEN: value is being overridden by hardware or external system
  Bit 3 — OUT_OF_SERVICE: object is disconnected from physical I/O

out-of-service: Boolean. When true, present-value is decoupled from physical I/O. \
The value can be written manually for testing. Status-flags bit 3 mirrors this.

reliability: Indicates fault condition:
  0 = no-fault-detected (normal)
  2 = over-range (sensor reading above max-pres-value)
  3 = under-range (sensor reading below min-pres-value)
  7 = unreliable-other
  See bacnet://reference/reliability for the complete list.

event-state: Current alarm state:
  0 = normal
  1 = fault
  2 = offnormal
  3 = high-limit (analog exceeded high-limit)
  4 = low-limit (analog exceeded low-limit)
  5 = life-safety-alarm (life safety system triggered)

units: Engineering units for analog objects (e.g., degrees-fahrenheit=62, percent=98). \
See bacnet://reference/units for the complete list.

priority-array: Array of 16 command slots for commandable objects (outputs and values). \
See bacnet://reference/priority-array for how priorities work.

description: Free-text description of the object's purpose.

cov-increment: For analog objects, the minimum change in present-value that triggers \
a COV (Change of Value) notification. Smaller values = more notifications.

high-limit / low-limit: Alarm thresholds for analog objects.

deadband: Hysteresis value for returning to normal from an alarm state.

polarity: For binary objects, whether the physical state is normal (0) or reversed (1).

relinquish-default: The fallback value used when all 16 priority slots are null.
";

pub const UNITS: &str = "\
BACnet Engineering Units — Common units for analog objects.

Temperature: degrees-celsius (62), degrees-fahrenheit (64), degrees-kelvin (63)
Pressure: pascals (53), kilopascals (54), bars (55), psi (56), centimeters-of-water (57)
Flow: liters-per-second (87), cubic-meters-per-hour (135), cubic-feet-per-minute (84)
Humidity: percent-relative-humidity (29)
Speed: rpm (104), meters-per-second (74)
Electrical: volts (5), amperes (3), watts (47), kilowatts (48), kilowatt-hours (19)
Light: lux (37), foot-candles (38)
Concentration: ppm (96), percent (98)
Time: seconds (73), minutes (72), hours (71), days (70)
Dimensionless: no-units (95), percent (98)

The 'units' property on an analog object is an enumerated value from this list. \
When reading a present-value, always check the units property to understand what the number means.
";

pub const ERRORS: &str = "\
BACnet Errors — Error classes and codes returned by devices.

Error Class: DEVICE (device-level issues)
  operational-problem — device is in a state that prevents the operation
  configuration-error — device configuration issue
  internal-error — unexpected device-internal failure

Error Class: OBJECT (object-level issues)
  unknown-object — the requested object does not exist on this device
  object-identifier-already-exists — CreateObject failed, object already exists
  no-space-for-object — device cannot create more objects (resource limit)
  dynamic-creation-not-supported — device doesn't support CreateObject

Error Class: PROPERTY (property-level issues)
  unknown-property — this object type does not have the requested property
  read-access-denied — property exists but cannot be read
  write-access-denied — property exists but cannot be written
  value-out-of-range — the written value is outside the acceptable range
  not-writable — this property is read-only on this device

Error Class: SERVICES (service-level issues)
  inconsistent-parameters — request parameters are contradictory
  invalid-parameter-data-type — wrong data type for this property
  service-request-denied — device rejected the request
  other — unspecified error

Error Class: RESOURCES
  no-space-for-object — out of memory/storage for new objects
  no-space-to-write-property — out of storage for property data

Error Class: SECURITY
  authentication-failed — access credentials rejected
  not-configured — security not configured on this device

Common troubleshooting:
  unknown-object → verify the object type and instance number exist on the target device
  unknown-property → the device may not support this property; check the property-list
  write-access-denied → the property may be read-only, or a password/authentication is required
  value-out-of-range → check min/max constraints; for analog writes, verify units match
  service-request-denied → device may be in DCC disable state or the service is not supported
";

pub const RELIABILITY: &str = "\
BACnet Reliability Values — Indicates why an object is in a fault state.

0 = no-fault-detected — Normal operation, no issues.
1 = no-sensor — Physical sensor is not connected or not responding.
2 = over-range — Sensor reading exceeds the max-pres-value. Check physical sensor.
3 = under-range — Sensor reading is below the min-pres-value. Check physical sensor.
4 = open-loop — Control loop is open (feedback missing for output objects).
5 = shorted-loop — Control loop is shorted (output objects).
6 = no-output — Output device is not responding.
7 = unreliable-other — Unspecified reliability issue.
8 = process-error — Internal processing error.
9 = multi-state-fault — Multi-state object in an invalid state number.
10 = configuration-error — Object is misconfigured.
12 = communication-failure — Communication with a monitored device or service has failed.
13 = member-fault — A member of a group or collection is in fault.
14 = monitored-object-fault — The object being monitored is in fault.
15 = tripped — A protective device (breaker, fuse) has tripped.
16 = lamp-failure — A lamp has burned out or failed.
17 = activation-failure — Failed to activate (e.g., damper actuator stuck).
18 = renew-dhcp-failure — DHCP lease renewal failed.
19 = renew-fd-registration-failure — Foreign device registration renewal failed.
20 = restart-auto-negotiation-failure — Network auto-negotiation failed after restart.
21 = restart-failure — Device restart failed.
22 = proprietary-command-failure — A vendor-specific command failed.
23 = faults-listed — Multiple faults are active (check fault-values property for list).
24 = referenced-object-fault — A referenced object is in fault.

When reliability is non-zero:
  - status-flags.fault will be true
  - event-state will typically be 'fault'
  - present-value may be stale or invalid

To clear a fault:
  - Fix the underlying physical or configuration issue
  - For some faults, writing out-of-service=true then false can reset the state
  - Check the device's event/alarm log for more context
";

pub const PRIORITY_ARRAY: &str = "\
BACnet Priority Array — 16-level command priority scheme for outputs and commandable values.

Priority 1:  Manual-Life-Safety     (highest — fire, smoke, emergency override)
Priority 2:  Automatic-Life-Safety  (automatic fire/safety systems)
Priority 3:  (available)
Priority 4:  (available)
Priority 5:  Critical-Equipment-Control (critical equipment protection)
Priority 6:  Minimum-On/Off         (minimum runtime protection)
Priority 7:  (available)
Priority 8:  Manual-Operator        (operator manual override from workstation)
Priority 9:  (available)
Priority 10: (available)
Priority 11: (available)
Priority 12: (available)
Priority 13: (available)
Priority 14: (available)
Priority 15: (available)
Priority 16: (available — lowest, often used for scheduling/default)

How it works:
  - Each priority level is a slot that can hold a value or be null.
  - The present-value is determined by the highest (lowest-numbered) non-null slot.
  - Writing present-value with a priority sets that slot; writing null at a priority relinquishes it.
  - If ALL 16 slots are null, present-value falls back to relinquish-default.

Common patterns:
  - BAS schedules write at priority 16
  - Operator overrides write at priority 8
  - Safety systems write at priority 1 or 2
  - To release an override: write null at the override's priority level

Pitfalls:
  - Writing without specifying a priority defaults to priority 16 (lowest)
  - A value stuck at a high priority blocks lower-priority commands
  - Reading priority-array shows all 16 slots; look for non-null entries to find active commands
";

pub const NETWORKING: &str = "\
BACnet Networking — How devices communicate across networks.

Network Numbers:
  Every BACnet network segment has a unique network number (1-65534).
  Devices on the same physical segment share a network number.
  Network 0 means 'local network' (no routing needed).

Transports:
  BACnet/IP (BIP) — UDP/IP, uses BVLL framing (Annex J). Most common.
  BACnet/SC — WebSocket over TLS, hub-and-spoke topology. Modern/secure.
  MS/TP — RS-485 serial token-passing. Common for field devices.
  BACnet/IPv6 — UDP over IPv6 with virtual MAC addresses.
  Ethernet — Raw IEEE 802.3 LLC frames.

Routing:
  BACnet routers connect different network segments.
  Each router port is assigned to a network number.
  The router forwards messages between networks based on the destination network in the NPDU header.
  Routing is transparent — devices don't need to know about routers for basic communication.
  Who-Is-Router-To-Network discovers which router can reach a given network.
  I-Am-Router-To-Network announces reachability.

BBMDs (BACnet Broadcast Management Devices):
  On BACnet/IP, UDP broadcasts don't cross IP subnets.
  BBMDs solve this by forwarding broadcasts between subnets.
  Each BBMD maintains a BDT (Broadcast Distribution Table) listing all BBMDs.
  BBMDs forward Original-Broadcast-NPDU to all BDT peers.

Foreign Devices:
  A device on a remote subnet that doesn't have its own BBMD.
  Registers with a BBMD, which forwards broadcasts to it.
  Must periodically re-register (TTL-based).
  The BBMD maintains an FDT (Foreign Device Table) of registered devices.

Common Issues:
  - Devices not discovered → check BBMD configuration, verify BDT entries
  - Cross-subnet communication fails → BBMDs not configured or BDT incomplete
  - Intermittent connectivity → foreign device TTL expiring, re-registration failing
  - MS/TP devices unreachable → check router, verify RS-485 wiring and baud rate
";

pub const SERVICES: &str = "\
BACnet Services — When to use each one.

Property Access:
  ReadProperty — Read one property from one object. Simple, low overhead.
  ReadPropertyMultiple (RPM) — Read multiple properties from multiple objects in one request. \
    Much more efficient for bulk reads. Use this when reading more than 2-3 properties.
  WriteProperty — Write one property value with optional priority.
  WritePropertyMultiple (WPM) — Write multiple properties in one request.

Discovery:
  WhoIs — Broadcast to discover devices. Optionally filter by instance range.
  IAm — Response to WhoIs. Contains device instance, vendor ID, max APDU, segmentation support.
  WhoHas — Find devices that have an object with a specific name or identifier.
  IHave — Response to WhoHas.

Change of Value (COV):
  SubscribeCOV — Subscribe to value changes. More efficient than polling.
    Confirmed: device sends confirmed notification (reliable, device retries).
    Unconfirmed: device sends unconfirmed notification (fire-and-forget).
  SubscribeCOVProperty — Subscribe to a specific property (vs. all COV properties).
  Lifetime: subscriptions expire. Client must re-subscribe before lifetime ends.

Object Management:
  CreateObject — Create a new object on a remote device.
  DeleteObject — Delete an object from a remote device.
  AddListElement / RemoveListElement — Modify list properties.

Device Management:
  DeviceCommunicationControl (DCC) — Enable/disable a device's communication.
  ReinitializeDevice — Trigger a warm/cold restart.
  TimeSynchronization — Set the device's clock.

Alarms & Events:
  GetEventInformation — Query active alarms/events.
  AcknowledgeAlarm — Acknowledge an alarm condition.
  GetEnrollmentSummary — List event enrollment objects and their states.

File Access:
  AtomicReadFile — Read from a file object (firmware, logs, config).
  AtomicWriteFile — Write to a file object.
  ReadRange — Read a range of records from a list (trend logs, event logs).
";

pub const TROUBLESHOOTING: &str = "\
BACnet Troubleshooting — Common problems and diagnostic steps.

Device Not Responding:
  1. Verify the device is powered on and connected to the network
  2. Check the network number — is it on a different segment requiring a router?
  3. Try discover_devices tool to see if the device responds to WhoIs
  4. Use ping_device tool to check reachability of a specific device
  5. Check if the device is in DCC (DeviceCommunicationControl) disabled state
  6. Verify the MAC address is correct (use list_known_devices to check cached MAC)
  7. For MS/TP: check RS-485 wiring, baud rate, and station address

Property Read Returns Error:
  unknown-object → the object doesn't exist; list the device's objects first
  unknown-property → this property isn't supported; read property-list to see what's available
  read-access-denied → security restrictions; may need authentication

Cannot Write to Property:
  write-access-denied → property may be read-only, or higher-priority command is active
  value-out-of-range → value is outside the object's acceptable range
  For commandable objects: check priority-array for higher-priority overrides

COV Notifications Not Arriving:
  1. Verify the subscription is active (list_cov_subscriptions)
  2. Check if the subscription lifetime has expired
  3. For confirmed COV: the server may be in DCC disabled-initiation state
  4. Check cov-increment — if too large, small changes won't trigger
  5. Verify network connectivity between subscriber and notifier

Cross-Network Communication Fails:
  1. Check routing table (use get_routing_table tool) — is there a route to the destination network?
  2. Use who_is_router_to_network tool to discover available routers
  3. Verify router ports are active (use read_router_network_ports tool on the router device)
  4. For BIP across subnets: check BBMD BDT configuration (use read_bdt tool)
  5. For MS/TP: verify the router's serial port is active and baud rate matches

BBMD Issues:
  1. Read BDT from each BBMD (use read_bdt tool) — all should have matching entries
  2. Verify BBMDs can reach each other (check for firewall rules on port 47808)
  3. For foreign devices: verify registration is active (use read_fdt tool)
  4. Check if foreign device TTL is expiring before re-registration
";

pub const BIBBS: &str = "\
BACnet Interoperability Building Blocks (BIBBs) — ASHRAE 135-2020 Annex K.

A BIBB is a named bundle of BACnet services that two devices must implement
to interoperate for a specific function. Standard device profiles are defined
as sets of BIBBs, so 'this device claims profile X' is shorthand for 'it
implements every BIBB in X's required set'.

Naming convention:
  <CATEGORY>-<FUNCTION>-<SIDE>

  Category — what kind of work the BIBB covers:
    DS    — Data Sharing (read/write properties, COV)
    AE    — Alarm and Event
    SCHED — Scheduling
    T     — Trending
    DM    — Device Management
    NM    — Network Management

  Function — the specific operation (e.g. RP = ReadProperty, WP = WriteProperty,
    RPM = ReadPropertyMultiple, COV = Change-Of-Value, DDB = Dynamic Device
    Binding, DCC = Device Communication Control).

  Side — A = initiator (client; the device that asks), B = executor (server;
    the device that responds). Most BIBBs are pair-defined (A and B exist
    independently). A few are one-sided.

Common BIBBs (the load-bearing subset agents see in real networks):

  Data Sharing:
    DS-RP-A / DS-RP-B           ReadProperty (single property fetch)
    DS-RPM-A / DS-RPM-B         ReadPropertyMultiple (batched reads)
    DS-WP-A / DS-WP-B           WriteProperty (single property write)
    DS-WPM-A / DS-WPM-B         WritePropertyMultiple (batched writes)
    DS-COV-A / DS-COV-B         Change-Of-Value subscription (whole object)
    DS-COVP-A / DS-COVP-B       Change-Of-Value subscription (per property)
    DS-COVU-A / DS-COVU-B       Unconfirmed COV notifications

  Alarm and Event:
    AE-N-A / AE-N-I-B / AE-N-E-B   Notifications (initiator / internal / external)
    AE-ACK-A / AE-ACK-B            Alarm acknowledgement
    AE-ASUM-A / AE-ASUM-B          GetAlarmSummary
    AE-ESUM-A / AE-ESUM-B          GetEnrollmentSummary
    AE-INFO-A / AE-INFO-B          GetEventInformation

  Scheduling:
    SCHED-A   Read/write a remote Schedule object
    SCHED-I-B Internal — schedule executes inside the device
    SCHED-E-B External — schedule writes targets in other devices

  Trending:
    T-VMT-A / T-VMT-I-B / T-VMT-E-B  Viewing/managing trends
    T-ATR-A / T-ATR-B                Automatic trend retrieval (ReadRange)

  Device Management:
    DM-DDB-A / DM-DDB-B   Dynamic Device Binding (Who-Is / I-Am)
    DM-DOB-A / DM-DOB-B   Dynamic Object Binding (Who-Has / I-Have)
    DM-DCC-A / DM-DCC-B   Device Communication Control (disable / enable comms)
    DM-TM-A / DM-TM-B     Text Message
    DM-TS-A / DM-TS-B     Time Synchronization
    DM-UTC-A / DM-UTC-B   UTC Time Synchronization
    DM-RD-A / DM-RD-B     ReinitializeDevice (warm/cold restart)
    DM-BR-A / DM-BR-B     Backup and Restore (file-based config sync)
    DM-LM-A / DM-LM-B     List Manipulation (AddListElement / RemoveListElement)
    DM-OCD-A / DM-OCD-B   Object Creation and Deletion
    DM-VT-A / DM-VT-B     Virtual Terminal

  Network Management:
    NM-CE-A / NM-CE-B     Connection Establishment (point-to-point links)
    NM-RC-A / NM-RC-B     Router Configuration (BBMDs, BDT/FDT, network numbers)

Standard Device Profiles (each profile = 'must implement these BIBBs'):

  B-OWS  Operator Workstation         — broad client surface; reads, writes,
                                         alarms, schedules, trends across the
                                         site. Exists on the human-facing end.
  B-AWS  Advanced Operator Workstation — B-OWS + remote configuration tools
                                         (NM-RC-A, DM-BR-A, DM-OCD-A).
  B-BC   Building Controller          — site-level supervisory device:
                                         executes schedules and event logic
                                         that touch multiple field controllers.
  B-AAC  Advanced Application Controller — programmable field controller;
                                         runs control loops, hosts trend logs
                                         and event enrollment.
  B-ASC  Application-Specific Controller — fixed-function field controller
                                         (VAV box, fan-coil unit). Limited
                                         object set, no programmable logic.
  B-SA   Smart Actuator               — narrow-scope output device (damper
                                         actuator with feedback).
  B-SS   Smart Sensor                 — narrow-scope input device (pressure
                                         transducer with COV).

Why this matters for an agent driving the network:

  1. A device's protocol-services-supported (Device property 97) and
     protocol-object-types-supported (96) are how it advertises which BIBBs
     it implements. Read those before assuming any service will work.

  2. Profile names appear in marketing copy and PICS documents, not on the
     wire. The BIBBs are the durable contract — when a device says it 'is a
     B-BC', the verifiable claim is 'every BIBB in B-BC's required set is
     implemented'.

  3. Asymmetric pairs matter. If you only see DS-RP-B advertised, the device
     can answer reads but cannot initiate them — agents that try to chain
     a ReadProperty call from this device will fail.

  4. SCHED-I-B vs SCHED-E-B is the question 'does this schedule write
     locally, or out to other devices?'. The Schedule object's
     list-of-object-property-references answers this directly — see
     bacnet://reference/object-types/schedule.

  5. Routing and BBMD setup are NM-RC concerns. If you're configuring a
     BBMD (write_bdt, register_foreign_device), you're operating on the
     NM-RC-A side and the target device must implement NM-RC-B.
";
