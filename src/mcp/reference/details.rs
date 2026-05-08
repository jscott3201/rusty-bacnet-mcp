//! Per-object-type detailed reference content.
//! Split from content.rs to keep each file under the 700 LOC project cap.

use bacnet_types::enums::ObjectType;

/// Generate detailed reference content for a specific object type.
pub fn object_type_detail(type_name: &str) -> Option<String> {
    let normalized = type_name.to_lowercase().replace('-', "_");

    // Find the matching ObjectType.
    let obj_type = ObjectType::ALL_NAMED
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(&normalized))
        .map(|(_, val)| *val)?;

    let display_name = type_name.replace('_', "-").to_lowercase();

    // Generate content based on the type category.
    let content = match obj_type {
        ObjectType::ANALOG_INPUT => format!(
            "\
{display_name} (type {})

Category: Input / Sensor
Commandable: No (read-only from physical sensor)
COV Support: Yes (triggers on present-value change exceeding cov-increment)

Purpose:
Represents a physical analog sensor — temperature, pressure, humidity, flow rate, CO2 level, etc. \
The present-value reflects the current sensor reading in the configured engineering units.

Key Properties:
  present-value — Current sensor reading (Real)
  units — Engineering units (e.g., degrees-fahrenheit, pascals)
  out-of-service — When true, present-value is manually set (not from sensor)
  status-flags — [in-alarm, fault, overridden, out-of-service]
  reliability — no-fault-detected, over-range, under-range, open-loop, etc.
  high-limit / low-limit — Alarm thresholds
  deadband — Hysteresis for alarm return-to-normal
  cov-increment — Minimum change to trigger COV notification
  min-pres-value / max-pres-value — Expected sensor range
  event-state — normal, high-limit, low-limit, fault

Common Configurations:
  Temperature sensor: units=degrees-fahrenheit, high-limit=90, low-limit=55
  Pressure sensor: units=pascals, cov-increment=100
  Humidity sensor: units=percent-relative-humidity

Troubleshooting:
  reliability=over-range → sensor reading above max-pres-value, check physical sensor
  reliability=under-range → sensor reading below min-pres-value, check wiring
  status-flags.fault=true → check reliability value for specific fault type
  present-value not updating → check out-of-service flag
",
            obj_type.to_raw()
        ),

        ObjectType::ANALOG_OUTPUT => format!(
            "\
{display_name} (type {})

Category: Output / Actuator
Commandable: Yes (via 16-level priority array)
COV Support: Yes

Purpose:
Represents a physical analog actuator — valve position, damper position, VFD speed, dimmer level. \
The present-value is the commanded output percentage or engineering value.

Key Properties:
  present-value — Commanded output value (Real)
  priority-array — 16 command priority slots (see bacnet://reference/priority-array)
  relinquish-default — Fallback value when all priority slots are null
  units — Engineering units for the output value
  min-pres-value / max-pres-value — Output range limits
  out-of-service — When true, output is disconnected from physical actuator

Troubleshooting:
  Output not responding → check priority-array for higher-priority overrides
  Value stuck → look for non-null entries in priority-array above your write priority
  To release an override → write null at that priority level
",
            obj_type.to_raw()
        ),

        ObjectType::ANALOG_VALUE => format!(
            "\
{display_name} (type {})

Category: Value / Software Point
Commandable: Yes (via 16-level priority array)
COV Support: Yes

Purpose:
A software analog point with no physical I/O. Used for setpoints, calculation results, \
intermediate values, and configuration parameters. Commonly used for zone temperature setpoints, \
schedule outputs, and energy calculations.

Key Properties:
  present-value — Current value (Real)
  priority-array — 16 command priority slots
  relinquish-default — Fallback when all priorities null
  units — Engineering units (often degrees or percent)
  cov-increment — Minimum change for COV notification

Common Uses:
  Zone temperature setpoint: units=degrees-fahrenheit, relinquish-default=72.0
  Calculated value: energy totalization, average, etc.
  Configuration parameter: PID tuning constants
",
            obj_type.to_raw()
        ),

        ObjectType::BINARY_INPUT => format!(
            "\
{display_name} (type {})

Category: Input / Sensor
Commandable: No
COV Support: Yes (triggers on any state change)

Purpose:
Represents a physical digital input — door switch, relay status, occupancy sensor, \
limit switch, or any on/off sensor. Present-value is 0 (inactive) or 1 (active).

Key Properties:
  present-value — Current state: inactive (0) or active (1)
  polarity — Normal (0) or Reverse (1). Reverse inverts the physical input.
  out-of-service — When true, present-value is decoupled from physical input
  status-flags — [in-alarm, fault, overridden, out-of-service]
",
            obj_type.to_raw()
        ),

        ObjectType::BINARY_OUTPUT => format!(
            "\
{display_name} (type {})

Category: Output / Actuator
Commandable: Yes (via 16-level priority array)
COV Support: Yes

Purpose:
Represents a physical digital output — relay, contactor, on/off valve, fan start/stop. \
Present-value is inactive (0) or active (1).

Key Properties:
  present-value — Commanded state: inactive (0) or active (1)
  priority-array — 16 command priority slots
  relinquish-default — Fallback when all priorities null
  polarity — Normal or Reverse
  minimum-on-time / minimum-off-time — Minimum runtime protection (seconds)
",
            obj_type.to_raw()
        ),

        ObjectType::BINARY_VALUE => format!(
            "\
{display_name} (type {})

Category: Value / Software Point
Commandable: Yes (via 16-level priority array)
COV Support: Yes

Purpose:
A software boolean point with no physical I/O. Used for mode flags, enable/disable switches, \
and boolean logic results. Present-value is inactive (0) or active (1).

Key Properties:
  present-value — Current state: inactive (0) or active (1)
  priority-array — 16 command priority slots
  relinquish-default — Fallback when all priorities null
",
            obj_type.to_raw()
        ),

        ObjectType::DEVICE => format!(
            "\
{display_name} (type {})

Category: Infrastructure (required — one per device)
Commandable: No
COV Support: No

Purpose:
The Device object represents the BACnet device itself. Every device must have exactly one. \
It exposes device identity, protocol support, and configuration.

Key Properties:
  object-name — Device name (human-readable)
  system-status — operational(0), non-operational, etc.
  vendor-name — Manufacturer name
  vendor-identifier — ASHRAE vendor ID number
  model-name — Device model
  firmware-revision — Firmware version string
  application-software-version — Application version
  protocol-version — BACnet protocol version (typically 1)
  protocol-revision — Protocol revision (higher = newer features)
  max-apdu-length-accepted — Maximum message size this device handles
  segmentation-supported — Whether device supports segmented messages
  object-list — Array of all object identifiers in this device
  protocol-services-supported — Bitstring of supported services
  protocol-object-types-supported — Bitstring of supported object types
",
            obj_type.to_raw()
        ),

        ObjectType::SCHEDULE => format!(
            "\
{display_name} (type {})

Category: Scheduling
Commandable: No
COV Support: Yes

Purpose:
Implements a weekly time schedule with exception dates (holidays). Writes a value to one or more \
objects at specified times. The present-value reflects the current scheduled output.

Key Properties:
  present-value — Current schedule output value
  weekly-schedule — Array of 7 daily schedules (Monday–Sunday), each with time/value pairs
  exception-schedule — Special dates that override the weekly schedule
  schedule-default — Value when no schedule entry is active
  list-of-object-property-references — Objects that receive the scheduled value
  effective-period — Date range when the schedule is active
",
            obj_type.to_raw()
        ),

        ObjectType::TREND_LOG => format!(
            "\
{display_name} (type {})

Category: Trending / Data Logging
Commandable: No
COV Support: No

Purpose:
Records historical data for an object property. Samples at fixed intervals (polling) \
or on change-of-value (COV). Stores timestamped records in a circular buffer.

Key Properties:
  log-device-object-property — The object/property being logged
  logging-type — Polled (1), COV (2), or Triggered (3)
  log-interval — Polling interval in centiseconds (e.g., 6000 = 60 seconds)
  stop-when-full — false = circular buffer, true = stops when full
  buffer-size — Maximum number of records
  record-count — Current number of records
  total-record-count — Total records ever logged (may exceed buffer-size)
  enable — true to start logging
",
            obj_type.to_raw()
        ),

        ObjectType::NOTIFICATION_CLASS => format!(
            "\
{display_name} (type {})

Category: Alarming
Commandable: No
COV Support: No

Purpose:
Defines how alarm notifications are routed. Specifies recipients, priorities, \
and which transitions (to-offnormal, to-fault, to-normal) generate notifications.

Key Properties:
  notification-class — The class number (referenced by event-enabled objects)
  recipient-list — List of (device, address) recipients for each transition
  priority — Array of 3 priorities (to-offnormal, to-fault, to-normal)
  ack-required — Which transitions require acknowledgment
",
            obj_type.to_raw()
        ),

        ObjectType::NETWORK_PORT => format!(
            "\
{display_name} (type {})

Category: Infrastructure / Network Configuration
Commandable: No
COV Support: No

Purpose:
Represents a network interface on the device. Exposes configuration for BACnet/IP ports, \
MS/TP ports, BACnet/SC connections, etc. One Network Port object per physical or logical interface.

Key Properties:
  network-type — Port type: ipv4 (5), mstp (9), sc (14), etc.
  network-number — BACnet network number assigned to this port
  mac-address — This port's MAC address
  link-speed — Physical link speed
  ip-address / ip-subnet-mask — For BIP ports
  bdt-table — For BIP BBMD ports
  fd-bbmd-address — For foreign device ports
  bacnet-ip-udp-port — UDP port (default 47808)
  routing-table — For routers, the routing table entries
  command — restart/other management commands
",
            obj_type.to_raw()
        ),

        ObjectType::MULTI_STATE_INPUT => format!(
            "\
{display_name} (type {})

Category: Input / Sensor
Commandable: No
COV Support: Yes (triggers on any state change)

Purpose:
Represents a multi-position physical input — fan speed selector, damper position switch, \
or any sensor with discrete states. Present-value is an unsigned integer (1-based) \
representing the current state.

Key Properties:
  present-value — Current state number (Unsigned, 1 to number-of-states)
  number-of-states — How many valid states this input has
  state-text — Optional array of human-readable names for each state
  out-of-service — When true, present-value is manually set
  status-flags — [in-alarm, fault, overridden, out-of-service]

Common Configurations:
  Fan speed: number-of-states=3, state-text=[\"Off\", \"Low\", \"High\"]
  Damper position: number-of-states=3, state-text=[\"Closed\", \"Partially Open\", \"Fully Open\"]
",
            obj_type.to_raw()
        ),

        ObjectType::MULTI_STATE_OUTPUT => format!(
            "\
{display_name} (type {})

Category: Output / Actuator
Commandable: Yes (via 16-level priority array)
COV Support: Yes

Purpose:
Represents a multi-position physical output — fan speed command, multi-stage equipment, \
or any actuator with discrete positions. Present-value is an unsigned integer (1-based).

Key Properties:
  present-value — Commanded state number (Unsigned, 1 to number-of-states)
  priority-array — 16 command priority slots
  relinquish-default — Fallback state when all priorities null
  number-of-states — How many valid states
  state-text — Optional array of names for each state
",
            obj_type.to_raw()
        ),

        ObjectType::MULTI_STATE_VALUE => format!(
            "\
{display_name} (type {})

Category: Value / Software Point
Commandable: Yes (via 16-level priority array)
COV Support: Yes

Purpose:
A software multi-state point with no physical I/O. Used for mode selection, \
operating modes, and enumerated configuration values.

Key Properties:
  present-value — Current state number (Unsigned, 1 to number-of-states)
  priority-array — 16 command priority slots
  relinquish-default — Fallback state
  number-of-states — How many valid states
  state-text — Optional array of names for each state

Common Uses:
  Operating mode: number-of-states=4, state-text=[\"Off\", \"Heat\", \"Cool\", \"Auto\"]
  Occupancy mode: number-of-states=3, state-text=[\"Unoccupied\", \"Occupied\", \"Standby\"]
",
            obj_type.to_raw()
        ),

        ObjectType::INTEGER_VALUE => format!(
            "\
{display_name} (type {})

Category: Value / Software Point
Commandable: Yes (via 16-level priority array)
COV Support: Yes

Purpose:
A software integer point. Used for counters, integer setpoints, and configuration \
values that require whole numbers. Present-value is a signed 32-bit integer.

Key Properties:
  present-value — Current value (Signed integer)
  priority-array — 16 command priority slots
  relinquish-default — Fallback value
  units — Engineering units
  min-pres-value / max-pres-value — Valid range
",
            obj_type.to_raw()
        ),

        ObjectType::FILE => format!(
            "\
{display_name} (type {})

Category: File / Data Transfer
Commandable: No
COV Support: No

Purpose:
Represents a file on the device — firmware image, configuration backup, log export, etc. \
Used with AtomicReadFile and AtomicWriteFile services for reliable file transfer.

Key Properties:
  file-type — MIME-like type string
  file-size — Size in bytes (may be approximate for stream files)
  modification-date — Last modified timestamp
  archive — Whether the file has been modified since last backup
  read-only — Whether the file can be written
  file-access-method — record-access (fixed records) or stream-access (byte stream)

Usage:
  Use AtomicReadFile to download file contents
  Use AtomicWriteFile to upload new contents
  For record-access files, specify start-record and record-count
  For stream-access files, specify start-position and byte-count
",
            obj_type.to_raw()
        ),

        ObjectType::CALENDAR => format!(
            "\
{display_name} (type {})

Category: Scheduling
Commandable: No
COV Support: Yes

Purpose:
A list of dates or date patterns — holidays, special events, maintenance windows. \
Referenced by Schedule objects as exception schedules.

Key Properties:
  present-value — Boolean: true if today matches any entry in the date-list
  date-list — Array of date entries (specific dates, date ranges, or weekly patterns)

Usage:
  Create a Calendar with holiday dates
  Reference it from a Schedule's exception-schedule
  The Schedule uses the Calendar to override its weekly schedule on matching days
",
            obj_type.to_raw()
        ),

        ObjectType::EVENT_ENROLLMENT => format!(
            "\
{display_name} (type {})

Category: Alarming / Event Detection
Commandable: No
COV Support: No

Purpose:
Defines an event detection rule — monitors a property on another object and triggers \
alarm notifications when conditions are met (out-of-range, change-of-state, etc.).

Key Properties:
  event-type — Type of detection: change-of-bitstring (0), change-of-state (1), \
    change-of-value (2), floating-limit (4), out-of-range (5), etc.
  object-property-reference — The object+property being monitored
  notification-class — Which Notification Class handles the alarm routing
  event-parameters — Detection parameters (thresholds, deadbands, time delays)
  event-state — Current state: normal, offnormal, fault, high-limit, low-limit
  event-enable — Which transitions are enabled (to-offnormal, to-fault, to-normal)
  acked-transitions — Which transitions have been acknowledged

Troubleshooting:
  event-state stuck in offnormal → check if the monitored property has returned to normal range
  No notifications → check event-enable bits and notification-class recipient-list
",
            obj_type.to_raw()
        ),

        ObjectType::LOOP => format!(
            "\
{display_name} (type {})

Category: Control
Commandable: No
COV Support: Yes

Purpose:
A PID (Proportional-Integral-Derivative) control loop. Reads a process variable, \
compares it to a setpoint, and writes a control output to maintain the setpoint.

Key Properties:
  present-value — Current output value (0-100% typically)
  controlled-variable-reference — The input (process variable) object+property
  controlled-variable-value — Current process variable reading
  setpoint-reference — The setpoint object+property
  setpoint — Current setpoint value
  manipulated-variable-reference — The output object+property being controlled
  action — direct (output increases when PV > SP) or reverse
  proportional-constant — P gain
  integral-constant — I gain (minutes)
  derivative-constant — D gain (minutes)
  output-units — Engineering units for the output
",
            obj_type.to_raw()
        ),

        // Generic fallback for types without detailed descriptions.
        _ => format!(
            "\
{display_name} (type {})

A standard BACnet object type defined in ASHRAE 135-2020. \
Use read_property to examine its properties, or read the property-list \
property to see which properties this object supports.

Use list_local_objects or read_property with object-list on the Device object \
to find instances of this type on a device.
",
            obj_type.to_raw()
        ),
    };

    Some(content)
}
