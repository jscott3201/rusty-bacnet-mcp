//! Schedule write MCP tools — `write_schedule_weekly`, `write_schedule_exceptions`.
//!
//! Whole-array replacement matching WriteProperty semantics for the Schedule
//! object's constructed-array properties (`weekly-schedule`,
//! `exception-schedule`). There's no per-element write in the spec, so the
//! tools take the entire array as input and replace it atomically. Operators
//! who want to "add one entry to Tuesday" do read → mutate → write
//! client-side; the tool surface stays small and the contract stays clear.
//!
//! Both tools route through the same gate as `write_property`:
//! `WritePolicy` → audit `allow`/`deny`/`error` → optional `dry_run`. On a
//! real write the `allow` audit lands BEFORE the wire await so a crash
//! mid-flight still records intent.
//!
//! v1 scope:
//! - **Values** — tagged JSON: `{"real": 72.0}`, `{"boolean": true}`,
//!   `{"unsigned": 3}`, `{"null": null}`. Other primitives (signed,
//!   double, character_string, octet_string, bit_string, enumerated) are
//!   v2 work.
//! - **Periods (exception-schedule only)** — `{"date": "YYYY-MM-DD"}` (or
//!   `"YYYY-MM-DD-Mon"`) and `{"week_n_day": "month/week/dow"}` patterns
//!   matching `format_week_n_day` output. `DateRange` and
//!   `CalendarReference` are v2 work.
//! - **Times** — `"HH:MM:SS"` or `"HH:MM"`. Hundredths default to 0.
//! - **WriteProperty priority** — None. Schedule arrays aren't
//!   priority-array-managed; the priority field on individual exception
//!   events (`event_priority`) lives in the data, not the wire request.

use bacnet_encoding::primitives::{
    encode_app_boolean, encode_app_null, encode_app_real, encode_app_unsigned,
};
use bacnet_services::schedule::{encode_exception_schedule, encode_weekly_schedule};
use bacnet_types::constructed::{
    BACnetCalendarEntry, BACnetSpecialEvent, BACnetTimeValue, BACnetWeekNDay, SpecialEventPeriod,
};
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{Date, ObjectIdentifier, Time};
use bytes::BytesMut;
use schemars::JsonSchema;
use serde::Deserialize;

use super::properties::WriteAudit;
use crate::safety::PolicyDecision;
use crate::state::GatewayState;

// ─── parameters ─────────────────────────────────────────────────────────────

/// One time-value pair in tagged JSON form. Tagged because BACnet
/// `BACnetTimeValue.value` is polymorphic — the schedule writes whatever
/// type matches its target property — and JSON's untyped numbers can't tell
/// us whether `3` is unsigned-3 or real-3.0.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TimeValueInput {
    /// Time-of-day as `"HH:MM:SS"` or `"HH:MM"` (24-hour).
    #[schemars(description = "Time of day, 24-hour (e.g. '08:00' or '08:30:00')")]
    pub time: String,
    /// Tagged value. Exactly one variant set.
    #[schemars(
        description = "Tagged value, e.g. {\"real\": 72.0}, {\"boolean\": true}, {\"unsigned\": 3}, or {\"null\": null}"
    )]
    pub value: ScheduleValueInput,
}

/// Polymorphic time-value `value` field. v1 supports the four most common
/// types; widen with `#[serde(untagged)]` variants in v2 as needed.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleValueInput {
    Real(f32),
    Boolean(bool),
    Unsigned(u64),
    /// Null — equivalent to "no override at this time" / fall-through.
    /// JSON: `{"null": null}`.
    Null(serde_json::Value),
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteScheduleWeeklyParams {
    #[schemars(description = "Device instance number hosting the Schedule object")]
    pub device_instance: u32,
    #[schemars(description = "Schedule object instance number")]
    pub schedule_instance: u32,
    /// Exactly 7 lists, Mon..Sun. Empty list = no entries that day.
    #[schemars(
        description = "7 lists of (time, value) entries, Mon..Sun in order. Each empty list = no entries that day."
    )]
    pub days: Vec<Vec<TimeValueInput>>,
    #[schemars(
        description = "If true, validate + audit but do not send the WriteProperty (default false)"
    )]
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExceptionInput {
    /// Tagged period: `{"date": "YYYY-MM-DD"}` (with optional `-Mon`
    /// day-of-week suffix) or `{"week_n_day": "month/week/dow"}` pattern.
    #[schemars(
        description = "Period: {\"date\": \"YYYY-MM-DD\"} or {\"week_n_day\": \"month/week/dow\"}"
    )]
    pub period: PeriodInput,
    /// Time-value pairs that fire during this period.
    pub time_values: Vec<TimeValueInput>,
    /// Conflict-resolution priority (1=highest..16=lowest) against the weekly schedule.
    #[schemars(description = "Conflict priority 1..=16 (1 highest)")]
    pub priority: u8,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeriodInput {
    /// Concrete date `"YYYY-MM-DD"`, optionally with `-Mon`..`-Sun` suffix.
    /// Pattern dates (sentinel month/day) deferred to v2.
    Date(String),
    /// Recurring pattern `"month/week/dow"` matching `format_week_n_day`
    /// output: month is 1-12 / "odd" / "even" / "*"; week is 1-6 / "*";
    /// dow is `Mon`..`Sun` / "*".
    WeekNDay(String),
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteScheduleExceptionsParams {
    #[schemars(description = "Device instance number hosting the Schedule object")]
    pub device_instance: u32,
    #[schemars(description = "Schedule object instance number")]
    pub schedule_instance: u32,
    #[schemars(description = "List of special events (replaces the entire exception-schedule)")]
    pub events: Vec<ExceptionInput>,
    #[schemars(
        description = "If true, validate + audit but do not send the WriteProperty (default false)"
    )]
    #[serde(default)]
    pub dry_run: bool,
}

// ─── implementations ────────────────────────────────────────────────────────

pub async fn write_schedule_weekly_impl(
    state: &GatewayState,
    params: WriteScheduleWeeklyParams,
) -> Result<String, String> {
    let audit = WriteAudit {
        state,
        tool: "write_schedule_weekly",
        target: format!("schedule:{}", params.schedule_instance),
        property: "weekly-schedule".to_string(),
        priority: None,
        dry_run: params.dry_run,
    };

    state.require_writable().map_err(|m| audit.deny(m))?;

    let oid = ObjectIdentifier::new(ObjectType::SCHEDULE, params.schedule_instance)
        .map_err(|e| audit.deny(format!("{e}")))?;

    if let PolicyDecision::Deny(reason) = state.flags.policy().evaluate(oid, None) {
        return Err(format!("Policy denied: {}", audit.deny(reason)));
    }

    if params.days.len() != 7 {
        return Err(audit.deny(format!(
            "weekly_schedule.days must have exactly 7 entries (Mon..Sun), got {}",
            params.days.len()
        )));
    }

    // Build the [Vec<BACnetTimeValue>; 7] structure the encoder expects.
    let mut days: [Vec<BACnetTimeValue>; 7] = Default::default();
    for (i, day_entries) in params.days.iter().enumerate() {
        for (j, tv) in day_entries.iter().enumerate() {
            days[i].push(
                build_time_value(tv).map_err(|e| {
                    audit.deny(format!("weekly_schedule.days[{i}].entries[{j}]: {e}"))
                })?,
            );
        }
        // Duplicate times in a single day's list are invalid on many
        // devices and would produce a write error after a "successful"
        // dry-run. Reject up front.
        if let Some(dup) = find_duplicate_time(&days[i]) {
            return Err(audit.deny(format!("weekly_schedule.days[{i}]: duplicate time {dup}")));
        }
    }

    let mut payload = BytesMut::new();
    encode_weekly_schedule(&mut payload, &days);

    if params.dry_run {
        audit.allow();
        let total: usize = days.iter().map(|d| d.len()).sum();
        return Ok(format!(
            "[dry-run] Would write {} time-value entries across 7 days to {} weekly-schedule ({} bytes)",
            total,
            audit.target,
            payload.len(),
        ));
    }

    let client = state.require_client().map_err(|m| audit.err(m))?;
    let dev = state
        .resolve_device(params.device_instance)
        .await
        .map_err(|m| audit.err(m))?;

    audit.allow();

    match client
        .write_property(
            &dev.mac_address,
            oid,
            PropertyIdentifier::WEEKLY_SCHEDULE,
            None,
            payload.to_vec(),
            None,
        )
        .await
    {
        Ok(()) => {
            let total: usize = days.iter().map(|d| d.len()).sum();
            Ok(format!(
                "Wrote weekly-schedule to {} ({} time-value entries across 7 days)",
                audit.target, total,
            ))
        }
        Err(e) => Err(format!(
            "Error writing weekly-schedule: {}",
            audit.err(format!("{e}")),
        )),
    }
}

pub async fn write_schedule_exceptions_impl(
    state: &GatewayState,
    params: WriteScheduleExceptionsParams,
) -> Result<String, String> {
    let audit = WriteAudit {
        state,
        tool: "write_schedule_exceptions",
        target: format!("schedule:{}", params.schedule_instance),
        property: "exception-schedule".to_string(),
        priority: None,
        dry_run: params.dry_run,
    };

    state.require_writable().map_err(|m| audit.deny(m))?;

    let oid = ObjectIdentifier::new(ObjectType::SCHEDULE, params.schedule_instance)
        .map_err(|e| audit.deny(format!("{e}")))?;

    let policy = state.flags.policy();
    // Object-level pre-check (matters for the empty-events case — clearing
    // the schedule still has to clear allow/deny gates even though there's
    // no per-event priority to evaluate).
    if let PolicyDecision::Deny(reason) = policy.evaluate(oid, None) {
        return Err(format!("Policy denied: {}", audit.deny(reason)));
    }

    let mut events = Vec::with_capacity(params.events.len());
    for (i, e) in params.events.iter().enumerate() {
        // Per-event priority must clear the safety-plane priority caps
        // (`min_priority`/`max_priority`) — exception events embed their
        // own priority, so the policy must apply per-event, not just
        // once at object level.
        if !(1..=16).contains(&e.priority) {
            return Err(audit.deny(format!(
                "events[{i}].priority {} out of range; BACnetSpecialEvent.event_priority must be 1..=16",
                e.priority
            )));
        }
        if let PolicyDecision::Deny(reason) = policy.evaluate(oid, Some(e.priority)) {
            return Err(format!(
                "Policy denied: {}",
                audit.deny(format!("events[{i}] (priority {}): {reason}", e.priority))
            ));
        }
        events
            .push(build_special_event(e).map_err(|msg| audit.deny(format!("events[{i}]: {msg}")))?);
    }

    let mut payload = BytesMut::new();
    encode_exception_schedule(&mut payload, &events);

    if params.dry_run {
        audit.allow();
        return Ok(format!(
            "[dry-run] Would write {} exception events to {} exception-schedule ({} bytes)",
            events.len(),
            audit.target,
            payload.len(),
        ));
    }

    let client = state.require_client().map_err(|m| audit.err(m))?;
    let dev = state
        .resolve_device(params.device_instance)
        .await
        .map_err(|m| audit.err(m))?;

    audit.allow();

    match client
        .write_property(
            &dev.mac_address,
            oid,
            PropertyIdentifier::EXCEPTION_SCHEDULE,
            None,
            payload.to_vec(),
            None,
        )
        .await
    {
        Ok(()) => Ok(format!(
            "Wrote exception-schedule to {} ({} events)",
            audit.target,
            events.len(),
        )),
        Err(e) => Err(format!(
            "Error writing exception-schedule: {}",
            audit.err(format!("{e}")),
        )),
    }
}

// ─── builders ───────────────────────────────────────────────────────────────

fn build_time_value(input: &TimeValueInput) -> Result<BACnetTimeValue, String> {
    let time = parse_time(&input.time)?;
    let mut buf = BytesMut::new();
    match &input.value {
        ScheduleValueInput::Real(v) => encode_app_real(&mut buf, *v),
        ScheduleValueInput::Boolean(v) => encode_app_boolean(&mut buf, *v),
        ScheduleValueInput::Unsigned(v) => encode_app_unsigned(&mut buf, *v),
        ScheduleValueInput::Null(v) => {
            // Tagged `null` requires a literal null payload — silently
            // accepting `{"null": 5}` would convert a malformed request
            // into a real BACnet NULL write.
            if !v.is_null() {
                return Err(format!(
                    "'null' tag requires a literal null payload, got {v}"
                ));
            }
            encode_app_null(&mut buf);
        }
    }
    Ok(BACnetTimeValue {
        time,
        value: buf.to_vec(),
    })
}

fn build_special_event(input: &ExceptionInput) -> Result<BACnetSpecialEvent, String> {
    // Range check still happens here as defense-in-depth; the wrapper in
    // `write_schedule_exceptions_impl` also enforces it (with audit) so
    // policy/priority callouts get a clean deny entry before reaching
    // this builder.
    if !(1..=16).contains(&input.priority) {
        return Err(format!(
            "priority {} out of range; BACnetSpecialEvent.event_priority must be 1..=16",
            input.priority
        ));
    }
    let period = build_period(&input.period)?;
    let mut list_of_time_values = Vec::with_capacity(input.time_values.len());
    for (i, tv) in input.time_values.iter().enumerate() {
        list_of_time_values
            .push(build_time_value(tv).map_err(|e| format!("time_values[{i}]: {e}"))?);
    }
    if let Some(dup) = find_duplicate_time(&list_of_time_values) {
        return Err(format!("duplicate time {dup} in time_values"));
    }
    Ok(BACnetSpecialEvent {
        period,
        list_of_time_values,
        event_priority: input.priority,
    })
}

/// Scan a TimeValue list for any duplicated `time` field. Returns a
/// formatted "HH:MM:SS.HH" so the caller can put the duplicate in the
/// error message.
fn find_duplicate_time(tvs: &[BACnetTimeValue]) -> Option<String> {
    let mut seen = std::collections::HashSet::new();
    for tv in tvs {
        let key = (
            tv.time.hour,
            tv.time.minute,
            tv.time.second,
            tv.time.hundredths,
        );
        if !seen.insert(key) {
            return Some(format!(
                "{:02}:{:02}:{:02}.{:02}",
                tv.time.hour, tv.time.minute, tv.time.second, tv.time.hundredths
            ));
        }
    }
    None
}

fn build_period(input: &PeriodInput) -> Result<SpecialEventPeriod, String> {
    match input {
        PeriodInput::Date(s) => Ok(SpecialEventPeriod::CalendarEntry(
            BACnetCalendarEntry::Date(parse_concrete_date(s)?),
        )),
        PeriodInput::WeekNDay(s) => Ok(SpecialEventPeriod::CalendarEntry(
            BACnetCalendarEntry::WeekNDay(parse_week_n_day(s)?),
        )),
    }
}

// ─── parsers ────────────────────────────────────────────────────────────────

/// Parse `HH:MM`, `HH:MM:SS`, or `HH:MM:SS.HH` (with hundredths). The
/// hundredths form round-trips with `format_time`, which renders non-zero
/// hundredths so read-modify-write loops on existing schedules don't
/// silently truncate sub-second precision.
fn parse_time(s: &str) -> Result<Time, String> {
    let (head, hundredths) = match s.split_once('.') {
        Some((h, frac)) => {
            let hh: u8 = frac
                .parse()
                .map_err(|_| format!("time '{s}': bad hundredths"))?;
            if hh > 99 {
                return Err(format!("time '{s}': hundredths {hh} out of 0..=99"));
            }
            (h, hh)
        }
        None => (s, 0u8),
    };
    let parts: Vec<&str> = head.split(':').collect();
    if !(2..=3).contains(&parts.len()) {
        return Err(format!(
            "time '{s}' must be 'HH:MM', 'HH:MM:SS', or 'HH:MM:SS.HH'"
        ));
    }
    if hundredths != 0 && parts.len() != 3 {
        return Err(format!(
            "time '{s}': hundredths require the 'HH:MM:SS.HH' form"
        ));
    }
    let hour: u8 = parts[0]
        .parse()
        .map_err(|_| format!("time '{s}': bad hour"))?;
    let minute: u8 = parts[1]
        .parse()
        .map_err(|_| format!("time '{s}': bad minute"))?;
    let second: u8 = if parts.len() == 3 {
        parts[2]
            .parse()
            .map_err(|_| format!("time '{s}': bad second"))?
    } else {
        0
    };
    if hour > 23 || minute > 59 || second > 59 {
        return Err(format!("time '{s}': field out of range"));
    }
    Ok(Time {
        hour,
        minute,
        second,
        hundredths,
    })
}

/// Parse a concrete `YYYY-MM-DD` (with optional `-Mon`..`-Sun` suffix).
/// Pattern dates (sentinel month/day) are deferred to v2 because the
/// vocabulary (odd / even / last) overlaps with valid concrete strings if
/// we widen this naively. v2 will introduce a separate
/// `{"date_pattern": ...}` variant.
fn parse_concrete_date(s: &str) -> Result<Date, String> {
    let (date_part, dow) = match s.rfind('-') {
        // YYYY-MM-DD-Mon → split off the Mon
        Some(i) if dow_index(&s[i + 1..]).is_some() => (&s[..i], dow_index(&s[i + 1..]).unwrap()),
        _ => (s, Date::UNSPECIFIED),
    };
    let parts: Vec<&str> = date_part.split('-').collect();
    if parts.len() != 3 {
        return Err(format!(
            "date '{s}' must be 'YYYY-MM-DD' (optionally with '-Mon..-Sun' suffix)"
        ));
    }
    let year_full: u16 = parts[0]
        .parse()
        .map_err(|_| format!("date '{s}': bad year"))?;
    if !(1900..=2155).contains(&year_full) {
        return Err(format!("date '{s}': year {year_full} outside 1900..=2155"));
    }
    let month: u8 = parts[1]
        .parse()
        .map_err(|_| format!("date '{s}': bad month"))?;
    if !(1..=12).contains(&month) {
        return Err(format!(
            "date '{s}': month {month} not in 1..=12 (sentinel patterns deferred to v2)"
        ));
    }
    let day: u8 = parts[2]
        .parse()
        .map_err(|_| format!("date '{s}': bad day"))?;
    if !(1..=31).contains(&day) {
        return Err(format!(
            "date '{s}': day {day} not in 1..=31 (sentinel patterns deferred to v2)"
        ));
    }
    // Reject impossible calendar days (Feb 30, Apr 31, etc.). Many devices
    // reject these on the wire, so dry-runs that succeed here would mislead
    // callers about real-write outcomes.
    let dim = days_in_month(year_full, month);
    if day > dim {
        return Err(format!(
            "date '{s}': day {day} invalid for {year_full}-{month:02} (max {dim})"
        ));
    }
    // If a weekday suffix was supplied, verify it matches the actual
    // calendar weekday. A mismatched suffix produces a Date whose
    // constraints are internally inconsistent — schedules built around
    // it may never trigger.
    if dow != Date::UNSPECIFIED {
        let actual = iso_weekday(year_full, month, day);
        if dow != actual {
            return Err(format!(
                "date '{s}': day-of-week suffix doesn't match calendar (computed {}, supplied {})",
                weekday_name(actual),
                weekday_name(dow),
            ));
        }
    }
    Ok(Date {
        year: (year_full - 1900) as u8,
        month,
        day,
        day_of_week: dow,
    })
}

fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// ISO weekday: 1=Mon..7=Sun. Matches BACnet `Date.day_of_week`. Computed
/// via Zeller's congruence (Gregorian).
fn iso_weekday(year: u16, month: u8, day: u8) -> u8 {
    let (y, m) = if month < 3 {
        (year as i32 - 1, month as i32 + 12)
    } else {
        (year as i32, month as i32)
    };
    let k = y % 100;
    let j = y / 100;
    // h: 0=Sat, 1=Sun, 2=Mon..6=Fri
    let h = (day as i32 + (13 * (m + 1)) / 5 + k + k / 4 + j / 4 + 5 * j).rem_euclid(7);
    match h {
        0 => 6, // Sat
        1 => 7, // Sun
        2 => 1, // Mon
        3 => 2, // Tue
        4 => 3, // Wed
        5 => 4, // Thu
        6 => 5, // Fri
        _ => unreachable!("rem_euclid 7"),
    }
}

fn weekday_name(d: u8) -> &'static str {
    match d {
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        6 => "Sat",
        7 => "Sun",
        _ => "?",
    }
}

fn dow_index(name: &str) -> Option<u8> {
    match name {
        "Mon" => Some(1),
        "Tue" => Some(2),
        "Wed" => Some(3),
        "Thu" => Some(4),
        "Fri" => Some(5),
        "Sat" => Some(6),
        "Sun" => Some(7),
        _ => None,
    }
}

/// Parse `month/week/dow` matching `format_week_n_day` output. Each field
/// accepts `*` for "any". `month` accepts `odd` / `even` (sentinels 13/14).
/// `dow` accepts the three-letter weekday name. `week` accepts 1..=6.
fn parse_week_n_day(s: &str) -> Result<BACnetWeekNDay, String> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 3 {
        return Err(format!("week_n_day '{s}' must be 'month/week/dow'"));
    }
    let month = match parts[0] {
        "*" => BACnetWeekNDay::ANY,
        "odd" => 13,
        "even" => 14,
        n => n
            .parse::<u8>()
            .map_err(|_| format!("week_n_day '{s}': bad month"))?,
    };
    if month != BACnetWeekNDay::ANY && !(1..=14).contains(&month) {
        return Err(format!(
            "week_n_day '{s}': month {month} not in 1..=14 (or 'odd', 'even', '*')"
        ));
    }
    let week = match parts[1] {
        "*" => BACnetWeekNDay::ANY,
        n => n
            .parse::<u8>()
            .map_err(|_| format!("week_n_day '{s}': bad week"))?,
    };
    if week != BACnetWeekNDay::ANY && !(1..=6).contains(&week) {
        return Err(format!(
            "week_n_day '{s}': week {week} not in 1..=6 (or '*')"
        ));
    }
    let dow = match parts[2] {
        "*" => BACnetWeekNDay::ANY,
        name => dow_index(name)
            .ok_or_else(|| format!("week_n_day '{s}': day-of-week '{name}' not Mon..Sun or '*'"))?,
    };
    Ok(BACnetWeekNDay {
        month,
        week_of_month: week,
        day_of_week: dow,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_time_short_form() {
        let t = parse_time("08:30").unwrap();
        assert_eq!(t.hour, 8);
        assert_eq!(t.minute, 30);
        assert_eq!(t.second, 0);
        assert_eq!(t.hundredths, 0);
    }

    #[test]
    fn parse_time_long_form() {
        let t = parse_time("23:59:59").unwrap();
        assert_eq!((t.hour, t.minute, t.second), (23, 59, 59));
    }

    #[test]
    fn parse_time_rejects_out_of_range() {
        assert!(parse_time("24:00").is_err());
        assert!(parse_time("12:60").is_err());
        assert!(parse_time("12:00:60").is_err());
    }

    #[test]
    fn parse_time_rejects_garbage() {
        assert!(parse_time("not-a-time").is_err());
        assert!(parse_time("12").is_err());
    }

    #[test]
    fn parse_concrete_date_no_dow() {
        let d = parse_concrete_date("2026-12-25").unwrap();
        assert_eq!(d.year, 126);
        assert_eq!(d.month, 12);
        assert_eq!(d.day, 25);
        assert_eq!(d.day_of_week, Date::UNSPECIFIED);
    }

    #[test]
    fn parse_concrete_date_with_dow() {
        let d = parse_concrete_date("2026-12-25-Fri").unwrap();
        assert_eq!(d.year, 126);
        assert_eq!(d.month, 12);
        assert_eq!(d.day, 25);
        assert_eq!(d.day_of_week, 5);
    }

    #[test]
    fn parse_concrete_date_rejects_year_out_of_range() {
        assert!(parse_concrete_date("1899-01-01").is_err());
        assert!(parse_concrete_date("2200-01-01").is_err());
    }

    #[test]
    fn parse_concrete_date_rejects_sentinel_month() {
        // Pattern dates (odd/even months) deferred to v2 — must error
        // explicitly so an agent doesn't get a silent encoding to month 13.
        let err = parse_concrete_date("****-13-01").unwrap_err();
        assert!(err.contains("year"));
    }

    #[test]
    fn parse_week_n_day_concrete() {
        let w = parse_week_n_day("12/1/Mon").unwrap();
        assert_eq!(w.month, 12);
        assert_eq!(w.week_of_month, 1);
        assert_eq!(w.day_of_week, 1);
    }

    #[test]
    fn parse_week_n_day_with_wildcards_and_sentinels() {
        let w = parse_week_n_day("odd/*/Sun").unwrap();
        assert_eq!(w.month, 13);
        assert_eq!(w.week_of_month, BACnetWeekNDay::ANY);
        assert_eq!(w.day_of_week, 7);
        let w2 = parse_week_n_day("*/*/*").unwrap();
        assert_eq!(w2.month, BACnetWeekNDay::ANY);
        assert_eq!(w2.week_of_month, BACnetWeekNDay::ANY);
        assert_eq!(w2.day_of_week, BACnetWeekNDay::ANY);
    }

    #[test]
    fn parse_week_n_day_rejects_bad_dow() {
        assert!(parse_week_n_day("12/1/Funday").is_err());
    }

    #[test]
    fn parse_week_n_day_rejects_wrong_part_count() {
        assert!(parse_week_n_day("12/1").is_err());
        assert!(parse_week_n_day("12/1/Mon/extra").is_err());
    }

    // ─── Codex callout regressions (PR #13) ─────────────────────────────────

    #[test]
    fn parse_time_accepts_hundredths() {
        let t = parse_time("08:30:00.50").unwrap();
        assert_eq!((t.hour, t.minute, t.second, t.hundredths), (8, 30, 0, 50));
    }

    #[test]
    fn parse_time_rejects_hundredths_without_seconds() {
        // Hundredths only make sense alongside seconds; reject 'HH:MM.HH'
        // so we don't silently lose the precision.
        assert!(parse_time("08:30.50").is_err());
    }

    #[test]
    fn parse_time_rejects_oversize_hundredths() {
        assert!(parse_time("08:30:00.100").is_err());
    }

    #[test]
    fn parse_time_round_trips_hundredths_with_format() {
        // Mirrors src/mcp/schedules.rs::format_time output for non-zero
        // hundredths — read-modify-write loops must be lossless.
        let t = Time {
            hour: 8,
            minute: 30,
            second: 0,
            hundredths: 50,
        };
        let rendered = format!(
            "{:02}:{:02}:{:02}.{:02}",
            t.hour, t.minute, t.second, t.hundredths
        );
        let parsed = parse_time(&rendered).unwrap();
        assert_eq!(
            (parsed.hour, parsed.minute, parsed.second, parsed.hundredths),
            (t.hour, t.minute, t.second, t.hundredths),
        );
    }

    #[test]
    fn parse_concrete_date_rejects_feb_30() {
        let err = parse_concrete_date("2026-02-30").unwrap_err();
        assert!(err.contains("invalid for"), "got: {err}");
    }

    #[test]
    fn parse_concrete_date_rejects_apr_31() {
        let err = parse_concrete_date("2026-04-31").unwrap_err();
        assert!(err.contains("invalid for"), "got: {err}");
    }

    #[test]
    fn parse_concrete_date_accepts_feb_29_in_leap_year() {
        let d = parse_concrete_date("2024-02-29").unwrap();
        assert_eq!((d.month, d.day), (2, 29));
    }

    #[test]
    fn parse_concrete_date_rejects_feb_29_in_non_leap_year() {
        let err = parse_concrete_date("2026-02-29").unwrap_err();
        assert!(err.contains("invalid for"), "got: {err}");
    }

    #[test]
    fn parse_concrete_date_rejects_wrong_weekday_suffix() {
        // 2026-12-25 is a Friday, not a Monday.
        let err = parse_concrete_date("2026-12-25-Mon").unwrap_err();
        assert!(err.contains("day-of-week"), "got: {err}");
    }

    #[test]
    fn parse_concrete_date_accepts_correct_weekday_suffix() {
        let d = parse_concrete_date("2026-12-25-Fri").unwrap();
        assert_eq!(d.day_of_week, 5);
    }

    #[test]
    fn iso_weekday_known_dates() {
        // Spot-check a few well-known calendar dates.
        // 2026-01-01 was a Thursday.
        assert_eq!(iso_weekday(2026, 1, 1), 4);
        // 2024-02-29 was a Thursday (leap-day edge).
        assert_eq!(iso_weekday(2024, 2, 29), 4);
        // 2000-01-01 was a Saturday (Y2K leap-century corner).
        assert_eq!(iso_weekday(2000, 1, 1), 6);
        // 1999-12-31 was a Friday.
        assert_eq!(iso_weekday(1999, 12, 31), 5);
    }

    #[test]
    fn null_value_requires_literal_null() {
        let bad = TimeValueInput {
            time: "08:00".to_string(),
            value: ScheduleValueInput::Null(serde_json::json!(5)),
        };
        let err = build_time_value(&bad).unwrap_err();
        assert!(err.contains("literal null"), "got: {err}");

        let good = TimeValueInput {
            time: "08:00".to_string(),
            value: ScheduleValueInput::Null(serde_json::Value::Null),
        };
        assert!(build_time_value(&good).is_ok());
    }

    #[test]
    fn duplicate_times_rejected_in_event_list() {
        let e = ExceptionInput {
            period: PeriodInput::Date("2026-12-25-Fri".to_string()),
            time_values: vec![
                TimeValueInput {
                    time: "08:00".to_string(),
                    value: ScheduleValueInput::Real(72.0),
                },
                TimeValueInput {
                    time: "08:00".to_string(),
                    value: ScheduleValueInput::Real(75.0),
                },
            ],
            priority: 10,
        };
        let err = build_special_event(&e).unwrap_err();
        assert!(err.contains("duplicate time"), "got: {err}");
    }
}
