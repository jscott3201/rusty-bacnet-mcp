use bacnet_services::rpm::{ReadPropertyMultipleACK, ReadResultElement};
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::primitives::ObjectIdentifier;

use crate::mcp::value_format::compact_json_value;
use crate::parse::{decode_raw_property_to_json_with_context, object_type_name, property_name};

const MAX_COMPACT_RPM_FIELDS_PER_OBJECT: usize = 64;
const MAX_COMPACT_RPM_TOTAL_FIELDS: usize = 512;

pub(super) fn format_compact_object_list(
    device_instance: u32,
    oids: &[ObjectIdentifier],
    total_count: usize,
) -> String {
    let mut groups = std::collections::BTreeMap::<String, Vec<u32>>::new();
    for oid in oids {
        groups
            .entry(object_type_name(oid.object_type()))
            .or_default()
            .push(oid.instance_number());
    }

    let shown = if total_count > oids.len() {
        format!(" (showing first {})", oids.len())
    } else {
        String::new()
    };
    let mut out =
        format!("Device {device_instance} has {total_count} object(s){shown}; names omitted:\n");
    for (obj_type, mut instances) in groups {
        instances.sort_unstable();
        instances.dedup();
        out.push_str(&format!(
            "  {obj_type}: {}\n",
            format_instance_ranges(&instances)
        ));
    }
    out.push_str("Set include_names=true to fetch object-name values.\n");
    out
}

pub(super) fn format_compact_rpm_ack(ack: &ReadPropertyMultipleACK) -> String {
    if ack.list_of_read_access_results.is_empty() {
        return "RPM compact: no results\n".to_string();
    }

    let mut stats = RpmStats::from_ack(ack);
    let mut out = format!(
        "RPM compact: {} object(s), {} value(s), {} error(s), {} missing\n",
        stats.objects, stats.values, stats.errors, stats.missing
    );
    for result in &ack.list_of_read_access_results {
        let oid = result.object_identifier;
        out.push_str(&format!(
            "  {}:{}",
            object_type_name(oid.object_type()),
            oid.instance_number()
        ));
        if result.list_of_results.is_empty() {
            out.push_str(" (no properties)\n");
            continue;
        }
        let mut shown_for_object = 0usize;
        let mut omitted_for_object = 0usize;
        for elem in &result.list_of_results {
            if stats.rendered_fields >= MAX_COMPACT_RPM_TOTAL_FIELDS
                || shown_for_object >= MAX_COMPACT_RPM_FIELDS_PER_OBJECT
            {
                omitted_for_object += 1;
                continue;
            }
            out.push(' ');
            out.push_str(&format!(
                "{}={}",
                property_label(elem.property_identifier, elem.property_array_index),
                compact_result_value(elem)
            ));
            shown_for_object += 1;
            stats.rendered_fields += 1;
        }
        if omitted_for_object > 0 {
            out.push_str(&format!(
                " ... omitted {omitted_for_object} property result(s)"
            ));
        }
        out.push('\n');
    }
    out
}

#[derive(Default)]
struct RpmStats {
    objects: usize,
    values: usize,
    errors: usize,
    missing: usize,
    rendered_fields: usize,
}

impl RpmStats {
    fn from_ack(ack: &ReadPropertyMultipleACK) -> Self {
        let mut stats = Self {
            objects: ack.list_of_read_access_results.len(),
            ..Self::default()
        };
        for result in &ack.list_of_read_access_results {
            for elem in &result.list_of_results {
                if elem.error.is_some() {
                    stats.errors += 1;
                } else if elem.property_value.is_some() {
                    stats.values += 1;
                } else {
                    stats.missing += 1;
                }
            }
        }
        stats
    }
}

fn property_label(property: PropertyIdentifier, array_index: Option<u32>) -> String {
    let idx = array_index.map(|i| format!("[{i}]")).unwrap_or_default();
    format!("{}{idx}", property_name(property))
}

fn compact_result_value(elem: &ReadResultElement) -> String {
    if let Some((class, code)) = elem.error {
        return format!("err({class:?}/{code:?})");
    }
    let Some(bytes) = &elem.property_value else {
        return "missing".into();
    };
    let decoded = decode_raw_property_to_json_with_context(bytes, elem.property_identifier);
    compact_json_value(&decoded)
}

fn format_instance_ranges(instances: &[u32]) -> String {
    if instances.is_empty() {
        return String::new();
    }

    let mut parts = Vec::new();
    let mut start = instances[0];
    let mut prev = instances[0];
    for &n in &instances[1..] {
        if n == prev.saturating_add(1) {
            prev = n;
            continue;
        }
        push_range(&mut parts, start, prev);
        start = n;
        prev = n;
    }
    push_range(&mut parts, start, prev);
    parts.join(",")
}

fn push_range(parts: &mut Vec<String>, start: u32, end: u32) {
    if start == end {
        parts.push(start.to_string());
    } else {
        parts.push(format!("{start}-{end}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_services::rpm::{ReadAccessResult, ReadPropertyMultipleACK, ReadResultElement};
    use bacnet_types::enums::{ObjectType, PropertyIdentifier};

    #[test]
    fn compact_object_list_groups_types_ranges_and_truncation() {
        let oids = vec![
            ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap(),
            ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 2).unwrap(),
            ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 3).unwrap(),
            ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 5).unwrap(),
            ObjectIdentifier::new(ObjectType::BINARY_VALUE, 2).unwrap(),
            ObjectIdentifier::new(ObjectType::DEVICE, 1234).unwrap(),
        ];
        let out = format_compact_object_list(1234, &oids, 10);
        assert!(out.contains("Device 1234 has 10 object(s) (showing first 6)"));
        assert!(out.contains("  analog-input: 1-3,5\n"));
        assert!(out.contains("  binary-value: 2\n"));
        assert!(out.contains("  device: 1234\n"));
        assert!(out.contains("names omitted"));
        assert!(out.contains("include_names=true"));
    }

    #[test]
    fn compact_object_list_sorts_and_dedups_instances() {
        let oids = vec![
            ObjectIdentifier::new(ObjectType::ANALOG_OUTPUT, 4).unwrap(),
            ObjectIdentifier::new(ObjectType::ANALOG_OUTPUT, 2).unwrap(),
            ObjectIdentifier::new(ObjectType::ANALOG_OUTPUT, 3).unwrap(),
            ObjectIdentifier::new(ObjectType::ANALOG_OUTPUT, 4).unwrap(),
        ];
        let out = format_compact_object_list(9, &oids, 4);
        assert!(out.contains("  analog-output: 2-4\n"));
        assert!(!out.contains("showing first"));
    }

    #[test]
    fn compact_rpm_ack_omits_fields_after_per_object_cap() {
        let count = MAX_COMPACT_RPM_FIELDS_PER_OBJECT + 2;
        let ack = ReadPropertyMultipleACK {
            list_of_read_access_results: vec![ReadAccessResult {
                object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap(),
                list_of_results: (1..=count)
                    .map(|idx| ReadResultElement {
                        property_identifier: PropertyIdentifier::PRESENT_VALUE,
                        property_array_index: Some(idx as u32),
                        property_value: None,
                        error: None,
                    })
                    .collect(),
            }],
        };

        let out = format_compact_rpm_ack(&ack);
        assert!(out.contains(&format!(
            "1 object(s), 0 value(s), 0 error(s), {count} missing"
        )));
        assert!(out.contains("present-value[64]=missing"));
        assert!(!out.contains("present-value[65]=missing"));
        assert!(out.contains("omitted 2 property result(s)"));
    }

    #[test]
    fn format_instance_ranges_compacts_adjacent_values() {
        assert_eq!(format_instance_ranges(&[1, 2, 3, 5, 7, 8]), "1-3,5,7-8");
        assert_eq!(format_instance_ranges(&[42]), "42");
        assert_eq!(format_instance_ranges(&[]), "");
    }
}
