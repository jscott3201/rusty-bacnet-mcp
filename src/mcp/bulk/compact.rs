use bacnet_types::primitives::ObjectIdentifier;

use crate::parse::object_type_name;

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
    use bacnet_types::enums::ObjectType;

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
    fn format_instance_ranges_compacts_adjacent_values() {
        assert_eq!(format_instance_ranges(&[1, 2, 3, 5, 7, 8]), "1-3,5,7-8");
        assert_eq!(format_instance_ranges(&[42]), "42");
        assert_eq!(format_instance_ranges(&[]), "");
    }
}
