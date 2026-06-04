//! Shared compact display helpers for MCP tool responses.

const MAX_COMPACT_VALUE_CHARS: usize = 160;
const MAX_LIST_PREVIEW_ITEMS: usize = 4;

pub(crate) fn compact_json_value(decoded: &serde_json::Value) -> String {
    if decoded.is_null() {
        return "null".into();
    }
    if let Some(name) = decoded.get("name").and_then(|v| v.as_str()) {
        return truncate_text(name);
    }
    let ty = decoded.get("type").and_then(|v| v.as_str());
    if let Some(value) = decoded.get("value") {
        return compact_json_inner(value, ty);
    }
    compact_json_inner(decoded, None)
}

fn compact_json_inner(value: &serde_json::Value, value_type: Option<&str>) -> String {
    match value {
        serde_json::Value::Null => "null".into(),
        serde_json::Value::Bool(_) | serde_json::Value::Number(_) => value.to_string(),
        serde_json::Value::String(s) => compact_string_value(s, value_type),
        serde_json::Value::Array(items) => compact_json_array(items),
        serde_json::Value::Object(_) => truncate_text(&value.to_string()),
    }
}

fn compact_string_value(value: &str, value_type: Option<&str>) -> String {
    match value_type {
        Some("string") | None => quote_json_string(&truncate_text(value)),
        _ => truncate_text(value),
    }
}

fn compact_json_array(items: &[serde_json::Value]) -> String {
    if items.is_empty() {
        return "list[0]".into();
    }
    let mut preview: Vec<String> = items
        .iter()
        .take(MAX_LIST_PREVIEW_ITEMS)
        .map(compact_json_value)
        .collect();
    if items.len() > MAX_LIST_PREVIEW_ITEMS {
        preview.push(format!("+{} more", items.len() - MAX_LIST_PREVIEW_ITEMS));
    }
    format!("list[{}]({})", items.len(), preview.join(","))
}

fn quote_json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"<invalid>\"".into())
}

fn truncate_text(raw: &str) -> String {
    if raw.chars().count() <= MAX_COMPACT_VALUE_CHARS {
        return raw.to_string();
    }
    let keep = MAX_COMPACT_VALUE_CHARS.saturating_sub(3);
    let mut out: String = raw.chars().take(keep).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_json_value_prefers_enum_names() {
        let decoded = serde_json::json!({
            "type": "enumerated",
            "value": 0,
            "name": "no-fault-detected"
        });
        assert_eq!(compact_json_value(&decoded), "no-fault-detected");
    }

    #[test]
    fn compact_json_value_previews_lists() {
        let decoded = serde_json::json!({
            "type": "list",
            "value": [
                {"type": "unsigned", "value": 1},
                {"type": "unsigned", "value": 2},
                {"type": "unsigned", "value": 3},
                {"type": "unsigned", "value": 4},
                {"type": "unsigned", "value": 5}
            ]
        });
        assert_eq!(compact_json_value(&decoded), "list[5](1,2,3,4,+1 more)");
    }

    #[test]
    fn compact_json_value_truncates_long_strings() {
        let decoded = serde_json::json!({
            "type": "string",
            "value": "a".repeat(MAX_COMPACT_VALUE_CHARS + 10)
        });
        let rendered = compact_json_value(&decoded);
        assert!(rendered.ends_with("...\""));
        assert!(rendered.len() < MAX_COMPACT_VALUE_CHARS + 16);
    }
}
