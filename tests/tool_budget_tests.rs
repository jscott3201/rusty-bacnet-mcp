//! MCP tool-list token budget regression tests.

#![cfg(feature = "mcp")]

const MCP_MOD_RS: &str = include_str!("../src/mcp/mod.rs");
const MAX_DESCRIPTION_CHARS: usize = 96;
const MAX_TOTAL_CHARS: usize = 3_000;
const MAX_TOTAL_WORDS: usize = 420;

#[test]
fn mcp_tool_descriptions_stay_compact() {
    let descriptions = tool_descriptions(MCP_MOD_RS);
    assert!(
        descriptions.len() >= 30,
        "parsed only {} tool descriptions; parser likely drifted",
        descriptions.len()
    );

    let total_chars: usize = descriptions.iter().map(|d| d.len()).sum();
    let total_words: usize = descriptions
        .iter()
        .map(|d| d.split_whitespace().count())
        .sum();

    assert!(
        total_chars <= MAX_TOTAL_CHARS,
        "tool descriptions use {total_chars} chars; cap is {MAX_TOTAL_CHARS}"
    );
    assert!(
        total_words <= MAX_TOTAL_WORDS,
        "tool descriptions use {total_words} words; cap is {MAX_TOTAL_WORDS}"
    );

    for description in descriptions {
        assert!(
            description.len() <= MAX_DESCRIPTION_CHARS,
            "tool description too long ({} chars): {description}",
            description.len()
        );
    }
}

fn tool_descriptions(src: &str) -> Vec<String> {
    let mut descriptions = Vec::new();
    let mut rest = src;
    while let Some(start) = rest.find("description") {
        rest = &rest[start + "description".len()..];
        let Some(eq) = rest.find('=') else {
            continue;
        };
        rest = &rest[eq + 1..];
        let trimmed = rest.trim_start();
        let Some(after_quote) = trimmed.strip_prefix('"') else {
            rest = trimmed;
            continue;
        };
        let Some(end) = after_quote.find('"') else {
            break;
        };
        descriptions.push(after_quote[..end].to_string());
        rest = &after_quote[end + 1..];
    }
    descriptions
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    #[test]
    fn parser_handles_multiline_attributes() {
        let src = r#"
            #[tool(
                description = "Short read tool."
            )]
            async fn read_it(&self) {}

            #[tool(description = "Another concise tool.")]
            async fn write_it(&self) {}
        "#;
        assert_eq!(
            tool_descriptions(src),
            vec!["Short read tool.", "Another concise tool."]
        );
    }
}
