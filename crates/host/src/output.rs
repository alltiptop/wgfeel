//! Human-readable command results.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::fmt::Write;

pub fn render(title: &str, value: &Value) -> String {
    let mut output = format!("{title}\n");
    fields(&mut output, value, 2);
    output
}

fn fields(output: &mut String, value: &Value, indent: usize) {
    match value {
        Value::Object(object) if !object.is_empty() => {
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_by_key(|(key, _)| match key.as_str() {
                "id" | "node_id" | "recipient" => 0,
                "name" => 1,
                "generation" => 2,
                _ => 3,
            });
            let width = entries
                .iter()
                .map(|(key, _)| label(key).len())
                .max()
                .unwrap_or(0);
            for (key, value) in entries {
                let label = label(key);
                if let Some(text) = scalar(key, value) {
                    writeln!(output, "{:indent$}{label:width$} : {text}", "").unwrap();
                } else {
                    let count = value
                        .as_array()
                        .map(|items| format!(" ({})", items.len()))
                        .unwrap_or_default();
                    writeln!(output, "{:indent$}{label}{count}:", "").unwrap();
                    fields(output, value, indent + 2);
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                if let Some(text) = scalar("", item) {
                    writeln!(output, "{:indent$}- {text}", "").unwrap();
                } else {
                    writeln!(output, "{:indent$}[{}]", "", index + 1).unwrap();
                    fields(output, item, indent + 2);
                }
            }
        }
        _ => writeln!(
            output,
            "{:indent$}{}",
            "",
            scalar("", value).unwrap_or_default()
        )
        .unwrap(),
    }
}

fn scalar(key: &str, value: &Value) -> Option<String> {
    Some(match value {
        Value::Null => "-".into(),
        Value::String(value) => escape(value),
        Value::Bool(value) => if *value { "yes" } else { "no" }.into(),
        Value::Number(value) => value.to_string(),
        Value::Array(items) if items.is_empty() => "none".into(),
        Value::Object(items) if items.is_empty() => "none".into(),
        Value::Array(items) if key.ends_with("public_key") && items.len() == 32 => {
            let bytes = items
                .iter()
                .map(|item| item.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect::<Option<Vec<_>>>()?;
            STANDARD.encode(bytes)
        }
        _ => return None,
    })
}

fn label(key: &str) -> String {
    key.split('_')
        .map(|word| match word {
            "id" => "ID".into(),
            "ip" => "IP".into(),
            "api" => "API".into(),
            "gateway" => "Node".into(),
            "gateways" => "Nodes".into(),
            other => {
                let mut chars = other.chars();
                chars
                    .next()
                    .map(|first| first.to_uppercase().to_string() + chars.as_str())
                    .unwrap_or_default()
            }
        })
        .collect::<Vec<String>>()
        .join(" ")
}

pub fn escape(text: &str) -> String {
    let mut safe = String::new();
    for character in text.chars() {
        if character.is_control()
            || matches!(character, '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            write!(safe, "{}", character.escape_default()).unwrap();
        } else {
            safe.push(character);
        }
    }
    safe
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_keep_nested_data_full_values_and_escape_terminal_controls() {
        let value = json!({"id":"alice", "devices":[{"id":"phone", "metadata":{"name":"Телефон\n\u{1b}[31m", "description":"я".repeat(100)}}], "networks":[], "endpoint":null});
        let text = render("User", &value);
        assert!(text.starts_with("User\n  ID"));
        assert!(text.contains("Devices (1):\n    [1]\n      ID"));
        assert!(text.contains("Телефон\\n\\u{1b}[31m"));
        assert!(text.contains(&"я".repeat(100)));
        assert!(text.contains("Networks : none"));
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn public_keys_are_copyable_wireguard_base64() {
        let text = render(
            "Node",
            &json!({"public_key":vec![42;32], "auto_networks":true}),
        );
        assert!(text.contains(&STANDARD.encode([42; 32])));
        assert!(text.contains("Auto Networks : yes"));
    }
}
