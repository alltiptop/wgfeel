use serde_json::Value;

const INVALID: &str = "invalid Management list response";

pub(super) fn render(kind: &str, body: &[u8]) -> Result<String, &'static str> {
    let value: Value = serde_json::from_slice(body).map_err(|_| INVALID)?;
    let (collection, headings): (_, &[&str]) = match kind {
        "user" => ("users", &["ID", "DEVICES"]),
        "device" => ("devices", &["ID", "NAME", "DESCRIPTION"]),
        "node" => (
            "gateways",
            &["ID", "HOSTNAME", "ENDPOINTS", "USERS", "AUTO USERS"],
        ),
        _ => return Err(INVALID),
    };
    let items = value[collection].as_array().ok_or(INVALID)?;
    if items.is_empty() {
        let label = if kind == "node" { "nodes" } else { collection };
        return Ok(format!("No {label}.\n"));
    }
    let mut rows = Vec::with_capacity(items.len() + 1);
    rows.push(
        headings
            .iter()
            .map(|heading| (*heading).to_owned())
            .collect::<Vec<_>>(),
    );
    for item in items {
        let row = match kind {
            "user" => vec![required(&item["id"])?, count(&item["devices"])?],
            "device" => vec![
                required(&item["id"])?,
                optional(&item["metadata"]["name"])?,
                optional(&item["metadata"]["description"])?,
            ],
            "node" => vec![
                required(&item["recipient"])?,
                optional(&item["hostname"])?,
                endpoints(&item["endpoints"])?,
                count(&item["users"])?,
                match &item["auto_users"] {
                    Value::Null | Value::Bool(false) => "no",
                    Value::Bool(true) => "yes",
                    _ => return Err(INVALID),
                }
                .into(),
            ],
            _ => unreachable!(),
        };
        rows.push(row);
    }
    let widths: Vec<_> = (0..headings.len())
        .map(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut output = String::new();
    for row in rows {
        for (column, cell) in row.iter().enumerate() {
            output.push_str(cell);
            if column + 1 < headings.len() {
                output.extend(std::iter::repeat_n(
                    ' ',
                    widths[column] - cell.chars().count() + 2,
                ));
            }
        }
        output.push('\n');
    }
    Ok(output)
}

fn count(value: &Value) -> Result<String, &'static str> {
    Ok(value.as_array().ok_or(INVALID)?.len().to_string())
}
fn endpoints(value: &Value) -> Result<String, &'static str> {
    let addresses = value.as_array().ok_or(INVALID)?;
    if addresses.is_empty() {
        return Ok("-".into());
    }
    Ok(addresses
        .iter()
        .map(required)
        .collect::<Result<Vec<_>, _>>()?
        .join(", "))
}
fn required(value: &Value) -> Result<String, &'static str> {
    Ok(cell(value.as_str().ok_or(INVALID)?))
}
fn optional(value: &Value) -> Result<String, &'static str> {
    if value.is_null() {
        Ok("-".into())
    } else {
        required(value)
    }
}
fn cell(text: &str) -> String {
    let mut safe = crate::output::escape(text);
    if safe.chars().count() > 72 {
        safe = safe.chars().take(71).collect();
        safe.push('…');
    }
    safe
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn node_table_includes_hostname_and_both_address_families() {
        let body = json!({"gateways":[{"recipient":"node-id", "hostname":"vps1", "endpoints":["203.0.113.4:55125", "[2001:db8::4]:55125"], "users":[], "auto_users":true}]});
        let screen = render("node", &serde_json::to_vec(&body).unwrap()).unwrap();
        for text in [
            "HOSTNAME",
            "ENDPOINTS",
            "vps1",
            "203.0.113.4:55125",
            "[2001:db8::4]:55125",
        ] {
            assert!(screen.contains(text), "missing {text}");
        }
    }

    #[test]
    fn unicode_metadata_is_aligned_and_missing_values_are_explicit() {
        let body = json!({"devices":[
            {"id":"phone","metadata":{"name":"Телефон","description":null}},
            {"id":"pc","metadata":{"name":null,"description":"Рабочий"}}
        ]});
        let table = render("device", &serde_json::to_vec(&body).unwrap()).unwrap();
        let mut rows = table.lines();
        let mut header_columns = None;
        for cells in [
            ["ID", "NAME", "DESCRIPTION"],
            ["phone", "Телефон", "-"],
            ["pc", "-", "Рабочий"],
        ] {
            let row = rows.next().unwrap();
            assert!(row.split_whitespace().eq(cells));
            let columns = cells.map(|cell| row[..row.find(cell).unwrap()].chars().count());
            assert_eq!(columns, *header_columns.get_or_insert(columns));
        }
        assert!(rows.next().is_none());
    }

    #[test]
    fn terminal_controls_are_escaped_and_long_values_are_bounded() {
        assert_eq!(cell("a\n\t\x1b[31m\u{202e}"), "a\\n\\t\\u{1b}[31m\\u{202e}");
        let long = cell(&"я".repeat(100));
        assert_eq!(long.chars().count(), 72);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn empty_lists_and_invalid_responses_are_distinguished() {
        for (kind, collection) in [
            ("user", "users"),
            ("device", "devices"),
            ("node", "gateways"),
        ] {
            let body = serde_json::to_vec(&json!({collection:[]})).unwrap();
            let label = if kind == "node" { "nodes" } else { collection };
            assert_eq!(render(kind, &body).unwrap(), format!("No {label}.\n"));
            assert!(render(kind, br#"{"error":"unauthorized"}"#).is_err());
        }
    }
}
