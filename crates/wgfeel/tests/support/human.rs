pub fn summary(bytes: &[u8]) -> serde_json::Value {
    let text = std::str::from_utf8(bytes).unwrap();
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("Local state"));
    let mut result = serde_json::Map::new();
    for line in lines {
        let (label, value) = line.trim().split_once(':').unwrap();
        let key = label.trim().to_ascii_lowercase().replace(' ', "_");
        let value = value.trim();
        let value = match value.parse::<u64>() {
            Ok(number) => number.into(),
            Err(_) => value.into(),
        };
        assert!(result.insert(key, value).is_none());
    }
    result.into()
}
