//! A minimal dotenv reader: finds one key, with **no variable expansion**, so the result never
//! depends on the broker's environment or on other keys.
//!
//! Supported: `KEY=value`, `export KEY=value`, `'single quoted'` (literal), `"double quoted"`
//! (escapes `\n`, `\r`, `\t`, `\"`, `\\`), unquoted values with a trailing ` # comment`, blank
//! lines and `#` comments. The last definition of a key wins, like a shell.

/// The value of `key`, if the file defines it.
pub fn lookup(text: &str, key: &str) -> Option<String> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map(str::trim_start).unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else { continue };
        if k.trim_end() == key {
            found = Some(parse_value(v.trim_start()));
        }
    }
    found
}

fn parse_value(v: &str) -> String {
    if let Some(rest) = v.strip_prefix('\'') {
        return rest.split_once('\'').map_or(rest, |(inner, _)| inner).to_owned();
    }
    if let Some(rest) = v.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some(other) => out.push(other),
                    None => break,
                },
                c => out.push(c),
            }
        }
        return out;
    }
    let v = match v.find(" #") {
        Some(i) => &v[..i],
        None => v,
    };
    v.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::lookup;

    #[test]
    fn reads_the_common_forms() {
        let text = "# db\nPOSTGRES_PASSWORD=plain\nexport QUOTED=\"a \\\"b\\\" c\"\nSINGLE='x $HOME y'\nTRAIL=val # comment\nHASH=a#b\n";
        assert_eq!(lookup(text, "POSTGRES_PASSWORD").as_deref(), Some("plain"));
        assert_eq!(lookup(text, "QUOTED").as_deref(), Some("a \"b\" c"));
        assert_eq!(lookup(text, "SINGLE").as_deref(), Some("x $HOME y"));
        assert_eq!(lookup(text, "TRAIL").as_deref(), Some("val"));
        assert_eq!(lookup(text, "HASH").as_deref(), Some("a#b"));
        assert_eq!(lookup(text, "MISSING"), None);
    }

    #[test]
    fn never_expands_variables() {
        let text = "A=one\nB=${A}-$HOME-${PATH}\nC=\"${A}\"\n";
        assert_eq!(lookup(text, "B").as_deref(), Some("${A}-$HOME-${PATH}"));
        assert_eq!(lookup(text, "C").as_deref(), Some("${A}"));
    }

    #[test]
    fn last_definition_wins() {
        assert_eq!(lookup("K=1\nK=2\n", "K").as_deref(), Some("2"));
    }
}
