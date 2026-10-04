//! A small dotenv reader: finds one key, with **no variable expansion**, so the result never
//! depends on the broker's environment or on other keys.
//!
//! Supported: `KEY=value`, `export KEY=value` (space or tab), `'single quoted'` (literal),
//! `"double quoted"` (escapes `\n`, `\r`, `\t`, `\"`, `\\`), quoted values spanning several lines
//! (PEM keys), unquoted values with a trailing ` #` or `\t#` comment, blank lines, `#` comments, a
//! UTF-8 byte-order mark, and CRLF line endings. The last definition of a key wins, like a shell.
//!
//! **Differs from loaders that expand `${VAR}`** (python-dotenv, the `dotenv` npm package): here
//! `${VAR}` stays literal. An unterminated quote anywhere is an error, not a guess.

/// Why a file can't be read reliably.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DotenvError {
    #[error("an unterminated quoted value starts on line {line}")]
    Unterminated { line: usize },
}

/// The value of `key`, if the file defines it.
pub fn lookup(text: &str, key: &str) -> Result<Option<String>, DotenvError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let lines: Vec<&str> = text.lines().collect();
    let mut found = None;
    let mut i = 0;
    while i < lines.len() {
        let start = i;
        let line = lines[i].trim_start_matches([' ', '\t']);
        i += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = strip_export(line);
        let Some((k, rest)) = line.split_once('=') else {
            continue;
        };
        let rest = rest.trim_start_matches([' ', '\t']);
        let value = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => {
                let mut body = rest[1..].to_owned();
                loop {
                    if let Some(v) = parse_quoted(&body, q) {
                        break v;
                    }
                    let Some(next) = lines.get(i) else {
                        return Err(DotenvError::Unterminated { line: start + 1 });
                    };
                    body.push('\n');
                    body.push_str(next);
                    i += 1;
                }
            }
            _ => unquoted(rest),
        };
        if k.trim_end_matches([' ', '\t']) == key {
            found = Some(value);
        }
    }
    Ok(found)
}

fn strip_export(line: &str) -> &str {
    match line.strip_prefix("export") {
        Some(rest) if rest.starts_with([' ', '\t']) => rest.trim_start_matches([' ', '\t']),
        _ => line,
    }
}

/// The value of a quoted body, if its closing quote is present.
fn parse_quoted(body: &str, quote: char) -> Option<String> {
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c == quote => return Some(out),
            '\\' if quote == '"' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => return None,
            },
            c => out.push(c),
        }
    }
    None
}

fn unquoted(v: &str) -> String {
    let mut end = v.len();
    for (i, w) in v.char_indices() {
        if w == '#' && i > 0 && matches!(v.as_bytes()[i - 1], b' ' | b'\t') {
            end = i;
            break;
        }
    }
    v[..end].trim_end_matches([' ', '\t']).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(text: &str, key: &str) -> Option<String> {
        lookup(text, key).unwrap()
    }

    #[test]
    fn reads_the_common_forms() {
        let text = "# db\nPOSTGRES_PASSWORD=plain\nexport QUOTED=\"a \\\"b\\\" c\"\nSINGLE='x $HOME y'\nTRAIL=val # comment\nTAB=val\t# comment\nHASH=a#b\nexport\tTABBED=t\n";
        assert_eq!(get(text, "POSTGRES_PASSWORD").as_deref(), Some("plain"));
        assert_eq!(get(text, "QUOTED").as_deref(), Some("a \"b\" c"));
        assert_eq!(get(text, "SINGLE").as_deref(), Some("x $HOME y"));
        assert_eq!(get(text, "TRAIL").as_deref(), Some("val"));
        assert_eq!(get(text, "TAB").as_deref(), Some("val"));
        assert_eq!(get(text, "HASH").as_deref(), Some("a#b"));
        assert_eq!(get(text, "TABBED").as_deref(), Some("t"));
        assert_eq!(get(text, "MISSING"), None);
    }

    #[test]
    fn never_expands_variables() {
        let text = "A=one\nB=${A}-$HOME-${PATH}\nC=\"${A}\"\n";
        assert_eq!(get(text, "B").as_deref(), Some("${A}-$HOME-${PATH}"));
        assert_eq!(get(text, "C").as_deref(), Some("${A}"));
    }

    #[test]
    fn multi_line_quoted_values_bom_and_crlf() {
        let pem = "\u{feff}KEY=\"-----BEGIN KEY-----\r\nabc\r\n-----END KEY-----\"\r\nNEXT=1\r\n";
        assert_eq!(
            get(pem, "KEY").as_deref(),
            Some("-----BEGIN KEY-----\nabc\n-----END KEY-----")
        );
        assert_eq!(get(pem, "NEXT").as_deref(), Some("1"));
        assert_eq!(
            get("\u{feff}FIRST=yes\n", "FIRST").as_deref(),
            Some("yes"),
            "a BOM doesn't hide the first key"
        );
        assert_eq!(get("S='line1\nline2'\n", "S").as_deref(), Some("line1\nline2"));
    }

    #[test]
    fn unterminated_quotes_are_errors() {
        assert_eq!(
            lookup("OK=1\nBAD=\"never closed\nOTHER=2\n", "OK"),
            Err(DotenvError::Unterminated { line: 2 })
        );
        assert!(lookup("X='open\n", "X").is_err());
    }

    #[test]
    fn last_definition_wins() {
        assert_eq!(get("K=1\nK=2\n", "K").as_deref(), Some("2"));
    }
}
