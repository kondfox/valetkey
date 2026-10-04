//! Making untrusted text safe to show a human (§6.10). Target ids, hosts, paths and SQL in an
//! approval prompt or an `allow` diff may come from the agent, so they must not be able to hide
//! or disguise anything on the terminal.

/// Escapes everything that could change how the terminal shows the text: control characters
/// (ANSI escapes start with one), bidi overrides and isolates, and zero-width characters. Each
/// becomes a visible `\u{…}` escape. Other text is unchanged.
pub fn for_display(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if needs_escape(c) {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether the text contains non-ASCII characters. Identifiers that do get flagged, because
/// look-alike letters can disguise one name as another.
pub fn has_non_ascii(text: &str) -> bool {
    !text.is_ascii()
}

fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200b}'..='\u{200f}'   // zero-width space/joiners, LRM, RLM
            | '\u{202a}'..='\u{202e}' // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{feff}'              // zero-width no-break space / BOM
            | '\u{00ad}'              // soft hyphen
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_terminal_tricks() {
        assert_eq!(for_display("plain host-1.example"), "plain host-1.example");
        assert_eq!(for_display("a\u{1b}[2Jb"), "a\\u{001b}[2Jb");
        assert_eq!(for_display("x\ny"), "x\\u{000a}y");
        assert_eq!(for_display("admin\u{202e}txt.exe"), "admin\\u{202e}txt.exe");
        assert_eq!(for_display("pro\u{200b}d"), "pro\\u{200b}d");
    }

    #[test]
    fn flags_non_ascii() {
        assert!(!has_non_ascii("staging-app"));
        assert!(has_non_ascii("st\u{0430}ging-app")); // Cyrillic а
    }
}
