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

/// Control (Cc), format (Cf), line/paragraph separators (Zl, Zp), plus invisible characters that
/// aren't format characters: variation selectors, the combining grapheme joiner and Hangul fillers.
fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00ad}' | '\u{034f}' | '\u{061c}' | '\u{070f}' | '\u{08e2}'
            | '\u{0600}'..='\u{0605}' | '\u{06dd}' | '\u{0890}'..='\u{0891}'
            | '\u{115f}' | '\u{1160}' | '\u{17b4}' | '\u{17b5}' | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}'
            | '\u{3164}' | '\u{fe00}'..='\u{fe0f}' | '\u{feff}' | '\u{ffa0}' | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}' | '\u{110cd}' | '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}' | '\u{e0000}'..='\u{e0fff}'
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
        assert_eq!(for_display("a\u{2028}b"), "a\\u{2028}b");
        assert_eq!(for_display("tag\u{e0041}"), "tag\\u{e0041}");
        assert_eq!(for_display("x\u{fe0f}"), "x\\u{fe0f}");
        assert_eq!(for_display("h\u{3164}"), "h\\u{3164}");
    }

    #[test]
    fn flags_non_ascii() {
        assert!(!has_non_ascii("staging-app"));
        assert!(has_non_ascii("st\u{0430}ging-app")); // Cyrillic а
    }
}
