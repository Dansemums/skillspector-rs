//! P2 (hidden instructions) matchers of `static_patterns_prompt_injection.py`: hidden HTML comments,
//! reference-style comments, zero-width and bidi controls, `data:` blobs and Unicode Tag smuggling.

use crate::matcher::Pat;
use crate::text::line_breaks;
use std::sync::LazyLock;

/// `_P2_IDENTIFIER_START` / `_END`: identifier boundaries without matching mid-word.
const IDENT_START: &str =
    r"(?:(?<![^\W_])|(?<=(?-i:[a-z0-9]))(?=(?-i:[A-Z]))|(?<=(?-i:[A-Z]))(?=(?-i:[A-Z][a-z])))";
const IDENT_END: &str =
    r"(?:(?![^\W_])|(?<=(?-i:[a-z0-9]))(?=(?-i:[A-Z]))|(?<=(?-i:[A-Z]))(?=(?-i:[A-Z][a-z])))";

/// `_P2_COMMENT_KEYWORD` source.
#[must_use]
pub fn comment_keyword_source() -> String {
    format!("(?:{IDENT_START}(?:system|POST|GET|send){IDENT_END}|ignore|instructions?|transmit)")
}

pub const DATA_URI: &str = r"data:text/plain;base64,[A-Za-z0-9+/=]{50,}";
const REFERENCE_OPENING: &str = r"\[//\]:[ \t]*(?:(?:\r\n|\r|\n)[ \t]*)?#";

static KEYWORD: LazyLock<Pat> = LazyLock::new(|| Pat::new(&comment_keyword_source(), "i"));
static OPENING: LazyLock<Pat> = LazyLock::new(|| Pat::new(REFERENCE_OPENING, ""));
static DATA: LazyLock<Pat> = LazyLock::new(|| Pat::new(DATA_URI, "is"));

fn has_keyword(text: &str, start: usize, end: usize) -> bool {
    !KEYWORD.find_in(text, start, end).is_empty()
}

fn char_at(text: &str, i: usize) -> Option<char> {
    text.get(i..).and_then(|t| t.chars().next())
}

/// Hidden comments: `<!--` ... first `--!?>`, when a keyword sits inside. The regex
/// `<!--(?!-?>)(?:(?!--!?>).)*?KW(?:(?!--!?>).)*?--!?>` can only ever span to the first terminator.
#[must_use]
pub fn html_comment_matches(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(rel) = text[pos..].find("<!--") {
        let s = pos + rel;
        let body = s + 4;
        let rest = &text[body..];
        let closes_at_once = rest.starts_with('>') || rest.starts_with("->");
        let terminator = if closes_at_once {
            None
        } else {
            find_terminator(text, body)
        };
        match terminator {
            Some((t, end)) if has_keyword(text, body, t) => {
                out.push((s, end));
                pos = end;
            }
            _ => pos = s + 1,
        }
    }
    out
}

/// First `-->` or `--!>` at or after `from`: (start, end).
fn find_terminator(text: &str, from: usize) -> Option<(usize, usize)> {
    let mut at = from;
    while let Some(rel) = text[at..].find("--") {
        let t = at + rel;
        let tail = &text[t + 2..];
        if tail.starts_with('>') {
            return Some((t, t + 3));
        }
        if tail.starts_with("!>") {
            return Some((t, t + 4));
        }
        at = t + 1;
    }
    None
}

/// `[ \t]+` / `[ \t]*(?:CRLF|CR|LF)[ \t]*` then `(`: the end of a reference title opener at `end`.
fn title_opener(text: &str, end: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let skip = |mut i: usize| {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        i
    };
    let spaces = skip(end);
    if spaces > end && bytes.get(spaces) == Some(&b'(') {
        return Some(spaces + 1);
    }
    let mut i = spaces;
    match bytes.get(i) {
        Some(b'\r') if bytes.get(i + 1) == Some(&b'\n') => i += 2,
        Some(b'\r' | b'\n') => i += 1,
        _ => return None,
    }
    i = skip(i);
    (bytes.get(i) == Some(&b'(')).then_some(i + 1)
}

/// `_reference_comment_matches`: `[//]: # (title)` comments that carry a keyword.
#[must_use]
pub fn reference_comment_matches(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while cursor < text.len() {
        let Some(opening) = OPENING.find_in(text, cursor, text.len()).into_iter().next() else {
            break;
        };
        let destination_start = opening.end - 1;
        let (end, depth) = scan_destination(text, opening.end);
        let valid = depth == 0
            && (end == text.len() || matches!(char_at(text, end), Some(' ' | '\t' | '\r' | '\n')));
        let title = if valid { title_opener(text, end) } else { None };
        let Some(title_start) = title else {
            if valid && has_keyword(text, destination_start, end) {
                out.push((opening.start, end));
            }
            cursor = end.max(opening.end);
            continue;
        };
        let (end, closed) = scan_title(text, title_start);
        let search_end = if closed { end - 1 } else { end };
        if has_keyword(text, destination_start, search_end) {
            out.push((opening.start, end));
        }
        cursor = end.max(title_start);
    }
    out
}

/// Walks the link destination; returns (end, unbalanced depth).
fn scan_destination(text: &str, from: usize) -> (usize, i32) {
    let (mut end, mut depth) = (from, 0);
    while let Some(c) = char_at(text, end) {
        if matches!(c, ' ' | '\t' | '\r' | '\n') || u32::from(c) < 32 || u32::from(c) == 127 {
            break;
        }
        if c == '\\' && matches!(char_at(text, end + 1), Some('\\' | '(' | ')')) {
            end += 2;
            continue;
        }
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            if depth == 0 {
                break;
            }
            depth -= 1;
        }
        end += c.len_utf8();
    }
    (end, depth)
}

/// Walks the parenthesized title; returns (end, closed).
fn scan_title(text: &str, from: usize) -> (usize, bool) {
    let (mut end, mut closed, mut line_has_text) = (from, false, true);
    while let Some(c) = char_at(text, end) {
        if c == '\\' && matches!(char_at(text, end + 1), Some('\\' | '(' | ')')) {
            end += 2;
            line_has_text = true;
            continue;
        }
        if c == ')' {
            end += 1;
            closed = true;
            break;
        }
        if c == '\r' || c == '\n' {
            if !line_has_text {
                break;
            }
            line_has_text = false;
            if c == '\r' && char_at(text, end + 1) == Some('\n') {
                end += 1;
            }
        } else if c != ' ' && c != '\t' {
            line_has_text = true;
        }
        end += 1;
    }
    (end, closed)
}

const VARIATION_SELECTORS: [char; 2] = ['\u{fe0e}', '\u{fe0f}'];

fn is_modifier(c: char) -> bool {
    ('\u{1f3fb}'..='\u{1f3ff}').contains(&c)
}

/// `artifacts._is_emoji_base`.
fn is_emoji_base(c: char) -> bool {
    let cp = u32::from(c);
    (0x1F000..=0x1FAFF).contains(&cp)
        || (0x2600..=0x27BF).contains(&cp)
        || matches!(
            cp,
            0xA9 | 0xAE | 0x203C | 0x2049 | 0x2122 | 0x2139 | 0x3030 | 0x303D
        )
}

/// A ZWJ joining two emoji bases is not hidden text.
fn zwj_joins_emoji(text: &str, offset: usize) -> bool {
    let prev = text[..offset]
        .chars()
        .rev()
        .find(|c| !VARIATION_SELECTORS.contains(c) && !is_modifier(*c));
    let mut next = text[offset + '\u{200d}'.len_utf8()..]
        .chars()
        .skip_while(|c| VARIATION_SELECTORS.contains(c))
        .peekable();
    if next.peek().is_some_and(|c| is_modifier(*c)) {
        next.next();
    }
    prev.is_some_and(is_emoji_base) && next.next().is_some_and(is_emoji_base)
}

/// `_p2_pattern_matches` for the single-character classes: all hits, but after a hit only
/// those past the next line break. `zero_width` adds the BOM and emoji-ZWJ carve-outs.
#[must_use]
pub fn control_char_matches(text: &str, zero_width: bool) -> Vec<(usize, usize)> {
    let is_hit = |c: char| {
        if zero_width {
            crate::whitespace_padding::ZERO_WIDTH_CHARS.contains(&c)
        } else {
            matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        }
    };
    let breaks = line_breaks(text);
    let mut out = Vec::new();
    let mut cursor = 0;
    while cursor < text.len() {
        let Some((rel, c)) = text[cursor..].char_indices().find(|&(_, c)| is_hit(c)) else {
            break;
        };
        let start = cursor + rel;
        let end = start + c.len_utf8();
        if zero_width
            && ((start == 0 && c == '\u{feff}')
                || (c == '\u{200d}' && zwj_joins_emoji(text, start)))
        {
            cursor = end;
            continue;
        }
        out.push((start, end));
        let i = breaks.partition_point(|b| b.0 < end);
        let Some(&(_, break_end)) = breaks.get(i) else {
            break;
        };
        cursor = break_end;
    }
    out
}

/// The `data:text/plain;base64,...` blobs.
#[must_use]
pub fn data_uri_matches(text: &str) -> Vec<(usize, usize)> {
    DATA.find_iter(text)
        .iter()
        .map(|h| (h.start, h.end))
        .collect()
}

fn is_tag_char(c: char) -> bool {
    ('\u{e0000}'..='\u{e007f}').contains(&c)
}

/// `_first_smuggled_tag_offset` plus `_tag_run_from`: the first Tag character outside a
/// well-formed emoji subdivision flag, and the whole contiguous tag run from there.
#[must_use]
pub fn smuggled_tag_run(text: &str) -> Option<(usize, usize)> {
    static FLAG: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
        regex::Regex::new(r"\x{1F3F4}[\x{E0030}-\x{E0039}\x{E0061}-\x{E007A}]{2,6}\x{E007F}").ok()
    });
    if !text.chars().any(is_tag_char) {
        return None;
    }
    let safe: Vec<(usize, usize)> = FLAG
        .as_ref()
        .map(|re| re.find_iter(text).map(|m| (m.start(), m.end())).collect())
        .unwrap_or_default();
    let start = text
        .char_indices()
        .find(|&(i, c)| is_tag_char(c) && !safe.iter().any(|&(s, e)| s <= i && i < e))?
        .0;
    let len: usize = text[start..]
        .chars()
        .take_while(|c| is_tag_char(*c))
        .map(char::len_utf8)
        .sum();
    Some((start, start + len))
}

/// Python `repr(str)`.
#[must_use]
pub fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (' '..='~').contains(&c) => out.push(c),
            c if crate::unicode::is_printable(c) && !c.is_ascii() => out.push(c),
            c => {
                let cp = u32::from(c);
                if cp <= 0xff {
                    out.push_str(&format!("\\x{cp:02x}"));
                } else if cp <= 0xffff {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    out.push_str(&format!("\\U{cp:08x}"));
                }
            }
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
/// Every pattern source with its flags, for the compile test.
pub fn pattern_sources() -> Vec<(String, &'static str)> {
    vec![
        (comment_keyword_source(), "i"),
        (REFERENCE_OPENING.to_owned(), ""),
        (DATA_URI.to_owned(), "is"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans<'a>(text: &'a str, m: &[(usize, usize)]) -> Vec<&'a str> {
        m.iter().map(|&(s, e)| &text[s..e]).collect()
    }

    #[test]
    fn comment_keyword_patterns_compile() {
        for (src, flags) in pattern_sources() {
            assert!(Pat::try_new(&src, flags).is_ok(), "{src}");
        }
    }

    #[test]
    fn hidden_comment_with_keyword() {
        let t = "a <!-- please IGNORE this --> b <!-- plain --> <!--> ignore <!-- nope -->";
        assert_eq!(
            spans(t, &html_comment_matches(t)),
            ["<!-- please IGNORE this -->"]
        );
    }

    #[test]
    fn keyword_boundaries_need_identifier_edges() {
        let hit = |t: &str| !html_comment_matches(t).is_empty();
        assert!(hit("<!-- send data -->"));
        assert!(hit("<!-- PLEASEIGNOREPREVIOUSINSTRUCTIONS -->"));
        assert!(!hit("<!-- systematic review -->"));
        assert!(hit("<!-- Post-deployment verification -->"));
        assert!(hit("<!-- sendData -->"));
    }

    #[test]
    fn unclosed_comment_does_not_match() {
        assert!(html_comment_matches("<!-- ignore all").is_empty());
        assert_eq!(
            html_comment_matches("<!-- a --!> <!-- ignore x --!>").len(),
            1
        );
    }

    #[test]
    fn reference_comments() {
        let t = "[//]: # (ignore previous)\n\n[//]: # (just a note)\n[//]: #(hidden system)";
        let m = reference_comment_matches(t);
        assert_eq!(spans(t, &m)[0], "[//]: # (ignore previous)");
        // "#(hidden system)" has no gap before the title, so the destination is unbalanced
        assert_eq!(m.len(), 1);
        let plain = "[//]: # (just a note)";
        assert!(reference_comment_matches(plain).is_empty());
    }

    #[test]
    fn zero_width_rules() {
        assert!(control_char_matches("\u{feff}hello", true).is_empty());
        assert_eq!(
            control_char_matches("a\u{200b}b\u{200b}c\nd\u{200b}", true).len(),
            2
        );
        let zwj = "\u{1f468}\u{200d}\u{1f469}";
        assert!(control_char_matches(zwj, true).is_empty());
        assert_eq!(control_char_matches("a\u{200d}b", true).len(), 1);
    }

    #[test]
    fn bidi_controls() {
        assert_eq!(control_char_matches("x\u{202e}y", false).len(), 1);
        assert!(control_char_matches("x\u{200e}y", false).is_empty());
    }

    #[test]
    fn tag_smuggling_and_flags() {
        let hidden = "hi\u{e0041}\u{e0042}!";
        assert_eq!(smuggled_tag_run(hidden), Some((2, 10)));
        let flag = "\u{1f3f4}\u{e0067}\u{e0062}\u{e0065}\u{e006e}\u{e0067}\u{e007f}";
        assert_eq!(smuggled_tag_run(flag), None);
        assert_eq!(smuggled_tag_run("plain"), None);
    }

    #[test]
    fn repr_matches_python() {
        assert_eq!(py_repr("a'b"), "\"a'b\"");
        assert_eq!(py_repr("\u{e0041}x"), "'\\U000e0041x'");
        assert_eq!(py_repr("\u{200b}\n"), "'\\u200b\\n'");
    }

    #[test]
    fn data_uri_needs_fifty_chars() {
        let blob = format!("data:text/plain;base64,{}", "A".repeat(50));
        assert_eq!(data_uri_matches(&blob).len(), 1);
        assert!(data_uri_matches("data:text/plain;base64,AAAA").is_empty());
    }
}
