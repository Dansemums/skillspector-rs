//! The bounded backward JavaScript recognizer of `static_patterns_output_handling.py` that tells
//! `/re/.exec(output)` (a RegExp method call) from a dangerous `exec(output)` sink.
//!
//! Python indexes `str` by character, so the content is a `&[char]` here and every index is a
//! character index.

use crate::skill::FileType;
use crate::unicode::{casefold, is_space};

pub const LOOKBACK_CHARS: usize = 4_096;
const LINE_TERMINATORS: [char; 4] = ['\r', '\n', '\u{2028}', '\u{2029}'];
const REGEXP_FLAGS: &str = "dgimsuvy";
const EXPRESSION_PREFIX_CHARS: &str = "=([{,:;!?&|+-*%^~<>";
const EXPRESSION_PREFIX_KEYWORDS: [&str; 11] = [
    "case",
    "delete",
    "do",
    "else",
    "in",
    "instanceof",
    "new",
    "return",
    "throw",
    "typeof",
    "void",
];
const JS_EXTENSIONS: [&str; 8] = [".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"];

fn is_terminator(c: char) -> bool {
    LINE_TERMINATORS.contains(&c)
}

/// `_is_javascript_source`.
fn is_javascript_source(path: &str, ft: FileType) -> bool {
    if matches!(ft, FileType::Javascript | FileType::Typescript) {
        return true;
    }
    path.rfind('.')
        .is_some_and(|i| JS_EXTENSIONS.contains(&casefold(&path[i..]).as_str()))
}

/// `_skip_javascript_whitespace_backward`.
fn skip_ws_back(c: &[char], mut index: usize, floor: usize) -> usize {
    while index > floor && is_space(c[index - 1]) {
        index -= 1;
    }
    index
}

/// `_is_javascript_character_escaped`: odd backslash prefix.
fn is_escaped(c: &[char], index: usize, floor: usize) -> bool {
    let mut backslashes = 0;
    let mut cursor = index;
    while cursor > floor && c[cursor - 1] == '\\' {
        backslashes += 1;
        cursor -= 1;
    }
    backslashes % 2 == 1
}

/// `_is_javascript_identifier_part`.
fn is_identifier_part(ch: char) -> bool {
    if is_space(ch) {
        return false;
    }
    u32::from(ch) > 0x7F || ch == '$' || ch == '_' || ch.is_ascii_alphanumeric()
}

/// `max(content.rfind(t, floor, end) for t in terminators)`, `None` for -1.
fn last_terminator(c: &[char], floor: usize, end: usize) -> Option<usize> {
    (floor..end).rev().find(|&i| is_terminator(c[i]))
}

/// The start of the line holding `end`, or `None` when the window starts mid-line (fail closed).
fn line_start_in_window(c: &[char], floor: usize, end: usize) -> Option<usize> {
    match last_terminator(c, floor, end) {
        Some(lb) => Some(lb + 1),
        None if floor == 0 || is_terminator(c[floor - 1]) => Some(floor),
        None => None,
    }
}

fn starts_with_at(c: &[char], at: usize, end: usize, needle: &str) -> bool {
    let n = needle.chars().count();
    at + n <= end && c[at..at + n].iter().copied().eq(needle.chars())
}

/// `_javascript_whitespace_crosses_possible_line_comment`.
fn whitespace_crosses_possible_line_comment(
    c: &[char],
    ws_start: usize,
    ws_end: usize,
    floor: usize,
) -> bool {
    if !c[ws_start..ws_end].iter().any(|&ch| is_terminator(ch)) {
        return false;
    }
    let last_break = last_terminator(c, floor, ws_start);
    let Some(line_start) = line_start_in_window(c, floor, ws_start) else {
        return true;
    };
    let prefix = &c[line_start..ws_start];
    if prefix.contains(&'`') || prefix.windows(2).any(|w| w == ['*', '/']) {
        return true;
    }
    let trimmed = prefix.iter().skip_while(|&&ch| is_space(ch)).count();
    if starts_with_at(c, ws_start - trimmed, ws_start, "-->") {
        return true;
    }
    if let Some(lb) = last_break {
        let mut ts = lb;
        while ts > floor && is_terminator(c[ts - 1]) {
            ts -= 1;
        }
        if is_escaped(c, ts, floor) {
            return true;
        }
    }

    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut saw_unquoted_slash = false;
    let mut cursor = line_start;
    while cursor < ws_start {
        let ch = c[cursor];
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
        } else if ch == '"' || ch == '\'' {
            if saw_unquoted_slash {
                return true;
            }
            quote = Some(ch);
        } else if ch == '`' || starts_with_at(c, cursor, ws_start, "<!--") {
            return true;
        } else if ch == '/' {
            if cursor + 1 < ws_start && (c[cursor + 1] == '/' || c[cursor + 1] == '*') {
                return true;
            }
            saw_unquoted_slash = true;
        }
        cursor += 1;
    }
    quote.is_some()
}

/// `_javascript_braced_unicode_escape_ends_at`.
fn braced_unicode_escape_ends_at(c: &[char], index: usize, floor: usize) -> bool {
    if index <= floor || c[index - 1] != '}' {
        return false;
    }
    let first = index as isize - 2;
    let mut cursor = first;
    while cursor >= floor as isize && c[cursor as usize].is_ascii_hexdigit() {
        cursor -= 1;
    }
    if cursor == first {
        return false;
    }
    if cursor < floor as isize {
        return true;
    }
    let cursor = cursor as usize;
    if c[cursor] != '{' {
        return false;
    }
    if cursor < floor + 2 {
        return true;
    }
    c[cursor - 2..cursor] == ['\\', 'u']
}

/// `_javascript_regexp_opening_has_unambiguous_line_prefix`.
fn opening_has_unambiguous_line_prefix(c: &[char], opening: usize, floor: usize) -> bool {
    let Some(line_start) = line_start_in_window(c, floor, opening) else {
        return false;
    };
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for &ch in &c[line_start..opening] {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else if ch == '`' || ch == '/' {
            return false;
        }
    }
    quote.is_none()
}

/// `_find_javascript_regexp_opening_slash`.
fn find_opening_slash(c: &[char], closing: usize, floor: usize) -> Option<usize> {
    let mut in_class = false;
    let mut cursor = closing;
    while cursor > floor {
        cursor -= 1;
        let ch = c[cursor];
        if is_terminator(ch) {
            return None;
        }
        if matches!(ch, '/' | '[' | ']') && !is_escaped(c, cursor, floor) {
            if ch == ']' {
                in_class = true;
            } else if ch == '[' && in_class {
                in_class = false;
            } else if ch == '/' && !in_class {
                return (cursor + 1 < closing).then_some(cursor);
            }
        }
    }
    None
}

/// `_javascript_expression_can_start_at`.
fn expression_can_start_at(c: &[char], index: usize, floor: usize) -> bool {
    let cursor = skip_ws_back(c, index, floor);
    if whitespace_crosses_possible_line_comment(c, cursor, index, floor) {
        return false;
    }
    if cursor == floor {
        return floor == 0;
    }
    let previous = c[cursor - 1];
    if EXPRESSION_PREFIX_CHARS.contains(previous) {
        if previous == '>' {
            return cursor - floor >= 2 && c[cursor - 2] == '=';
        }
        if (previous == '+' || previous == '-') && cursor - floor >= 2 && c[cursor - 2] == previous
        {
            return false;
        }
        if previous == '!' {
            let mut operator_start = cursor - 1;
            loop {
                let prefix_end = skip_ws_back(c, operator_start, floor);
                if prefix_end <= floor || c[prefix_end - 1] != '!' {
                    break;
                }
                operator_start = prefix_end - 1;
            }
            return expression_can_start_at(c, operator_start, floor);
        }
        return true;
    }
    if !is_identifier_part(previous) {
        return false;
    }
    let mut token_start = cursor - 1;
    while token_start > floor && is_identifier_part(c[token_start - 1]) {
        token_start -= 1;
    }
    let token: String = c[token_start..cursor].iter().collect();
    if braced_unicode_escape_ends_at(c, token_start, floor) {
        return false;
    }
    let token_prefix = skip_ws_back(c, token_start, floor);
    if token_prefix == floor && floor > 0 {
        return false;
    }
    if token_prefix > floor && matches!(c[token_prefix - 1], '.' | '#') {
        return false;
    }
    EXPRESSION_PREFIX_KEYWORDS.contains(&token.as_str())
}

/// `_is_javascript_regexp_literal_exec`: `match_start` is the character index of the `exec` match.
pub fn is_regexp_literal_exec(c: &[char], match_start: usize, path: &str, ft: FileType) -> bool {
    if !is_javascript_source(path, ft) {
        return false;
    }
    if !starts_with_at(c, match_start, c.len(), "exec") {
        return false;
    }
    let floor = match_start.saturating_sub(LOOKBACK_CHARS);
    let mut cursor = skip_ws_back(c, match_start, floor);
    if cursor <= floor || c[cursor - 1] != '.' {
        return false;
    }
    cursor = skip_ws_back(c, cursor - 1, floor);
    if cursor > floor && c[cursor - 1] == '?' {
        cursor = skip_ws_back(c, cursor - 1, floor);
    }
    let mut closing_parentheses = 0;
    while cursor > floor && c[cursor - 1] == ')' {
        closing_parentheses += 1;
        cursor = skip_ws_back(c, cursor - 1, floor);
    }
    while cursor > floor && REGEXP_FLAGS.contains(c[cursor - 1]) {
        cursor -= 1;
    }
    if cursor <= floor || c[cursor - 1] != '/' {
        return false;
    }
    let Some(opening) = find_opening_slash(c, cursor - 1, floor) else {
        return false;
    };
    if !opening_has_unambiguous_line_prefix(c, opening, floor)
        || !expression_can_start_at(c, opening, floor)
    {
        return false;
    }
    let mut wrapper_start = opening;
    for _ in 0..closing_parentheses {
        wrapper_start = skip_ws_back(c, wrapper_start, floor);
        if wrapper_start <= floor || c[wrapper_start - 1] != '(' {
            return false;
        }
        wrapper_start -= 1;
    }
    closing_parentheses == 0 || expression_can_start_at(c, wrapper_start, floor)
}
