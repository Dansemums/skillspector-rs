//! Shell expansion skipping: ANSI-C escapes, `${}`, `$()`, backticks (`static_patterns_tool_misuse.py`
//! `_decode_ansi_c_escape`, `_skip_shell_delimited_expansion` and friends). Char indices throughout.

use super::ShellError;
use super::digit_table::DIGIT_RANGES;
use crate::unicode::{is_alnum, is_alpha, is_space};

/// `str.isdigit()` for one character.
pub(super) fn is_digit(c: char) -> bool {
    let c = u32::from(c);
    DIGIT_RANGES
        .binary_search_by(|&(lo, hi)| {
            if c < lo {
                std::cmp::Ordering::Greater
            } else if c > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `chr(value)`; a lone surrogate (not representable in Rust) becomes U+FFFD.
pub(super) fn chr(value: u32) -> char {
    char::from_u32(value).unwrap_or('\u{fffd}')
}

pub(super) fn starts_with(content: &[char], at: usize, pat: &str) -> bool {
    pat.chars()
        .enumerate()
        .all(|(k, p)| content.get(at + k) == Some(&p))
}

/// `_decode_ansi_c_escape`: decode one bounded Bash ANSI-C escape.
///
/// # Errors
/// `\c` followed by a character whose `upper()` is not one character (Python `TypeError`).
pub(super) fn decode_ansi_c_escape(
    content: &[char],
    start: usize,
    limit: usize,
) -> Result<(String, usize), ShellError> {
    if start + 1 >= limit {
        return Ok(("\\".to_string(), start + 1));
    }
    let escaped = content[start + 1];
    let simple = match escaped {
        'a' => Some('\x07'),
        'b' => Some('\x08'),
        'e' | 'E' => Some('\x1b'),
        'f' => Some('\x0c'),
        'n' => Some('\n'),
        'r' => Some('\r'),
        't' => Some('\t'),
        'v' => Some('\x0b'),
        '\\' | '\'' | '"' | '?' => Some(escaped),
        _ => None,
    };
    if let Some(c) = simple {
        return Ok((c.to_string(), start + 2));
    }
    if matches!(escaped, 'x' | 'X' | 'u' | 'U') {
        let max_digits = match escaped {
            'x' | 'X' => 2,
            'u' => 4,
            _ => 8,
        };
        let mut cursor = start + 2;
        while cursor < limit
            && cursor < start + 2 + max_digits
            && content[cursor].is_ascii_hexdigit()
        {
            cursor += 1;
        }
        if cursor > start + 2 {
            let digits: String = content[start + 2..cursor].iter().collect();
            if let Ok(value) = u32::from_str_radix(&digits, 16)
                && value <= 0x10_FFFF
            {
                return Ok((chr(value).to_string(), cursor));
            }
        }
    }
    if ('0'..='7').contains(&escaped) {
        let mut cursor = start + 1;
        while cursor < limit && cursor < start + 4 && ('0'..='7').contains(&content[cursor]) {
            cursor += 1;
        }
        let digits: String = content[start + 1..cursor].iter().collect();
        let value = u32::from_str_radix(&digits, 8).unwrap_or(0);
        return Ok((chr(value).to_string(), cursor));
    }
    if escaped == 'c' && start + 2 < limit {
        let mut upper = content[start + 2].to_uppercase();
        return match (upper.next(), upper.next()) {
            (Some(u), None) => Ok((chr(u32::from(u) ^ 0x40).to_string(), start + 3)),
            _ => Err(ShellError::UpperNotSingleChar),
        };
    }
    Ok((format!("\\{escaped}"), start + 2))
}

/// `_skip_ansi_c_quote_tail`: the real closing quote after a NUL, skipping escaped quotes.
pub(super) fn skip_ansi_c_quote_tail(
    content: &[char],
    start: usize,
    limit: usize,
) -> Option<usize> {
    let mut cursor = start;
    while cursor < limit {
        if content[cursor] == '\\' && cursor + 1 < limit {
            cursor += 2;
            continue;
        }
        if content[cursor] == '\'' {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Command,
    Parameter,
    Backtick,
    Paren,
    Brace,
}

struct Frame {
    kind: Kind,
    quote: Option<char>,
    ansi_c_quote: bool,
    word_started: bool,
    inherited_double_quote: bool,
    inherited_quote_closed: bool,
    pending_case_clauses: u32,
    open_case_clauses: u32,
}

impl Frame {
    fn new(kind: Kind, inherited_double_quote: bool) -> Self {
        Self {
            kind,
            quote: None,
            ansi_c_quote: false,
            word_started: false,
            inherited_double_quote,
            inherited_quote_closed: false,
            pending_case_clauses: 0,
            open_case_clauses: 0,
        }
    }

    fn is_param_like(&self) -> bool {
        matches!(self.kind, Kind::Parameter | Kind::Brace)
    }

    fn is_cmd_like(&self) -> bool {
        matches!(self.kind, Kind::Command | Kind::Paren)
    }
}

fn push(frames: &mut Vec<Frame>, cursor: &mut usize, kind: Kind, width: usize) {
    let mut inherited = false;
    if let Some(parent) = frames.last_mut() {
        if matches!(kind, Kind::Parameter | Kind::Command | Kind::Backtick) && parent.is_cmd_like()
        {
            parent.word_started = true;
        }
        inherited = matches!(kind, Kind::Parameter | Kind::Brace)
            && (parent.quote == Some('"')
                || (parent.inherited_double_quote
                    && parent.is_param_like()
                    && parent.quote.is_none()));
    }
    frames.push(Frame::new(kind, inherited));
    *cursor += width;
}

fn at_shell_keyword(content: &[char], cursor: usize, limit: usize, keyword: &str) -> bool {
    let end = cursor + keyword.chars().count();
    if end > limit || !starts_with(content, cursor, keyword) {
        return false;
    }
    let delimiters = ";|&(){}<>! \t\r\n";
    let before = if cursor > 0 { content[cursor - 1] } else { ' ' };
    let after = if end < limit { content[end] } else { ' ' };
    delimiters.contains(before) && delimiters.contains(after)
}

fn is_delimiter_word_char(c: char) -> bool {
    !"$'\"`\\(){}<>#;|&!".contains(c) && !is_space(c)
}

/// `_skip_shell_delimited_expansion`: skip nested shell delimiters iteratively.
/// `root_kind` is `"command"`, `"parameter"` or `"backtick"`; returns the index after the closer.
pub(super) fn skip_shell_delimited_expansion(
    content: &[char],
    start: usize,
    limit: usize,
    root_kind: &str,
    root_inherited_double_quote: bool,
    mut inherited_quote_closed: Option<&mut bool>,
) -> Result<Option<usize>, ShellError> {
    let (kind, width) = match root_kind {
        "backtick" => (Kind::Backtick, 1),
        "parameter" => (Kind::Parameter, 2),
        _ => (Kind::Command, 2),
    };
    let mut frames = vec![Frame::new(kind, root_inherited_double_quote)];
    let mut cursor = start + width;
    while cursor < limit {
        let top = frames.len() - 1;
        let character = content[cursor];
        if frames[top].kind == Kind::Backtick {
            if character == '\\' && cursor + 1 < limit {
                cursor += 2;
                continue;
            }
            cursor += 1;
            if character == '`' {
                frames.pop();
                if frames.is_empty() {
                    return Ok(Some(cursor));
                }
            }
            continue;
        }
        if let Some(quote) = frames[top].quote {
            if quote == '"' && starts_with(content, cursor, "${") {
                push(&mut frames, &mut cursor, Kind::Parameter, 2);
                continue;
            }
            if quote == '"' && starts_with(content, cursor, "$(") {
                push(&mut frames, &mut cursor, Kind::Command, 2);
                continue;
            }
            if quote == '"' && character == '`' {
                push(&mut frames, &mut cursor, Kind::Backtick, 1);
                continue;
            }
            if character == quote {
                frames[top].quote = None;
                frames[top].ansi_c_quote = false;
            } else if character == '\\' && frames[top].ansi_c_quote {
                cursor = decode_ansi_c_escape(content, cursor, limit)?.1;
                continue;
            } else if character == '\\' && quote == '"' && cursor + 1 < limit {
                cursor += 2;
                continue;
            }
            cursor += 1;
            continue;
        }

        // Ordinary words cannot change the delimiter stack: consume them in one bounded run.
        let word_end_limit = limit.min(cursor + 4096);
        let mut word_end = cursor;
        while word_end < word_end_limit && is_delimiter_word_char(content[word_end]) {
            word_end += 1;
        }
        if word_end > cursor {
            let frame = &mut frames[top];
            if frame.is_cmd_like() {
                if at_shell_keyword(content, cursor, limit, "case") {
                    frame.pending_case_clauses += 1;
                } else if frame.pending_case_clauses > 0
                    && at_shell_keyword(content, cursor, limit, "in")
                {
                    frame.pending_case_clauses -= 1;
                    frame.open_case_clauses += 1;
                } else if frame.open_case_clauses > 0
                    && at_shell_keyword(content, cursor, limit, "esac")
                {
                    frame.open_case_clauses -= 1;
                }
                frame.word_started = true;
            }
            cursor = word_end;
            continue;
        }

        if starts_with(content, cursor, "${") {
            push(&mut frames, &mut cursor, Kind::Parameter, 2);
            continue;
        }
        if starts_with(content, cursor, "$(") {
            push(&mut frames, &mut cursor, Kind::Command, 2);
            continue;
        }
        if (character == '<' || character == '>')
            && cursor + 1 < limit
            && content[cursor + 1] == '('
        {
            push(&mut frames, &mut cursor, Kind::Command, 2);
            continue;
        }
        if character == '`' {
            push(&mut frames, &mut cursor, Kind::Backtick, 1);
            continue;
        }
        let next_is_quote =
            cursor + 1 < limit && (content[cursor + 1] == '\'' || content[cursor + 1] == '"');
        let inherited_param = frames[top].inherited_double_quote && frames[top].is_param_like();
        if character == '$' && next_is_quote && !inherited_param {
            let q = content[cursor + 1];
            frames[top].quote = Some(q);
            frames[top].ansi_c_quote = q == '\'';
            if frames[top].is_cmd_like() {
                frames[top].word_started = true;
            }
            cursor += 2;
            continue;
        }
        if character == '"' && inherited_param {
            // ksh: `$"` inside a parameter expansion of a double-quoted word is a literal `$`
            // then the closing quote, not a locale-translation string.
            frames[top].inherited_double_quote = false;
            frames[top].inherited_quote_closed = true;
            if let Some(flag) = inherited_quote_closed.as_deref_mut() {
                *flag = true;
            }
            for parent in frames[..top].iter_mut().rev() {
                if parent.is_param_like() {
                    parent.inherited_double_quote = false;
                    parent.inherited_quote_closed = true;
                }
                if parent.quote == Some('"') {
                    parent.quote = None;
                    parent.ansi_c_quote = false;
                    break;
                }
            }
            cursor += 1;
            continue;
        }
        if (character == '\'' || character == '"') && !(character == '\'' && inherited_param) {
            frames[top].quote = Some(character);
            frames[top].ansi_c_quote = false;
            if frames[top].is_cmd_like() {
                frames[top].word_started = true;
            }
            cursor += 1;
            continue;
        }
        if character == '\\' && cursor + 1 < limit {
            if frames[top].is_cmd_like() {
                frames[top].word_started = true;
            }
            cursor += 2;
            continue;
        }

        if frames[top].is_param_like() {
            if character == '{' {
                push(&mut frames, &mut cursor, Kind::Brace, 1);
                continue;
            }
            cursor += 1;
            if character == '}' {
                frames.pop();
                if frames.is_empty() {
                    return Ok(Some(cursor));
                }
            }
            continue;
        }

        if character == '(' {
            push(&mut frames, &mut cursor, Kind::Paren, 1);
            continue;
        }
        if character == ')' {
            if frames[top].open_case_clauses > 0 {
                // `)` ends a case pattern, not the surrounding substitution.
                frames[top].word_started = false;
                cursor += 1;
                continue;
            }
            cursor += 1;
            frames.pop();
            if frames.is_empty() {
                return Ok(Some(cursor));
            }
            continue;
        }
        if character == '#' && !frames[top].word_started {
            let newline = (cursor + 1..limit).find(|&i| content[i] == '\n');
            match newline {
                None => return Ok(None),
                Some(n) => {
                    cursor = n;
                    continue;
                }
            }
        }
        frames[top].word_started = !(is_space(character) || ";|&".contains(character));
        cursor += 1;
    }
    Ok(None)
}

/// `_skip_parameter_expansion` (no caches): index after `$name`, `$1`, `${...}`, or `None`.
pub(super) fn skip_parameter_expansion(
    content: &[char],
    start: usize,
    limit: usize,
    inherited_double_quote: bool,
    inherited_quote_closed: Option<&mut bool>,
) -> Result<Option<usize>, ShellError> {
    if start + 1 >= limit || content[start] != '$' {
        return Ok(None);
    }
    let next = content[start + 1];
    if next == '{' {
        return skip_shell_delimited_expansion(
            content,
            start,
            limit,
            "parameter",
            inherited_double_quote,
            inherited_quote_closed,
        );
    }
    if is_alpha(next) || next == '_' {
        let mut cursor = start + 2;
        while cursor < limit && (is_alnum(content[cursor]) || content[cursor] == '_') {
            cursor += 1;
        }
        return Ok(Some(cursor));
    }
    if is_digit(next) || "*@#?$!-".contains(next) {
        return Ok(Some(start + 2));
    }
    Ok(None)
}

/// `_skip_command_substitution` (no caches).
pub(super) fn skip_command_substitution(
    content: &[char],
    start: usize,
    limit: usize,
) -> Result<Option<usize>, ShellError> {
    skip_shell_delimited_expansion(content, start, limit, "command", false, None)
}

/// `_skip_backtick_substitution` (no caches).
pub(super) fn skip_backtick_substitution(
    content: &[char],
    start: usize,
    limit: usize,
) -> Result<Option<usize>, ShellError> {
    skip_shell_delimited_expansion(content, start, limit, "backtick", false, None)
}

/// `_is_ifs_expansion`.
pub(super) fn is_ifs_expansion(content: &[char], start: usize, end: usize) -> bool {
    let text: String = content[start..end.min(content.len())].iter().collect();
    text == "$IFS" || text == "${IFS}"
}

/// `_command_wrapper_quote`.
pub(super) fn command_wrapper_quote(content: &[char], command_start: usize) -> Option<char> {
    if command_start == 0 || !matches!(content[command_start - 1], '\'' | '"' | '`') {
        return None;
    }
    let mut backslashes = 0;
    let mut cursor = command_start as isize - 2;
    while cursor >= 0 && content[cursor as usize] == '\\' {
        backslashes += 1;
        cursor -= 1;
    }
    (backslashes % 2 == 0).then(|| content[command_start - 1])
}
