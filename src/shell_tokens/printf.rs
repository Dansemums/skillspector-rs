//! Static `printf` substitution evaluation (`_static_printf_substitution`, `_is_printf_substitution`
//! with `check_command_context=False`, `_next_shell_invocation_word`, `_consume_printf_invocation`).

use super::ShellError;
use super::expand::{
    chr, decode_ansi_c_escape, skip_ansi_c_quote_tail, skip_backtick_substitution,
    skip_command_substitution, skip_parameter_expansion, starts_with,
};
use super::powershell::is_powershell_replace_value_context;
use crate::unicode::{casefold, is_space};

pub(super) const DYNAMIC_SENTINEL: char = '\u{e001}';
pub(super) const RUNTIME_SENTINEL: char = '\u{e002}';
const SHELL_COMMAND_WORD_CHARS: usize = 4096;
const PRINTF_STATIC_CHARS: usize = 256;
const PRINTF_STATIC_ARGUMENTS: usize = 32;

fn contains_sentinel(word: &str, sentinel: char) -> bool {
    word.contains(sentinel)
}

/// `casefold().rsplit("/", 1)[-1]`.
fn command_basename(word: &str) -> String {
    let folded = casefold(word);
    match folded.rfind('/') {
        Some(i) => folded[i + 1..].to_string(),
        None => folded,
    }
}

/// `_PRINTF_FORMAT_CONVERSION_RE.search`: `%[-+ #0-9.*']*[A-Za-z%]`.
fn has_format_conversion(operand: &str) -> bool {
    let chars: Vec<char> = operand.chars().collect();
    (0..chars.len()).any(|i| {
        if chars[i] != '%' {
            return false;
        }
        let mut j = i + 1;
        while j < chars.len() && ("-+ #.*'".contains(chars[j]) || chars[j].is_ascii_digit()) {
            j += 1;
        }
        j < chars.len() && (chars[j].is_ascii_alphabetic() || chars[j] == '%')
    })
}

fn is_env_assignment(word: &str) -> bool {
    let mut it = word.chars();
    match it.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    for c in it {
        if c == '=' {
            return true;
        }
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }
    false
}

fn is_env_long_option_assignment(word: &str) -> bool {
    ["--unset=", "--chdir="].iter().any(|p| {
        word.strip_prefix(p)
            .is_some_and(|rest| !rest.is_empty() && !rest.contains('\n'))
    })
}

type NextWord<'a> = dyn FnMut() -> Result<Option<String>, ShellError> + 'a;

/// `_consume_printf_invocation`: returns `(recognized, exact)`.
fn consume_printf_invocation(
    next_word: &mut NextWord<'_>,
    runtime_command_context: bool,
) -> Result<(bool, bool), ShellError> {
    let mut pending: Option<String> = None;
    for _ in 0..4 {
        let word = match pending.take() {
            Some(w) => Some(w),
            None => next_word()?,
        };
        let Some(word) = word else {
            return Ok((false, false));
        };
        if contains_sentinel(&word, DYNAMIC_SENTINEL) {
            return Ok((true, false));
        }
        let command = command_basename(&word);
        if contains_sentinel(&word, RUNTIME_SENTINEL)
            && matches!(command.as_str(), "printf" | "command" | "builtin" | "env")
        {
            return Ok((true, false));
        }
        if contains_sentinel(&command, RUNTIME_SENTINEL) {
            if runtime_command_context {
                return Ok((true, false));
            }
            let mut characters = 0;
            for _ in 0..PRINTF_STATIC_ARGUMENTS {
                let Some(operand) = next_word()? else {
                    return Ok((false, false));
                };
                characters += operand.chars().count();
                if characters > PRINTF_STATIC_CHARS
                    || command_basename(&operand) == "printf"
                    || has_format_conversion(&operand)
                {
                    return Ok((true, false));
                }
            }
            return Ok((true, false));
        }
        if command == "printf" {
            return Ok((true, true));
        }
        if command == "command" {
            let mut word = next_word()?;
            loop {
                if word.as_deref() == Some("-p") {
                    word = next_word()?;
                    continue;
                }
                if word.as_deref() == Some("--") {
                    word = next_word()?;
                }
                break;
            }
            match word {
                Some(w) if !w.starts_with('-') => {
                    pending = Some(w);
                    continue;
                }
                _ => return Ok((false, false)),
            }
        }
        if command == "builtin" {
            let mut word = next_word()?;
            if word.as_deref() == Some("--") {
                word = next_word()?;
            }
            match word {
                Some(w) if !w.starts_with('-') => {
                    pending = Some(w);
                    continue;
                }
                _ => return Ok((false, false)),
            }
        }
        if command != "env" {
            return Ok((false, false));
        }
        while let Some(word) = next_word()? {
            if word == "--" {
                pending = next_word()?;
                break;
            }
            if is_env_assignment(&word) {
                continue;
            }
            if word == "-i" || word == "--ignore-environment" {
                continue;
            }
            if matches!(word.as_str(), "-u" | "--unset" | "-C" | "--chdir") {
                if next_word()?.is_none() {
                    return Ok((true, false));
                }
                continue;
            }
            if is_env_long_option_assignment(&word) {
                continue;
            }
            if word.starts_with('-') {
                return Ok((true, false));
            }
            pending = Some(word);
            break;
        }
        if pending.is_none() {
            return Ok((false, false));
        }
    }
    Ok((true, false))
}

fn is_value_head(chars: &[char], pos: usize) -> bool {
    // `_VALUE_PARAMETER_EXPANSION_HEAD_RE.match(expansion, pos)`.
    if !starts_with(chars, pos, "${") {
        return false;
    }
    let body = pos + 2;
    if starts_with(chars, body, "...}") {
        return true;
    }
    let op_ok = |p: usize| -> bool {
        match chars.get(p) {
            Some('}' | '-' | '=' | '?' | '+' | '#' | '%' | '/' | '^' | ',') => true,
            Some(':') => matches!(chars.get(p + 1), Some('-' | '=' | '?' | '+')),
            _ => false,
        }
    };
    let name_ends = |p: usize| -> Vec<usize> {
        let mut ends = Vec::new();
        match chars.get(p) {
            Some(&c) if c.is_ascii_alphabetic() || c == '_' => {
                let mut e = p + 1;
                while e < chars.len() && (chars[e].is_ascii_alphanumeric() || chars[e] == '_') {
                    e += 1;
                }
                if chars.get(e) == Some(&'[') {
                    let mut k = e + 1;
                    if matches!(chars.get(k), Some('@' | '*')) {
                        k += 1;
                    } else {
                        let ds = k;
                        while k < chars.len() && chars[k].is_ascii_digit() {
                            k += 1;
                        }
                        if k == ds {
                            k = 0;
                        }
                    }
                    if k != 0 && chars.get(k) == Some(&']') {
                        ends.push(k + 1);
                    }
                }
                ends.push(e);
            }
            Some(&c) if c.is_ascii_digit() => {
                let mut e = p + 1;
                while e < chars.len() && chars[e].is_ascii_digit() {
                    e += 1;
                }
                ends.push(e);
            }
            _ => {}
        }
        if matches!(chars.get(p), Some('@' | '*' | '#' | '?' | '$' | '!' | '-')) {
            ends.push(p + 1);
        }
        ends
    };
    let mut starts = vec![body];
    if chars.get(body) == Some(&'#') {
        starts.push(body + 1);
    }
    starts
        .into_iter()
        .any(|s| name_ends(s).into_iter().any(op_ok))
}

/// `_is_value_parameter_expansion`.
fn is_value_parameter_expansion(content: &[char], start: usize, end: usize) -> bool {
    let expansion: Vec<char> = content[start..end.min(content.len())].to_vec();
    let text: String = expansion.iter().collect();
    if ["`", "$(", "$[", "<(", ">("]
        .iter()
        .any(|m| text.contains(m))
    {
        return false;
    }
    let mut i = 0;
    while i < expansion.len() {
        if starts_with(&expansion, i, "${") {
            if !is_value_head(&expansion, i) {
                return false;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    true
}

/// `_invocation_expansion_marker`.
fn invocation_expansion_marker(content: &[char], start: usize, end: usize) -> char {
    if starts_with(content, start, "$(")
        || (starts_with(content, start, "${") && !is_value_parameter_expansion(content, start, end))
    {
        DYNAMIC_SENTINEL
    } else {
        RUNTIME_SENTINEL
    }
}

/// `_next_shell_invocation_word`: `(word, cursor, limited)`.
pub(super) fn next_shell_invocation_word(
    content: &[char],
    start: usize,
) -> Result<(Option<String>, usize, bool), ShellError> {
    let mut cursor = start;
    let limit = content.len();
    while cursor < limit {
        if is_space(content[cursor]) {
            cursor += 1;
        } else if starts_with(content, cursor, "\\\r\n") {
            cursor += 3;
        } else if starts_with(content, cursor, "\\\n") {
            cursor += 2;
        } else {
            break;
        }
    }
    if cursor >= limit || ");|&()<>".contains(content[cursor]) {
        return Ok((None, cursor, false));
    }

    let mut output = String::new();
    let mut quote: Option<char> = None;
    let mut ansi_c_quote = false;
    let mut word_started = false;
    let mut unquoted_characters = 0;
    while cursor < limit {
        let character = content[cursor];
        if let Some(q) = quote {
            if character == q {
                quote = None;
                ansi_c_quote = false;
            } else if character == '\\' && ansi_c_quote {
                let (decoded, next) = decode_ansi_c_escape(content, cursor, limit)?;
                cursor = next;
                if decoded.contains('\0') {
                    match skip_ansi_c_quote_tail(content, cursor, limit) {
                        None => return Ok((None, cursor, true)),
                        Some(closing) => {
                            cursor = closing;
                            continue;
                        }
                    }
                }
                output.push_str(&decoded);
                word_started = true;
                continue;
            } else if q == '"' && character == '\\' && cursor + 1 < limit {
                let escaped = content[cursor + 1];
                if escaped == '\n' {
                    cursor += 2;
                    continue;
                }
                if escaped == '\r' && cursor + 2 < limit && content[cursor + 2] == '\n' {
                    cursor += 3;
                    continue;
                }
                if "$`\"\\".contains(escaped) {
                    output.push(escaped);
                } else {
                    output.push('\\');
                    output.push(escaped);
                }
                cursor += 2;
                continue;
            } else if q == '"' && character == '$' {
                let mut closed = false;
                let end = if cursor + 1 < limit && content[cursor + 1] == '(' {
                    skip_command_substitution(content, cursor, limit)?
                } else {
                    skip_parameter_expansion(content, cursor, limit, true, Some(&mut closed))?
                };
                let Some(end) = end else {
                    if cursor + 1 < limit && "({".contains(content[cursor + 1]) {
                        return Ok((None, cursor, true));
                    }
                    output.push('$');
                    word_started = true;
                    cursor += 1;
                    continue;
                };
                output.push(invocation_expansion_marker(content, cursor, end));
                word_started = true;
                cursor = end;
                if closed {
                    quote = None;
                    ansi_c_quote = false;
                }
                continue;
            } else if q == '"' && character == '`' {
                let Some(end) = skip_backtick_substitution(content, cursor, limit)? else {
                    return Ok((None, cursor, true));
                };
                output.push(DYNAMIC_SENTINEL);
                word_started = true;
                cursor = end;
                continue;
            } else {
                output.push(character);
            }
        } else if character == '\'' || character == '"' {
            quote = Some(character);
            ansi_c_quote = false;
            word_started = true;
        } else if character == '\\' && cursor + 1 < limit {
            let escaped = content[cursor + 1];
            if escaped == '\n' {
                cursor += 2;
                continue;
            }
            if escaped == '\r' && cursor + 2 < limit && content[cursor + 2] == '\n' {
                cursor += 3;
                continue;
            }
            output.push(escaped);
            word_started = true;
            cursor += 2;
            continue;
        } else if character == '$' {
            if cursor + 1 < limit && (content[cursor + 1] == '\'' || content[cursor + 1] == '"') {
                let q = content[cursor + 1];
                quote = Some(q);
                ansi_c_quote = q == '\'';
                word_started = true;
                cursor += 2;
                continue;
            }
            let end = if cursor + 1 < limit && content[cursor + 1] == '(' {
                skip_command_substitution(content, cursor, limit)?
            } else {
                skip_parameter_expansion(content, cursor, limit, false, None)?
            };
            let Some(end) = end else {
                if cursor + 1 < limit && "({".contains(content[cursor + 1]) {
                    return Ok((None, cursor, true));
                }
                output.push('$');
                word_started = true;
                cursor += 1;
                continue;
            };
            output.push(invocation_expansion_marker(content, cursor, end));
            word_started = true;
            cursor = end;
            continue;
        } else if character == '`' {
            let Some(end) = skip_backtick_substitution(content, cursor, limit)? else {
                return Ok((None, cursor, true));
            };
            output.push(DYNAMIC_SENTINEL);
            word_started = true;
            cursor = end;
            continue;
        } else if (character == '<' || character == '>')
            && cursor + 1 < limit
            && content[cursor + 1] == '('
        {
            let Some(end) = skip_command_substitution(content, cursor, limit)? else {
                return Ok((None, cursor, true));
            };
            output.push(DYNAMIC_SENTINEL);
            word_started = true;
            cursor = end;
            continue;
        } else if is_space(character) || ";|&()<>".contains(character) {
            break;
        } else if character == '#' && !word_started {
            return Ok((None, cursor, false));
        } else {
            output.push(character);
            word_started = true;
            unquoted_characters += 1;
            if unquoted_characters > SHELL_COMMAND_WORD_CHARS {
                return Ok((None, cursor, true));
            }
        }
        cursor += 1;
    }
    if quote.is_some() {
        return Ok((None, cursor, true));
    }
    Ok((word_started.then_some(output), cursor, false))
}

/// `_printf_invocation_arguments`: `(recognized, arguments)`.
pub(super) fn printf_invocation_arguments(
    inner: &[char],
    runtime_command_context: bool,
) -> Result<(bool, Vec<String>), ShellError> {
    use std::cell::Cell;
    let cursor = Cell::new(0usize);
    let limited = Cell::new(false);
    let mut next_word = || -> Result<Option<String>, ShellError> {
        let (word, next, word_limited) = next_shell_invocation_word(inner, cursor.get())?;
        cursor.set(next);
        limited.set(limited.get() || word_limited || (word.is_none() && next < inner.len()));
        Ok(word)
    };
    let (recognized, exact) = consume_printf_invocation(&mut next_word, runtime_command_context)?;
    if !recognized || !exact || limited.get() {
        return Ok((recognized, Vec::new()));
    }
    let mut arguments = Vec::new();
    while cursor.get() < inner.len() {
        match next_word()? {
            None => {
                return Ok((
                    true,
                    if limited.get() || cursor.get() < inner.len() {
                        Vec::new()
                    } else {
                        arguments
                    },
                ));
            }
            Some(w) => arguments.push(w),
        }
    }
    Ok((true, arguments))
}

fn decode_printf_escapes(text: &[char]) -> Option<String> {
    let mut output = String::new();
    let mut cursor = 0;
    while cursor < text.len() {
        let character = text[cursor];
        if character != '\\' {
            output.push(character);
            cursor += 1;
            continue;
        }
        if cursor + 1 >= text.len() {
            return None;
        }
        let escaped = text[cursor + 1];
        let simple = match escaped {
            'a' => Some('\x07'),
            'b' => Some('\x08'),
            'e' | 'E' => Some('\x1b'),
            'f' => Some('\x0c'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            'v' => Some('\x0b'),
            '\\' | '\'' | '"' => Some(escaped),
            _ => None,
        };
        if let Some(c) = simple {
            output.push(c);
            cursor += 2;
            continue;
        }
        if escaped == 'x' {
            let mut end = cursor + 2;
            while end < text.len() && end < cursor + 4 && text[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end == cursor + 2 {
                return None;
            }
            let digits: String = text[cursor + 2..end].iter().collect();
            output.push(chr(u32::from_str_radix(&digits, 16).ok()?));
            cursor = end;
            continue;
        }
        if ('0'..='7').contains(&escaped) {
            let mut end = cursor + 1;
            while end < text.len() && end < cursor + 4 && ('0'..='7').contains(&text[end]) {
                end += 1;
            }
            let digits: String = text[cursor + 1..end].iter().collect();
            let value = u32::from_str_radix(&digits, 8).ok()?;
            if value > 0o377 {
                return None;
            }
            output.push(chr(value));
            cursor = end;
            continue;
        }
        return None;
    }
    Some(output)
}

fn bounded_printf_word(result: String) -> Option<String> {
    let ok = result.chars().all(|c| {
        matches!(c, '\x01'..='\x08' | '\x0e'..='\x1f' | '\x7f'..='\u{ff}')
            || c.is_ascii_alphanumeric()
            || "_./*?%<>-".contains(c)
    });
    ok.then_some(result)
}

fn is_static_word(word: &str, allow_backslash: bool) -> bool {
    word.chars().count() <= 64
        && word.chars().all(|c| {
            c.is_ascii_alphanumeric() || "-_./*?%".contains(c) || (allow_backslash && c == '\\')
        })
}

/// `_static_printf_substitution`: evaluate a tiny bounded `printf` subset.
pub(super) fn static_printf_substitution(
    content: &[char],
    start: usize,
    end: usize,
    backtick: bool,
) -> Result<Option<String>, ShellError> {
    let inner_start = start + usize::from(!backtick) + 1;
    let inner = &content[inner_start..end - 1];
    let (recognized, mut arguments) = printf_invocation_arguments(inner, false)?;
    if !recognized
        || inner.len() > PRINTF_STATIC_CHARS
        || inner.iter().any(|c| ";|&<>\r\n".contains(*c))
    {
        return Ok(None);
    }
    if arguments.first().map(String::as_str) == Some("--") {
        arguments.remove(0);
    }
    if arguments.is_empty() || arguments.len() > PRINTF_STATIC_ARGUMENTS + 1 {
        return Ok(None);
    }
    let format_word = arguments.remove(0);
    let values = arguments;
    if !is_static_word(&format_word, true) || values.iter().any(|v| !is_static_word(v, false)) {
        return Ok(None);
    }
    let format: Vec<char> = format_word.chars().collect();
    let mut segments: Vec<Option<String>> = Vec::new();
    let mut literal: Vec<char> = Vec::new();
    let flush = |literal: &mut Vec<char>, segments: &mut Vec<Option<String>>| -> bool {
        let text = if literal.contains(&'\\') {
            match decode_printf_escapes(literal) {
                Some(d) => d,
                None => return false,
            }
        } else {
            literal.iter().collect()
        };
        literal.clear();
        segments.push(Some(text));
        true
    };
    let mut cursor = 0;
    while cursor < format.len() {
        let character = format[cursor];
        if character != '%' {
            literal.push(character);
            cursor += 1;
            continue;
        }
        if cursor + 1 >= format.len() || !matches!(format[cursor + 1], 's' | '%') {
            return Ok(None);
        }
        if !literal.is_empty() && !flush(&mut literal, &mut segments) {
            return Ok(None);
        }
        segments.push(if format[cursor + 1] == 's' {
            None
        } else {
            Some("%".to_string())
        });
        cursor += 2;
    }
    if !literal.is_empty() && !flush(&mut literal, &mut segments) {
        return Ok(None);
    }
    let conversions = segments.iter().filter(|s| s.is_none()).count();
    if conversions == 0 {
        let joined: String = segments.into_iter().flatten().collect();
        return Ok(bounded_printf_word(joined));
    }
    let mut remaining = values.iter();
    let mut output = String::new();
    let cycles = values.len().div_ceil(conversions).max(1);
    for _ in 0..cycles {
        for segment in &segments {
            match segment {
                None => output.push_str(remaining.next().map_or("", String::as_str)),
                Some(s) => output.push_str(s),
            }
        }
        if output.chars().count() > 64 {
            return Ok(None);
        }
    }
    Ok(bounded_printf_word(output))
}

/// `_is_printf_substitution(check_command_context=False)`.
pub(super) fn is_printf_substitution(
    content: &[char],
    start: usize,
    end: usize,
    backtick: bool,
) -> Result<bool, ShellError> {
    let inner_start = start + usize::from(!backtick) + 1;
    let inner = &content[inner_start..end - 1];
    if !backtick && is_powershell_replace_value_context(content, start, end, inner) {
        return Ok(false);
    }
    Ok(printf_invocation_arguments(inner, false)?.0)
}
