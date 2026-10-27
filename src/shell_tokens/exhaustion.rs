//! `_has_shell_command_word_exhaustion` and its command-string reparsing helpers: does a destructive
//! `rm`-shaped command exceed the parser's bounds? (Python-source ownership and the Markdown
//! complete-context projection are not modelled; see `tool_misuse::has_bounded_parse_exhaustion`.)

use super::ShellError;
use super::destructive::{
    has_destructive_root_glob, has_destructive_root_path, has_quoted_assignment_prefix,
    has_unsupported_brace_expansion, is_printf_substitution_in_context,
    is_shell_command_word_start, parse_owning,
};
use super::expand::{command_wrapper_quote, skip_command_substitution};
use super::printf::{DYNAMIC_SENTINEL, RUNTIME_SENTINEL, next_shell_invocation_word};
use super::tokens::{ROOT_GLOB_COMMAND_CHARS, bounded_shell_tokens};
use crate::unicode::{casefold, is_space};
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

const SHELL_COMMAND_WORD_CHARS: usize = 4096;
const COMMAND_STRING_ARGUMENTS: usize = 32;
const CLAUSE_PREFIX_WORDS: [&str; 6] = ["do", "else", "elif", "then", "time", "!"];
const COMMAND_STRING_SHELLS: [&str; 7] = ["sh", "ash", "bash", "dash", "ksh", "yash", "zsh"];

static ROOT_TARGET_ESCAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\\(?:[/~*?]|x(?:2[fF]|7[eE]|2[aA]|3[fF])|u(?:002[fF]|007[eE]|002[aA]|003[fF])|U(?:0000002[fF]|0000007[eE]|0000002[aA]|0000003[fF])|(?:057|176|052|077)(?:[^0-7]|\z))",
    )
    .unwrap_or_else(|_| unreachable!("constant pattern"))
});
static RECURSIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-(?:[A-Za-z]*[rR]|-recursive)").unwrap_or_else(|_| unreachable!("constant"))
});
static FORCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-(?:[A-Za-z]*f|-force)").unwrap_or_else(|_| unreachable!("constant"))
});
static ASSIGN_WORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\A[A-Za-z_][A-Za-z0-9_]*=.*\z").unwrap_or_else(|_| unreachable!("constant"))
});
static SIMPLE_BACKTICK_PARAM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A`\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})`\z")
        .unwrap_or_else(|_| unreachable!("constant"))
});

fn to_string(chars: &[char]) -> String {
    chars.iter().collect()
}

/// `_has_constructed_recursive_force_option_source`.
fn has_constructed_recursive_force_option_source(content: &[char]) -> bool {
    for (i, &c) in content.iter().enumerate() {
        if c != '-' || content.get(i + 1).is_none_or(|&n| is_space(n)) {
            continue;
        }
        let mut fragment: Vec<char> = content[i..content.len().min(i + 128)].to_vec();
        if fragment.starts_with(&['-', '$', '(']) {
            if let Some(close) = fragment.iter().position(|&c| c == ')') {
                fragment.truncate(close + 1);
            }
        } else if let Some(b) = fragment
            .iter()
            .position(|&c| is_space(c) || ";|&".contains(c))
        {
            fragment.truncate(b);
        }
        let text = to_string(&fragment);
        if !["\\", "'", "\"", "{", "}", "$("]
            .iter()
            .any(|m| text.contains(m))
        {
            continue;
        }
        let lowered = casefold(&text);
        if lowered.contains('r') && lowered.contains('f') {
            return true;
        }
    }
    false
}

/// `_may_have_destructive_outer_operands`.
fn may_have_destructive_outer_operands(content: &[char]) -> bool {
    let text = to_string(content);
    let target = text.chars().any(|c| "/~*?".contains(c)) || ROOT_TARGET_ESCAPE.is_match(&text);
    let option = (RECURSIVE.is_match(&text) && FORCE.is_match(&text))
        || has_constructed_recursive_force_option_source(content);
    target && option
}

/// `_has_runtime_command_operand_exhaustion`.
fn has_runtime_command_operand_exhaustion(
    content: &[char],
    start: usize,
    word_end: usize,
) -> Result<bool, ShellError> {
    let parsed = bounded_shell_tokens(content, start, word_end)?;
    let mut exhausted = parsed.limited;
    if exhausted && parsed.end - start < ROOT_GLOB_COMMAND_CHARS {
        exhausted = may_have_destructive_outer_operands(&content[start..parsed.end]);
    }
    Ok(exhausted
        || has_unsupported_brace_expansion(&parsed.tokens)
        || has_destructive_root_glob(&parsed.tokens)
        || has_destructive_root_path(&parsed.tokens))
}

/// `_assignment_value_wrapper`.
fn assignment_value_wrapper(content: &[char], value_start: usize) -> Option<char> {
    let mut name_start = value_start - 1;
    if name_start > 0 && content[name_start - 1] == '+' {
        name_start -= 1;
    }
    while name_start > 0
        && (content[name_start - 1] == '_' || content[name_start - 1].is_ascii_alphanumeric())
    {
        name_start -= 1;
    }
    command_wrapper_quote(content, name_start)
}

/// `_SHELL_COMMENT_START_RE.search(content, from, to)`.
fn has_comment_start(content: &[char], from: usize, to: usize) -> bool {
    (from..to).any(|i| {
        content[i] == '#'
            && (i == 0 || {
                let p = content[i - 1];
                is_space(p) || ";&|()<>".contains(p)
            })
    })
}

/// `_shell_clause_starts`.
fn shell_clause_starts(content: &[char]) -> Vec<usize> {
    let mut out = vec![0];
    let mut quote: Option<char> = None;
    let mut word_started = false;
    let mut cursor = 0;
    while cursor < content.len() {
        let c = content[cursor];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if q == '"' && c == '\\' && cursor + 1 < content.len() {
                cursor += 2;
                continue;
            }
        } else if c == '\'' || c == '"' {
            quote = Some(c);
            word_started = true;
        } else if c == '\\' && cursor + 1 < content.len() {
            cursor += 2;
            word_started = true;
            continue;
        } else if c == '#' && !word_started {
            match content[cursor + 1..].iter().position(|&x| x == '\n') {
                None => return out,
                Some(i) => {
                    cursor = cursor + 1 + i + 1;
                    word_started = false;
                    out.push(cursor);
                    continue;
                }
            }
        } else if ";|&(){}\n".contains(c) {
            word_started = false;
            out.push(cursor + 1);
        } else {
            word_started = !is_space(c);
        }
        cursor += 1;
    }
    out
}

/// `_SHELL_REDIRECTION_PREFIX_RE.match(source, cursor)`: end index of the redirection operator.
fn redirection_end(s: &[char], at: usize) -> Option<(usize, bool)> {
    let mut digits = at;
    while digits < s.len() && s[digits].is_ascii_digit() {
        digits += 1;
    }
    let try_at = |p: usize| -> Option<(usize, bool)> {
        let a = s.get(p).copied();
        let b = s.get(p + 1).copied();
        let c = s.get(p + 2).copied();
        match (a, b, c) {
            (Some('&'), Some('>'), Some('>')) => Some((p + 3, false)),
            (Some('&'), Some('>'), _) => Some((p + 2, false)),
            (Some('<'), Some('>'), _) => Some((p + 2, false)),
            (Some('>'), Some('>'), _) => Some((p + 2, false)),
            (Some('>'), _, _) => Some((p + 1, false)),
            (Some('<'), Some('<'), Some('-')) => Some((p + 3, true)),
            (Some('<'), Some('<'), _) => Some((p + 2, true)),
            (Some('<'), Some('&'), _) => Some((p + 2, false)),
            (Some('<'), _, _) => Some((p + 1, false)),
            _ => None,
        }
    };
    try_at(digits).or_else(|| (digits != at).then(|| try_at(at)).flatten())
}

fn is_sentinel_word(word: &str) -> bool {
    word.contains(DYNAMIC_SENTINEL) || word.contains(RUNTIME_SENTINEL)
}

/// `_eval_command_string`.
fn eval_command_string(content: &[char], start: usize) -> Result<Option<String>, ShellError> {
    let source: Vec<char> =
        content[start..content.len().min(start + ROOT_GLOB_COMMAND_CHARS + 1)].to_vec();
    let mut cursor = 0;
    let mut operands: Vec<String> = Vec::new();
    for count in 0..=COMMAND_STRING_ARGUMENTS {
        while cursor < source.len() {
            if source[cursor..].starts_with(&['\\', '\r', '\n']) {
                cursor += 3;
            } else if source[cursor..].starts_with(&['\\', '\n']) {
                cursor += 2;
            } else if is_space(source[cursor]) && !"\r\n".contains(source[cursor]) {
                cursor += 1;
            } else {
                break;
            }
        }
        if cursor > ROOT_GLOB_COMMAND_CHARS {
            return Ok(None);
        }
        let redirection = redirection_end(&source, cursor);
        if redirection.is_none()
            && (cursor == source.len() || "\r\n;|&()#".contains(source[cursor]))
        {
            return Ok(Some(operands.join(" ")));
        }
        if count == COMMAND_STRING_ARGUMENTS {
            return Ok(None);
        }
        if let Some((end, heredoc)) = redirection {
            if heredoc {
                return Ok(None);
            }
            cursor = end;
            while cursor < source.len() && " \t".contains(source[cursor]) {
                cursor += 1;
            }
            if cursor == source.len() || "\r\n;|&()#".contains(source[cursor]) {
                return Ok(None);
            }
        }
        let (word, next, limited) = next_shell_invocation_word(&source, cursor)?;
        cursor = next;
        let Some(word) = word.filter(|_| !limited && cursor <= ROOT_GLOB_COMMAND_CHARS) else {
            return Ok(None);
        };
        if redirection.is_some() {
            continue;
        }
        if is_sentinel_word(&word) {
            return Ok(None);
        }
        if operands.is_empty() && word == "--" {
            continue;
        }
        operands.push(word);
    }
    Ok(None)
}

/// `_ends_wrapped_clause`.
fn ends_wrapped_clause(content: &[char], cursor: usize) -> bool {
    let Some(&c) = content.get(cursor) else {
        return false;
    };
    ";|)".contains(c) || (c == '&' && content.get(cursor + 1) != Some(&'>'))
}

/// Result of resolving a clause: `(recognized, command_string)`.
type Clause = (bool, Option<String>);

/// `_command_string_from_clause`.
#[allow(clippy::too_many_lines)]
fn command_string_from_clause(content: &[char], start: usize) -> Result<Clause, ShellError> {
    let mut cursor = start;
    let mut pending: Option<String> = None;
    let mut wrapper_seen = false;
    // (word, limited)
    let next_word = |cursor: &mut usize| -> Result<(Option<String>, bool), ShellError> {
        let (w, c, l) = next_shell_invocation_word(content, *cursor)?;
        *cursor = c;
        Ok((w, l))
    };
    for _ in 0..32 {
        while cursor < content.len() && is_space(content[cursor]) {
            cursor += 1;
        }
        if let Some((end, _)) = redirection_end(content, cursor) {
            cursor = end;
            let (target, limited) = next_word(&mut cursor)?;
            if limited || target.is_none() {
                return Ok((wrapper_seen, None));
            }
            continue;
        }
        let (word, limited) = match pending.take() {
            Some(p) => (Some(p), false),
            None => next_word(&mut cursor)?,
        };
        if limited {
            return Ok((wrapper_seen, None));
        }
        let Some(word) = word else {
            return Ok((false, None));
        };
        if ASSIGN_WORD.is_match(&word) {
            continue;
        }
        let folded = casefold(&word);
        let command = folded.rsplit('/').next().unwrap_or("");
        if CLAUSE_PREFIX_WORDS.contains(&command) {
            continue;
        }
        if command == "eval" {
            return Ok((true, eval_command_string(content, cursor)?));
        }
        if COMMAND_STRING_SHELLS.contains(&command) {
            for _ in 0..16 {
                let (option, limited) = next_word(&mut cursor)?;
                if limited {
                    return Ok((true, None));
                }
                let Some(option) = option else {
                    return Ok((false, None));
                };
                if option.starts_with('-') && !option.starts_with("--") {
                    if option[1..].contains('c') {
                        let (cs, limited) = next_word(&mut cursor)?;
                        let resolved = cs.filter(|w| !limited && !is_sentinel_word(w));
                        return Ok((true, resolved));
                    }
                    continue;
                }
                if option.starts_with('+') || option.starts_with("--") {
                    continue;
                }
                return Ok((false, None));
            }
            return Ok((true, None));
        }
        if matches!(command, "env" | "command" | "nohup") {
            wrapper_seen = true;
            continue;
        }
        if matches!(command, "sudo" | "nice" | "xargs") {
            wrapper_seen = true;
            loop {
                let (option, limited) = next_word(&mut cursor)?;
                if limited {
                    return Ok((true, None));
                }
                let Some(option) = option else {
                    return Ok((!ends_wrapped_clause(content, cursor), None));
                };
                if option == "--" {
                    let (p, limited) = next_word(&mut cursor)?;
                    if limited {
                        return Ok((true, None));
                    }
                    pending = p;
                    break;
                }
                if !option.starts_with('-') {
                    pending = Some(option);
                    break;
                }
                if [
                    "-u", "-g", "-h", "-p", "-C", "-T", "-R", "-D", "-n", "-I", "-L", "-P", "-s",
                ]
                .contains(&option.as_str())
                {
                    let (_, limited) = next_word(&mut cursor)?;
                    if limited {
                        return Ok((true, None));
                    }
                }
            }
            continue;
        }
        if command == "timeout" {
            wrapper_seen = true;
            loop {
                let (option, limited) = next_word(&mut cursor)?;
                if limited {
                    return Ok((true, None));
                }
                let Some(option) = option else {
                    return Ok((!ends_wrapped_clause(content, cursor), None));
                };
                if ["-k", "--kill-after", "-s", "--signal"].contains(&option.as_str()) {
                    let (_, limited) = next_word(&mut cursor)?;
                    if limited {
                        return Ok((true, None));
                    }
                    continue;
                }
                if option.starts_with('-') {
                    continue;
                }
                break;
            }
            let (p, limited) = next_word(&mut cursor)?;
            if limited {
                return Ok((true, None));
            }
            pending = p;
            continue;
        }
        return Ok((false, None));
    }
    Ok((wrapper_seen, None))
}

/// `_has_shell_command_word_exhaustion` for a text without Python-source ownership
/// (`python_source=None`, no Perl `eval BLOCK`).
///
/// # Errors
/// See [`ShellError`].
pub fn has_shell_command_word_exhaustion(
    content: &[char],
    depth: usize,
) -> Result<bool, ShellError> {
    has_shell_command_word_exhaustion_json(content, depth, None)
}

/// Offsets of the quotes that open and close validated JSON strings
/// (`structural_quote_openers` / `structural_quote_closers`).
pub struct JsonQuotes<'a> {
    pub openers: &'a std::collections::BTreeSet<usize>,
    pub closers: &'a std::collections::BTreeSet<usize>,
}

/// [`has_shell_command_word_exhaustion`] with the structural quote hints of a Markdown file.
///
/// # Errors
/// See [`ShellError`].
#[allow(clippy::too_many_lines)]
pub fn has_shell_command_word_exhaustion_json(
    content: &[char],
    depth: usize,
    json: Option<&JsonQuotes>,
) -> Result<bool, ShellError> {
    let mut parsed_through = 0usize;
    let mut owned: HashSet<usize> = HashSet::new();
    let may_have_outer = may_have_destructive_outer_operands(content);
    for start in 0..content.len() {
        if !"rRdDeE$'\"`\\".contains(content[start]) || owned.contains(&start) {
            continue;
        }
        if json.is_some_and(|j| j.closers.contains(&start)) {
            continue;
        }
        let json_string_start = json.is_some_and(|j| {
            j.openers.contains(&start) || (start > 0 && j.openers.contains(&(start - 1)))
        });
        let assignment_quote =
            start > 0 && content[start - 1] == '=' && "'\"".contains(content[start]);
        if start < parsed_through
            || (!json_string_start
                && !assignment_quote
                && !is_shell_command_word_start(content, start))
        {
            continue;
        }
        if has_quoted_assignment_prefix(content, start) {
            continue;
        }
        let mut candidate_positions: Vec<usize> = Vec::new();
        let enclosing = if assignment_quote {
            assignment_value_wrapper(content, start)
        } else {
            None
        };
        let Some(parsed) = parse_owning(content, start, enclosing, Some(&mut candidate_positions))?
        else {
            let substitution_start = if "'\"".contains(content[start])
                && content[start + 1..].starts_with(&['$', '('])
            {
                start + 1
            } else {
                start
            };
            if content[substitution_start..].starts_with(&['$', '(']) {
                let end = skip_command_substitution(content, substitution_start, content.len())?;
                if let Some(end) = end
                    && is_printf_substitution_in_context(content, substitution_start, end, false)?
                {
                    return Ok(true);
                }
            }
            // A validated JSON value owns its bytes and is checked separately.
            let unresolved_end = json
                .and_then(|j| j.openers.range(start + 1..).next().copied())
                .unwrap_or(content.len());
            if unresolved_end - start > SHELL_COMMAND_WORD_CHARS {
                return Ok(true);
            }
            continue;
        };
        let word_slice = &content[start..parsed.end];
        let confined = word_slice.contains(&'\n')
            && (assignment_quote
                || has_comment_start(
                    content,
                    content[..start]
                        .iter()
                        .rposition(|&c| c == '\n')
                        .map_or(0, |i| i + 1),
                    start,
                ));
        if !confined {
            owned.extend(
                candidate_positions
                    .into_iter()
                    .filter(|&p| !matches!(content.get(p + 1), Some('$' | '`'))),
            );
        }
        let raw: String = to_string(word_slice);
        let simple_backtick = SIMPLE_BACKTICK_PARAM.is_match(&raw);
        if (!parsed.dynamic
            || !raw.contains('$')
            || !(raw.contains("$(") || raw.contains('`'))
            || simple_backtick)
            && !(assignment_quote && confined)
        {
            parsed_through = parsed_through.max(parsed.end);
        }
        if assignment_quote {
            continue;
        }
        if parsed.limited {
            return Ok(true);
        }
        if parsed.dynamic
            && may_have_outer
            && has_runtime_command_operand_exhaustion(content, start, parsed.end)?
        {
            // No Python ownership available: Python's `value is None` branch.
            return Ok(true);
        }
    }
    for clause_start in shell_clause_starts(content) {
        let (recognized, command_string) = command_string_from_clause(content, clause_start)?;
        if !recognized {
            continue;
        }
        let Some(text) = command_string.filter(|_| depth < 8) else {
            return Ok(true);
        };
        let chars: Vec<char> = text.chars().collect();
        if has_shell_command_word_exhaustion(&chars, depth + 1)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(s: &str) -> bool {
        let c: Vec<char> = s.chars().collect();
        has_shell_command_word_exhaustion(&c, 0).unwrap_or(false)
    }

    #[test]
    fn plain_commands_are_decidable() {
        assert!(!run("rm -rf /tmp/x\n"));
        assert!(!run("echo hello\n"));
    }

    #[test]
    fn unclosed_quote_to_end_exhausts() {
        let s = format!("echo \"{}", "a".repeat(5000));
        assert!(run(&s));
    }

    #[test]
    fn eval_of_a_dynamic_string_is_undecidable() {
        assert!(run("eval \"$cmd\"\n"));
        assert!(!run("eval \"echo hi\"\n"));
    }

    #[test]
    fn redirection_prefixes() {
        let c: Vec<char> = "2>&1".chars().collect();
        assert_eq!(redirection_end(&c, 0), Some((2, false)));
        let c: Vec<char> = "<<-EOF".chars().collect();
        assert_eq!(redirection_end(&c, 0), Some((3, true)));
    }
}
