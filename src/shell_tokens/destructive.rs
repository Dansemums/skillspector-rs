//! Destructive-command discovery for tool misuse (`static_patterns_tool_misuse.py`):
//! `_destructive_command_words`, `_parse_shell_command_word`, `_is_printf_substitution` with
//! `check_command_context=True`, `_is_root_glob_documentation` and the `_has_destructive_*` predicates.
//! Char indices throughout, like the rest of this module.

use super::expand::{
    command_wrapper_quote, decode_ansi_c_escape, is_ifs_expansion, skip_ansi_c_quote_tail,
    skip_backtick_substitution, skip_command_substitution, skip_parameter_expansion,
};
use super::powershell::is_powershell_replace_value_context;
use super::printf::{printf_invocation_arguments, static_printf_substitution};
use super::tokens::{ROOT_GLOB_COMMAND_CHARS, bounded_shell_tokens};
use super::{ShellError, ShellToken};
use crate::matcher::Pat;
use crate::unicode::{is_alnum, is_alpha, is_space};
use std::sync::LazyLock;

const SHELL_COMMAND_WORD_CHARS: usize = 4096;
const PRINTF_STATIC_CHARS: usize = 256;
const STATIC_BRACE_WORD_CHARS: usize = 256;
const CLAUSE_BOUNDARY: &str = "\r\n;|&(){}`";
const ASSIGNMENT_PREFIX_WORDS: [&str; 14] = [
    "do", "else", "elif", "then", "time", "!", "if", "while", "until", "export", "local",
    "declare", "readonly", "typeset",
];

/// `_ShellCommandWord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandWord {
    pub text: String,
    pub end: usize,
    pub dynamic: bool,
    pub limited: bool,
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `_is_shell_command_word_start`.
pub(super) fn is_shell_command_word_start(content: &[char], start: usize) -> bool {
    if start == 0 {
        return true;
    }
    let previous = content[start - 1];
    if is_space(previous) || ";|&()<>/".contains(previous) {
        return true;
    }
    if "'\"`".contains(previous) {
        return match start.checked_sub(2) {
            None => true,
            Some(before) => is_space(content[before]) || ";|&()<>{}/".contains(content[before]),
        };
    }
    false
}

/// `_has_quoted_assignment_prefix`.
pub(super) fn has_quoted_assignment_prefix(content: &[char], start: usize) -> bool {
    if start >= content.len() || !"'\"".contains(content[start]) {
        return false;
    }
    let mut cursor = start + 1;
    if cursor >= content.len() || !(is_alpha(content[cursor]) || content[cursor] == '_') {
        return false;
    }
    cursor += 1;
    while cursor < content.len() && (is_alnum(content[cursor]) || content[cursor] == '_') {
        cursor += 1;
    }
    cursor < content.len() && content[cursor] == '='
}

/// `_previous_word_end`.
fn previous_word_end(content: &[char], start: usize) -> Option<usize> {
    let mut cursor = start;
    while cursor > 0 && " \t".contains(content[cursor - 1]) {
        cursor -= 1;
    }
    if cursor == 0 || CLAUSE_BOUNDARY.contains(content[cursor - 1]) {
        return None;
    }
    Some(cursor)
}

/// `_SHELL_ASSIGNMENT_PREFIX_RE.match(content, at)`: end of `NAME=` or `NAME+=`.
fn assignment_prefix_end(content: &[char], at: usize) -> Option<usize> {
    let first = *content.get(at)?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    let mut cursor = at + 1;
    while cursor < content.len() && is_name_char(content[cursor]) {
        cursor += 1;
    }
    if content.get(cursor) == Some(&'+') {
        cursor += 1;
    }
    (content.get(cursor) == Some(&'=')).then_some(cursor + 1)
}

/// `_is_assignment_word`.
fn is_assignment_word(content: &[char], start: usize) -> bool {
    let mut word_start = start;
    if 0 < start
        && start < content.len()
        && "'\"".contains(content[start])
        && content[start - 1] == '='
    {
        word_start = start - 1;
        if word_start > 0 && content[word_start - 1] == '+' {
            word_start -= 1;
        }
        while word_start > 0 && is_name_char(content[word_start - 1]) {
            word_start -= 1;
        }
    }
    let Some(prefix_end) = assignment_prefix_end(content, word_start) else {
        return false;
    };
    if word_start != start && prefix_end != start {
        return false;
    }
    let Some(previous_end) = previous_word_end(content, word_start) else {
        return true;
    };
    if previous_end == word_start {
        return false;
    }
    let mut previous_start = previous_end;
    while previous_start > 0
        && !" \t".contains(content[previous_start - 1])
        && !CLAUSE_BOUNDARY.contains(content[previous_start - 1])
    {
        previous_start -= 1;
    }
    let word: String = content[previous_start..previous_end].iter().collect();
    ASSIGNMENT_PREFIX_WORDS.contains(&word.as_str())
        && previous_word_end(content, previous_start).is_none()
}

static RECURSIVE_OPTION_SOURCE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"-(?:[A-Za-z]*[rR]|-recursive)").unwrap_or_else(|_| unreachable!())
});
static FORCE_OPTION_SOURCE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"-(?:[A-Za-z]*f|-force)").unwrap_or_else(|_| unreachable!())
});

/// `_is_printf_substitution(check_command_context=True)`.
pub(super) fn is_printf_substitution_in_context(
    content: &[char],
    start: usize,
    end: usize,
    backtick: bool,
) -> Result<bool, ShellError> {
    let inner_start = start + if backtick { 1 } else { 2 };
    let inner = &content[inner_start..end - 1];
    if !backtick && is_powershell_replace_value_context(content, start, end, inner) {
        return Ok(false);
    }
    let (recognized, _) = printf_invocation_arguments(inner, false)?;
    if recognized {
        return Ok(true);
    }
    if !inner.contains(&'$') {
        return Ok(false);
    }
    let (mut command_start, mut body_start) = (start, end);
    if start > 0 && content[start - 1] == '"' && end < content.len() && content[end] == '"' {
        command_start -= 1;
        body_start += 1;
    }
    let tail_end = content.len().min(body_start + ROOT_GLOB_COMMAND_CHARS);
    let tail_chars = &content[body_start.min(tail_end)..tail_end];
    let has = |m: char| tail_chars.contains(&m);
    if !has('\\') && (!has('-') || !"/~*?".chars().any(has)) {
        return Ok(false);
    }
    let tail: String = tail_chars.iter().collect();
    if !['\\', '\'', '"', '{', '}'].iter().any(|&m| has(m))
        && !tail.to_lowercase().contains("printf")
        && (!RECURSIVE_OPTION_SOURCE.is_match(&tail) || !FORCE_OPTION_SOURCE.is_match(&tail))
    {
        return Ok(false);
    }
    let (possible_runtime, _) = printf_invocation_arguments(inner, true)?;
    if !possible_runtime {
        return Ok(false);
    }
    let parsed = bounded_shell_tokens(content, command_start, body_start)?;
    Ok(parsed.limited
        || has_unsupported_brace_expansion(&parsed.tokens)
        || has_destructive_root_glob(&parsed.tokens)
        || has_destructive_root_path(&parsed.tokens))
}

/// `_parse_shell_command_word` (no caches; `enclosing_delimiter` is the exhaustion sweep's hook).
///
/// # Errors
/// See [`ShellError`].
pub fn parse_shell_command_word(
    content: &[char],
    start: usize,
    enclosing_delimiter: Option<char>,
) -> Result<Option<CommandWord>, ShellError> {
    parse_owning(content, start, enclosing_delimiter, None)
}

/// [`parse_shell_command_word`] that also records `owned_word_positions` (closing quotes and the
/// closing backtick of an enclosing substitution).
///
/// # Errors
/// See [`ShellError`].
#[allow(clippy::too_many_lines)]
pub(super) fn parse_owning(
    content: &[char],
    start: usize,
    enclosing_delimiter: Option<char>,
    mut owned: Option<&mut Vec<usize>>,
) -> Result<Option<CommandWord>, ShellError> {
    let assignment = is_assignment_word(content, start);
    let reconstructs = |s: usize, e: usize, backtick: bool| -> Result<bool, ShellError> {
        if assignment {
            Ok(false)
        } else {
            is_printf_substitution_in_context(content, s, e, backtick)
        }
    };
    let mut output = String::new();
    let wrapper_quote = enclosing_delimiter.or_else(|| {
        if "$`".contains(content[start]) {
            command_wrapper_quote(content, start)
        } else {
            None
        }
    });
    let mut quote: Option<char> = None;
    let mut ansi_c_quote = false;
    let mut dynamic = false;
    let mut limited = false;
    let mut unquoted_characters = 0usize;
    let mut cursor = start;
    let limit = content.len();
    while cursor < limit {
        let character = content[cursor];
        if let Some(q) = quote {
            if character == q {
                if let Some(o) = owned.as_deref_mut() {
                    o.push(cursor);
                }
                quote = None;
                ansi_c_quote = false;
            } else if character == '\\' && ansi_c_quote {
                let (decoded, next) = decode_ansi_c_escape(content, cursor, limit)?;
                cursor = next;
                if decoded.contains('\0') {
                    let Some(closing) = skip_ansi_c_quote_tail(content, cursor, limit) else {
                        return Ok(None);
                    };
                    cursor = closing;
                    continue;
                }
                output.push_str(&decoded);
                continue;
            } else if q == '"' && character == '$' && cursor + 1 < limit {
                let mut closed = false;
                if content[cursor + 1] == '(' {
                    let Some(end) = skip_command_substitution(content, cursor, limit)? else {
                        return Ok(None);
                    };
                    match static_printf_substitution(content, cursor, end, false)? {
                        None => {
                            output.push_str("$()");
                            dynamic = true;
                            limited = limited || reconstructs(cursor, end, false)?;
                        }
                        Some(v) => output.push_str(&v),
                    }
                    cursor = end;
                    continue;
                }
                if let Some(end) =
                    skip_parameter_expansion(content, cursor, limit, true, Some(&mut closed))?
                {
                    output.push_str("$PARAM");
                    dynamic = true;
                    cursor = end;
                    if closed {
                        quote = None;
                        ansi_c_quote = false;
                    }
                    continue;
                }
            } else if q == '"' && character == '`' {
                let Some(end) = skip_backtick_substitution(content, cursor, limit)? else {
                    return Ok(None);
                };
                match static_printf_substitution(content, cursor, end, true)? {
                    None => {
                        output.push_str("$()");
                        dynamic = true;
                        limited = limited || reconstructs(cursor, end, true)?;
                    }
                    Some(v) => output.push_str(&v),
                }
                cursor = end;
                continue;
            } else if character == '\\' && q == '"' && cursor + 1 < limit {
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
            } else {
                output.push(character);
            }
        } else if character == '$' && cursor + 1 < limit && "'\"".contains(content[cursor + 1]) {
            let q = content[cursor + 1];
            quote = Some(q);
            ansi_c_quote = q == '\'';
            cursor += 2;
            continue;
        } else if character == '$' && cursor + 1 < limit && content[cursor + 1] == '(' {
            let Some(end) = skip_command_substitution(content, cursor, limit)? else {
                return Ok(None);
            };
            match static_printf_substitution(content, cursor, end, false)? {
                None => {
                    output.push_str("$()");
                    dynamic = true;
                    limited = limited || reconstructs(cursor, end, false)?;
                }
                Some(v) => output.push_str(&v),
            }
            cursor = end;
            continue;
        } else if character == '$' {
            if let Some(end) = skip_parameter_expansion(content, cursor, limit, false, None)? {
                if is_ifs_expansion(content, cursor, end) {
                    cursor = end;
                    break;
                }
                output.push_str("$PARAM");
                dynamic = true;
                cursor = end;
                continue;
            }
        } else if character == '`' {
            if enclosing_delimiter == Some('`') {
                if let Some(o) = owned.as_deref_mut() {
                    o.push(cursor);
                }
                break;
            }
            let Some(end) = skip_backtick_substitution(content, cursor, limit)? else {
                return Ok(None);
            };
            match static_printf_substitution(content, cursor, end, true)? {
                None => {
                    output.push_str("$()");
                    dynamic = true;
                    limited = limited || reconstructs(cursor, end, true)?;
                }
                Some(v) => output.push_str(&v),
            }
            cursor = end;
            continue;
        } else if character == '\'' || character == '"' {
            if Some(character) == wrapper_quote {
                break;
            }
            quote = Some(character);
        } else if character == '\\' && cursor + 1 < limit {
            if content[cursor + 1] == '\n' {
                cursor += 2;
                continue;
            }
            if content[cursor + 1] == '\r' && cursor + 2 < limit && content[cursor + 2] == '\n' {
                cursor += 3;
                continue;
            }
            cursor += 1;
            output.push(content[cursor]);
        } else if is_space(character) || ";|&()<>".contains(character) {
            break;
        } else {
            output.push(character);
            unquoted_characters += 1;
            if unquoted_characters > SHELL_COMMAND_WORD_CHARS {
                return Ok(Some(CommandWord {
                    text: output,
                    end: cursor,
                    dynamic,
                    limited: true,
                }));
            }
        }
        cursor += 1;
    }
    if quote.is_some() {
        return Ok(None);
    }
    Ok(Some(CommandWord {
        text: output,
        end: cursor,
        dynamic,
        limited,
    }))
}

/// `_bounded_static_substitution_end`.
fn bounded_static_substitution_end(
    content: &[char],
    start: usize,
) -> Result<Option<usize>, ShellError> {
    let inner_start = start + 2;
    let scan_limit = content.len().min(inner_start + PRINTF_STATIC_CHARS + 1);
    let end = skip_command_substitution(content, start, scan_limit)?;
    Ok(end.filter(|&e| e - 1 - inner_start <= PRINTF_STATIC_CHARS))
}

/// `_destructive_command_words`: `(command_start, body_start)` of every literal `rm`/`del`/`erase`.
///
/// # Errors
/// See [`ShellError`].
pub fn destructive_command_words(content: &[char]) -> Result<Vec<(usize, usize)>, ShellError> {
    let mut out = Vec::new();
    let mut parsed_through = 0usize;
    for start in 0..content.len() {
        if !"rRdDeE$'\"`\\".contains(content[start]) || start < parsed_through {
            continue;
        }
        if !is_shell_command_word_start(content, start)
            || has_quoted_assignment_prefix(content, start)
        {
            continue;
        }
        if content[start] == '$' && content.get(start + 1) == Some(&'(') {
            let static_value = match bounded_static_substitution_end(content, start)? {
                None => None,
                Some(end) => static_printf_substitution(content, start, end, false)?,
            };
            if static_value.is_none() {
                continue;
            }
        }
        let Some(parsed) = parse_shell_command_word(content, start, None)? else {
            continue;
        };
        if "'\"".contains(content[start]) && !parsed.dynamic && !parsed.text.chars().any(is_space) {
            parsed_through = parsed_through.max(parsed.end);
        }
        let folded = crate::unicode::casefold(&parsed.text);
        let basename = folded.rsplit('/').next().unwrap_or("");
        if !parsed.dynamic && !parsed.limited && matches!(basename, "rm" | "del" | "erase") {
            parsed_through = parsed_through.max(parsed.end);
            out.push((start, parsed.end));
        }
    }
    Ok(out)
}

fn rfind_in(content: &[char], needle: char, from: usize, to: usize) -> Option<usize> {
    (from..to).rev().find(|&i| content[i] == needle)
}

fn find_in(content: &[char], needle: char, from: usize, to: usize) -> Option<usize> {
    (from..to).find(|&i| content[i] == needle)
}

fn pat(src: &str) -> Pat {
    Pat::new(src, "i")
}

/// Anchored on both ends: Python `re.fullmatch`.
fn full(src: &str) -> Pat {
    Pat::new(&format!(r"\A(?:{src})\z"), "i")
}

static DOC_LINE: LazyLock<Pat> = LazyLock::new(|| {
    full(
        r"[ \t]*(?:(?:[-*+]|#{1,6})[ \t]+)?(?:(?:(?:documentation|note|example)[ \t]*:[ \t]*)(?:(?:the|this|a|an)[ \t]+)?|(?:the|this|a|an)[ \t]+)(?:(?:gnu|posix(?:\.[0-9]+)?|unix)[ \t]+)?rm[ \t]+(?:utility|command|tool)\b[^;\n]{0,160}\b(?:accepts?|supports?)\b[^;\n]{0,160}\b(?:denotes?|means?|represents?)\b[^;\n]{0,80}\b(?:wildcard|glob|option|flag)\b[.!?]?[ \t]*",
    )
});
static EXECUTION_PREFIX: LazyLock<Pat> = LazyLock::new(|| {
    pat(
        r"\b(?P<action>run|execute|invoke|issue|launch|perform|call|eval|type|submit|enter|paste|carry[ \t]+out)\b[^.;\n]{0,240}$",
    )
});
static NEGATED_EXECUTION: LazyLock<Pat> = LazyLock::new(|| {
    pat(
        r"(?:(?:\bdo[ \t]+not|\bdon't|\bnever|\bavoid|\bmust[ \t]+not)(?:(?:[ \t]*,[ \t]*|[ \t]+)(?!(?:so|but|yet|then|therefore|however|instead)\b)\w+){0,8}[ \t,]*|\bnot[ \t,]*|\bnot(?:[ \t]*,[ \t]*|[ \t]+)(?:ever|directly|immediately|actually)[ \t,]*|\bnot(?:[ \t]*,[ \t]*|[ \t]+)(?:under|in)(?:[ \t]*,[ \t]*|[ \t]+)(?:any|all|these|those)(?:(?:[ \t]*,[ \t]*|[ \t]+)\w+){0,4}[ \t,]*)$",
    )
});
static SAFETY_WARNING_PREFIX: LazyLock<Pat> = LazyLock::new(|| {
    full(
        r"[ \t]*(?:please[ \t]+)?(?:(?:do[ \t]+not|don't|never|must[ \t]+not)[ \t]+(?:run|execute|invoke|issue|launch|perform|call|eval|type|submit|enter|paste|use)|avoid[ \t]+(?:running|executing|invoking|issuing|launching|performing|calling|evaluating|typing|submitting|entering|pasting|using)|refrain[ \t]+from[ \t]+(?:running|executing|invoking|issuing|launching|performing|calling|evaluating|typing|submitting|entering|pasting|using))[ \t]+(?:the[ \t]+)?",
    )
});
static AFFIRMATIVE_NEGATION_PREFIX: LazyLock<Pat> = LazyLock::new(|| {
    full(
        r".*\b(?:do[ \t]+not|don't|never)[ \t]+(?:forget(?:[ \t]+to|[ \t]+that(?:[ \t]+you)?[ \t]+(?:must|should|shall|will|need[ \t]+to)|[ \t]*,[ \t]*(?:and[ \t]+)?(?:be|make)[ \t]+sure[ \t]+to)|hesitate(?:[ \t]+at[ \t]+all)?[ \t]+to|fail[ \t]+to)[ \t]*",
    )
});
static WRAPPER_PREFIX: LazyLock<Pat> =
    LazyLock::new(|| pat(r"\b(?:sudo|env|xargs|command)\b[^.;\n]{0,64}$"));
static ARTICLE_PREFIX: LazyLock<Pat> =
    LazyLock::new(|| full(r"[ \t]*(?:the|this|a|an)(?:[ \t]+(?:gnu|posix|unix))?[ \t]*"));
static DOCUMENTARY_PREFIX: LazyLock<Pat> = LazyLock::new(|| {
    pat(
        r"(?:\b(?:explain|describe|document|note|state|say)(?:[ \t]+that)?|(?:documentation|docs?|guide|manual|reference|note|example)[ \t]*:)[ \t]*$",
    )
});
static DOCUMENTARY_LEADIN: LazyLock<Pat> = LazyLock::new(|| {
    full(
        r"[ \t]*(?:(?:in|under)[ \t]+(?:the[ \t]+)?(?:posix(?:\.[0-9]+)?|gnu|unix)(?:[ \t]+(?:standard|specification))?|according[ \t]+to[ \t]+(?:the[ \t]+)?(?:manual|documentation|reference|(?:posix(?:\.[0-9]+)?|gnu|unix)(?:[ \t]+(?:standard|specification))?)|for[ \t]+reference|this[ \t]+(?:section|guide|documentation)[ \t]+(?:explains?|describes?|documents?|notes?|states?|says?)(?:[ \t]+that)?)[ \t]*,?[ \t]+(?:(?:the|this|a|an)[ \t]+)?(?:(?:gnu|posix(?:\.[0-9]+)?|unix)[ \t]+)?",
    )
});
static DESCRIBES_FLAGS: LazyLock<Pat> =
    LazyLock::new(|| pat(r"\b(?:command|utility|tool)\b|\b(?:accepts?|supports?|uses?|takes?)\b"));
static DESCRIBES_GLOB: LazyLock<Pat> = LazyLock::new(|| {
    pat(
        r"\b(?:denotes?|means?|represents?|matches?|wildcards?|globs?)\b|\b(?:all|every)[ \t]+files?\b",
    )
});

fn matches(p: &Pat, text: &str) -> bool {
    !p.find_iter(text).is_empty()
}

/// `_is_root_glob_documentation`: `rm` is the noun of a bounded prose description.
#[must_use]
pub fn is_root_glob_documentation(
    content: &[char],
    command_start: usize,
    body_start: usize,
) -> bool {
    let context_start = command_start.saturating_sub(256);
    let previous_boundary = [
        rfind_in(content, '\n', context_start, command_start),
        rfind_in(content, ';', context_start, command_start),
    ]
    .into_iter()
    .flatten()
    .max();
    let prefix_truncated = previous_boundary.is_none() && context_start > 0;
    let clause_start = previous_boundary.map_or(context_start, |b| b + 1);
    let context_end = content.len().min(command_start + 512);
    let clause_end = [
        find_in(content, '\n', command_start, context_end),
        find_in(content, ';', command_start, context_end),
    ]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(context_end);
    let clause: String = content[clause_start..clause_end].iter().collect();
    if matches(&DOC_LINE, &clause) {
        return true;
    }
    let relative_start = command_start - clause_start;
    let clause_chars: Vec<char> = content[clause_start..clause_end].to_vec();
    let prefix: String = clause_chars[..relative_start.min(clause_chars.len())]
        .iter()
        .collect();
    let suffix_from = relative_start.max(body_start.saturating_sub(clause_start));
    let suffix: String = clause_chars[suffix_from.min(clause_chars.len())..]
        .iter()
        .collect();
    if prefix.chars().all(is_space) || prefix_truncated {
        return false;
    }
    let mut negated_execution = false;
    if let Some(execution) = EXECUTION_PREFIX.find_iter(&prefix).first() {
        let action_start = execution
            .groups
            .iter()
            .flatten()
            .nth(1)
            .map_or(execution.start, |g| g.0);
        let negation_prefix = &prefix[..action_start];
        if matches(&AFFIRMATIVE_NEGATION_PREFIX, negation_prefix)
            || !matches(&NEGATED_EXECUTION, negation_prefix)
        {
            return false;
        }
        negated_execution = true;
    }
    if matches(&SAFETY_WARNING_PREFIX, &prefix) {
        return true;
    }
    if matches(&WRAPPER_PREFIX, &prefix) {
        return false;
    }
    if !matches(&ARTICLE_PREFIX, &prefix)
        && !matches(&DOCUMENTARY_PREFIX, &prefix)
        && !matches(&DOCUMENTARY_LEADIN, &prefix)
        && !negated_execution
    {
        return false;
    }
    matches(&DESCRIBES_FLAGS, &suffix) && matches(&DESCRIBES_GLOB, &suffix) && suffix.contains('*')
}

/// `_static_brace_expansions`: a small literal Bash brace word, or `None`.
fn static_brace_expansions(word: &str) -> Option<Vec<String>> {
    if word.chars().count() > STATIC_BRACE_WORD_CHARS {
        return None;
    }
    let mut expanded = vec![word.to_owned()];
    let mut changed = false;
    for _ in 0..4 {
        let mut next_words: Vec<String> = Vec::new();
        let mut expanded_this_round = false;
        for candidate in &expanded {
            let chars: Vec<char> = candidate.chars().collect();
            let found = (0..chars.len()).find_map(|i| {
                if chars[i] != '{' {
                    return None;
                }
                let j = (i + 1..chars.len()).find(|&j| chars[j] == '{' || chars[j] == '}')?;
                (chars[j] == '}').then_some((i, j))
            });
            let Some((open, close)) = found.filter(|&(o, c)| chars[o + 1..c].contains(&',')) else {
                next_words.push(candidate.clone());
                continue;
            };
            let body: String = chars[open + 1..close].iter().collect();
            let alternatives: Vec<&str> = body.split(',').collect();
            if alternatives.len() > 8 {
                return None;
            }
            let head: String = chars[..open].iter().collect();
            let tail: String = chars[close + 1..].iter().collect();
            next_words.extend(alternatives.iter().map(|a| format!("{head}{a}{tail}")));
            if next_words.len() > 32 {
                return None;
            }
            expanded_this_round = true;
            changed = true;
        }
        expanded = next_words;
        if !expanded_this_round {
            break;
        }
    }
    if expanded.iter().any(|c| c.contains('{') || c.contains('}')) {
        return None;
    }
    changed.then_some(expanded)
}

fn is_short_option(word: &str) -> bool {
    word.len() > 1 && word.starts_with('-') && word[1..].chars().all(|c| c.is_ascii_alphabetic())
}

/// `_has_recursive_force_options`.
fn has_recursive_force_options(tokens: &[ShellToken]) -> bool {
    let options_end = tokens
        .iter()
        .position(|t| t.text == "--")
        .unwrap_or(tokens.len());
    let mut words: Vec<String> = Vec::new();
    for token in &tokens[..options_end] {
        if token.brace_expansion
            && let Some(expanded) = static_brace_expansions(&token.text)
        {
            words.extend(expanded);
            continue;
        }
        words.push(token.text.clone());
    }
    let short: Vec<&str> = words
        .iter()
        .filter(|w| is_short_option(w))
        .map(|w| &w[1..])
        .collect();
    let recursive = words.iter().any(|w| w == "--recursive")
        || short.iter().any(|o| o.contains('r') || o.contains('R'));
    let force = words.iter().any(|w| w == "--force") || short.iter().any(|o| o.contains('f'));
    recursive && force
}

/// `_has_destructive_root_glob`.
#[must_use]
pub fn has_destructive_root_glob(tokens: &[ShellToken]) -> bool {
    let is_root_glob = |token: &ShellToken| -> bool {
        if token.root_glob {
            return true;
        }
        if !token.brace_expansion {
            return false;
        }
        static_brace_expansions(&token.glob_projection).is_some_and(|e| {
            e.iter()
                .any(|w| !w.is_empty() && w.chars().all(|c| c == '*' || c == '?'))
        })
    };
    tokens.iter().any(is_root_glob) && has_recursive_force_options(tokens)
}

/// `_has_destructive_root_path`.
#[must_use]
pub fn has_destructive_root_path(tokens: &[ShellToken]) -> bool {
    let is_root_path = |token: &ShellToken| -> bool {
        let candidates = if token.brace_expansion {
            static_brace_expansions(&token.text).unwrap_or_else(|| vec![token.text.clone()])
        } else {
            vec![token.text.clone()]
        };
        candidates.iter().any(|c| c.starts_with('/'))
            || (token.leading_tilde_unquoted && candidates.iter().any(|c| c.starts_with('~')))
    };
    tokens.iter().any(is_root_path) && has_recursive_force_options(tokens)
}

/// `_has_unsupported_brace_expansion`.
#[must_use]
pub fn has_unsupported_brace_expansion(tokens: &[ShellToken]) -> bool {
    tokens
        .iter()
        .any(|t| t.brace_expansion && static_brace_expansions(&t.text).is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    #[test]
    fn finds_literal_rm() {
        let c = chars("echo hi; rm -rf /tmp/x\n");
        let words = destructive_command_words(&c).unwrap_or_default();
        assert_eq!(words, vec![(9, 11)]);
    }

    #[test]
    fn rejects_rmm_prefix() {
        let c = chars("rmm/foo -rf /");
        assert!(destructive_command_words(&c).unwrap_or_default().is_empty());
    }

    #[test]
    fn root_options() {
        let c = chars("rm -rf /");
        let t = bounded_shell_tokens(&c, 0, 2)
            .map(|b| b.tokens)
            .unwrap_or_default();
        assert!(has_destructive_root_path(&t));
        let c = chars("rm -r foo");
        let t = bounded_shell_tokens(&c, 0, 2)
            .map(|b| b.tokens)
            .unwrap_or_default();
        assert!(!has_destructive_root_path(&t));
    }

    #[test]
    fn brace_words() {
        assert_eq!(
            static_brace_expansions("-{r,f}"),
            Some(vec!["-r".into(), "-f".into()])
        );
        assert_eq!(static_brace_expansions("plain"), None);
    }

    #[test]
    fn documentation_prose() {
        let c = chars("The rm utility accepts * which means all files, wildcard.");
        assert!(is_root_glob_documentation(&c, 4, 6));
    }
}
