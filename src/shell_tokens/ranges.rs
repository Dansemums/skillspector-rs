//! `_e1_shell_command_ranges` (data_exfiltration) and `_sc2_shell_command_ranges` (supply_chain),
//! with the regexes they use hand-coded over char slices (Python `pos`/`endpos` semantics).

use super::ShellError;
use super::expand::{skip_backtick_substitution, skip_command_substitution};
use super::markdown::markdown_shell_text_fences;
use super::powershell::ci;
use super::tokens::{ROOT_GLOB_COMMAND_CHARS, bounded_shell_tokens};
use crate::unicode::is_space;

/// `(start, end)` char range; `end == None` keeps the legacy open-ended matcher.
pub type CharRange = (usize, Option<usize>);

fn is_break(c: char) -> bool {
    matches!(
        c,
        '\r' | '\n'
            | '\x0b'
            | '\x0c'
            | '\x1c'
            | '\x1d'
            | '\x1e'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

fn lit(s: &[char], pos: usize, word: &str) -> Option<usize> {
    let mut i = pos;
    for w in word.chars() {
        if !ci(*s.get(i)?, w) {
            return None;
        }
        i += 1;
    }
    Some(i)
}

/// `[ \t]` run end.
fn blanks(s: &[char], pos: usize) -> usize {
    let mut i = pos;
    while s.get(i).is_some_and(|&c| c == ' ' || c == '\t') {
        i += 1;
    }
    i
}

fn spaces_end(s: &[char], pos: usize) -> usize {
    let mut i = pos;
    while s.get(i).is_some_and(|&c| is_space(c)) {
        i += 1;
    }
    i
}

fn is_fetch_word(s: &[char], p: usize) -> Option<usize> {
    lit(s, p, "curl").or_else(|| lit(s, p, "wget"))
}

fn fence_open(s: &[char]) -> Option<(char, usize, usize)> {
    // MARKDOWN_FENCE_OPEN.fullmatch(s): (marker char, begin, end of group 1).
    let spaces = s.iter().take_while(|&&c| c == ' ').count();
    if spaces > 3 {
        return None;
    }
    let marker = *s.get(spaces)?;
    if marker != '`' && marker != '~' {
        return None;
    }
    let run = s[spaces..].iter().take_while(|&&c| c == marker).count();
    if run < 3 {
        return None;
    }
    let end = spaces + run;
    if (marker == '`' && s[end..].contains(&'`'))
        || s[end..].iter().any(|&c| c == '\r' || c == '\n')
    {
        return None;
    }
    Some((marker, spaces, end))
}

fn fence_close(s: &[char]) -> Option<(char, usize)> {
    // MARKDOWN_FENCE_CLOSE.fullmatch(s): (marker char, run length).
    let spaces = s.iter().take_while(|&&c| c == ' ').count();
    if spaces > 3 {
        return None;
    }
    let marker = *s.get(spaces)?;
    if marker != '`' && marker != '~' {
        return None;
    }
    let run = s[spaces..].iter().take_while(|&&c| c == marker).count();
    let end = spaces + run;
    (run >= 3 && s[end..].iter().all(|&c| c == ' ' || c == '\t')).then_some((marker, run))
}

/// `_e1_shell_regions`: regions whose physical separators have shell semantics.
fn e1_shell_regions(content: &[char], is_shell: bool, is_markdown: bool) -> Vec<(usize, usize)> {
    if is_shell {
        return vec![(0, content.len())];
    }
    if !is_markdown {
        return Vec::new();
    }
    // CommonMark HTML blocks can hide fences: keep legacy matching for any possible tag.
    let has_tag = content
        .windows(2)
        .any(|w| w[0] == '<' && (matches!(w[1], '/' | '!' | '?') || w[1].is_ascii_alphabetic()));
    if has_tag {
        return Vec::new();
    }
    let mut regions = Vec::new();
    // (marker, length, region start, is shell language)
    let mut active: Option<(char, usize, usize, bool)> = None;
    let trimmed: Vec<char> = content
        .iter()
        .skip_while(|&&c| c == '\u{feff}')
        .copied()
        .collect();
    let starts = |p: &str| {
        trimmed
            .iter()
            .take(p.chars().count())
            .copied()
            .eq(p.chars())
    };
    let mut frontmatter = starts("---\n") || starts("---\r");
    let mut offset = 0;
    while offset < content.len() {
        let e = (offset..content.len()).find(|&i| content[i] == '\r' || content[i] == '\n');
        let (line_end, term) = match e {
            None => (content.len(), 0),
            Some(i) if content[i] == '\r' && content.get(i + 1) == Some(&'\n') => (i, 2),
            Some(i) => (i, 1),
        };
        let physical = &content[offset..line_end];
        let next_offset = line_end + term;
        if frontmatter {
            let text: String = physical.iter().collect();
            if offset > 0 && (text == "---" || text == "...") {
                frontmatter = false;
            }
        } else if active.is_none() {
            if let Some((marker, begin, end)) = fence_open(physical) {
                let info: String = physical[end..].iter().collect();
                let first = crate::unicode::py_split(&info)
                    .next()
                    .map(str::to_lowercase);
                let shell = first.is_some_and(|f| {
                    matches!(
                        f.as_str(),
                        "sh" | "bash" | "shell" | "dash" | "zsh" | "ksh" | "console"
                    )
                });
                active = Some((marker, end - begin, next_offset, shell));
            }
        } else if let Some((mc, ml, region_start, shell)) = active
            && let Some((marker, run)) = fence_close(physical)
            && marker == mc
            && run >= ml
        {
            if shell {
                regions.push((region_start, offset));
            }
            active = None;
        }
        offset = next_offset;
    }
    if let Some((_, _, region_start, true)) = active {
        regions.push((region_start, content.len()));
    }
    regions
}

/// `_E1_UNPROVED_SHELL_SPACE.search(content, start, end)`: `(?!\r\n)[^\S \t\n]`.
fn has_unproved_shell_space(content: &[char], start: usize, end: usize) -> bool {
    let end = end.min(content.len());
    (start..end).any(|i| {
        let c = content[i];
        is_space(c)
            && c != ' '
            && c != '\t'
            && c != '\n'
            && !(c == '\r' && i + 1 < end && content[i + 1] == '\n')
    })
}

/// `_E1_UNPROVED_SHELL_SYNTAX.search(content, start, end)`: `(?<!\S)--%(?=\s|$)|[{}]|<#`.
fn has_unproved_shell_syntax(content: &[char], start: usize, end: usize) -> bool {
    let end = end.min(content.len());
    (start..end).any(|i| {
        let c = content[i];
        if c == '{' || c == '}' {
            return true;
        }
        if c == '<' && i + 1 < end && content[i + 1] == '#' {
            return true;
        }
        c == '-'
            && (i == 0 || is_space(content[i - 1]))
            && i + 2 < end
            && content[i + 1] == '-'
            && content[i + 2] == '%'
            && (i + 3 == end || is_space(content[i + 3]))
    })
}

/// `re.search(r"\^[ \t]*\r?$", text)` (no MULTILINE: `$` is the end or before a final `\n`).
fn has_caret_continuation(text: &[char]) -> bool {
    let dollar = |r: usize| r == text.len() || (r + 1 == text.len() && text[r] == '\n');
    text.iter().enumerate().any(|(p, &c)| {
        if c != '^' {
            return false;
        }
        let q = blanks(text, p + 1);
        dollar(q) || (text.get(q) == Some(&'\r') && dollar(q + 1))
    })
}

/// Port of `_e1_shell_command_ranges(content, file_type)` over chars.
///
/// # Errors
/// Never in practice: the Python `TypeError`/`ValueError` from the tokenizer is caught and turned
/// into an open-ended range, exactly as in Python.
pub fn e1_ranges_chars(content: &[char], is_shell: bool, is_markdown: bool) -> Vec<CharRange> {
    let mut ranges: Vec<CharRange> = Vec::new();
    let mut previous_end = 0;
    let regions = e1_shell_regions(content, is_shell, is_markdown);
    let mut region_index = 0;
    let mut p = 0;
    while p < content.len() {
        // `(?:curl|wget)(?=\s)`
        let Some(word_end) =
            is_fetch_word(content, p).filter(|&e| content.get(e).is_some_and(|&c| is_space(c)))
        else {
            p += 1;
            continue;
        };
        let (fetch_start, fetch_end) = (p, word_end);
        p = fetch_end;
        if fetch_start < previous_end {
            ranges.push((fetch_start, None));
            break;
        }
        while region_index < regions.len() && regions[region_index].1 <= fetch_start {
            region_index += 1;
        }
        if region_index == regions.len() || fetch_start < regions[region_index].0 {
            ranges.push((fetch_start, None));
            break;
        }
        let tokens = match bounded_shell_tokens(content, fetch_start, fetch_end) {
            Ok(t) => t,
            Err(ShellError::UpperNotSingleChar) => {
                ranges.push((fetch_start, None));
                break;
            }
        };
        let (end, limited) = (tokens.end, tokens.limited);
        let after = content.get(end).copied();
        let unproved = limited
            || end > regions[region_index].1
            || content[fetch_start..end.min(content.len())]
                .windows(2)
                .any(|w| w == ['<', '<'])
            || after.is_some_and(|c| matches!(c, '\'' | '"' | '`' | '(' | ')' | ';' | '#'))
            || has_unproved_shell_space(content, fetch_start, end + 1)
            || has_unproved_shell_syntax(content, fetch_start, end + 1)
            || has_caret_continuation(&content[fetch_start..end.min(content.len())]);
        if unproved {
            ranges.push((fetch_start, None));
            break;
        }
        ranges.push((fetch_start, Some(end)));
        previous_end = end;
    }
    ranges
}

// ---------------------------------------------------------------------------------------------
// SC2
// ---------------------------------------------------------------------------------------------

/// `_sc2_substitution_ranges`.
fn sc2_substitution_ranges(shell_text: &[char]) -> Result<Vec<(usize, usize)>, ShellError> {
    let mut ranges = Vec::new();
    let mut cursor = 0;
    while let Some(start) = (cursor..shell_text.len()).find(|&i| {
        shell_text[i] == '`' || (shell_text[i] == '$' && shell_text.get(i + 1) == Some(&'('))
    }) {
        let limit = shell_text.len().min(start + ROOT_GLOB_COMMAND_CHARS);
        let end = if shell_text[start] == '$' {
            skip_command_substitution(shell_text, start, limit)?
        } else {
            skip_backtick_substitution(shell_text, start, limit)?
        };
        match end {
            None => {
                ranges.push((start, shell_text.len()));
                break;
            }
            Some(end) => {
                ranges.push((start, end));
                cursor = end;
            }
        }
    }
    Ok(ranges)
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Group {
    Quoted,
    Escaped,
    Comment,
    Heredoc,
    Word,
    Delimiter,
    UnclosedQuote,
}

const COMPOUND_WORDS: [&str; 12] = [
    "if", "fi", "for", "while", "until", "select", "done", "case", "esac", "begin", "end",
    "function",
];

/// One `_SC2_COMPOUND_TOKEN` match at `p` (searching within `[.., end)`): `(group, match end)`.
fn compound_token_at(s: &[char], p: usize, end: usize) -> Option<(Group, usize)> {
    let c = s[p];
    if c == '"' {
        let mut q = p + 1;
        while q < end {
            match s[q] {
                '"' => return Some((Group::Quoted, q + 1)),
                '\\' if q + 1 < end && s[q + 1] != '\n' => q += 2,
                '\\' => break,
                _ => q += 1,
            }
        }
    } else if c == '\''
        && let Some(q) = (p + 1..end).find(|&i| s[i] == '\'')
    {
        return Some((Group::Quoted, q + 1));
    }
    if c == '\\' && p + 1 < end {
        return Some((Group::Escaped, p + 2));
    }
    if c == '#' && (p == 0 || is_space(s[p - 1]) || ";&|()<>".contains(s[p - 1])) {
        let mut q = p + 1;
        while q < end && s[q] != '\r' && s[q] != '\n' {
            q += 1;
        }
        return Some((Group::Comment, q));
    }
    if c == '<' && p + 1 < end && s[p + 1] == '<' {
        return Some((Group::Heredoc, p + 2));
    }
    if p == 0 || is_space(s[p - 1]) || ";|&(){}".contains(s[p - 1]) {
        for w in COMPOUND_WORDS {
            let n = w.chars().count();
            if p + n <= end && w.chars().enumerate().all(|(k, ch)| s[p + k] == ch) {
                let after_ok = p + n == end || is_space(s[p + n]) || ";|&(){}".contains(s[p + n]);
                if after_ok {
                    return Some((Group::Word, p + n));
                }
            }
        }
    }
    if "(){}".contains(c) {
        return Some((Group::Delimiter, p + 1));
    }
    if matches!(c, '\'' | '"' | '`') {
        return Some((Group::UnclosedQuote, p + 1));
    }
    None
}

/// `_SC2_CLAUSE_PREFIX.fullmatch(s)`: `[ \t]*(?:(?:then|do|else|elif|time(?:[ \t]+-p)?|!)[ \t]+)*`.
fn clause_prefix_full(s: &[char]) -> bool {
    fn rec(s: &[char], pos: usize) -> bool {
        if pos == s.len() {
            return true;
        }
        let mut cands: Vec<usize> = Vec::new();
        for w in ["then", "do", "else", "elif", "!"] {
            if super::expand::starts_with(s, pos, w) {
                cands.push(pos + w.chars().count());
            }
        }
        if super::expand::starts_with(s, pos, "time") {
            let after = pos + 4;
            let b = blanks(s, after);
            if b > after && super::expand::starts_with(s, b, "-p") {
                cands.push(b + 2);
            }
            cands.push(after);
        }
        cands.into_iter().any(|e| {
            let b = blanks(s, e);
            b > e && rec(s, b)
        })
    }
    rec(s, blanks(s, 0))
}

/// `_sc2_has_unproved_compound_context`.
fn sc2_has_unproved_compound_context(
    content: &[char],
    offset: usize,
    fence_ends: &[usize],
) -> bool {
    let mut start = offset.saturating_sub(ROOT_GLOB_COMMAND_CHARS);
    let fence_index = fence_ends.partition_point(|&e| e <= offset);
    if fence_index > 0 && fence_ends[fence_index - 1] >= start {
        start = fence_ends[fence_index - 1];
    } else if start > 0 {
        return true;
    }
    let mut stack: Vec<&str> = Vec::new();
    let mut p = start;
    while p < offset {
        let Some((group, end)) = compound_token_at(content, p, offset) else {
            p += 1;
            continue;
        };
        let value: String = content[p..end].iter().collect();
        if matches!(group, Group::UnclosedQuote | Group::Heredoc) {
            return true;
        }
        if group == Group::Escaped && (value.contains('\r') || value.contains('\n')) {
            return true;
        }
        if matches!(group, Group::Word | Group::Delimiter) {
            if group == Group::Word || value == "}" {
                let boundary = (start..p)
                    .rev()
                    .find(|&i| "\n;|&(){}".contains(content[i]))
                    .map_or(0, |i| i + 1);
                if !clause_prefix_full(&content[boundary..p]) {
                    if value == "}" {
                        return true;
                    }
                    p = end;
                    continue;
                }
            }
            let endings = match value.as_str() {
                "if" => Some("fi"),
                "for" | "while" | "until" | "select" => Some("done"),
                "case" => Some("esac"),
                "begin" | "function" => Some("end"),
                "(" => Some(")"),
                "{" => Some("}"),
                _ => None,
            };
            if let Some(e) = endings {
                stack.push(e);
            } else if stack.last().is_some_and(|&top| top == value) {
                stack.pop();
            } else if matches!(value.as_str(), "fi" | "done" | "esac" | "end" | "}")
                // A case arm's `)` is not a parenthesis-group close.
                || (value == ")" && stack.contains(&")"))
            {
                return true;
            }
        }
        p = end;
    }
    !stack.is_empty()
}

/// `_SC2_ATTACHED_EXECUTOR.match(content, pos)`: the match end.
fn sc2_attached_executor(s: &[char], pos: usize) -> Option<usize> {
    let after_op = match s.get(pos)? {
        '|' => pos + 1,
        '&' if s.get(pos + 1) == Some(&'&') => pos + 2,
        _ => return None,
    };
    let q = spaces_end(s, after_op);
    let exec = |at: usize| -> Option<usize> {
        if let Some(e) = lit(s, at, "bash") {
            return Some(e);
        }
        if let Some(e) = lit(s, at, "sh") {
            return Some(e);
        }
        if let Some(e) = lit(s, at, "python") {
            return Some(if s.get(e) == Some(&'3') { e + 1 } else { e });
        }
        lit(s, at, "node")
            .or_else(|| lit(s, at, "ruby"))
            .or_else(|| lit(s, at, "perl"))
    };
    if let Some(sudo) = lit(s, q, "sudo") {
        let r = spaces_end(s, sudo);
        if r > sudo
            && let Some(e) = exec(r)
        {
            return Some(e);
        }
    }
    exec(q)
}

/// `_SC2_FENCE_LINE.finditer(content)`: `(start, end, marker_start, marker_end)`.
fn sc2_fence_lines(content: &[char]) -> Vec<(usize, usize, usize, usize)> {
    let mut out = Vec::new();
    let mut p = 0;
    while p <= content.len() {
        let mut starts = Vec::new();
        if p == 0 {
            starts.push(0);
        }
        if p < content.len() && is_break(content[p]) {
            let n = if content[p] == '\r' && content.get(p + 1) == Some(&'\n') {
                2
            } else {
                1
            };
            starts.push(p + n);
        }
        let mut matched = None;
        for q in starts {
            let m_start = blanks(content, q);
            let Some(&marker) = content.get(m_start) else {
                continue;
            };
            if marker != '`' && marker != '~' {
                continue;
            }
            let run = content[m_start..]
                .iter()
                .take_while(|&&c| c == marker)
                .count();
            if run < 3 {
                continue;
            }
            let m_end = m_start + run;
            let mut e = m_end;
            while e < content.len() && !is_break(content[e]) {
                e += 1;
            }
            matched = Some((p, e, m_start, m_end));
            break;
        }
        if let Some(m) = matched {
            out.push(m);
            p = m.1.max(p + 1);
        } else {
            p += 1;
        }
    }
    out
}

/// `LOGICAL_LINE_BREAK.sub(lambda m: "\n" + " " * (len(m) - 1), text)`.
fn proof_text(shell_text: &[char]) -> Vec<char> {
    let mut out = Vec::with_capacity(shell_text.len());
    let mut i = 0;
    while i < shell_text.len() {
        if is_break(shell_text[i]) {
            if shell_text[i] == '\r' && shell_text.get(i + 1) == Some(&'\n') {
                out.extend(['\n', ' ']);
                i += 2;
            } else {
                out.push('\n');
                i += 1;
            }
        } else {
            out.push(shell_text[i]);
            i += 1;
        }
    }
    out
}

/// Port of `_sc2_shell_command_ranges(content, file_type)` over chars.
///
/// # Errors
/// Propagates the tokenizer's [`ShellError`] (an uncaught `TypeError` in Python).
pub fn sc2_ranges_chars(
    content: &[char],
    is_markdown_or_text: bool,
) -> Result<Vec<CharRange>, ShellError> {
    let mut ranges: Vec<CharRange> = Vec::new();
    let shell_text: Vec<char> = if is_markdown_or_text {
        markdown_shell_text_fences(content)
    } else {
        content.to_vec()
    };
    let proof: Vec<char> = if is_markdown_or_text {
        proof_text(&shell_text)
    } else {
        shell_text.clone()
    };
    let fences: Vec<(usize, usize)> = sc2_fence_lines(content)
        .into_iter()
        .filter(|&(_, _, ms, me)| shell_text[ms..me].iter().all(|&c| is_space(c)))
        .map(|(s, e, _, _)| (s, e))
        .collect();
    let fence_starts: Vec<usize> = fences.iter().map(|f| f.0).collect();
    let fence_ends: Vec<usize> = fences.iter().map(|f| f.1).collect();
    let substitutions = sc2_substitution_ranges(&shell_text)?;
    let mut substitution_index = 0;
    let mut p = 0;
    while p < content.len() {
        // `(?:curl|wget)\s+`
        let Some(word_end) =
            is_fetch_word(content, p).filter(|&e| content.get(e).is_some_and(|&c| is_space(c)))
        else {
            p += 1;
            continue;
        };
        let fetch_start = p;
        p = spaces_end(content, word_end);
        while substitution_index < substitutions.len()
            && substitutions[substitution_index].1 <= fetch_start
        {
            substitution_index += 1;
        }
        if substitution_index < substitutions.len()
            && substitutions[substitution_index].0 < fetch_start
        {
            ranges.push((fetch_start, None));
            break;
        }
        if sc2_has_unproved_compound_context(&shell_text, fetch_start, &fence_ends)
            || sc2_has_unproved_compound_context(&proof, fetch_start, &fence_ends)
        {
            ranges.push((fetch_start, None));
            break;
        }
        let fence_index = fence_starts.partition_point(|&s| s <= fetch_start);
        let document_end = if fence_index < fences.len() {
            fence_starts[fence_index]
        } else {
            content.len()
        };
        let parse_start = fetch_start.saturating_sub(ROOT_GLOB_COMMAND_CHARS);
        let parse_end = document_end.min(fetch_start + 4 + ROOT_GLOB_COMMAND_CHARS + 1);
        let window = &shell_text[parse_start..parse_end.max(parse_start)];
        let tokens = bounded_shell_tokens(
            window,
            fetch_start - parse_start,
            fetch_start + 4 - parse_start,
        )?;
        let command_end = parse_start + tokens.end;
        if tokens.limited
            || content
                .get(command_end)
                .is_some_and(|&c| matches!(c, '\'' | '"' | '`' | ')'))
            || has_caret_continuation(&content[fetch_start..command_end.min(content.len())])
            || sc2_has_unproved_compound_context(&shell_text, command_end, &fence_ends)
            || sc2_has_unproved_compound_context(&proof, command_end, &fence_ends)
        {
            ranges.push((fetch_start, None));
            break;
        }
        if let Some(end) = sc2_attached_executor(content, command_end) {
            ranges.push((fetch_start, Some(end)));
        }
    }
    Ok(ranges)
}
