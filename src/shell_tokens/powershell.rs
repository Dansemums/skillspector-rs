//! `_is_powershell_replace_value_context`: a bounded PowerShell `-replace` value statement.
//! Python `re.IGNORECASE` literals are matched with [`ci`] (ASCII plus the four non-ASCII
//! characters that fold to ASCII letters: U+0130, U+0131, U+017F, U+212A).

use crate::unicode::is_space;

const PLACEHOLDER: char = '\u{e003}';

/// One IGNORECASE literal character; `lower` is the lowercase ASCII (or punctuation) pattern char.
pub(super) fn ci(c: char, lower: char) -> bool {
    match lower {
        'i' => matches!(c, 'i' | 'I' | '\u{130}' | '\u{131}'),
        's' => matches!(c, 's' | 'S' | '\u{17f}'),
        'k' => matches!(c, 'k' | 'K' | '\u{212a}'),
        _ => c.eq_ignore_ascii_case(&lower),
    }
}

/// `[A-Za-z]` under IGNORECASE.
fn az(c: char) -> bool {
    c.is_ascii_alphabetic() || matches!(c, '\u{130}' | '\u{131}' | '\u{17f}' | '\u{212a}')
}

fn az_09_(c: char) -> bool {
    az(c) || c.is_ascii_digit() || c == '_'
}

fn lit_ci(s: &[char], pos: usize, word: &str) -> Option<usize> {
    let mut i = pos;
    for w in word.chars() {
        if !ci(*s.get(i)?, w) {
            return None;
        }
        i += 1;
    }
    Some(i)
}

fn blanks(s: &[char], pos: usize) -> usize {
    let mut i = pos;
    while i < s.len() && (s[i] == ' ' || s[i] == '\t') {
        i += 1;
    }
    i
}

fn blanks1(s: &[char], pos: usize) -> Option<usize> {
    let e = blanks(s, pos);
    (e > pos).then_some(e)
}

fn py_strip(s: &[char]) -> Vec<char> {
    let a = s.iter().position(|&c| !is_space(c)).unwrap_or(s.len());
    let b = s.iter().rposition(|&c| !is_space(c)).map_or(a, |i| i + 1);
    s[a..b.max(a)].to_vec()
}

fn contains_str(s: &[char], needle: &str) -> bool {
    (0..s.len()).any(|i| super::expand::starts_with(s, i, needle))
}

fn is_word_char(c: char) -> bool {
    crate::unicode::is_alnum(c) || c == '_'
}

/// `_POWERSHELL_REPLACE_EXPRESSION_RE.search(inner)` (anchored with `\A`).
fn matches_replace_expression(inner: &[char]) -> bool {
    let mut i = 0;
    while i < inner.len() && is_space(inner[i]) {
        i += 1;
    }
    if inner.get(i) != Some(&'$') {
        return false;
    }
    i += 1;
    let tail = |e: usize| -> bool {
        let mut w = e;
        while w < inner.len() && is_space(inner[w]) {
            w += 1;
        }
        if w == e || inner.get(w) != Some(&'-') {
            return false;
        }
        let Some(end) = lit_ci(inner, w + 1, "replace") else {
            return false;
        };
        inner.get(end).is_none_or(|&c| !is_word_char(c))
    };
    // Alternative 1: name then `.name` properties.
    if inner.get(i).is_some_and(|&c| az(c) || c == '_') {
        let mut e = i + 1;
        while e < inner.len() && az_09_(inner[e]) {
            e += 1;
        }
        loop {
            if inner.get(e) == Some(&'.') && inner.get(e + 1).is_some_and(|&c| az(c) || c == '_') {
                e += 2;
                while e < inner.len() && az_09_(inner[e]) {
                    e += 1;
                }
            } else {
                break;
            }
        }
        if tail(e) {
            return true;
        }
    }
    // Alternative 2: `_` then any of `[A-Za-z0-9_.]*`.
    if inner.get(i) == Some(&'_') {
        let mut e = i + 1;
        while e < inner.len() && (az_09_(inner[e]) || inner[e] == '.') {
            e += 1;
        }
        return tail(e);
    }
    false
}

/// `re.match(container)`: returns the end of a block-quote / list / heading prefix.
fn container_end(s: &[char]) -> Option<usize> {
    if s.first() == Some(&'>') {
        let mut i = 0;
        while s.get(i) == Some(&'>') {
            i = blanks(s, i + 1);
        }
        return Some(i);
    }
    let marker_end = match s.first() {
        Some('-' | '*' | '+') => 1,
        Some(c) if c.is_ascii_digit() => {
            let mut i = 1;
            while s.get(i).is_some_and(char::is_ascii_digit) {
                i += 1;
            }
            if matches!(s.get(i), Some('.' | ')')) {
                i + 1
            } else {
                return None;
            }
        }
        Some('#') => {
            let mut i = 0;
            while s.get(i) == Some(&'#') {
                i += 1;
            }
            if i > 6 {
                return None;
            }
            i
        }
        _ => return None,
    };
    blanks1(s, marker_end)
}

/// The IGNORECASE documentary prefix `(The following is (a )?)?PowerShell( example|snippet|command)?\s*:\s*`.
fn prefix_end(s: &[char]) -> Option<usize> {
    let header = |s: &[char]| -> Option<usize> {
        let mut i = lit_ci(s, 0, "the")?;
        i = blanks1(s, i)?;
        i = lit_ci(s, i, "following")?;
        i = blanks1(s, i)?;
        i = lit_ci(s, i, "is")?;
        i = blanks1(s, i)?;
        if let Some(j) = lit_ci(s, i, "a").and_then(|j| blanks1(s, j))
            && lit_ci(s, j, "powershell").is_some()
        {
            return Some(j);
        }
        Some(i)
    };
    let rest = |start: usize| -> Option<usize> {
        let mut i = lit_ci(s, start, "powershell")?;
        let with_word = blanks1(s, i).and_then(|j| {
            ["example", "snippet", "command"]
                .iter()
                .find_map(|w| lit_ci(s, j, w))
        });
        for cand in [with_word, Some(i)].into_iter().flatten() {
            let k = blanks(s, cand);
            if s.get(k) == Some(&':') {
                i = blanks(s, k + 1);
                return Some(i);
            }
        }
        None
    };
    if let Some(e) = header(s).and_then(rest) {
        return Some(e);
    }
    rest(0)
}

fn eq_value(s: &[char], pos: usize) -> Option<usize> {
    (s.get(pos) == Some(&'"')
        && s.get(pos + 1) == Some(&PLACEHOLDER)
        && s.get(pos + 2) == Some(&'"'))
    .then_some(pos + 3)
}

/// `{V}|\([ \t]*{V}[ \t]*\)` fullmatching the remainder from `pos`.
fn value_or_paren_full(s: &[char], pos: usize) -> bool {
    if eq_value(s, pos) == Some(s.len()) {
        return true;
    }
    if s.get(pos) != Some(&'(') {
        return false;
    }
    let Some(e) = eq_value(s, blanks(s, pos + 1)) else {
        return false;
    };
    let e = blanks(s, e);
    s.get(e) == Some(&')') && e + 1 == s.len()
}

fn shape_matches(s: &[char]) -> bool {
    // Write-Output[ \t]+(V|(V))
    if let Some(e) = lit_ci(s, 0, "write-output").and_then(|e| blanks1(s, e))
        && value_or_paren_full(s, e)
    {
        return true;
    }
    // Write-Host([ \t]+-NoNewline)?[ \t]+(V|(V))
    if let Some(h) = lit_ci(s, 0, "write-host") {
        let with_flag = blanks1(s, h)
            .and_then(|j| lit_ci(s, j, "-nonewline"))
            .and_then(|j| blanks1(s, j));
        let without = blanks1(s, h);
        if [with_flag, without]
            .into_iter()
            .flatten()
            .any(|e| value_or_paren_full(s, e))
        {
            return true;
        }
    }
    // V[ \t]*\|[ \t]*Write-Output
    if let Some(e) = eq_value(s, 0) {
        let e = blanks(s, e);
        if s.get(e) == Some(&'|') && lit_ci(s, blanks(s, e + 1), "write-output") == Some(s.len()) {
            return true;
        }
    }
    // \$[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*V
    if s.first() == Some(&'$') && s.get(1).is_some_and(|&c| az(c) || c == '_') {
        let mut e = 2;
        while e < s.len() && az_09_(s[e]) {
            e += 1;
        }
        let e = blanks(s, e);
        if s.get(e) == Some(&'=') {
            return eq_value(s, blanks(s, e + 1)) == Some(s.len());
        }
    }
    false
}

/// ``(?P<ticks>`+)(?P<body>.*)(?P=ticks)`` fullmatch: returns the body.
fn inline_code_body(s: &[char]) -> Option<Vec<char>> {
    let run = s.iter().take_while(|&&c| c == '`').count();
    if s.contains(&'\n') {
        return None;
    }
    for k in (1..=run).rev() {
        let rest = &s[k..];
        if rest.len() >= k && rest[rest.len() - k..].iter().all(|&c| c == '`') {
            return Some(rest[..rest.len() - k].to_vec());
        }
    }
    None
}

/// `_is_powershell_replace_value_context`.
pub(super) fn is_powershell_replace_value_context(
    content: &[char],
    start: usize,
    end: usize,
    inner: &[char],
) -> bool {
    if !matches_replace_expression(inner)
        || inner.iter().any(|c| ";|&\n".contains(*c))
        || ["$(", "`", "<(", ">("]
            .iter()
            .any(|m| contains_str(inner, m))
    {
        return false;
    }
    let line_start = content[..start]
        .iter()
        .rposition(|&c| c == '\n')
        .map_or(0, |i| i + 1);
    let line_end = content[end..]
        .iter()
        .position(|&c| c == '\n')
        .map_or(content.len(), |i| end + i);
    let mut statement: Vec<char> = content[line_start..start].to_vec();
    statement.push(PLACEHOLDER);
    statement.extend_from_slice(&content[end..line_end]);
    let mut statement = py_strip(&statement);

    if statement.first() == Some(&'|') && statement.last() == Some(&'|') {
        let body = if statement.len() >= 2 {
            &statement[1..statement.len() - 1]
        } else {
            &[][..]
        };
        let cells: Vec<Vec<char>> = body.split(|&c| c == '|').map(py_strip).collect();
        let value_cells: Vec<&Vec<char>> =
            cells.iter().filter(|c| c.contains(&PLACEHOLDER)).collect();
        if value_cells.len() != 1 {
            return false;
        }
        statement = value_cells[0].clone();
    }
    if let Some(e) = container_end(&statement) {
        statement = py_strip(&statement[e..]);
    }
    if let Some(e) = prefix_end(&statement) {
        statement = py_strip(&statement[e..]);
        if statement.last() == Some(&'.') {
            statement.pop();
            let keep = statement
                .iter()
                .rposition(|&c| !is_space(c))
                .map_or(0, |i| i + 1);
            statement.truncate(keep);
        }
    }
    if let Some(body) = inline_code_body(&statement) {
        statement = py_strip(&body);
    }
    shape_matches(&statement)
}
