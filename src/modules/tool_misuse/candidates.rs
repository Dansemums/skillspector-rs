//! `_tm1_candidates`: every TM1 match in source order, from the direct `shell=True` calls, the
//! ordinary patterns and the token-parsed destructive `rm` commands.

use super::patterns::{DIRECT_PATS, SHELL_TRUE_VALUE, TM1_PATS};
use super::variable_shell::variable_shell_matches;
use crate::matcher::{Pat, paragraph_matches};
use crate::shell_tokens::{
    Chars, bounded_shell_tokens, destructive_command_words, has_destructive_root_glob,
    has_destructive_root_path, is_root_glob_documentation,
};
use std::collections::HashSet;
use std::sync::LazyLock;

/// One candidate match (byte offsets into the scanned text).
#[derive(Debug, Clone)]
pub struct Candidate {
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub confidence: f32,
    pub direct: bool,
    /// Byte offset of the outer-call `shell=True` literal.
    pub anchor: Option<usize>,
    pub alternate_start: Option<usize>,
    pub alternate_text: Option<String>,
}

static METHOD: LazyLock<Pat> = LazyLock::new(|| Pat::new(r"\Asubprocess\.(\w+)", "i"));

/// `_outer_shell_true_anchor`: first `shell=True` directly inside the outer call, ignoring quoted
/// and commented lookalikes. Offsets are bytes.
pub fn outer_shell_true_anchor(matched: &str) -> Option<usize> {
    let chars: Vec<(usize, char)> = matched.char_indices().collect();
    let at = |i: usize| chars.get(i).map(|c| c.1);
    let starts = |i: usize, pat: &str| pat.chars().enumerate().all(|(k, p)| at(i + k) == Some(p));
    let mut stack: Vec<char> = Vec::new();
    let mut quote: Option<char> = None;
    let mut triple = false;
    let mut in_comment = false;
    let mut cursor = 0;
    while cursor < chars.len() {
        let c = chars[cursor].1;
        if in_comment {
            if "\n\r\x0b\x0c\x1c\x1d\x1e\u{85}\u{2028}\u{2029}".contains(c) {
                in_comment = false;
            }
            cursor += 1;
            continue;
        }
        if let Some(q) = quote {
            if c == '\\' {
                cursor = chars.len().min(cursor + 2);
                continue;
            }
            let width = if triple { 3 } else { 1 };
            if (0..width).all(|k| at(cursor + k) == Some(q)) {
                cursor += width;
                quote = None;
                triple = false;
            } else {
                cursor += 1;
            }
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            triple = (0..3).all(|k| at(cursor + k) == Some(c));
            cursor += if triple { 3 } else { 1 };
            continue;
        }
        if c == '#' {
            in_comment = true;
            cursor += 1;
            continue;
        }
        if "([{".contains(c) {
            stack.push(c);
            cursor += 1;
            continue;
        }
        if let Some(open) = match c {
            ')' => Some('('),
            ']' => Some('['),
            '}' => Some('{'),
            _ => None,
        } {
            if stack.last() == Some(&open) {
                stack.pop();
            }
            cursor += 1;
            continue;
        }
        let word_before =
            cursor > 0 && at(cursor - 1).is_some_and(|p| crate::unicode::is_alnum(p) || p == '_');
        if stack == ['('] && !word_before && starts_shell_true(&chars, cursor, matched) {
            return Some(chars[cursor].0);
        }
        let _ = starts;
        cursor += 1;
    }
    None
}

/// `_DIRECT_SHELL_TRUE_VALUE.match(text, at)` with `at` given as a char index.
fn starts_shell_true(chars: &[(usize, char)], cursor: usize, matched: &str) -> bool {
    SHELL_TRUE_VALUE
        .find_in(matched, chars[cursor].0, matched.len())
        .first()
        .is_some_and(|h| h.start == chars[cursor].0)
}

/// `_subprocess_qualifier_start` on the raw view: a `subprocess.` qualifier right before a bare `Popen`.
/// (Derived security views are slice F; they only add obfuscated spellings of the qualifier.)
fn subprocess_qualifier_start(content: &str, popen_start: usize) -> Option<usize> {
    let qualifier = "subprocess.";
    let before = &content[..popen_start];
    let start = before
        .char_indices()
        .rev()
        .nth(qualifier.chars().count() - 1)
        .map(|(i, _)| i)?;
    (crate::unicode::casefold(&before[start..]) == qualifier).then_some(start)
}

fn direct_candidates(content: &str) -> Vec<Candidate> {
    let mut hits: Vec<(usize, usize, crate::matcher::Hit, f32)> = Vec::new();
    for (idx, (pat, confidence)) in DIRECT_PATS.iter().enumerate() {
        hits.extend(
            pat.find_iter(content)
                .into_iter()
                .map(|h| (h.start, idx, h, *confidence)),
        );
    }
    hits.sort_by_key(|h| (h.0, h.1));
    let mut qualified: HashSet<usize> = HashSet::new();
    let mut out = Vec::new();
    for (_, idx, hit, confidence) in hits {
        let text = hit.text(content);
        let (mut alternate_start, mut alternate_text) = (None, None);
        if idx == 0 {
            if let Some(m) = METHOD
                .find_iter(text)
                .first()
                .and_then(|m| m.groups.get(1).copied().flatten())
                && crate::unicode::casefold(&text[m.0..m.1]) == "popen"
            {
                let a = hit.start + m.0;
                alternate_start = Some(a);
                alternate_text = Some(content[a..hit.end].to_owned());
                qualified.insert(a);
            }
        } else if qualified.remove(&hit.start) {
            continue;
        } else if let Some(q) = subprocess_qualifier_start(content, hit.start) {
            alternate_start = Some(q);
            alternate_text = Some(content[q..hit.end].to_owned());
        }
        let relative = outer_shell_true_anchor(text)
            .or_else(|| SHELL_TRUE_VALUE.find_iter(text).last().map(|h| h.start));
        out.push(Candidate {
            start: hit.start,
            end: hit.end,
            text: text.to_owned(),
            confidence,
            direct: true,
            anchor: relative.map(|r| hit.start + r),
            alternate_start,
            alternate_text,
        });
    }
    out
}

fn ordinary_candidates(content: &str) -> Vec<Candidate> {
    let mut hits: Vec<(usize, usize, usize, usize, f32)> = Vec::new();
    for (idx, (pat, confidence, prose)) in TM1_PATS.iter().enumerate() {
        let found = if idx == 0 {
            variable_shell_matches(content)
                .into_iter()
                .map(|w| (w.start, w.end))
                .collect()
        } else if *prose {
            paragraph_matches(pat, content)
                .into_iter()
                .map(|h| (h.start, h.end))
                .collect::<Vec<_>>()
        } else {
            pat.find_iter(content)
                .into_iter()
                .map(|h| (h.start, h.end))
                .collect()
        };
        hits.extend(found.into_iter().map(|(s, e)| (s, idx, s, e, *confidence)));
    }
    hits.sort_by_key(|h| (h.0, h.1));
    hits.into_iter()
        .map(|(_, _, s, e, confidence)| Candidate {
            start: s,
            end: e,
            text: content[s..e].to_owned(),
            confidence,
            direct: false,
            anchor: None,
            alternate_start: None,
            alternate_text: None,
        })
        .collect()
}

/// `destructive_candidates`: literal `rm`/`del`/`erase` commands that recursively force-delete a
/// root, home or bare glob target.
fn destructive_candidates(content: &str) -> Vec<Candidate> {
    let chars = Chars::new(content);
    let mut out = Vec::new();
    // A tokenizer error (Python TypeError) would abort `analyze`; keep what was found.
    let Ok(words) = destructive_command_words(&chars.chars) else {
        return out;
    };
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    let mut covered_until = 0usize;
    for (command_start, body_start) in words {
        if command_start < covered_until || !seen.insert((command_start, body_start)) {
            continue;
        }
        if is_root_glob_documentation(&chars.chars, command_start, body_start) {
            continue;
        }
        let Ok(parsed) = bounded_shell_tokens(&chars.chars, command_start, body_start) else {
            return out;
        };
        covered_until = covered_until.max(parsed.end);
        if has_destructive_root_glob(&parsed.tokens) || has_destructive_root_path(&parsed.tokens) {
            let (s, e) = (chars.byte_of(command_start), chars.byte_of(parsed.end));
            out.push(Candidate {
                start: s,
                end: e,
                text: content[s..e].to_owned(),
                confidence: 0.9,
                direct: false,
                anchor: None,
                alternate_start: None,
                alternate_text: None,
            });
        }
    }
    out
}

/// `_tm1_candidates`: stable merge by start (direct, ordinary, destructive on `content`, then on
/// the Perl print projection `shell_content`).
pub fn tm1_candidates(content: &str, shell_content: Option<&str>) -> Vec<Candidate> {
    let mut lists = vec![direct_candidates(content), ordinary_candidates(content)];
    lists.push(destructive_candidates(content));
    if let Some(shell) = shell_content.filter(|s| *s != content) {
        lists.push(destructive_candidates(shell));
    }
    let mut keyed: Vec<(usize, usize, usize, Candidate)> = Vec::new();
    for (list_index, list) in lists.into_iter().enumerate() {
        for (position, c) in list.into_iter().enumerate() {
            keyed.push((c.start, list_index, position, c));
        }
    }
    keyed.sort_by_key(|k| (k.0, k.1, k.2));
    keyed.into_iter().map(|k| k.3).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_skips_quoted_lookalikes() {
        let m = "subprocess.run(\"shell=True\", shell=True";
        assert_eq!(outer_shell_true_anchor(m), m.rfind("shell=True"));
        assert_eq!(outer_shell_true_anchor("subprocess.run(f(shell=True"), None);
    }

    #[test]
    fn qualified_popen_is_one_candidate() {
        let c = direct_candidates("subprocess.Popen(cmd, shell=True)");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].alternate_start, Some(11));
    }

    #[test]
    fn destructive_rm_is_found() {
        let c = destructive_candidates("do it: rm -rf /var/x\n");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].text, "rm -rf /var/x");
    }
}
