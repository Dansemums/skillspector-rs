//! `references.resolve_bundle_references_with_metadata` for the primary skill file: path-like
//! strings in `SKILL.md` that name a file of the bundle, with their source line.
//!
//! Not ported: the runtime deadline, and the fence / HTML / indented-code tracking that only
//! decides whether a Markdown image counts as a passive image (`kind_image`); here every
//! passive-shaped image is one.

use crate::matcher::Pat;
use crate::unicode::{collapse_ws, is_space};
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

const MAX_DEST: usize = 512;
const MAX_EVIDENCE: usize = 160;
const MAX_RAW_CANDIDATES: usize = 4096;
const MAX_ACCEPTED: usize = 256;
const MAX_RECORDS: usize = 1024;
const MAX_SOURCE_CHARS: usize = 1_000_000;

/// Compiles a Python-syntax pattern; under test a pattern that fails to compile panics.
fn pat(src: &str, flags: &str) -> Pat {
    #[cfg(test)]
    assert!(
        Pat::try_new(src, flags).is_ok(),
        "pattern does not compile: {src}"
    );
    Pat::new(src, flags)
}

const TITLE: &str = r#"(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|\((?:\\.|[^)\\\r\n])*\))"#;

static MD_START: LazyLock<Pat> = LazyLock::new(|| {
    pat(
        r"(?:!\[[^\]\n]{0,200}\]|(?<!!)\[[^\]\n]{1,200}\])\(|^[ \t]{0,3}\[[^\]\n]{1,200}\]:[ \t]*",
        "",
    )
});
static INLINE_END: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(&format!(r"^[ \t]*(?:{TITLE})?[ \t]*\)")).ok());
static DEF_END: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(&format!(r"^[ \t]*(?:{TITLE})?[ \t]*(?:\r?\n)?\z")).ok());
static ESCAPE: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"\\([\\()<>])").ok());
static PASSIVE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"^[^\s\x1c-\x1f\\()\[\]<>]+(?:[ \t]+(?:"[^"\\\r\n()]*"|'[^'\\\r\n()]*'))?$"#).ok()
});
static INLINE_CMD: LazyLock<Pat> = LazyLock::new(|| {
    pat(
        r"`(?:python(?:\d+(?:\.\d+)*)?|py|node|deno|bun|bash|sh|zsh|fish|ruby|perl|php|pwsh|powershell)\b[ \t]+((?:\./)?(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+)(?![\w/.-])",
        "",
    )
});
static QUOTED: LazyLock<Pat> = LazyLock::new(|| {
    pat(
        r#"(?:`|'|")((?:\./)?(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,12})(?:`|'|")"#,
        "",
    )
});
static PLAIN: LazyLock<Pat> = LazyLock::new(|| {
    pat(
        r"(?<![\w:/.@-])((?:\./(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+|(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,12}))(?![\w/.@-])",
        "",
    )
});

/// Which syntax produced a candidate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    MarkdownLink,
    MarkdownImage,
    Other,
}

struct Cand {
    raw: String,
    start: usize,
    end: usize,
    kind: Kind,
    syntax_start: usize,
    passive: bool,
}

/// One resolved mention of a bundled file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    pub line: u32,
    pub evidence: String,
    pub target: String,
    /// The mention is a passive Markdown image (`reference_kind == markdown_image`).
    pub image: bool,
}

fn evidence(cleaned: &[char], column: usize) -> String {
    if cleaned.len() <= MAX_EVIDENCE {
        return cleaned.iter().collect();
    }
    let start = column
        .saturating_sub(1)
        .min(cleaned.len())
        .saturating_sub(MAX_EVIDENCE / 2);
    cleaned[start..(start + MAX_EVIDENCE).min(cleaned.len())]
        .iter()
        .collect()
}

fn markdown_candidates(line: &str, chars: &[char], c2b: &[usize]) -> Vec<Cand> {
    // `chars[i]` starts at byte `c2b[i]`; `c2b` has one extra entry for the end.
    let b2c = |b: usize| c2b.partition_point(|&x| x < b);
    let mut out = Vec::new();
    let mut consumed_until = 0usize;
    for opening in MD_START.find_iter(line) {
        let (o_start, o_end) = (b2c(opening.start), b2c(opening.end));
        if o_start < consumed_until {
            continue;
        }
        let mut start = o_end;
        while start < chars.len() && matches!(chars[start], ' ' | '\t') {
            start += 1;
        }
        if start >= chars.len() {
            continue;
        }
        let limit = chars.len().min(start + MAX_DEST + 2);
        let mut end = start;
        let (raw, dest_end): (String, usize);
        if chars[start] == '<' {
            start += 1;
            end = start;
            while end < limit && !matches!(chars[end], '<' | '>' | '\r' | '\n') {
                if chars[end] == '\\' && end + 1 < limit {
                    end += 1;
                }
                end += 1;
            }
            if end - start > MAX_DEST || end >= limit || chars[end] != '>' {
                continue;
            }
            raw = chars[start..end].iter().collect();
            dest_end = end + 1;
        } else {
            let mut depth = 0usize;
            while end < limit && !is_space(chars[end]) {
                match chars[end] {
                    '\\' if end + 1 < limit => {
                        end += 2;
                        continue;
                    }
                    '(' => depth += 1,
                    ')' => {
                        if depth == 0 {
                            break;
                        }
                        depth -= 1;
                    }
                    '<' | '>' => break,
                    _ => {}
                }
                end += 1;
            }
            let end = end.min(chars.len());
            if end - start > MAX_DEST || depth > 0 || end == start {
                continue;
            }
            raw = chars[start..end].iter().collect();
            dest_end = end;
        }
        let inline = opening.text(line).ends_with('(');
        let tail_from = c2b[dest_end.min(chars.len())];
        let consumed = if inline {
            let window_end = c2b[chars.len().min(dest_end + 512)];
            match INLINE_END
                .as_ref()
                .and_then(|r| r.find(&line[tail_from..window_end]))
            {
                Some(m) => b2c(tail_from + m.end()),
                None => continue,
            }
        } else {
            if chars.len() - dest_end > 512
                || !DEF_END
                    .as_ref()
                    .is_some_and(|r| r.is_match(&line[tail_from..]))
            {
                continue;
            }
            chars.len()
        };
        consumed_until = consumed;
        let is_image = opening.text(line).starts_with("![");
        let label: String = if is_image && o_end >= o_start + 4 {
            chars[o_start + 2..o_end - 2].iter().collect()
        } else {
            String::new()
        };
        let body_from = c2b[o_end];
        let body_to = c2b[consumed.saturating_sub(1).max(o_end)];
        let passive = is_image
            && !label.contains(['[', ']', '\\'])
            && body_to >= body_from
            && PASSIVE
                .as_ref()
                .is_some_and(|r| r.is_match(&line[body_from..body_to]));
        out.push(Cand {
            raw: ESCAPE
                .as_ref()
                .map_or_else(|| raw.clone(), |r| r.replace_all(&raw, "$1").into_owned()),
            start,
            end: consumed,
            kind: if is_image {
                Kind::MarkdownImage
            } else {
                Kind::MarkdownLink
            },
            syntax_start: o_start,
            passive,
        });
    }
    out
}

fn pattern_candidates(p: &Pat, line: &str, b2c: &dyn Fn(usize) -> usize) -> Vec<Cand> {
    p.find_iter(line)
        .into_iter()
        .filter_map(|h| {
            let (s, e) = h.groups.get(1).copied().flatten()?;
            Some(Cand {
                raw: line[s..e].to_owned(),
                start: b2c(s),
                end: b2c(e),
                kind: Kind::Other,
                syntax_start: b2c(s),
                passive: false,
            })
        })
        .collect()
}

/// `(raw, line, column, evidence, is_image)` for every candidate of `text`, in source order.
fn candidate_strings(text: &str) -> Vec<(String, u32, usize, String, Kind)> {
    let mut out = Vec::new();
    let mut seen: HashSet<(u32, usize, String)> = HashSet::new();
    let mut inline_delim: Option<usize> = None;
    for (idx, line) in text.split_inclusive('\n').enumerate() {
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        let chars: Vec<char> = line.chars().collect();
        let mut c2b: Vec<usize> = line.char_indices().map(|(b, _)| b).collect();
        c2b.push(line.len());
        let b2c = |b: usize| c2b.partition_point(|&x| x < b);
        let cleaned: Vec<char> = collapse_ws(line.trim_matches(is_space)).chars().collect();
        let mut all: Vec<(usize, usize, Cand)> = Vec::new();
        for (pi, cands) in [
            markdown_candidates(line, &chars, &c2b),
            pattern_candidates(&INLINE_CMD, line, &b2c),
            pattern_candidates(&QUOTED, line, &b2c),
            pattern_candidates(&PLAIN, line, &b2c),
        ]
        .into_iter()
        .enumerate()
        {
            all.extend(cands.into_iter().map(|c| (c.syntax_start, pi, c)));
        }
        all.sort_by_key(|(s, pi, _)| (*s, *pi));
        let mut image_labels: Vec<(usize, usize, String)> = Vec::new();
        let mut md_dest: Option<(usize, usize)> = None;
        let mut cursor = 0usize;
        for (sort_start, pi, c) in all {
            advance_inline(&chars, sort_start, &mut cursor, &mut inline_delim);
            let mut kind = c.kind;
            if kind == Kind::MarkdownImage
                && (inline_delim.is_some() || !c.passive || is_escaped(&chars, c.syntax_start))
            {
                kind = Kind::Other;
            }
            if kind == Kind::MarkdownImage {
                image_labels.push((c.syntax_start, c.start, c.raw.clone()));
            }
            let redundant = pi == 3
                && c.kind == Kind::Other
                && image_labels
                    .iter()
                    .any(|(s, e, d)| *s <= c.start && c.start < *e && *d == c.raw);
            let inside = pi != 0 && md_dest.is_some_and(|(s, e)| s <= c.start && c.start < e);
            if pi == 0 {
                md_dest = Some((c.start, c.end));
            }
            if inside || redundant {
                continue;
            }
            if seen.insert((line_no, c.start, c.raw.clone())) {
                out.push((
                    c.raw,
                    line_no,
                    c.start + 1,
                    evidence(&cleaned, c.start + 1),
                    kind,
                ));
                if out.len() >= MAX_RAW_CANDIDATES {
                    return out;
                }
            }
        }
        advance_inline(&chars, chars.len(), &mut cursor, &mut inline_delim);
    }
    out
}

fn is_escaped(chars: &[char], offset: usize) -> bool {
    chars[..offset.min(chars.len())]
        .iter()
        .rev()
        .take_while(|&&c| c == '\\')
        .count()
        % 2
        == 1
}

/// `_advance_inline_code_state`.
fn advance_inline(chars: &[char], end: usize, cursor: &mut usize, delim: &mut Option<usize>) {
    let end = end.min(chars.len());
    while *cursor < end {
        if chars[*cursor] != '`' {
            *cursor += 1;
            continue;
        }
        let escapes = chars[..*cursor]
            .iter()
            .rev()
            .take_while(|&&c| c == '\\')
            .count();
        let mut run_end = *cursor + 1;
        while run_end < end && chars[run_end] == '`' {
            run_end += 1;
        }
        if escapes % 2 == 0 {
            let run = run_end - *cursor;
            *delim = match *delim {
                None => Some(run),
                Some(d) if d == run => None,
                other => other,
            };
        }
        *cursor = run_end;
    }
}

/// `_normalize_candidate`: a contained relative POSIX path, or `None` when unsupported.
fn normalize(raw: &str, source: &str) -> Option<String> {
    let raw = raw.trim_matches(is_space);
    let rest = raw.split('#').next().unwrap_or("");
    if let Some(i) = raw.find(':').filter(|&i| i > 0) {
        let scheme = &raw[..i];
        let mut cs = scheme.chars();
        if cs.next().is_some_and(|c| c.is_ascii_alphabetic())
            && cs.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        {
            return None;
        }
    }
    if raw.starts_with("//") || raw.starts_with(['/', '\\', '#']) {
        return None;
    }
    let rest = rest.split('?').next().unwrap_or("");
    let path = unquote(rest).replace('\\', "/");
    let first_two: Vec<char> = path.chars().take(2).collect();
    if path.is_empty() || path.starts_with('/') || (first_two.len() == 2 && first_two[1] == ':') {
        return None;
    }
    let parent = source.rsplit_once('/').map_or("", |(p, _)| p);
    let joined = normpath(&if parent.is_empty() {
        path
    } else {
        format!("{parent}/{path}")
    });
    if matches!(joined.as_str(), "" | "." | "..") || joined.starts_with("../") {
        return None;
    }
    Some(joined.strip_prefix("./").unwrap_or(&joined).to_owned())
}

/// `urllib.parse.unquote` (UTF-8, invalid sequences become U+FFFD).
fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |x: u8| char::from(x).to_digit(16);
        if b[i] == b'%' && i + 2 < b.len() && hex(b[i + 1]).is_some() && hex(b[i + 2]).is_some() {
            out.push(
                u8::try_from(hex(b[i + 1]).unwrap_or(0) * 16 + hex(b[i + 2]).unwrap_or(0))
                    .unwrap_or(0),
            );
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `posixpath.normpath` for relative paths.
fn normpath(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|l| *l != "..") {
                    parts.pop();
                } else {
                    parts.push("..");
                }
            }
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        ".".into()
    } else {
        parts.join("/")
    }
}

/// Resolved references of `source_text` (the primary file `source_path`) against `known_paths`.
#[must_use]
pub fn resolve_references(
    source_path: &str,
    source_text: &str,
    known_paths: &[&str],
) -> Vec<Reference> {
    resolve(source_path, source_text, known_paths).0
}

/// Whether some mention of a file in `source_text` matches no known file, or several (SkillSpector's
/// `missing` / `ambiguous` reference statuses, which leave the analysis incomplete).
#[must_use]
pub fn has_unresolved_reference(
    source_path: &str,
    source_text: &str,
    known_paths: &[&str],
) -> bool {
    resolve(source_path, source_text, known_paths).1
}

fn resolve(source_path: &str, source_text: &str, known_paths: &[&str]) -> (Vec<Reference>, bool) {
    let mut unresolved = false;
    let text: String = source_text.chars().take(MAX_SOURCE_CHARS).collect();
    let known: BTreeSet<&str> = known_paths.iter().copied().collect();
    let mut by_name: HashMap<&str, Vec<&str>> = HashMap::new();
    for p in &known {
        by_name
            .entry(p.rsplit('/').next().unwrap_or(p))
            .or_default()
            .push(p);
    }
    let mut accepted: HashSet<(u8, String)> = HashSet::new();
    let mut records = 0usize;
    let mut out = Vec::new();
    for (raw, line, _col, ev, kind) in candidate_strings(&text) {
        let Some(target) = normalize(&raw, source_path) else {
            continue;
        };
        let name = target.rsplit('/').next().unwrap_or(&target);
        let (status, resolved): (u8, Option<String>) = if known.contains(target.as_str()) {
            (0, Some(target.clone()))
        } else if !unquote(&raw).replace('\\', "/").contains('/') {
            match by_name.get(name).map(Vec::as_slice) {
                Some([one]) => (0, Some((*one).to_owned())),
                Some(_) => (1, None),
                None => (2, None),
            }
        } else {
            (2, None)
        };
        unresolved |= status != 0;
        let key = (status, resolved.clone().unwrap_or_else(|| target.clone()));
        if !accepted.contains(&key) {
            if accepted.len() >= MAX_ACCEPTED {
                break;
            }
            accepted.insert(key);
        }
        if records >= MAX_RECORDS {
            break;
        }
        records += 1;
        if let Some(t) = resolved {
            out.push(Reference {
                line,
                evidence: ev,
                target: t,
                image: kind == Kind::MarkdownImage,
            });
        }
    }
    (out, unresolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs(text: &str, known: &[&str]) -> Vec<(u32, String)> {
        resolve_references("SKILL.md", text, known)
            .into_iter()
            .map(|r| (r.line, r.target))
            .collect()
    }

    #[test]
    fn markdown_link_and_code_path() {
        let t = "intro\nsee [Errors](references/e.md) and `scripts/run.py`\n";
        let r = refs(t, &["references/e.md", "scripts/run.py"]);
        assert_eq!(
            r,
            vec![(2, "references/e.md".into()), (2, "scripts/run.py".into())]
        );
    }

    #[test]
    fn urls_and_missing_are_not_resolved() {
        assert!(refs("[x](https://a.b/c.md) [y](nope/x.md)\n", &["a.md"]).is_empty());
    }

    #[test]
    fn bare_basename_resolves_when_unique() {
        assert_eq!(
            refs("`run.py`\n", &["scripts/run.py"]),
            vec![(1, "scripts/run.py".into())]
        );
        assert!(refs("`run.py`\n", &["a/run.py", "b/run.py"]).is_empty());
    }

    #[test]
    fn normalizes_dot_segments() {
        assert_eq!(normpath("a/./b/../c"), "a/c");
        assert_eq!(unquote("a%20b%2"), "a b%2");
    }

    #[test]
    fn constants_compile() {
        for p in [&*MD_START, &*INLINE_CMD, &*QUOTED, &*PLAIN] {
            assert!(!matches!(p, Pat::Fast(r) if r.as_str().is_empty()));
        }
        assert!(INLINE_END.as_ref().is_some_and(|r| r.is_match(" )")));
        assert!(DEF_END.as_ref().is_some_and(|r| r.is_match(" \n")));
        assert!(PASSIVE.as_ref().is_some_and(|r| r.is_match("a.png")));
        assert!(ESCAPE.is_some());
    }
}
