//! Comment ownership for AR2 in Python files (`python_tokens.python_literal_spans` and
//! `_PythonComments` of `static_patterns_anti_refusal.py`).
//!
//! shortcut: Python proves ownership only when `ast.parse` accepts the whole file; this scanner
//! cannot parse, so it assumes the file is valid and only refuses what it cannot tokenize
//! (lone CR, foreign shebang, unterminated strings, comments inside f-string fields). Upgrade when
//! a Python parser lands in `pyast`.

use crate::matcher::Pat;
use std::sync::LazyLock;

const MAX_SOURCE_CHARS: usize = 1_000_000;
const REPORT_PREFIX_CHARS: usize = 160;
const COMMENT_BLOCK_MAX_LINES: usize = 64;

const REPORT_VERBS: &str = "contains|contained|displays|displayed|emits|emitted|generates|generated|gives|gave|has|had|includes|included|issues|issued|logs|logged|outputs|prints|printed|produces|produced|raises|raised|reports|reported|returns|returned|sends|sent|shows|showed|surfaces|surfaced|throws|threw|writes|wrote|yields|yielded";
const OPENING_VERBS: &str = "emits|emitted|logs|logged|prints|printed|raises|raised|returns|returned|throws|threw|yields|yielded";
const PROGRAM_SUBJECTS: &str = "apis?|backends?|binary|binaries|builds?|calls?|checks?|cli|clients?|commands?|compilers?|daemons?|databases?|db|drivers?|endpoints?|functions?|handlers?|helpers?|interpreters?|jobs?|library|libraries|linters?|methods?|modules?|packages?|parsers?|pipelines?|process|processes|programs?|query|queries|requests?|runtimes?|scripts?|sdks?|servers?|services?|subprocess|subprocesses|tests?|tools?|upstream|validators?|wrappers?";
const ADVERBS: &str = r"(?:(?:[a-z]+ly|also|already|always|even|just|now|still|then)\s+){0,2}";

static BARE_NO_WARNING: LazyLock<Pat> = LazyLock::new(|| {
    Pat::new(
        r"\Ano\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?)\z",
        "i",
    )
});
static SUBJECT_REPORT: LazyLock<Pat> = LazyLock::new(|| {
    Pat::new(
        &format!(r"(?<![\w-])(?:{PROGRAM_SUBJECTS})\s+{ADVERBS}(?:{REPORT_VERBS})\s+\z"),
        "i",
    )
});
static COMMENT_OPENING: LazyLock<Pat> = LazyLock::new(|| {
    Pat::new(
        &format!(r"\A#+[ \t]*{ADVERBS}(?:{OPENING_VERBS})[ \t]+\z"),
        "i",
    )
});
static AGENT_ADDRESS: LazyLock<Pat> = LazyLock::new(|| {
    Pat::new(
        r"\b(?:you|your|yours|yourself|yourselves|assistants?|agents?|models?|ai|llms?|chatbots?|bots?|claude|chatgpt|gpt|copilot|gemini|codex|personas?|prompts?|instructions?)\b",
        "i",
    )
});
static PYTHON_SHEBANG: LazyLock<Pat> = LazyLock::new(|| {
    Pat::new(
        r"\A#![ \t]*+(?:\S*/)?(?:env[ \t]++(?:-\S*[ \t]++)*(?:\S*/)?)?(?:python[0-9.]*|pypy[0-9.]*|uv)(?=[ \t\r\n]|$)",
        "",
    )
});

/// Every pattern of this file with its flags, for the compile test.
#[cfg(test)]
pub fn all_patterns() -> Vec<(String, &'static str)> {
    vec![
        (
            r"\Ano\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?)\z".into(),
            "i",
        ),
        (
            format!(r"(?<![\w-])(?:{PROGRAM_SUBJECTS})\s+{ADVERBS}(?:{REPORT_VERBS})\s+\z"),
            "i",
        ),
        (
            format!(r"\A#+[ \t]*{ADVERBS}(?:{OPENING_VERBS})[ \t]+\z"),
            "i",
        ),
    ]
}

/// Outermost comment and string spans of a source taken to be a valid module.
#[derive(Debug)]
pub struct Spans {
    starts: Vec<usize>,
    ends: Vec<usize>,
}

fn string_start(b: &[u8], quote: usize, floor: usize) -> (usize, bool, bool) {
    let mut s = quote;
    let (mut raw, mut fmt) = (false, false);
    while s > floor && s > 0 && quote - s < 2 && b"rRbBuUfFtT".contains(&b[s - 1]) {
        s -= 1;
        raw |= matches!(b[s], b'r' | b'R');
        fmt |= matches!(b[s], b'f' | b'F' | b't' | b'T');
    }
    if s > floor && s > 0 && (b[s - 1].is_ascii_alphanumeric() || b[s - 1] == b'_') {
        return (quote, false, false);
    }
    (s, raw, fmt)
}

/// End of the string whose opening quote is at `q`, or `None` when unterminated or too odd.
fn scan_string(b: &[u8], q: usize, fmt: bool) -> Option<usize> {
    let quote = b[q];
    let triple = b.get(q + 1) == Some(&quote) && b.get(q + 2) == Some(&quote);
    let mut i = q + if triple { 3 } else { 1 };
    let mut depth = 0usize;
    while i < b.len() {
        let c = b[i];
        if depth == 0 {
            if c == b'\\' {
                i += if b.get(i + 1) == Some(&b'\r') && b.get(i + 2) == Some(&b'\n') {
                    3
                } else {
                    2
                };
                continue;
            }
            if c == quote {
                if !triple {
                    return Some(i + 1);
                }
                if b.get(i + 1) == Some(&quote) && b.get(i + 2) == Some(&quote) {
                    return Some(i + 3);
                }
            } else if (c == b'\n' || c == b'\r') && !triple {
                return None;
            }
            if fmt && c == b'{' {
                if b.get(i + 1) == Some(&b'{') {
                    i += 2;
                    continue;
                }
                depth = 1;
            }
            i += 1;
            continue;
        }
        match c {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            b'#' => return None,
            b'\'' | b'"' => {
                let (_, _, nested_fmt) = string_start(b, i, q + 1);
                i = scan_string(b, i, nested_fmt)?;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

impl Spans {
    /// `python_literal_spans`: `None` when ownership cannot be established.
    #[must_use]
    pub fn of(text: &str) -> Option<Self> {
        if text.chars().count() > MAX_SOURCE_CHARS {
            return None;
        }
        let b = text.as_bytes();
        let lone_cr = b
            .iter()
            .enumerate()
            .any(|(i, &c)| c == b'\r' && b.get(i + 1) != Some(&b'\n'));
        if lone_cr || (text.starts_with("#!") && PYTHON_SHEBANG.find_iter(text).is_empty()) {
            return None;
        }
        let (mut starts, mut ends) = (Vec::new(), Vec::new());
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'#' => {
                    let end = b[i..]
                        .iter()
                        .position(|&c| c == b'\n' || c == b'\r')
                        .map_or(b.len(), |p| i + p);
                    starts.push(i);
                    ends.push(end);
                    i = end;
                }
                b'\'' | b'"' => {
                    let floor = ends.last().copied().unwrap_or(0);
                    let (start, _, fmt) = string_start(b, i, floor);
                    let end = scan_string(b, i, fmt)?;
                    starts.push(start);
                    ends.push(end);
                    i = end;
                }
                _ => i += 1,
            }
        }
        Some(Self { starts, ends })
    }
}

/// Lazily built comment index of one Python text (`_PythonComments`).
pub struct PythonComments<'a> {
    text: &'a str,
    spans: Option<Spans>,
}

impl<'a> PythonComments<'a> {
    #[must_use]
    pub fn new(text: &'a str) -> Self {
        Self {
            text,
            spans: Spans::of(text),
        }
    }

    fn is_comment(&self, s: &Spans, i: usize) -> bool {
        self.text.as_bytes()[s.starts[i]] == b'#'
    }

    fn comment_index(&self, start: usize, end: usize) -> Option<usize> {
        let s = self.spans.as_ref()?;
        let i = s.starts.partition_point(|&x| x <= start).checked_sub(1)?;
        (end <= s.ends[i] && self.is_comment(s, i)).then_some(i)
    }

    fn adjacent(&self, s: &Spans, earlier: usize, later: usize) -> bool {
        if !(self.is_comment(s, earlier) && self.is_comment(s, later)) {
            return false;
        }
        let gap = &self.text[s.ends[earlier]..s.starts[later]];
        gap.matches('\n').count() == 1 && gap.chars().all(crate::unicode::is_space)
    }

    fn block_bounds(&self, s: &Spans, index: usize) -> Option<(usize, usize)> {
        let (mut first, mut last) = (index, index);
        let mut closed = false;
        for _ in 0..COMMENT_BLOCK_MAX_LINES {
            if first == 0 || !self.adjacent(s, first - 1, first) {
                closed = true;
                break;
            }
            first -= 1;
        }
        if !closed {
            return None;
        }
        closed = false;
        for _ in 0..COMMENT_BLOCK_MAX_LINES {
            if last + 1 == s.starts.len() || !self.adjacent(s, last, last + 1) {
                closed = true;
                break;
            }
            last += 1;
        }
        closed.then_some((first, last))
    }

    fn block_is_unaddressed(&self, s: &Spans, index: usize) -> bool {
        self.block_bounds(s, index).is_some_and(|(first, last)| {
            AGENT_ADDRESS
                .find_in(self.text, s.starts[first], s.ends[last])
                .is_empty()
        })
    }

    /// `_is_descriptive_python_comment`: a bare "no warnings" reporting a program's behaviour.
    #[must_use]
    pub fn is_descriptive(&self, start: usize, end: usize) -> bool {
        let text = self.text;
        if BARE_NO_WARNING.find_iter(&text[start..end]).is_empty() {
            return false;
        }
        let (Some(index), Some(s)) = (self.comment_index(start, end), self.spans.as_ref()) else {
            return false;
        };
        let comment_start = s.starts[index];
        let floor = text[comment_start..start]
            .char_indices()
            .rev()
            .nth(REPORT_PREFIX_CHARS - 1)
            .map_or(comment_start, |(i, _)| comment_start + i);
        let reports = !SUBJECT_REPORT.find_in(text, floor, start).is_empty()
            || (floor == comment_start
                && !COMMENT_OPENING
                    .find_iter(&text[comment_start..start])
                    .is_empty());
        reports && self.block_is_unaddressed(s, index)
    }
}
