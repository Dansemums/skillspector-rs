//! Line and paragraph helpers shared by every analyzer (`analyzers/common.py`).
//! Offsets are byte offsets; columns are converted to characters only in [`LineIndex::col_chars`].

use crate::skill::FileType;

/// Python-syntax pattern for one logical line break (for use with [`crate::matcher::Pat`]).
pub const LOGICAL_LINE_BREAK: &str = r"\r\n|[\r\n\x0b\x0c\x1c-\x1e\x85  ]";

const fn is_break_char(c: char) -> bool {
    matches!(
        c,
        '\r' | '\n' | '\x0b' | '\x0c' | '\x1c'..='\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// Every logical line break as `(start, end)`, `\r\n` counted once.
#[must_use]
pub fn line_breaks(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut iter = text.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        if !is_break_char(c) {
            continue;
        }
        let mut end = i + c.len_utf8();
        if c == '\r' && iter.peek().is_some_and(|&(_, n)| n == '\n') {
            end += 1;
            iter.next();
        }
        out.push((i, end));
    }
    out
}

/// `str.splitlines()`.
#[must_use]
pub fn py_splitlines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    for (s, e) in line_breaks(text) {
        out.push(&text[start..s]);
        start = e;
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// Offsets of every logical line start.
#[derive(Clone, Debug)]
pub struct LineIndex {
    starts: Vec<usize>,
    /// All-ASCII text: a character column equals the byte distance (keeps long lines linear).
    ascii: bool,
}

impl LineIndex {
    /// `logical_line_starts`.
    #[must_use]
    pub fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(line_breaks(text).into_iter().map(|(_, e)| e));
        Self {
            starts,
            ascii: text.is_ascii(),
        }
    }

    /// 1-based line of a byte offset.
    #[must_use]
    pub fn line(&self, byte: usize) -> u32 {
        u32::try_from(self.starts.partition_point(|&s| s <= byte)).unwrap_or(u32::MAX)
    }

    /// Byte offset where 1-based `line` starts (past the end when there is no such line).
    #[must_use]
    pub fn line_start(&self, line: u32) -> usize {
        usize::try_from(line)
            .ok()
            .and_then(|l| l.checked_sub(1))
            .and_then(|i| self.starts.get(i))
            .copied()
            .unwrap_or(usize::MAX)
    }

    /// Number of lines (line starts).
    #[must_use]
    pub fn len(&self) -> usize {
        self.starts.len()
    }

    /// Zero-based character column of a byte offset.
    #[must_use]
    pub fn col_chars(&self, text: &str, byte: usize) -> u32 {
        let start = self.starts[self
            .starts
            .partition_point(|&s| s <= byte)
            .saturating_sub(1)];
        let width = if self.ascii {
            byte - start
        } else {
            text[start..byte].chars().count()
        };
        u32::try_from(width).unwrap_or(u32::MAX)
    }
}

/// `_paragraph_ranges`: text split at `LB [ \t]* LB`; empty when there is no boundary.
#[must_use]
pub fn paragraph_ranges(text: &str) -> Vec<(usize, usize)> {
    let breaks = line_breaks(text);
    let bytes = text.as_bytes();
    let mut ranges = Vec::new();
    let (mut start, mut cursor) = (0, 0);
    for &(s, e) in &breaks {
        if s < cursor {
            continue;
        }
        let mut q = e;
        while q < bytes.len() && (bytes[q] == b' ' || bytes[q] == b'\t') {
            q += 1;
        }
        if let Ok(i) = breaks.binary_search_by_key(&q, |b| b.0) {
            ranges.push((start, s));
            start = breaks[i].1;
            cursor = start;
        }
    }
    if ranges.is_empty() {
        return ranges;
    }
    ranges.push((start, text.len()));
    ranges
}

const MAX_CONTEXT_CHARS: usize = 1_000;

fn bounded_context(context: &str, anchor: usize) -> String {
    let chars: Vec<char> = context.chars().collect();
    if chars.len() <= MAX_CONTEXT_CHARS {
        return context.to_owned();
    }
    let start = anchor
        .saturating_sub(MAX_CONTEXT_CHARS / 2)
        .min(chars.len() - MAX_CONTEXT_CHARS);
    chars[start..start + MAX_CONTEXT_CHARS].iter().collect()
}

/// `common.get_context(content, match_start)`: three lines either side of the match.
#[must_use]
pub fn get_context(text: &str, byte: usize) -> String {
    const CONTEXT_LINES: usize = 3;
    let lines = py_splitlines(text);
    let idx = LineIndex::new(text);
    let match_line = usize::try_from(idx.line(byte)).unwrap_or(1) - 1;
    let start_line = match_line.saturating_sub(CONTEXT_LINES);
    let end_line = lines.len().min(match_line + CONTEXT_LINES + 1);
    let Some(selected) = lines.get(start_line..end_line).filter(|s| !s.is_empty()) else {
        return String::new();
    };
    let relative = (match_line - start_line).min(selected.len() - 1);
    let line_start = text[..byte].rfind('\n').map_or(0, |p| p + 1);
    let column = text[line_start..byte]
        .chars()
        .count()
        .min(selected[relative].chars().count());
    let anchor: usize = selected[..relative]
        .iter()
        .map(|l| l.chars().count() + 1)
        .sum::<usize>()
        + column;
    bounded_context(&selected.join("\n"), anchor)
}

const CODE_EXAMPLE_INDICATORS: [&str; 17] = [
    "```",
    "example:",
    "for example",
    "e.g.",
    "such as",
    "documentation",
    "# warning:",
    "# note:",
    "**warning**",
    "**note**",
    "// \u{2705}",
    "// \u{274c}",
    "// good:",
    "// bad:",
    "// correct:",
    "// incorrect:",
    "// wrong:",
];

fn is_skill_md(path: &str) -> bool {
    path.replace('\\', "/").to_lowercase().ends_with("skill.md")
}

/// `common.is_code_example`: documentation-style context, never for `SKILL.md`.
#[must_use]
pub fn is_code_example(ctx: &str, path: &str) -> bool {
    if is_skill_md(path) {
        return false;
    }
    let lower = ctx.to_lowercase();
    CODE_EXAMPLE_INDICATORS.iter().any(|i| lower.contains(i))
}

/// `common.is_reference_material`: markdown/text under the top-level `references/` directory.
#[must_use]
pub fn is_reference_material(path: &str, ft: FileType) -> bool {
    if !matches!(ft, FileType::Markdown | FileType::Text) {
        return false;
    }
    let norm = path.replace('\\', "/");
    let segments: Vec<&str> = norm.split('/').collect();
    if segments
        .last()
        .is_some_and(|s| s.to_lowercase() == "skill.md")
    {
        return false;
    }
    segments.len() > 1 && segments[0] == "references"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_index_handles_every_break() {
        let t = "a\r\nb\x0bc\x0cd\x1ce\u{85}f\u{2028}g\rh\ni";
        let idx = LineIndex::new(t);
        assert_eq!(idx.len(), 9);
        for (i, ch) in "abcdefghi".chars().enumerate() {
            assert_eq!(
                idx.line(t.find(ch).unwrap_or(0)),
                u32::try_from(i + 1).unwrap_or(0),
                "{ch:?}"
            );
        }
        assert_eq!(py_splitlines("a\r\nb\n"), ["a", "b"]);
        assert_eq!(py_splitlines("a\u{2029}\u{2029}b"), ["a", "", "b"]);
    }

    #[test]
    fn crlf_is_one_break_and_columns_are_chars() {
        let t = "xx\r\n\u{e9}\u{e9}ab";
        let idx = LineIndex::new(t);
        assert_eq!(idx.line(t.find('a').unwrap_or(0)), 2);
        assert_eq!(idx.col_chars(t, t.find('a').unwrap_or(0)), 2);
        assert_eq!(idx.line_start(2), 4);
        assert_eq!(idx.col_chars(t, 0), 0);
    }

    #[test]
    fn paragraphs() {
        assert_eq!(paragraph_ranges("one\ntwo"), vec![]);
        assert_eq!(paragraph_ranges("a\n\nb"), vec![(0, 1), (3, 4)]);
        assert_eq!(
            paragraph_ranges("a\r\n \t\r\nb\x1c\x1cc"),
            vec![(0, 1), (7, 8), (10, 11)]
        );
        assert_eq!(paragraph_ranges("a\n\n\nb"), vec![(0, 1), (3, 5)]);
    }

    #[test]
    fn context_window() {
        let t = (1..=10)
            .map(|i| format!("l{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let at = t.find("l5").unwrap_or(0);
        assert_eq!(get_context(&t, at), "l2\nl3\nl4\nl5\nl6\nl7\nl8");
        assert_eq!(get_context("", 0), "");
        assert_eq!(get_context("only", 0), "only");
    }

    #[test]
    fn code_example_and_reference() {
        assert!(is_code_example("see ```x", "a.md"));
        assert!(!is_code_example("see ```x", "dir/SKILL.md"));
        assert!(is_reference_material("references/a.md", FileType::Markdown));
        assert!(!is_reference_material(
            "references/SKILL.md",
            FileType::Markdown
        ));
        assert!(!is_reference_material(
            "a/references/a.md",
            FileType::Markdown
        ));
    }
}
