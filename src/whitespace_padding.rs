//! `whitespace_padding.py`: the P9 scanner. All offsets are character offsets, as in Python.

use crate::skill::FileType;
use crate::unicode::{category, is_space};
use std::collections::{BTreeMap, HashMap, HashSet};

/// `ZERO_WIDTH_CHARS`.
pub const ZERO_WIDTH_CHARS: [char; 5] =
    ['\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}'];
pub const VERTICAL_HIGH_SEVERITY_LINES: usize = 40;
const VERTICAL_BLANK_LINES: usize = 20;
const HORIZONTAL_RUN_CHARS: usize = 80;
const BLOCK_BYTE_BUDGET: usize = 2048;
const RATIO_MIN_FILE_BYTES: usize = 4096;
const REPEATED_CHAR_THRESHOLD: usize = 512;
const REPEATED_LINE_THRESHOLD: usize = 64;
const SUMMARY_MAX_SEGMENTS: usize = 3;

/// `is_padding_char`.
#[must_use]
pub fn is_padding_char(c: char) -> bool {
    if c.is_ascii() {
        return matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c');
    }
    ZERO_WIDTH_CHARS.contains(&c)
        || c == '\u{85}'
        || c == '\u{180e}'
        || matches!(category(c), "Zs" | "Zl" | "Zp")
}

fn escape_for_summary(c: char) -> String {
    match c {
        '\n' => "\\n".into(),
        '\t' => "\\t".into(),
        '\r' => "\\r".into(),
        '\x0b' => "\\v".into(),
        '\x0c' => "\\f".into(),
        _ => format!("U+{:04X}", u32::from(c)),
    }
}

/// `summarize_run`: the most frequent code points as `"U+00A0 x82"` segments.
#[must_use]
pub fn summarize_run(text: &[char]) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for &c in text {
        *counts.entry(c).or_default() += 1;
    }
    let mut ordered: Vec<(char, usize)> = counts.into_iter().collect();
    ordered.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut segments: Vec<String> = ordered
        .iter()
        .take(SUMMARY_MAX_SEGMENTS)
        .map(|&(c, n)| format!("{} x{n}", escape_for_summary(c)))
        .collect();
    if ordered.len() > SUMMARY_MAX_SEGMENTS {
        segments.push(format!("+{} more", ordered.len() - SUMMARY_MAX_SEGMENTS));
    }
    segments.join(", ")
}

/// `PaddingRun.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Vertical,
    Horizontal,
    Block,
    Ratio,
    Repetition,
}

impl Kind {
    const fn name(self) -> &'static str {
        match self {
            Self::Vertical => "vertical",
            Self::Horizontal => "horizontal",
            Self::Block => "block",
            Self::Ratio => "ratio",
            Self::Repetition => "repetition",
        }
    }
}

/// `PaddingRun`; `length`'s unit depends on `kind`.
#[derive(Clone, Debug)]
pub struct PaddingRun {
    pub kind: Kind,
    pub start_offset: usize,
    pub start_line: usize,
    pub length: usize,
    pub followed_by_content: bool,
    pub summary: String,
    pub end_offset: usize,
}

/// `padding_run_match_fingerprint` without the hash: an injective, whitespace-free encoding of
/// (kind, payload), so runs group exactly when SkillSpector's digests are equal.
#[must_use]
pub fn padding_run_match_fingerprint(content: &[char], run: &PaddingRun) -> String {
    let payload: &[char] = if run.start_offset < run.end_offset && run.end_offset <= content.len() {
        &content[run.start_offset..run.end_offset]
    } else {
        content
    };
    let mut out = format!("padding-run-v1:P9:{}:", run.kind.name());
    for &c in payload {
        out.push_str(&format!("{:x},", u32::from(c)));
    }
    out
}

/// `_split_lines`: lines and the offset of each (plus a trailing `len` sentinel).
fn split_lines(content: &[char]) -> (Vec<&[char]>, Vec<usize>) {
    let (mut lines, mut offsets) = (Vec::new(), Vec::new());
    let (mut pos, mut i) = (0, 0);
    while i < content.len() {
        let width = match content[i] {
            '\r' if content.get(i + 1) == Some(&'\n') => 2,
            '\r' | '\n' | '\u{2028}' | '\u{2029}' | '\u{85}' => 1,
            _ => 0,
        };
        if width == 0 {
            i += 1;
            continue;
        }
        offsets.push(pos);
        lines.push(&content[pos..i]);
        i += width;
        pos = i;
    }
    offsets.push(pos);
    lines.push(&content[pos..]);
    offsets.push(content.len());
    (lines, offsets)
}

fn line_text(line: &[char]) -> String {
    line.iter().collect()
}

/// `_FENCE_RE = ^\s*(```|~~~)`.
fn is_fence(line: &[char]) -> bool {
    let rest: String = line.iter().skip_while(|c| is_space(**c)).take(3).collect();
    rest == "```" || rest == "~~~"
}

fn fence_flags(lines: &[&[char]]) -> Vec<bool> {
    let mut inside = false;
    lines
        .iter()
        .map(|l| {
            if is_fence(l) {
                inside = !inside;
                true
            } else {
                inside
            }
        })
        .collect()
}

fn strip_py(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `_markdown_table_cells`: cells of an outer-pipe row.
fn table_cells(line: &str) -> Option<Vec<&str>> {
    let stripped = strip_py(line);
    if stripped.len() < 2 || !stripped.starts_with('|') || !stripped.ends_with('|') {
        // A lone "|" starts and ends with a pipe but has no inner text: Python slices [1:-1] to "".
        if stripped == "|" {
            return Some(vec![""]);
        }
        return None;
    }
    Some(stripped[1..stripped.len() - 1].split('|').collect())
}

/// `_TABLE_DELIMITER_CELL_RE`: `^\s*:?-+:?\s*$`.
fn is_delimiter_cell(cell: &str) -> bool {
    let t = strip_py(cell);
    let t = t.strip_prefix(':').unwrap_or(t);
    let t = t.strip_suffix(':').unwrap_or(t);
    !t.is_empty() && t.chars().all(|c| c == '-')
}

fn pipes(line: &str) -> Vec<usize> {
    line.chars()
        .enumerate()
        .filter(|(_, c)| *c == '|')
        .map(|(i, _)| i)
        .collect()
}

fn aligned(row: &[usize], delimiter: &[usize]) -> HashSet<usize> {
    row.iter()
        .zip(delimiter)
        .filter(|(a, b)| a == b)
        .map(|(a, _)| *a)
        .collect()
}

/// `_markdown_table_boundaries`: row pipe positions aligned with a proven delimiter row.
fn table_boundaries(lines: &[String]) -> HashMap<usize, HashSet<usize>> {
    let mut out = HashMap::new();
    let mut index = 0;
    while index + 1 < lines.len() {
        let header = table_cells(&lines[index]);
        let delimiter = table_cells(&lines[index + 1]);
        let proven = match (&header, &delimiter) {
            (Some(h), Some(d)) => h.len() == d.len() && d.iter().all(|c| is_delimiter_cell(c)),
            _ => false,
        };
        if !proven {
            index += 1;
            continue;
        }
        let header_cells = header.map_or(0, |h| h.len());
        let delimiter_pipes = pipes(&lines[index + 1]);
        let header_pipes = pipes(&lines[index]);
        if header_pipes.len() == delimiter_pipes.len() {
            out.insert(index, aligned(&header_pipes, &delimiter_pipes));
        }
        index += 2;
        while index < lines.len() {
            match table_cells(&lines[index]) {
                Some(row) if row.len() == header_cells => {}
                _ => break,
            }
            let row_pipes = pipes(&lines[index]);
            if row_pipes.len() == delimiter_pipes.len() {
                out.insert(index, aligned(&row_pipes, &delimiter_pipes));
            }
            index += 1;
        }
    }
    out
}

fn detect_vertical(content: &[char], lines: &[&[char]], offsets: &[usize]) -> Vec<PaddingRun> {
    let blank: Vec<bool> = lines
        .iter()
        .map(|l| l.iter().all(|&c| is_padding_char(c)))
        .collect();
    let mut runs = Vec::new();
    let (mut i, n) = (0, lines.len());
    while i < n {
        if !blank[i] {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < n && blank[j] {
            j += 1;
        }
        if j - i >= VERTICAL_BLANK_LINES {
            runs.push(PaddingRun {
                kind: Kind::Vertical,
                start_offset: offsets[i],
                start_line: i + 1,
                length: j - i,
                followed_by_content: j < n && !blank[j],
                summary: summarize_run(&content[offsets[i]..offsets[j]]),
                end_offset: offsets[j],
            });
        }
        i = j;
    }
    runs
}

fn detect_horizontal(lines: &[&[char]], offsets: &[usize], file_type: FileType) -> Vec<PaddingRun> {
    let markdown = file_type == FileType::Markdown;
    let flags = markdown.then(|| fence_flags(lines));
    let (boundaries, _texts) = if markdown {
        let texts: Vec<String> = lines.iter().map(|l| line_text(l)).collect();
        (table_boundaries(&texts), texts)
    } else {
        (HashMap::new(), Vec::new())
    };
    let mut runs = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if flags.as_ref().is_some_and(|f| f[idx]) {
            continue;
        }
        let mut k = 0;
        while k < line.len() {
            if !is_padding_char(line[k]) {
                k += 1;
                continue;
            }
            let start = k;
            while k < line.len() && is_padding_char(line[k]) {
                k += 1;
            }
            let run_len = k - start;
            if run_len < HORIZONTAL_RUN_CHARS {
                continue;
            }
            let exempt = boundaries.get(&idx).is_some_and(|b| b.contains(&k))
                && line[start..k].iter().all(|&c| c == ' ');
            if exempt {
                continue;
            }
            runs.push(PaddingRun {
                kind: Kind::Horizontal,
                start_offset: offsets[idx] + start,
                start_line: idx + 1,
                length: run_len,
                followed_by_content: k < line.len(),
                summary: summarize_run(&line[start..k]),
                end_offset: offsets[idx] + start + run_len,
            });
        }
    }
    runs
}

fn detect_block_and_ratio(content: &[char]) -> Vec<PaddingRun> {
    let mut runs = Vec::new();
    let n = content.len();
    let (mut best_len, mut best) = (0usize, None);
    let mut i = 0;
    while i < n {
        if !is_padding_char(content[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && is_padding_char(content[i]) {
            i += 1;
        }
        let bytes: usize = content[start..i].iter().map(|c| c.len_utf8()).sum();
        if bytes > best_len {
            best_len = bytes;
            best = Some((start, i));
        }
    }
    if let (true, Some((start, end))) = (best_len > BLOCK_BYTE_BUDGET, best) {
        runs.push(PaddingRun {
            kind: Kind::Block,
            start_offset: start,
            start_line: content[..start].iter().filter(|&&c| c == '\n').count() + 1,
            length: end - start,
            followed_by_content: false,
            summary: summarize_run(&content[start..(start + 200).min(n)]),
            end_offset: end,
        });
    }
    let file_bytes: usize = content.iter().map(|c| c.len_utf8()).sum();
    if file_bytes > RATIO_MIN_FILE_BYTES {
        let padding: usize = content
            .iter()
            .filter(|&&c| is_padding_char(c))
            .map(|c| c.len_utf8())
            .sum();
        if padding as f64 / file_bytes as f64 > 0.90 {
            runs.push(PaddingRun {
                kind: Kind::Ratio,
                start_offset: 0,
                start_line: 1,
                length: padding,
                followed_by_content: false,
                summary: format!("{padding}/{file_bytes} bytes padding"),
                end_offset: 0,
            });
        }
    }
    runs
}

fn detect_repetition(content: &[char]) -> Vec<PaddingRun> {
    let mut runs = Vec::new();
    let mut index = 0;
    while index < content.len() {
        let mut end = index + 1;
        while end < content.len() && content[end] == content[index] {
            end += 1;
        }
        if end - index >= REPEATED_CHAR_THRESHOLD && !is_padding_char(content[index]) {
            runs.push(PaddingRun {
                kind: Kind::Repetition,
                start_offset: index,
                start_line: content[..index].iter().filter(|&&c| c == '\n').count() + 1,
                length: end - index,
                followed_by_content: end < content.len(),
                summary: format!(
                    "repeated U+{:04X} x{}",
                    u32::from(content[index]),
                    end - index
                ),
                end_offset: end,
            });
        }
        index = end;
    }
    let (lines, offsets) = split_lines(content);
    let mut index = 0;
    while index < lines.len() {
        let mut end = index + 1;
        let non_blank = lines[index].iter().any(|&c| !is_space(c));
        while end < lines.len() && lines[end] == lines[index] && non_blank {
            end += 1;
        }
        if end - index >= REPEATED_LINE_THRESHOLD {
            runs.push(PaddingRun {
                kind: Kind::Repetition,
                start_offset: offsets[index],
                start_line: index + 1,
                length: end - index,
                followed_by_content: end < lines.len(),
                summary: format!("repeated line x{}", end - index),
                end_offset: offsets[end],
            });
        }
        index = end;
    }
    runs
}

/// `detect_whitespace_padding`.
#[must_use]
pub fn detect_whitespace_padding(content: &[char], file_type: FileType) -> Vec<PaddingRun> {
    if content.is_empty() {
        return Vec::new();
    }
    let replacements = content.iter().filter(|&&c| c == '\u{fffd}').count();
    if replacements as f64 / content.len() as f64 > 0.30 {
        return Vec::new();
    }
    let (lines, offsets) = split_lines(content);
    let vertical = detect_vertical(content, &lines, &offsets);
    let horizontal = detect_horizontal(&lines, &offsets, file_type);
    let primary: Vec<&PaddingRun> = vertical.iter().chain(&horizontal).collect();
    let overlaps = |r: &PaddingRun| {
        primary
            .iter()
            .any(|p| r.start_offset < p.end_offset && p.start_offset < r.end_offset)
    };
    let mut block_ratio = Vec::new();
    let mut block_kept = false;
    for run in detect_block_and_ratio(content) {
        match run.kind {
            Kind::Block if overlaps(&run) => continue,
            Kind::Ratio if !primary.is_empty() || block_kept => continue,
            Kind::Block => block_kept = true,
            _ => {}
        }
        block_ratio.push(run);
    }
    let repetition: Vec<PaddingRun> = detect_repetition(content)
        .into_iter()
        .filter(|r| !overlaps(r))
        .collect();
    let mut all = vertical.clone();
    all.extend(horizontal.clone());
    all.extend(block_ratio);
    all.extend(repetition);
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str, ft: FileType) -> Vec<PaddingRun> {
        let chars: Vec<char> = text.chars().collect();
        detect_whitespace_padding(&chars, ft)
    }

    #[test]
    fn vertical_run_of_blank_lines() {
        let text = format!("a{}b", "\n".repeat(25));
        let r = run(&text, FileType::Markdown);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, Kind::Vertical);
        assert!(r[0].followed_by_content);
        assert_eq!(r[0].length, 24);
        assert_eq!(r[0].start_line, 2);
    }

    #[test]
    fn short_runs_are_clean() {
        assert!(run(&format!("a{}b", "\n".repeat(10)), FileType::Markdown).is_empty());
        assert!(run(&format!("a{}b", " ".repeat(79)), FileType::Markdown).is_empty());
        assert!(run("", FileType::Markdown).is_empty());
    }

    #[test]
    fn horizontal_run_and_summary() {
        let r = run(&format!("a{}b", "\u{a0}".repeat(82)), FileType::Other);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, Kind::Horizontal);
        assert_eq!(r[0].summary, "U+00A0 x82");
        assert_eq!(summarize_run(&['\n'; 3]), "\\n x3");
    }

    #[test]
    fn markdown_fences_hide_horizontal_runs() {
        let text = format!("```\na{}b\n```\n", " ".repeat(100));
        assert!(run(&text, FileType::Markdown).is_empty());
        assert_eq!(run(&text, FileType::Text).len(), 1);
    }

    #[test]
    fn aligned_table_padding_is_exempt() {
        let pad = " ".repeat(90);
        let text = format!("|a{pad}|\n|-{}|\n|b{pad}|\n", "-".repeat(90));
        assert!(run(&text, FileType::Markdown).is_empty());
        let misaligned = format!("|a{pad}|\n|-{}|\n|b{pad} |\n", "-".repeat(90));
        assert_eq!(run(&misaligned, FileType::Markdown).len(), 1);
    }

    #[test]
    fn unicode_line_separators_count_as_blank_lines() {
        let text = format!("a{}b", "\u{2028}".repeat(25));
        assert_eq!(run(&text, FileType::Other)[0].kind, Kind::Vertical);
    }

    #[test]
    fn block_suppressed_by_overlap_and_ratio_reported_once() {
        let text = format!("a{}b", "\n".repeat(3000));
        let r = run(&text, FileType::Other);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, Kind::Vertical);
        let tabs = format!("{}x", "\t".repeat(3000));
        let kinds: Vec<Kind> = run(&tabs, FileType::Other).iter().map(|r| r.kind).collect();
        assert_eq!(kinds, [Kind::Horizontal]);
    }

    #[test]
    fn repetition_of_characters_and_lines() {
        let r = run(&"A".repeat(600), FileType::Other);
        assert_eq!(r[0].kind, Kind::Repetition);
        assert_eq!(r[0].summary, "repeated U+0041 x600");
        let lines = "same\n".repeat(70);
        assert_eq!(run(&lines, FileType::Other)[0].summary, "repeated line x70");
    }

    #[test]
    fn binary_like_content_bails_out() {
        let text = format!("{}{}", "\u{fffd}".repeat(50), " ".repeat(90));
        assert!(run(&text, FileType::Other).is_empty());
    }

    #[test]
    fn fingerprint_distinguishes_payloads() {
        let a: Vec<char> = " ".repeat(90).chars().collect();
        let b: Vec<char> = " ".repeat(91).chars().collect();
        let (ra, rb) = (
            run(&" ".repeat(90), FileType::Other),
            run(&" ".repeat(91), FileType::Other),
        );
        assert_ne!(
            padding_run_match_fingerprint(&a, &ra[0]),
            padding_run_match_fingerprint(&b, &rb[0])
        );
    }
}
