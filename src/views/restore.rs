//! `static_runner._restore_source_lines`: map findings from a derived view back to the source text.

use super::SecurityTextView;
use crate::finding::RawFinding;
use crate::text::LineIndex;

/// Line and column lookup for character offsets of the source text.
pub struct RawCoords<'a> {
    text: &'a str,
    byte_of_char: Vec<usize>,
    index: LineIndex,
}

impl<'a> RawCoords<'a> {
    #[must_use]
    pub fn new(text: &'a str) -> Self {
        let mut byte_of_char: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
        byte_of_char.push(text.len());
        Self {
            text,
            byte_of_char,
            index: LineIndex::new(text),
        }
    }

    /// `source_position`: 1-based line and character column of a source character offset.
    fn position(&self, char_offset: usize) -> (u32, u32) {
        let byte = self.byte_of_char[char_offset.min(self.byte_of_char.len() - 1)];
        (self.index.line(byte), self.index.col_chars(self.text, byte))
    }
}

/// Character offset of the start of every logical line of `text`.
fn line_starts_chars(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    let mut chars = text.chars().enumerate().peekable();
    while let Some((i, c)) = chars.next() {
        if !matches!(
            c,
            '\r' | '\n' | '\x0b' | '\x0c' | '\x1c'..='\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}'
        ) {
            continue;
        }
        if c == '\r' && chars.peek().is_some_and(|&(_, n)| n == '\n') {
            chars.next();
            starts.push(i + 2);
        } else {
            starts.push(i + 1);
        }
    }
    starts
}

/// Moves the locations of `findings` (found in `view`) to source coordinates.
pub fn restore_source_lines(findings: &mut [RawFinding], view: &SecurityTextView, raw: &RawCoords) {
    let starts = line_starts_chars(&view.text);
    let len = view.text.chars().count();
    let derived_offset = |line: u32, column: Option<u32>| -> usize {
        let line_start = match usize::try_from(line).ok().and_then(|l| l.checked_sub(1)) {
            None | Some(0) => 0,
            Some(i) => starts.get(i).copied().unwrap_or(len),
        };
        (line_start + column.map_or(0, |c| c as usize)).min(len)
    };
    let source_end = |offset: usize| {
        if offset == 0 {
            view.source_offset(0)
        } else {
            view.source_offset(offset - 1) + 1
        }
    };
    for f in findings {
        let exact_start = f.start_column.is_some();
        let raw_start = view.source_offset(derived_offset(f.start_line, f.start_column));
        let (line, column) = raw.position(raw_start);
        f.start_line = line;
        f.start_column = exact_start.then_some(column);
        if let Some(end_line) = f.end_line {
            let exact_end = f.end_column.is_some();
            let end_offset = derived_offset(end_line, f.end_column);
            let raw_end = if exact_end {
                source_end(end_offset)
            } else {
                view.source_offset(end_offset)
            };
            let (line, column) = raw.position(raw_end);
            f.end_line = Some(line);
            f.end_column = exact_end.then_some(column);
        }
    }
}
