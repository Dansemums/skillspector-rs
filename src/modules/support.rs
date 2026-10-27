//! Helpers shared by the prompt-family static modules.

use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::text::LineIndex;

/// First `n` characters of `s`.
#[must_use]
pub fn cut_chars(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

/// What one rule reports: everything but the location.
#[derive(Clone, Copy)]
pub struct Rule {
    pub id: &'static str,
    pub message: &'static str,
    pub severity: Severity,
    pub tag: &'static str,
}

impl Rule {
    /// A finding for the matched text `full` on `line`; the location has no columns
    /// (`Location(file, start_line)`), so the runner resolves them.
    #[must_use]
    pub fn plain(&self, conf: f32, file: &str, line: u32, full: &str) -> RawFinding {
        let mut f = RawFinding::new(self.id, self.message, self.severity, conf, file, line);
        f.tags = vec![self.tag.to_owned()];
        f.matched_text = Some(cut_chars(full, 200).to_owned());
        f.fingerprint_text = Some(full.to_owned());
        f
    }

    /// Like [`Rule::plain`] with the exact `SourceLocationIndex` span of `start..end`.
    #[must_use]
    pub fn spanned(
        &self,
        conf: f32,
        file: &str,
        text: &str,
        idx: &LineIndex,
        (start, end): (usize, usize),
    ) -> RawFinding {
        let mut f = self.plain(conf, file, idx.line(start), &text[start..end]);
        f.end_line = Some(idx.line(end));
        f.start_column = Some(idx.col_chars(text, start));
        f.end_column = Some(idx.col_chars(text, end));
        f
    }
}
