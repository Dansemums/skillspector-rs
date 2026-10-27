//! Helpers shared by the H1 modules (agent snooping, rogue agent, anti-refusal).

use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::matcher::Hit;
use crate::text::LineIndex;

/// First `n` characters of `s` (Python `s[:n]`).
pub fn cut_chars(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

/// The one place the H1 modules ask `prohibition_context.is_directly_prohibited`.
///
/// TEMPORARY STUB: always false. The final merge swaps the body for
/// `crate::prohibition::is_directly_prohibited(text, start, end)` (byte offsets).
pub fn is_directly_prohibited(text: &str, start: usize, end: usize) -> bool {
    crate::prohibition::is_directly_prohibited(
        text,
        start,
        end,
        &crate::prohibition::Options::default(),
    )
}

/// What a rule reports: id, message, severity and category tag.
pub struct Head<'a> {
    pub rule: &'static str,
    pub message: &'a str,
    pub severity: Severity,
    pub tag: &'a str,
}

/// A static-pattern finding for one hit: `matched_text[:200]`, fingerprint from the whole match.
pub fn hit_finding(
    head: &Head<'_>,
    confidence: f32,
    file: &str,
    text: &str,
    hit: &Hit,
    index: &LineIndex,
) -> RawFinding {
    let mut f = RawFinding::new(
        head.rule,
        head.message,
        head.severity,
        confidence,
        file,
        index.line(hit.start),
    );
    f.tags = vec![head.tag.to_owned()];
    let full = hit.text(text);
    f.matched_text = Some(cut_chars(full, 200).to_owned());
    f.fingerprint_text = Some(full.to_owned());
    f
}

#[cfg(test)]
mod tests {
    use super::cut_chars;

    #[test]
    fn cut_is_by_character() {
        assert_eq!(cut_chars("a\u{e9}b", 2), "a\u{e9}");
        assert_eq!(cut_chars("ab", 5), "ab");
    }
}
