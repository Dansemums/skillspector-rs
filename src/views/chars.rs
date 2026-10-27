//! Character predicates and span scanners behind the security views (`artifacts.py`).
//!
//! Every function works on `&[char]` with character offsets, like the Python source.

use crate::unicode::{
    casefold, category, confusable, is_alnum, is_alpha, is_default_ignorable, is_space, nfkc,
};
use std::borrow::Cow;

pub type Span = (usize, usize);

const ASCII_BYTES: [u8; 128] = {
    let mut a = [0u8; 128];
    let mut i = 0;
    while i < 128 {
        a[i] = i as u8;
        i += 1;
    }
    a
};

fn ascii_str(c: char) -> &'static str {
    let i = c as usize;
    std::str::from_utf8(&ASCII_BYTES[i..=i]).unwrap_or("")
}

/// `_LOGICAL_LINE_BREAK_CHARACTERS`.
#[must_use]
pub const fn is_logical_break(c: char) -> bool {
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

pub fn alpha(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphabetic()
    } else {
        is_alpha(c)
    }
}

pub fn alnum(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphanumeric()
    } else {
        is_alnum(c)
    }
}

pub fn space(c: char) -> bool {
    if c.is_ascii() {
        matches!(
            c,
            ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c' | '\x1c'..='\x1f'
        )
    } else {
        is_space(c)
    }
}

/// `_is_unconditionally_ignored`: control and format characters except `\n`, `\r`, `\t`.
pub fn is_ignored(c: char) -> bool {
    if c.is_ascii() {
        return (c < ' ' && !matches!(c, '\t' | '\n' | '\r')) || c == '\x7f';
    }
    matches!(category(c), "Cf" | "Cc")
}

pub fn is_word(c: char) -> bool {
    alnum(c) || c == '_'
}

/// `_is_non_ascii_separator`.
pub fn is_non_ascii_separator(c: char) -> bool {
    !c.is_ascii() && category(c).starts_with('Z')
}

/// `_is_letter_spacing_separator`.
pub fn is_letter_spacing_separator(c: char) -> bool {
    if matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}') || alnum(c) {
        return false;
    }
    let cat = category(c);
    space(c)
        || cat.starts_with(['P', 'S', 'Z'])
        || is_ignored(c)
        || is_default_ignorable(c)
        || c == '\u{fffd}'
}

/// `_is_token_gap_character`.
pub fn is_token_gap(c: char) -> bool {
    is_ignored(c) || is_default_ignorable(c) || is_non_ascii_separator(c) || c == '\u{fffd}'
}

/// `_is_emoji_base`.
fn is_emoji_base(c: char) -> bool {
    let cp = u32::from(c);
    (0x1F000..=0x1FAFF).contains(&cp)
        || (0x2600..=0x27BF).contains(&cp)
        || matches!(
            cp,
            0xA9 | 0xAE | 0x203C | 0x2049 | 0x2122 | 0x2139 | 0x3030 | 0x303D
        )
}

/// `unicodedata.normalize("NFKC", c).translate(ASCII_CONFUSABLE_SKELETON)` appended to `out`.
pub fn push_normalized(c: char, out: &mut impl FnMut(char)) {
    let mut each = |ch: char| match confusable(ch) {
        Some(s) => s.chars().for_each(&mut *out),
        None => out(ch),
    };
    match nfkc(c) {
        Some(s) => s.chars().for_each(&mut each),
        None => each(c),
    }
}

/// `_security_skeleton_piece`: the case-folded NFKC/confusable skeleton of one character.
pub fn skeleton_piece(c: char) -> Cow<'static, str> {
    if c.is_ascii() {
        return Cow::Borrowed(ascii_str(c.to_ascii_lowercase()));
    }
    let mut folded = String::new();
    push_normalized(c, &mut |ch| folded.push(ch));
    let folded = casefold(&folded);
    if folded == "i\u{307}" {
        Cow::Borrowed("i")
    } else {
        Cow::Owned(folded)
    }
}

/// `_fold_security_character`: a one-letter ASCII skeleton, if there is one.
pub fn fold_letter(c: char) -> Option<char> {
    if c.is_ascii() {
        return c.is_ascii_alphabetic().then(|| c.to_ascii_lowercase());
    }
    let piece = skeleton_piece(c);
    let mut it = piece.chars();
    match (it.next(), it.next()) {
        (Some(f), None) if f.is_ascii_alphabetic() => Some(f),
        _ => None,
    }
}

/// `_is_security_word_character`.
pub fn is_security_word(c: char) -> bool {
    is_word(c) || skeleton_piece(c).chars().any(is_word)
}

/// `_is_contextual_default_ignorable_offset`.
pub fn is_contextual_ignorable(t: &[char], off: usize) -> bool {
    let ch = t[off];
    if !is_default_ignorable(ch) || is_ignored(ch) {
        return false;
    }
    let previous = off.checked_sub(1).map(|i| t[i]);
    let following = t.get(off + 1).copied();
    let variation = ('\u{FE00}'..='\u{FE0F}').contains(&ch);
    !(variation
        && (previous.is_some_and(is_emoji_base) || following.is_some_and(|f| category(f) == "Me")))
}

/// `_is_normalization_ignored_offset`.
pub fn is_normalization_ignored(t: &[char], off: usize) -> bool {
    is_ignored(t[off]) || is_contextual_ignorable(t, off)
}

/// `_is_existing_projection_gap_character`.
pub fn is_existing_projection_gap(c: char) -> bool {
    is_ignored(c) || is_default_ignorable(c) || is_non_ascii_separator(c) || c == '\u{fffd}'
}

fn ignorable_run_end(t: &[char], start: usize, limit: usize) -> usize {
    let mut e = start;
    while e < limit && is_default_ignorable(t[e]) {
        e += 1;
    }
    e
}

/// `_existing_projection_run_end`.
pub fn existing_projection_run_end(t: &[char], start: usize) -> Option<usize> {
    let c = t[start];
    if is_default_ignorable(c) {
        return Some(ignorable_run_end(t, start, t.len()));
    }
    if is_logical_break(c)
        || alpha(c)
        || (c.is_ascii() && space(c))
        || !is_existing_projection_gap(c)
        || fold_letter(c).is_some()
    {
        return None;
    }
    let mut e = start + 1;
    while e < t.len() && t[e] == c {
        e += 1;
    }
    (e - start >= 2).then_some(e)
}

/// `_letter_spacing_gap_signature`.
fn gap_signature(gap: &[char]) -> Option<(bool, char, usize)> {
    if gap.is_empty() {
        return None;
    }
    if gap.iter().all(|&c| space(c)) {
        return gap
            .iter()
            .all(|&c| c == gap[0])
            .then_some((true, gap[0], gap.len()));
    }
    let mut marker = gap.iter().copied().filter(|&c| !space(c));
    let first = marker.next()?;
    marker.all(|c| c == first).then_some((false, first, 0))
}

/// `_letter_spacing_run_spans` (consistent separator class). Stops after the first run when asked.
pub fn letter_spacing_runs(t: &[char], first_only: bool) -> Vec<Span> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < t.len() {
        if !alpha(t[offset]) || (offset > 0 && alpha(t[offset - 1])) {
            offset += 1;
            continue;
        }
        let run_start = offset;
        let mut last_letter_end = offset + 1;
        let mut run_sig = None;
        let mut letters = 1;
        let mut cursor = last_letter_end;
        while cursor < t.len() {
            let gap_start = cursor;
            while cursor < t.len() && is_letter_spacing_separator(t[cursor]) {
                cursor += 1;
            }
            if gap_start == cursor || cursor >= t.len() || !alpha(t[cursor]) {
                break;
            }
            let next_end = cursor + 1;
            if next_end < t.len() && alpha(t[next_end]) {
                break;
            }
            let Some(sig) = gap_signature(&t[gap_start..cursor]) else {
                break;
            };
            match run_sig {
                None => run_sig = Some(sig),
                Some(s) if s != sig => break,
                Some(_) => {}
            }
            letters += 1;
            last_letter_end = next_end;
            cursor = next_end;
        }
        if letters >= 6 {
            out.push((run_start, last_letter_end));
            if first_only {
                return out;
            }
            offset = last_letter_end;
        } else {
            offset = run_start + 1;
        }
    }
    out
}

/// `_letter_spacing_gap_offsets`.
pub fn letter_spacing_gap_offsets(t: &[char]) -> Vec<usize> {
    letter_spacing_runs(t, false)
        .into_iter()
        .flat_map(|(s, e)| (s..e).filter(|&o| is_letter_spacing_separator(t[o])))
        .collect()
}

/// `_token_bridging_gap_spans`.
pub fn token_bridging_gaps(t: &[char], require_word_boundaries: bool) -> Vec<Span> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < t.len() {
        if !is_token_gap(t[offset]) {
            offset += 1;
            continue;
        }
        let start = offset;
        while offset < t.len() && is_token_gap(t[offset]) {
            if is_default_ignorable(t[offset]) {
                offset = ignorable_run_end(t, offset, t.len());
                continue;
            }
            offset += 1;
        }
        let before = start > 0 && is_word(t[start - 1]);
        let after = offset < t.len() && is_word(t[offset]);
        let contextual = if require_word_boundaries {
            before && after
        } else {
            before || after
        };
        if contextual {
            out.push((start, offset));
        }
    }
    out
}

/// Maximal runs of default-ignorable characters inside `gap_start..gap_end`.
fn ignorable_runs(t: &[char], gap_start: usize, gap_end: usize) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = gap_start;
    while i < gap_end {
        if !is_default_ignorable(t[i]) {
            i += 1;
            continue;
        }
        let s = i;
        i = ignorable_run_end(t, i, gap_end);
        out.push((s, i));
    }
    out
}

/// `_contextual_default_ignorable_spans`.
pub fn contextual_ignorable_spans(t: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    for (gs, ge) in token_bridging_gaps(t, false) {
        for (start, end) in ignorable_runs(t, gs, ge) {
            let ch = t[start];
            if t[start..end].iter().all(|&c| c == ch) {
                if is_ignored(ch) {
                    continue;
                }
                let cs = if is_contextual_ignorable(t, start) {
                    start
                } else {
                    start + 1
                };
                let ce = if is_contextual_ignorable(t, end - 1) {
                    end
                } else {
                    end - 1
                };
                if cs < ce {
                    out.push((cs, ce));
                }
                continue;
            }
            let mut span_start: Option<usize> = None;
            for off in start..end {
                if is_contextual_ignorable(t, off) {
                    span_start.get_or_insert(off);
                } else if let Some(s) = span_start.take() {
                    out.push((s, off));
                }
            }
            if let Some(s) = span_start {
                out.push((s, end));
            }
        }
    }
    out
}

/// `_contextual_default_ignorable_offsets`.
pub fn contextual_ignorable_offsets(t: &[char]) -> Vec<usize> {
    contextual_ignorable_spans(t)
        .into_iter()
        .flat_map(|(s, e)| s..e)
        .collect()
}

/// `_normalization_ignored_spans`.
pub fn normalization_ignored_spans(t: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    for (gs, ge) in token_bridging_gaps(t, false) {
        for (start, end) in ignorable_runs(t, gs, ge) {
            let s = if is_ignored(t[start]) || is_contextual_ignorable(t, start) {
                start
            } else {
                start + 1
            };
            let e = if is_ignored(t[end - 1]) || is_contextual_ignorable(t, end - 1) {
                end
            } else {
                end - 1
            };
            if s < e {
                out.push((s, e));
            }
        }
    }
    out
}

/// `_compact_gap_offsets`.
pub fn compact_gap_offsets(t: &[char]) -> Vec<usize> {
    let mut out = Vec::new();
    for (start, end) in token_bridging_gaps(t, true) {
        let ch = t[start];
        if t[start..end].iter().all(|&c| c == ch) {
            if is_non_ascii_separator(ch) {
                out.extend(start..end);
            }
            continue;
        }
        if t[start..end].iter().any(|&c| is_non_ascii_separator(c)) {
            out.extend(start..end);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    #[test]
    fn letter_spacing_needs_six_letters() {
        assert_eq!(letter_spacing_runs(&v("i g n o r e"), false), [(0, 11)]);
        assert!(letter_spacing_runs(&v("i g n o r"), false).is_empty());
        assert!(letter_spacing_runs(&v("a b-c d.e f"), false).is_empty());
    }

    #[test]
    fn skeleton_folds_confusables() {
        assert_eq!(skeleton_piece('A'), "a");
        assert_eq!(skeleton_piece('\u{ff49}'), "i");
        assert_eq!(fold_letter('\u{430}'), Some('a'));
    }

    #[test]
    fn zero_width_between_letters_is_contextual() {
        let t = v("ig\u{200b}nore");
        assert_eq!(token_bridging_gaps(&t, true), [(2, 3)]);
        assert_eq!(normalization_ignored_spans(&t), [(2, 3)]);
    }

    #[test]
    fn confusable_table_has_no_ascii_keys() {
        assert!(
            (0u8..128)
                .all(|b| confusable(char::from(b)).is_none() && nfkc(char::from(b)).is_none())
        );
    }
}
