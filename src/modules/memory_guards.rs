//! The MP3 false-positive guards of `static_patterns_memory_poisoning.py`: benign reset-state
//! coverage lists, clocked hardware state machines and `$display` timestamp examples.
//! Windows are measured in characters, as in Python.

use crate::matcher::{Hit, Pat};
use crate::text::{LOGICAL_LINE_BREAK, line_breaks};
use crate::unicode::is_space;
use std::sync::LazyLock;

/// `_LOGICAL_BREAK`: CRLF is one break.
fn lb() -> String {
    format!("(?>{LOGICAL_LINE_BREAK})")
}

fn benign_reset_src() -> String {
    format!(
        r#"(?:\A|{lb})[ \t]*(?:-[ \t]+\*\*Incomplete[ \t]+state[ \t]+coverage\*\*[ \t]+(?:—|--|-)[ \t]+)?(?:a[ \t]+)?state[ \t]+machine[ \t]+or[ \t]+(?:a[ \t]+)?lookup[ \t]+missing[ \t]+its[ \t]+initial[ \t]*/[ \t]*(?P<target>reset[ \t]+state)[ \t]*,[ \t]+its[ \t]+miss[ \t]*/[ \t]*default[ \t]+case[ \t]*,[ \t]+or[ \t]+a[ \t]+transition[ \t]+for[ \t]+some[ \t]+state[ \t]+(?:×|x)[ \t]+input[ \t]+\([ \t]*an[ \t]+implicit[ \t]+["'`]otherwise["'`][ \t]*\)[ \t]*\.[ \t]*(?=\Z|{lb})"#,
        lb = lb()
    )
}

const PRECEDING_DIRECTIVE_SRC: &str = r"\b(?:you|your|agents?|assistants?|models?|llms?|bots?|must|shall|should|required|mandatory)\b|\bbefore[ \t]+(?:replying|responding)\b|\b(?:following|below|above|next|this|that|it|them|these|those|so|prior|previous|preceding|everything|all|former|latter|content|text|output|configuration|material)\b|\bthe[ \t]+same\b|\bwhat[ \t]+follows\b|:[ \t]*$";

const NEXT_LINE_REFERENCE_SRC: &str = r"\b(?:it|them|this|these|those|so|same|above|below|prior|previous|preceding|following|foregoing|everything|all|former|latter|content|text|output|configuration|material)\b|\b(?:the|this|that|these|those|same)[ \t]+(?:state|memory|context|history|conversation|operations?|actions?)\b|\b(?:do|execute|perform|apply|follow|obey|invoke|run|use|reset|clear|wipe|erase|overwrite|replace|swap|modify|change|corrupt|rewrite|inject|poison|store|save|persist|retain|keep|internalize|set|enter|switch)[ \t]+that\b";

fn timestamp_description_src() -> String {
    format!(
        r#"(?:\A|{lb})[ \t]*//[ \t]*(?:✅[ \t]*)?(?:GOOD:[ \t]*)?(?P<target>clear[ \t]+context)[ \t]+(?:with|using)[ \t]+(?P<format>%[0-9]{{0,3}}t)[ \t]*\.?[ \t]*(?=\Z|{lb})"#,
        lb = lb()
    )
}

const DISPLAY_SRC: &str = r#"\A[ \t]*\$display[ \t]*\([ \t]*"(?P<format_string>(?:[^"\\\r\n\v\f\x85  ]|\\[^\r\n\v\f\x85  ])*)"[ \t]*,[ \t]*\$(?:realtime|time)[ \t]*\)[ \t]*;[ \t]*(?://[^\r\n\v\f\x85  ]*)?\z"#;

const OWNERSHIP_SRC: &str = r"\b(?:instructions?|directives?|requirements?|orders?)\b|\b(?:the|this|that|these|those|next|following|above|below|displayed|shown|described|listed|same|attached)[ \t]+(?:comments?|examples?|operations?|actions?|steps?|instructions?|directives?|lines?|snippets?|samples?)\b|\b(?:comments?|examples?|operations?|actions?|steps?|instructions?|directives?|lines?|snippets?|samples?)[ \t]+(?:above|below|earlier|prior|previous|preceding|following|next)\b|\b(?:following|next|above|below|this|that)\b[^\r\n]{0,80}\b(?:order|directive|instruction|command)\b";

const AUTHORITY_HEADING_SRC: &str = r"\A(?:(?:[A-Za-z]+[ \t]+)*(?:commands?|instructions?|directions?|directives?|orders?|actions?|operations?|steps?|tasks?)(?=[ \t:]|$)[^:\r\n]{0,80}:[ \t]*)\z";

fn description_directive_src() -> String {
    format!(
        r"\b(?:you|agents?|assistants?|models?|llms?|bots?|must|shall|should|required|mandatory)\b|\byour[ \t]+(?:memory|context|state|history|conversation|task|objective|mission|instructions?)\b|\b(?:conversation|memory|history|chat|transcript|dialogue)\b|\b(?:follow|obey|apply|execute|perform|do|carry[ \t]+out|act[ \t]+(?:on|upon))[ \t]+(?:(?:the[ \t]+)?(?:following|next|above|below)[ \t]+)?(?:this|that|it|these|those|comments?|instructions?)\b|\b(?:follow|obey|apply|execute|perform|do|carry[ \t]+out|act[ \t]+(?:on|upon))\b[^\r\n\v\f\x85  ]{{0,160}}\b(?:described|displayed|documented|shown|listed|comments?|examples?|operations?|actions?|steps?|instructions?|directives?|lines?|snippets?|samples?)\b|\b(?:task|instructions?|directives?)[ \t]*:|\bbefore[ \t]+(?:replying|responding|answering)\b|{OWNERSHIP_SRC}"
    )
}

const BACK_REFERENCE_SRC: &str = r"\b(?:described|displayed|documented|shown|listed|above|earlier|prior|previous|preceding|foregoing|same)[ \t]+(?:comments?|examples?|operations?|actions?|steps?|instructions?)\b|\b(?:comments?|examples?|operations?|actions?|steps?|instructions?)[ \t]+(?:above|earlier|prior|previous|preceding|foregoing)\b|\b(?:follow|obey|apply|execute|perform|do|carry[ \t]+out|act[ \t]+(?:on|upon)|use|run|invoke)\b[^\r\n\v\f\x85  ]{0,160}\b(?:this|that|it|these|those|above|earlier|prior|previous|preceding|foregoing|same)\b|\bcontext\b[^\r\n\v\f\x85  ]{0,160}\b(?:conversation|memory|history|chat|transcript|dialogue)\b|\b(?:conversation|memory|history|chat|transcript|dialogue)\b[^\r\n\v\f\x85  ]{0,160}\bcontext\b";

const REFERENCE_CUE_SRC: &str = r"\b(?:follow|obey|apply|execute|perform|do|carry|act|use|run|invoke|context|described|displayed|documented|shown|listed|above|earlier|prior|previous|preceding|foregoing|same|commands?|instructions?|directives?|requirements?|orders?)\b";

const FENCE_LINE_SRC: &str = r"\A[ \t]*(?:`{3,}|~{3,})[ \t]*\z";
const FENCE_OPENER_SRC: &str = r"\A[ \t]*(?:`{3,}|~{3,})[ \t]*(?:systemverilog|verilog)?[ \t]*\z";
const FENCE_MARKER_SRC: &str = r"\A[ \t]*(?:`{3,}|~{3,})";
const HARDWARE_RESET_SRC: &str = r"\b(?:(?:finite[ \t-]+)?state[ \t-]+machines?|fsms?)[ \t]+(?:takes?|reach(?:es)?|enters?|returns?[ \t]+to)[ \t]+(?:its|their)[ \t]+(?P<target>reset[ \t]+state)\b";
const HARDWARE_CLOCK_SRC: &str = r"\bclocks?\b";
const HARDWARE_AGENT_SRC: &str = r"\b(?:you|your|agents?|assistants?|models?|llms?|bots?|conversation|memory|context|history|chat|transcript|dialogue|prompt|instructions?|directives?)\b|\bbefore[ \t]+(?:replying|responding|answering)\b";
const RESET_FULL_SRC: &str = r"\A(?:reset[ \t]+state)\z";
const NORMALIZE_PREFIX_SRC: &str =
    r"\A[ \t]*(?:(?:>|//)[ \t]*)*(?:(?:[-+*]|[0-9]{1,9}[.)])[ \t]+)?(?:#{1,6}[ \t]+)?";

fn blank_line_src() -> String {
    format!("{lb}[ \\t]*{lb}", lb = lb())
}

fn sources() -> Vec<(String, &'static str)> {
    vec![
        (benign_reset_src(), "i"),
        (PRECEDING_DIRECTIVE_SRC.to_owned(), "i"),
        (NEXT_LINE_REFERENCE_SRC.to_owned(), "i"),
        (timestamp_description_src(), "i"),
        (DISPLAY_SRC.to_owned(), ""),
        (OWNERSHIP_SRC.to_owned(), "i"),
        (AUTHORITY_HEADING_SRC.to_owned(), "i"),
        (description_directive_src(), "i"),
        (BACK_REFERENCE_SRC.to_owned(), "i"),
        (REFERENCE_CUE_SRC.to_owned(), "i"),
        (FENCE_LINE_SRC.to_owned(), ""),
        (FENCE_OPENER_SRC.to_owned(), "i"),
        (FENCE_MARKER_SRC.to_owned(), ""),
        (HARDWARE_RESET_SRC.to_owned(), "i"),
        (HARDWARE_CLOCK_SRC.to_owned(), "i"),
        (HARDWARE_AGENT_SRC.to_owned(), "i"),
        (RESET_FULL_SRC.to_owned(), "i"),
        (NORMALIZE_PREFIX_SRC.to_owned(), ""),
        (blank_line_src(), ""),
    ]
}

static C: LazyLock<Vec<Pat>> =
    LazyLock::new(|| sources().iter().map(|(s, f)| Pat::new(s, f)).collect());
const BENIGN_RESET: usize = 0;
const PRECEDING: usize = 1;
const NEXT_LINE_REF: usize = 2;
const TS_DESCRIPTION: usize = 3;
const DISPLAY: usize = 4;
const OWNERSHIP: usize = 5;
const AUTHORITY: usize = 6;
const DESC_DIRECTIVE: usize = 7;
const BACK_REF: usize = 8;
const CUE: usize = 9;
const FENCE_LINE: usize = 10;
const FENCE_OPENER: usize = 11;
const FENCE_MARKER: usize = 12;
const HW_RESET: usize = 13;
const HW_CLOCK: usize = 14;
const HW_AGENT: usize = 15;
const RESET_FULL: usize = 16;
const NORM_PREFIX: usize = 17;
const BLANK_LINE: usize = 18;

fn found(i: usize, text: &str) -> bool {
    !C[i].find_iter(text).is_empty()
}

fn found_in(i: usize, text: &str, a: usize, b: usize) -> bool {
    !C[i].find_in(text, a, b).is_empty()
}

fn matches_whole(i: usize, text: &str) -> Option<Hit> {
    C[i].find_iter(text).into_iter().next()
}

/// Byte offset `n` (at least 1) characters before `at`, floored at 0.
pub(super) fn back(text: &str, at: usize, n: usize) -> usize {
    text[..at]
        .char_indices()
        .rev()
        .nth(n - 1)
        .map_or(0, |(i, _)| i)
}

/// Byte offset `n` characters after `at`, capped at the text length.
pub(super) fn fwd(text: &str, at: usize, n: usize) -> usize {
    text[at..]
        .char_indices()
        .nth(n)
        .map_or(text.len(), |(i, _)| at + i)
}

/// `LOGICAL_LINE_BREAK.match(text, pos)`: the end of a break starting at `pos`.
pub(super) fn break_end_at(text: &str, pos: usize) -> Option<usize> {
    line_breaks(&text[pos..])
        .first()
        .filter(|b| b.0 == 0)
        .map(|b| pos + b.1)
}

/// `LOGICAL_LINE_BREAK.split`.
fn split_lines(text: &str) -> Vec<&str> {
    split_at_breaks(text, line_breaks(text))
}

fn split_at_breaks(text: &str, breaks: Vec<(usize, usize)>) -> Vec<&str> {
    let mut out = Vec::with_capacity(breaks.len() + 1);
    let mut start = 0;
    for (s, e) in breaks {
        out.push(&text[start..s]);
        start = e;
    }
    out.push(&text[start..]);
    out
}

/// `re.split(LB[ \t]*LB, text)`.
fn split_paragraphs(text: &str) -> Vec<&str> {
    let breaks = C[BLANK_LINE]
        .find_iter(text)
        .iter()
        .map(|h| (h.start, h.end))
        .collect();
    split_at_breaks(text, breaks)
}

fn strip_py(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `_normalize_timestamp_guard`: joins wrapped directives for boolean guards.
fn normalize(text: &str) -> String {
    let joined = split_lines(text)
        .into_iter()
        .map(|line| {
            let cut = matches_whole(NORM_PREFIX, line).map_or(0, |h| h.end);
            &line[cut..]
        })
        .collect::<Vec<_>>()
        .join(" ");
    joined.chars().filter(|c| !"`*_[]".contains(*c)).collect()
}

/// `_bounded_previous_nonblank_line`: (line, whether it was complete).
pub(super) fn previous_nonblank_line(text: &str, offset: usize) -> (&str, bool) {
    let window_start = back(text, offset, 512);
    let parts = split_lines(&text[window_start..offset]);
    for (i, part) in parts.iter().enumerate().rev() {
        if !strip_py(part).is_empty() {
            return (part, i > 0 || window_start == 0);
        }
    }
    ("", window_start == 0)
}

/// `_bounded_next_nonblank_line`.
pub(super) fn next_nonblank_line(text: &str, offset: usize) -> (&str, bool) {
    let window_end = fwd(text, offset, 512);
    let window = &text[offset..window_end];
    let mut cursor = 0;
    for (s, e) in line_breaks(window) {
        let line = &window[cursor..s];
        if !strip_py(line).is_empty() {
            return (line, true);
        }
        cursor = e;
    }
    if window_end == text.len() {
        return (&window[cursor..], true);
    }
    ("", false)
}

/// The shared tail of the two "own line" guards: the candidate ends at a break (or the text end),
/// the next non-blank line must not refer back, and the previous line must not be a directive.
pub(super) fn standalone_line_ok(text: &str, cand: &Hit, next_ref: &Pat) -> Option<bool> {
    if cand.end != text.len() {
        let end = break_end_at(text, cand.end)?;
        let (next_line, complete) = next_nonblank_line(text, end);
        if !complete || !next_ref.find_iter(next_line).is_empty() {
            return None;
        }
    }
    if cand.start == 0 {
        return Some(true);
    }
    let (previous, complete) = previous_nonblank_line(text, cand.start);
    Some(complete && !found(PRECEDING, previous))
}

/// `_is_benign_reset_state_coverage`.
fn is_benign_reset_state_coverage(text: &str, m: &Hit) -> bool {
    let (a, b) = (back(text, m.start, 256), fwd(text, m.end, 256));
    for cand in C[BENIGN_RESET].find_in(text, a, b) {
        if cand.groups.get(1).copied().flatten() != Some((m.start, m.end)) {
            continue;
        }
        match standalone_line_ok(text, &cand, &C[NEXT_LINE_REF]) {
            None => {}
            Some(verdict) => return verdict,
        }
    }
    false
}

/// `_is_benign_hardware_reset_state`.
fn is_benign_hardware_reset_state(text: &str, m: &Hit) -> bool {
    if matches_whole(RESET_FULL, m.text(text)).is_none() {
        return false;
    }
    let (ws, we) = (back(text, m.start, 512), fwd(text, m.end, 512));
    let preceding: Vec<(usize, usize)> = line_breaks(&text[..m.start])
        .into_iter()
        .filter(|b| b.0 >= ws)
        .collect();
    let line_start = preceding.last().map_or(ws, |b| b.1);
    let following = line_breaks(&text[..we]).into_iter().find(|b| b.0 >= m.end);
    let line_end = following.map_or(we, |b| b.0);
    if (preceding.is_empty() && ws != 0) || (following.is_none() && we != text.len()) {
        return false;
    }
    if !found_in(HW_CLOCK, text, line_start, line_end) {
        return false;
    }
    let owned = C[HW_RESET]
        .find_in(text, line_start, line_end)
        .iter()
        .any(|c| c.groups.get(1).copied().flatten() == Some((m.start, m.end)));
    if !owned {
        return false;
    }
    let (_, prev_complete) = previous_nonblank_line(text, line_start);
    let (_, next_complete) = next_nonblank_line(text, line_end);
    if !prev_complete || !next_complete {
        return false;
    }
    let surrounding = normalize(&text[back(text, line_start, 512)..fwd(text, line_end, 512)]);
    !found(HW_AGENT, &surrounding) && !found(BACK_REF, &surrounding)
}

fn has_authority_heading(text: &str) -> bool {
    split_lines(text)
        .into_iter()
        .chain(split_paragraphs(text))
        .any(|region| found(AUTHORITY, strip_py(&normalize(region))))
}

/// `_bounded_timestamp_following_context`: through a nearby fence and following paragraph.
fn following_context(text: &str, offset: usize) -> Option<&str> {
    let window_end = fwd(text, offset, 512);
    let window = &text[offset..window_end];
    let (mut cursor, mut closed_fence, mut following_paragraph) = (0, false, false);
    for (s, e) in line_breaks(window) {
        let line = &window[cursor..s];
        cursor = e;
        if closed_fence {
            if found(FENCE_MARKER, line) {
                return Some(&window[..cursor]);
            }
            if !strip_py(line).is_empty() {
                following_paragraph = true;
            } else if following_paragraph && window_end != text.len() {
                return Some(&window[..cursor]);
            }
        }
        if found(FENCE_LINE, line) {
            closed_fence = true;
        }
    }
    (window_end == text.len()).then_some(window)
}

/// `_has_timestamp_back_reference`.
fn has_back_reference(text: &str, offset: usize) -> bool {
    let window_end = fwd(text, offset, 512);
    let window = &text[offset..window_end];
    let normalized = normalize(window);
    if found(BACK_REF, &normalized)
        || found(OWNERSHIP, &normalized)
        || has_authority_heading(window)
    {
        return true;
    }
    if window_end != text.len() && break_end_at(text, window_end).is_none() {
        let last = split_paragraphs(window).pop().unwrap_or("");
        return found(CUE, &normalize(last));
    }
    false
}

/// Whether `format` occurs in `s` not directly after a `%` (a literal percent).
fn has_format(s: &str, format: &str) -> bool {
    s.match_indices(format).any(|(i, _)| !s[..i].ends_with('%'))
}

/// `_is_benign_timestamp_context_description`.
fn is_benign_timestamp_context(text: &str, m: &Hit) -> bool {
    let (a, b) = (back(text, m.start, 256), fwd(text, m.end, 256));
    for cand in C[TS_DESCRIPTION].find_in(text, a, b) {
        if cand.groups.get(1).copied().flatten() != Some((m.start, m.end)) {
            continue;
        }
        if cand.end != text.len() && break_end_at(text, cand.end).is_none() {
            continue;
        }
        if timestamp_candidate_is_benign(text, &cand) {
            return true;
        }
    }
    false
}

fn timestamp_candidate_is_benign(text: &str, cand: &Hit) -> bool {
    let (mut previous, complete) = previous_nonblank_line(text, cand.start);
    if !complete {
        return false;
    }
    if found(FENCE_OPENER, previous) {
        let lo = back(text, cand.start, 512);
        let Some(opener) = text[lo..cand.start].rfind(previous).map(|i| lo + i) else {
            return false;
        };
        let (line, complete) = previous_nonblank_line(text, opener);
        if !complete {
            return false;
        }
        previous = line;
    }
    if found(PRECEDING, &normalize(previous)) {
        return false;
    }
    let preceding = &text[back(text, cand.start, 512)..cand.start];
    let nearest = split_paragraphs(preceding).pop().unwrap_or("");
    if preceding_has_non_colon_directive(&normalize(nearest)) {
        return false;
    }
    if found(DESC_DIRECTIVE, &normalize(preceding)) || has_authority_heading(preceding) {
        return false;
    }
    let (next_line, next_complete) = next_nonblank_line(text, cand.end);
    if !next_complete {
        return false;
    }
    let Some(display) = matches_whole(DISPLAY, next_line) else {
        return false;
    };
    let format = cand.group(text, 2).unwrap_or("");
    let format_string = display.group(next_line, 1).unwrap_or("");
    if !has_format(format_string, format) {
        return false;
    }
    if found(DESC_DIRECTIVE, next_line) || found(NEXT_LINE_REF, next_line) {
        return false;
    }
    let window = &text[cand.end..fwd(text, cand.end, 512)];
    let Some(rel) = window.find(next_line) else {
        return false;
    };
    let display_end = cand.end + rel + next_line.len();
    if has_back_reference(text, display_end) {
        return false;
    }
    let Some(following) = following_context(text, display_end) else {
        return false;
    };
    let normalized = normalize(following);
    !(found(NEXT_LINE_REF, &normalized)
        || found(DESC_DIRECTIVE, &normalized)
        || has_authority_heading(following))
}

/// Any `_PRECEDING_DIRECTIVE` hit that is not a bare colon.
fn preceding_has_non_colon_directive(normalized: &str) -> bool {
    C[PRECEDING]
        .find_iter(normalized)
        .iter()
        .any(|h| strip_py(h.text(normalized)) != ":")
}

/// True when an MP3 match is one of the three documented benign shapes.
#[must_use]
pub fn is_benign_mp3(text: &str, m: &Hit) -> bool {
    is_benign_reset_state_coverage(text, m)
        || is_benign_hardware_reset_state(text, m)
        || is_benign_timestamp_context(text, m)
}

#[cfg(test)]
/// Every pattern source with its flags, for the compile test.
pub fn pattern_sources() -> Vec<(String, &'static str)> {
    sources()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mp3_hit(text: &str, needle: &str) -> Hit {
        let start = text.find(needle).unwrap_or(0);
        Hit {
            start,
            end: start + needle.len(),
            groups: vec![Some((start, start + needle.len()))],
        }
    }

    #[test]
    fn all_guard_patterns_compile() {
        for (src, flags) in pattern_sources() {
            assert!(Pat::try_new(&src, flags).is_ok(), "{src}");
        }
    }

    #[test]
    fn window_helpers_count_characters() {
        let t = "ééé abc";
        assert_eq!(back(t, t.len(), 3), t.len() - 3);
        assert_eq!(back(t, 2, 512), 0);
        assert_eq!(fwd(t, 0, 2), 4);
        assert_eq!(fwd(t, 0, 512), t.len());
    }

    #[test]
    fn previous_and_next_nonblank_lines() {
        let t = "one\n\n  \ntwo\nthree";
        assert_eq!(previous_nonblank_line(t, 12), ("two", true));
        assert_eq!(next_nonblank_line(t, 3), ("two", true));
        assert_eq!(next_nonblank_line("a\n \n", 1), ("", true));
    }

    #[test]
    fn normalize_strips_markers_and_joins() {
        assert_eq!(normalize("> - **Do** this\n// # that"), "Do this that");
    }

    #[test]
    fn timestamp_description_with_display_is_benign() {
        let t = "Notes\n\n// clear context with %t\n$display(\"%t done\", $realtime);\n";
        let m = mp3_hit(t, "clear context");
        let guarded = is_benign_timestamp_context(t, &m);
        // the heading-like "Example:" colon alone must not make it hostile
        assert!(guarded);
    }

    #[test]
    fn timestamp_description_without_display_is_not_benign() {
        let t = "Do this.\n// clear context with %t\nnothing\n";
        assert!(!is_benign_timestamp_context(
            t,
            &mp3_hit(t, "clear context")
        ));
    }

    #[test]
    fn hardware_reset_state() {
        let t = "# fsm\nOn each clock the FSM takes its reset state when rst is high.\nDone.\n";
        let m = mp3_hit(t, "reset state");
        assert!(is_benign_hardware_reset_state(t, &m));
        let agent = "Before replying, on each clock the FSM takes its reset state.\n";
        assert!(!is_benign_hardware_reset_state(
            agent,
            &mp3_hit(agent, "reset state")
        ));
    }

    #[test]
    fn reset_state_coverage_list_item() {
        let t = "Notes\n- **Incomplete state coverage** - a state machine or lookup missing its initial / reset state, its miss / default case, or a transition for some state x input (an implicit \"otherwise\").\n";
        assert!(is_benign_reset_state_coverage(
            t,
            &mp3_hit(t, "reset state")
        ));
        let hostile = t.replacen("Notes", "You must follow:", 1);
        assert!(!is_benign_reset_state_coverage(
            &hostile,
            &mp3_hit(&hostile, "reset state")
        ));
    }
}
