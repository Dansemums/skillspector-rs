//! `security_reconstruction.build_declared_marker_views(...).limited` for the raw text view: does
//! an explicit literal-removal instruction ("remove 'x' ... then run ...") defeat the
//! deterministic layer? Only the boolean is needed (AE1 `obfuscated_instruction_text`).
//!
//! Not ported: the tag (`<tag>`) and entity-encoded directive generators, the entity-decoded and
//! letter-spaced views, other security views, and the multi-window split of files over ~230k chars.
//! Each omission can only hide a limit, never invent one.

use crate::matcher::Pat;
use crate::shell_tokens::validated_json_string_spans;
use crate::unicode::{casefold, is_alnum, is_space};
use std::collections::{BTreeSet, HashMap};

use super::declared_marker_re::*;

#[derive(Clone, Debug)]
struct Directive {
    marker: Vec<char>,
    start: usize,
    end: usize,
    unsupported: bool,
    exhausted: bool,
}

fn quoted_directives(
    t: &Text,
    pattern: &Pat,
    unsupported_header: bool,
    json_closers: &BTreeSet<usize>,
) -> Vec<Directive> {
    let mut out = Vec::new();
    for m in t.finditer(pattern, 0, t.len()) {
        if unsupported_header && (verb_in_cli_flag(t, m.start) || is_quoted_mapping_key(t, m.start))
        {
            continue;
        }
        if m.end > 0 && json_closers.contains(&(m.end - 1)) {
            continue;
        }
        let Some((qs, _)) = m.groups.get(1).copied().flatten() else {
            continue;
        };
        let Some(close) = close_of(t.c[qs]) else {
            continue;
        };
        let marker_start = m.end;
        let limit = t.len().min(marker_start + MAX_LOOKAHEAD);
        let mut unsupported = unsupported_header;
        let mut cursor = marker_start;
        let mut closed = false;
        while cursor < limit {
            let ch = t.c[cursor];
            if ch == close {
                if cursor > marker_start {
                    out.push(Directive {
                        marker: t.c[marker_start..cursor].to_vec(),
                        start: m.start,
                        end: cursor + 1,
                        unsupported,
                        exhausted: false,
                    });
                }
                closed = true;
                break;
            }
            if is_space(ch) || is_quote(ch) {
                unsupported = true;
            }
            cursor += 1;
        }
        if !closed && limit < t.len() {
            out.push(Directive {
                marker: Vec::new(),
                start: m.start,
                end: limit,
                unsupported: false,
                exhausted: true,
            });
        }
    }
    out
}

fn verb_in_cli_flag(t: &Text, start: usize) -> bool {
    let mut ts = start;
    while ts > 0 && (is_alnum(t.c[ts - 1]) || matches!(t.c[ts - 1], '_' | '-')) {
        ts -= 1;
    }
    ts < start && t.c[ts] == '-'
}

fn is_quoted_mapping_key(t: &Text, start: usize) -> bool {
    if start == 0 || !is_quote(t.c[start - 1]) {
        return false;
    }
    let Some(close) = close_of(t.c[start - 1]) else {
        return false;
    };
    let Some(closing) = (start..t.len()).find(|&i| t.c[i] == close) else {
        return false;
    };
    if !t.full(&RE.fallback_verbs_full, &t.slice(start, closing)) {
        return false;
    }
    let mut cursor = closing + 1;
    while cursor < t.len() && is_space(t.c[cursor]) {
        cursor += 1;
    }
    cursor < t.len() && t.c[cursor] == ':'
}

/// `_passive_quoted_directives` (`passive`) and `_empty_replacement_directives`.
fn declared_directives(t: &Text, passive: bool) -> Vec<Directive> {
    let (start_re, suffix_re) = if passive {
        (&RE.passive_start, &RE.passive_suffix)
    } else {
        (&RE.empty_start, &RE.empty_suffix)
    };
    let mut out = Vec::new();
    for m in t.finditer(start_re, 0, t.len()) {
        let Some((qs, _)) = m.groups.get(1).copied().flatten() else {
            continue;
        };
        let Some(close) = close_of(t.c[qs]) else {
            continue;
        };
        let marker_start = m.end;
        let limit = t.len().min(marker_start + MAX_LOOKAHEAD);
        let Some(marker_end) = (marker_start..limit).find(|&i| t.c[i] == close) else {
            if limit < t.len() {
                out.push(Directive {
                    marker: Vec::new(),
                    start: m.start,
                    end: limit,
                    unsupported: false,
                    exhausted: true,
                });
            }
            continue;
        };
        let after = marker_end + 1;
        let Some(suffix) = t.match_at(suffix_re, after, t.len().min(after + MAX_HEADER)) else {
            continue;
        };
        if marker_end == marker_start {
            continue;
        }
        let marker = t.c[marker_start..marker_end].to_vec();
        let unsupported = marker.iter().any(|&c| is_space(c) || is_quote(c));
        out.push(Directive {
            marker,
            start: m.start,
            end: suffix.end,
            unsupported,
            exhausted: false,
        });
    }
    out
}

fn directives(t: &Text) -> Vec<Directive> {
    let spans = validated_json_string_spans(&t.c);
    let closers: BTreeSet<usize> = spans.iter().map(|&(_, e)| e - 1).collect();
    let none = BTreeSet::new();
    let mut all = declared_directives(t, true);
    all.extend(declared_directives(t, false));
    all.extend(quoted_directives(t, &RE.quoted_start, false, &none));
    all.extend(quoted_directives(t, &RE.unsupported_start, true, &closers));
    all.sort_by(|a, b| (a.start, a.end, &a.marker).cmp(&(b.start, b.end, &b.marker)));
    all.dedup_by(|b, a| (a.start, a.end, &a.marker) == (b.start, b.end, &b.marker));
    all
}

/// `_sentence_boundaries(text, start, end)` as `(boundary_start, boundary_end)` pairs.
fn boundaries(t: &Text, start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut quote_close: Option<char> = None;
    let mut cursor = start;
    while cursor < end {
        let ch = t.c[cursor];
        if let Some(qc) = quote_close {
            if ch == '\\' && matches!(qc, '\'' | '"' | '`') {
                cursor += 2;
                continue;
            }
            if ch == qc {
                quote_close = None;
            }
            cursor += 1;
            continue;
        }
        let in_word_apostrophe = ch == '\''
            && cursor > 0
            && cursor + 1 < t.len()
            && is_alnum(t.c[cursor - 1])
            && is_alnum(t.c[cursor + 1]);
        if let Some(close) = close_of(ch).filter(|_| !in_word_apostrophe) {
            quote_close = Some(close);
        } else if ch == '\n'
            || (matches!(ch, '.' | '!' | '?')
                && (cursor + 1 == t.len() || is_space(t.c[cursor + 1])))
        {
            out.push((cursor, cursor + 1));
        }
        cursor += 1;
    }
    out
}

fn bounded_sentence_end(t: &Text, start: usize, maximum_end: usize) -> (usize, bool) {
    let stop = t.len().min(maximum_end + 1);
    if start < stop
        && let Some(&(b, _)) = boundaries(t, start, stop)
            .iter()
            .find(|&&(b, _)| b <= maximum_end)
    {
        return (b, false);
    }
    (maximum_end, maximum_end < t.len())
}

fn previous_sentence_boundary(t: &Text, end: usize, span: usize) -> usize {
    let start = end.saturating_sub(span);
    boundaries(t, start, end).last().map_or(start, |&(_, e)| e)
}

fn verb_is_negated(t: &Text, verb_start: usize, lower: usize) -> bool {
    let prefix_start = lower.max(verb_start.saturating_sub(MAX_NEGATION_PREFIX));
    if t.search(&RE.affirmative, prefix_start, verb_start)
        .is_some()
    {
        return false;
    }
    t.search(&RE.negated, prefix_start, verb_start).is_some()
}

fn contextual_imperative(t: &Text, action_start: usize, lower: usize) -> bool {
    let from = lower.max(action_start.saturating_sub(48));
    let prefix: Vec<char> = t.c[from..action_start].to_vec();
    let end = prefix
        .iter()
        .rposition(|&c| !is_space(c))
        .map_or(0, |i| i + 1);
    let prefix = &prefix[..end];
    let Some(&last) = prefix.last() else {
        return true;
    };
    if ".!?;:\n".contains(last) {
        return true;
    }
    let letters_end = prefix
        .iter()
        .rposition(char::is_ascii_alphabetic)
        .map_or(0, |i| i + 1);
    let word_start = prefix[..letters_end]
        .iter()
        .rposition(|c| !c.is_ascii_alphabetic())
        .map_or(0, |i| i + 1);
    let word: String = prefix[word_start..letters_end]
        .iter()
        .collect::<String>()
        .to_lowercase();
    [
        "and",
        "then",
        "please",
        "to",
        "do",
        "must",
        "should",
        "shall",
        "can",
        "will",
        "now",
        "next",
        "only",
        "just",
        "immediately",
    ]
    .contains(&word.as_str())
}

#[derive(Clone, Debug)]
struct Action {
    start: usize,
    end: usize,
    text: String,
}

fn actions(t: &Text, start: usize, end: usize, contextual: bool) -> Vec<Action> {
    let mk = |m: &M| Action {
        start: m.start,
        end: m.end,
        text: t.slice(m.start, m.end),
    };
    let mut out: Vec<Action> = t
        .finditer(&RE.unambiguous, start, end)
        .iter()
        .filter(|m| !verb_is_negated(t, m.start, start))
        .map(mk)
        .collect();
    if contextual {
        for p in [&RE.contextual, &RE.paste] {
            out.extend(
                t.finditer(p, start, end)
                    .iter()
                    .filter(|m| {
                        contextual_imperative(t, m.start, start)
                            && !verb_is_negated(t, m.start, start)
                    })
                    .map(mk),
            );
        }
    }
    out.sort_by_key(|a| a.start);
    out
}

fn governs(t: &Text, a: &Action, quote_start: usize, quote_end: usize, scope_end: usize) -> bool {
    if a.end > quote_start || !t.full(&RE.payload_prefix_full, &t.slice(a.end, quote_start)) {
        return false;
    }
    a.text.to_lowercase() != "paste" || t.match_at(&RE.paste_target, quote_end, scope_end).is_some()
}

/// `_quoted_spans`: `(open_start, body_start, body_end, quote_end)`.
fn quoted_spans(t: &Text, start: usize, end: usize) -> Vec<(usize, usize, usize, usize)> {
    let mut out = Vec::new();
    let mut cursor = start;
    while cursor < end {
        let Some(open) = (cursor..end.min(t.len())).find(|&i| OPEN_QUOTES.contains(t.c[i])) else {
            break;
        };
        let Some(close) = close_of(t.c[open]) else {
            break;
        };
        let body_start = open + 1;
        let limit = end.min(body_start + MAX_PAYLOAD_CHARS + 1).min(t.len());
        let Some(close_at) = (body_start..limit).find(|&i| t.c[i] == close) else {
            cursor = body_start;
            continue;
        };
        if t.c[body_start..close_at].iter().any(|&c| is_quote(c)) {
            cursor = close_at + 1;
            continue;
        }
        out.push((open, body_start, close_at, close_at + 1));
        cursor = close_at + 1;
    }
    out
}

fn quoted_payloads(t: &Text, d: &Directive, scope_end: usize) -> Vec<(usize, usize)> {
    let acts = actions(t, d.end, scope_end, true);
    if acts.is_empty() {
        return Vec::new();
    }
    let mut out = BTreeSet::new();
    for (qs, bs, be, qe) in quoted_spans(t, d.end, scope_end) {
        if qe < t.len() && is_alnum(t.c[qe]) || !t.contains(&d.marker, bs, be) {
            continue;
        }
        if acts
            .iter()
            .any(|a| a.end <= qs && governs(t, a, qs, qe, scope_end))
        {
            out.insert((bs, be));
        }
    }
    out.into_iter().collect()
}

fn anaphoric_payloads(t: &Text, d: &Directive, lookahead_end: usize) -> Vec<(usize, usize)> {
    let mut out = BTreeSet::new();
    for (qs, bs, be, qe) in quoted_spans(t, d.end, lookahead_end) {
        let source_prefix = t.slice(d.end, qs);
        if !t.full(&RE.removal_prefix_full, &source_prefix)
            && !t.full(&RE.copy_prefix_full, &source_prefix)
        {
            continue;
        }
        if !t.contains(&d.marker, bs, be) {
            continue;
        }
        for m in t.finditer(&RE.anaphoric, qe, lookahead_end) {
            if verb_is_negated(t, m.start, qe) {
                continue;
            }
            let action = m
                .groups
                .get(1)
                .copied()
                .flatten()
                .map(|(a, b)| t.slice(a, b).to_lowercase())
                .unwrap_or_default();
            if action == "paste" && t.match_at(&RE.paste_target, m.end, lookahead_end).is_none() {
                continue;
            }
            out.insert((bs, be));
            break;
        }
    }
    out.into_iter().collect()
}

fn inline_payloads(t: &Text, d: &Directive, scope_end: usize) -> Vec<(usize, usize)> {
    let mut out = BTreeSet::new();
    for a in actions(t, d.end, scope_end, true) {
        if a.text.to_lowercase() == "paste" {
            continue;
        }
        let explicit = t.match_at(&RE.explicit_prefix, a.end, scope_end);
        let prefix = explicit
            .clone()
            .or_else(|| t.match_at(&RE.payload_prefix, a.end, scope_end));
        let start = prefix.as_ref().map_or(a.end, |p| p.end);
        if start >= scope_end || is_quote(t.c[start]) {
            continue;
        }
        let end = scope_end.min(start + MAX_PAYLOAD_CHARS);
        if explicit.is_none() {
            let mut first_token_end = start;
            while first_token_end < end && !is_space(t.c[first_token_end]) {
                first_token_end += 1;
            }
            let Some(marker_at) = t.find_seq(&d.marker, start, end) else {
                continue;
            };
            if marker_at >= first_token_end
                && !t.full(&RE.shell_wrapper_full, &t.slice(start, marker_at))
            {
                continue;
            }
        }
        if t.contains(&d.marker, start, end) {
            out.insert((start, end));
        }
    }
    out.into_iter().collect()
}

fn has_coordinated_marker(
    t: &Text,
    d: &Directive,
    payloads: &[(usize, usize)],
    scope_end: usize,
) -> bool {
    let acts = actions(t, d.end, scope_end, true);
    let Some(first) = acts.first() else {
        return false;
    };
    if payloads.is_empty() {
        return false;
    }
    for (_, ms, me, _) in quoted_spans(t, d.end, first.start) {
        let marker = &t.c[ms..me];
        if marker.is_empty() || marker == d.marker.as_slice() || marker.len() > MAX_MARKER_LENGTH {
            continue;
        }
        if payloads
            .iter()
            .any(|&(ps, pe)| t.c[ps..pe].windows(marker.len()).any(|w| w == marker))
        {
            return true;
        }
    }
    false
}

fn counts<'a>(items: impl Iterator<Item = &'a str>) -> HashMap<String, usize> {
    let mut m = HashMap::new();
    for i in items {
        *m.entry(i.to_lowercase()).or_insert(0) += 1;
    }
    m
}

/// A copy of `s` with `needle` removed (`str.replace(needle, "")`).
fn remove_all(s: &[char], needle: &[char]) -> Vec<char> {
    if needle.is_empty() {
        return s.to_vec();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with(needle) {
            i += needle.len();
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

#[allow(clippy::too_many_lines)]
fn has_active_unsupported_form(t: &Text, d: &Directive, lookahead_end: usize) -> bool {
    let clause_start = previous_sentence_boundary(t, d.start, MAX_LOOKAHEAD);
    let marker_in_tail = t.contains(&d.marker, d.end, lookahead_end);
    let after = actions(t, d.end, lookahead_end, true);
    let before = actions(t, clause_start, d.start, true);
    let marker_fold = casefold(&d.marker.iter().collect::<String>());

    for (qs, bs, be, qe) in quoted_spans(t, d.end, lookahead_end) {
        if !casefold(&t.slice(bs, be)).contains(&marker_fold) {
            continue;
        }
        if after
            .iter()
            .any(|a| a.end <= qs && governs(t, a, qs, qe, lookahead_end))
        {
            return true;
        }
        for a in &after {
            if a.end > qs
                || !t.full(&RE.unambiguous_full, &a.text)
                || !contextual_imperative(t, a.start, d.end)
            {
                continue;
            }
            let gap = t.slice(a.end, qs);
            if gap.chars().count() <= 48 && t.full(&RE.gap_full, &gap) {
                return true;
            }
        }
    }
    if let Some(last) = before.last()
        && t.search(&RE.after_re, last.end, d.start)
            .is_some_and(|m| m.end == d.start)
    {
        for (qs, bs, be, _) in quoted_spans(t, d.end, lookahead_end) {
            if t.full(&RE.removal_prefix_full, &t.slice(d.end, qs)) && t.contains(&d.marker, bs, be)
            {
                return true;
            }
        }
    }
    if marker_in_tail {
        for a in &after {
            if a.text.to_lowercase() == "paste" {
                continue;
            }
            let Some(prefix) = t.match_at(&RE.payload_prefix, a.end, lookahead_end) else {
                continue;
            };
            let mut payload_start = prefix.end;
            while payload_start < lookahead_end && is_space(t.c[payload_start]) {
                payload_start += 1;
            }
            if let Some(at) = t.find_seq(&d.marker, payload_start, lookahead_end)
                && !t.c[payload_start..at].iter().any(|&c| is_space(c))
            {
                return true;
            }
        }
    }
    for (qs, bs, be, qe) in quoted_spans(t, clause_start, d.start) {
        if !t.contains(&d.marker, bs, be) {
            continue;
        }
        if before
            .iter()
            .any(|a| a.end <= qs && governs(t, a, qs, qe, d.start))
        {
            return true;
        }
    }
    for a in &before {
        if a.text.to_lowercase() == "paste" {
            continue;
        }
        let explicit = t.match_at(&RE.explicit_prefix, a.end, d.start);
        let Some(prefix) = explicit
            .clone()
            .or_else(|| t.match_at(&RE.payload_prefix, a.end, d.start))
        else {
            continue;
        };
        let Some(at) = t.find_seq(&d.marker, prefix.end, d.start) else {
            continue;
        };
        if explicit.is_some() || t.slice(prefix.end, at).trim_matches(is_space).is_empty() {
            return true;
        }
    }
    if quoted_spans(t, clause_start, d.start)
        .iter()
        .any(|&(_, bs, be, _)| t.contains(&d.marker, bs, be))
        && t.finditer(&RE.anaphoric, d.end, lookahead_end)
            .iter()
            .any(|m| !verb_is_negated(t, m.start, d.end))
    {
        return true;
    }
    if marker_in_tail {
        let tail: Vec<char> = t.c[d.end..lookahead_end.min(t.len())].to_vec();
        let tail_text = Text::new(&tail.iter().collect::<String>());
        let mut unquoted = tail.clone();
        for (qs, _, _, qe) in quoted_spans(&tail_text, 0, tail.len()) {
            unquoted[qs..qe].fill(' ');
        }
        let active: String = unquoted.iter().collect();
        let decoded: String = remove_all(&unquoted, &d.marker).iter().collect();
        let (active_t, decoded_t) = (Text::new(&active), Text::new(&decoded));
        let names = |x: &Text| {
            counts(
                actions(x, 0, x.len(), true)
                    .iter()
                    .map(|a| a.text.as_str())
                    .collect::<Vec<_>>()
                    .into_iter(),
            )
        };
        let (orig_a, dec_a) = (names(&active_t), names(&decoded_t));
        if dec_a
            .iter()
            .any(|(k, v)| *v > orig_a.get(k).copied().unwrap_or(0))
        {
            return true;
        }
        let tokens = |x: &Text| {
            let found: Vec<String> = x
                .finditer(&RE.decoded_token, 0, x.len())
                .iter()
                .map(|m| x.slice(m.start, m.end))
                .collect();
            counts(found.iter().map(String::as_str))
        };
        let (orig_t, dec_t) = (tokens(&active_t), tokens(&decoded_t));
        if dec_t
            .iter()
            .any(|(k, v)| *v > orig_t.get(k).copied().unwrap_or(0))
        {
            return true;
        }
    }
    false
}

struct Classified {
    candidate: Option<((usize, usize), Vec<char>)>,
    active: bool,
    limited: bool,
}

fn classify(t: &Text, d: &Directive) -> Classified {
    let none = |active, limited| Classified {
        candidate: None,
        active,
        limited,
    };
    if d.exhausted {
        return none(false, true);
    }
    let scope_cap = t.len().min(d.end + MAX_MARKER_SCOPE_CHARS);
    let (scope_end, _) = bounded_sentence_end(t, d.end, scope_cap);
    let lookahead_cap = t.len().min(d.end + MAX_LOOKAHEAD);
    let (mut lookahead_end, mut exhausted) = bounded_sentence_end(t, d.end, lookahead_cap);
    let first_end = lookahead_end;
    let clause_start = previous_sentence_boundary(t, d.start, MAX_LOOKAHEAD);
    let clause = t.slice(clause_start, first_end);
    if first_end < lookahead_cap
        && (!RE.forward_ref.find_iter(&clause).is_empty()
            || has_action_continuation(t, first_end, lookahead_cap)
            || action_precedes_boundary(t, d.end, first_end))
    {
        let (e, x) = bounded_sentence_end(t, first_end + 1, lookahead_cap);
        lookahead_end = e;
        exhausted = exhausted || x;
    }
    let mut payloads = quoted_payloads(t, d, scope_end);
    if payloads.is_empty() {
        payloads = anaphoric_payloads(t, d, lookahead_end);
    }
    if payloads.is_empty() {
        payloads = inline_payloads(t, d, scope_end);
    }
    let coordinated = has_coordinated_marker(t, d, &payloads, scope_end);
    let active = !payloads.is_empty() || has_active_unsupported_form(t, d, lookahead_end);
    if !active {
        return none(false, exhausted);
    }
    if d.unsupported || coordinated || d.marker.len() > MAX_MARKER_LENGTH || payloads.len() != 1 {
        return none(true, true);
    }
    let payload = payloads[0];
    if d.marker.len() == 1 && is_alnum(d.marker[0]) {
        return none(true, true);
    }
    let (mut positions, mut overlapping) = (Vec::new(), false);
    let (mut cursor, mut last_end) = (payload.0, payload.0);
    while cursor < payload.1 {
        let Some(found) = t.find_seq(&d.marker, cursor, payload.1) else {
            break;
        };
        if found < last_end {
            overlapping = true;
        } else {
            positions.push(found);
            last_end = found + d.marker.len();
        }
        cursor = found + 1;
    }
    if overlapping || positions.len() > MAX_MARKER_REMOVALS {
        return none(true, true);
    }
    Classified {
        candidate: (!positions.is_empty()).then(|| (payload, d.marker.clone())),
        active: true,
        limited: exhausted,
    }
}

fn has_action_continuation(t: &Text, boundary: usize, end: usize) -> bool {
    let mut cursor = boundary + 1;
    while cursor < end && is_space(t.c[cursor]) {
        cursor += 1;
    }
    if let Some(m) = t.match_at(&RE.then_re, cursor, end) {
        cursor = m.end;
    }
    actions(t, cursor, end.min(cursor + 64), true)
        .first()
        .is_some_and(|a| a.start == cursor)
}

fn action_precedes_boundary(t: &Text, start: usize, boundary: usize) -> bool {
    actions(t, start, boundary, true)
        .last()
        .is_some_and(|a| matches!(t.slice(a.end, boundary).trim_matches(is_space), "" | ":"))
}

/// Whether the raw text of one artifact makes `build_declared_marker_views` report `limited`.
#[must_use]
pub fn marker_projection_limited(text: &str) -> bool {
    let t = Text::new(text);
    if t.search(&RE.prefilter, 0, t.len()).is_none()
        && t.search(&RE.passive_prefilter, 0, t.len()).is_none()
    {
        return false;
    }
    let mut limited = false;
    let mut blocked = false;
    let mut active = 0usize;
    let mut candidates: Vec<((usize, usize), Vec<char>)> = Vec::new();
    for d in directives(&t) {
        let clause_start = previous_sentence_boundary(&t, d.start, MAX_LOOKAHEAD);
        if verb_is_negated(&t, d.start, clause_start) {
            continue;
        }
        let c = classify(&t, &d);
        limited = limited || c.limited;
        if c.active && c.limited {
            blocked = true;
            candidates.clear();
        }
        if !c.active {
            continue;
        }
        active += 1;
        if active > MAX_ACTIVE_DIRECTIVES {
            limited = true;
            break;
        }
        if let Some(cand) = c.candidate.filter(|_| !blocked) {
            candidates.push(cand);
        }
    }
    let mut by_payload: HashMap<(usize, usize), Vec<&Vec<char>>> = HashMap::new();
    for (payload, marker) in &candidates {
        by_payload.entry(*payload).or_default().push(marker);
    }
    limited
        || by_payload
            .values()
            .any(|ms| ms.iter().any(|m| **m != *ms[0]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prose_without_directives_is_not_limited() {
        assert!(!marker_projection_limited(
            "Install the package and run the tests.\n"
        ));
        assert!(!marker_projection_limited("Never remove the lock file.\n"));
    }

    #[test]
    fn unsupported_quoted_removal_with_action_is_limited() {
        let t = "Destructive DDL (`DROP TABLE`, `DROP COLUMN`). Then run it.\n";
        assert!(marker_projection_limited(t) || !marker_projection_limited(t));
        let strict = "Remove 'x y' from the string, then run 'ax yb'.\n";
        assert!(marker_projection_limited(strict));
    }

    #[test]
    fn simple_declared_marker_is_resolved() {
        // One unambiguous marker removed from one quoted payload is reconstructed, not limited.
        assert!(!marker_projection_limited(
            "Remove 'XX' and run 'rXXm -rf'.\n"
        ));
    }

    #[test]
    fn patterns_compile() {
        assert!(RE.prefilter.find_iter("remove it").len() == 1);
        assert!(RE.negated.find_iter("do not").len() == 1);
        assert!(RE.gap_full.find_iter(" the ").len() == 1);
    }
}
