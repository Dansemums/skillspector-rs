//! Derived security views of a file's text (`artifacts.security_text_views`).
//!
//! A view is a projection of the raw text (NFKC, ASCII confusable skeleton, removed zero-width
//! and letter-spacing noise) plus, for every derived character, the character offset it came from.
//! ASCII text with no control characters, no letter spacing and no obfuscated instruction has only
//! the raw view, which is by far the common case.
//!
//! Not ported (nothing in the pinned static modules calls them): `normalized_security_prefix`,
//! `prompt_injection_letter_spacing_view`, `multiline_prompt_injection_view` and the continuity /
//! declared-marker views (see docs/ARCHITECTURE.md).

mod chars;
mod obfuscated;
mod restore;
#[rustfmt::skip]
mod tables;

pub use restore::{RawCoords, restore_source_lines};

use chars::{
    compact_gap_offsets, contextual_ignorable_offsets, is_ignored, is_logical_break,
    letter_spacing_gap_offsets, letter_spacing_runs, normalization_ignored_spans, push_normalized,
};
use obfuscated::{instruction_gap_offsets, instruction_matches};
use std::cell::RefCell;
use std::rc::Rc;

/// `SecurityTextView`: a derived text and the source character offset of each of its characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityTextView {
    pub name: &'static str,
    pub text: String,
    /// `None` for the raw view (identity mapping).
    pub source_offsets: Option<Vec<u32>>,
}

impl SecurityTextView {
    /// `SecurityTextView.source_offset` for a derived character offset.
    #[must_use]
    pub fn source_offset(&self, derived: usize) -> usize {
        match &self.source_offsets {
            None => derived.min(self.text.chars().count()),
            Some(o) if o.is_empty() => 0,
            Some(o) => o[derived.min(o.len() - 1)] as usize,
        }
    }
}

/// Walks a sorted offset list the way Python's `next(iterator)` bookkeeping does.
struct Marks {
    offsets: Vec<usize>,
    next: usize,
}

impl Marks {
    fn new(offsets: Vec<usize>) -> Self {
        Self { offsets, next: 0 }
    }

    fn hit(&mut self, offset: usize) -> bool {
        let hit = self.offsets.get(self.next) == Some(&offset);
        self.next += usize::from(hit);
        hit
    }
}

fn finish(name: &'static str, text: String, offsets: Vec<u32>) -> SecurityTextView {
    SecurityTextView {
        name,
        text,
        source_offsets: Some(offsets),
    }
}

fn emit(out: &mut String, offsets: &mut Vec<u32>, c: char, source: usize) {
    push_normalized(c, &mut |n| {
        out.push(n);
        offsets.push(source as u32);
    });
}

/// `normalized_security_view`.
fn normalized_view(t: &[char]) -> SecurityTextView {
    let spans = normalization_ignored_spans(t);
    let mut next = 0;
    let (mut out, mut offsets) = (String::new(), Vec::new());
    let mut off = 0;
    while off < t.len() {
        if let Some(&(start, end)) = spans.get(next)
            && off == start
        {
            off = end;
            next += 1;
            continue;
        }
        if !is_ignored(t[off]) {
            emit(&mut out, &mut offsets, t[off], off);
        }
        off += 1;
    }
    finish("normalized", out, offsets)
}

/// `obfuscated_instruction_view`.
fn obfuscated_view(t: &[char]) -> SecurityTextView {
    let mut contextual = Marks::new(contextual_ignorable_offsets(t));
    let mut instruction = Marks::new(instruction_gap_offsets(t));
    let (mut out, mut offsets) = (String::new(), Vec::new());
    for (off, &c) in t.iter().enumerate() {
        let is_contextual = contextual.hit(off);
        let is_instruction = instruction.hit(off);
        if (is_ignored(c) && !is_logical_break(c)) || is_contextual || is_instruction {
            continue;
        }
        emit(&mut out, &mut offsets, c, off);
    }
    finish("obfuscated-instruction", out, offsets)
}

/// `compact_letter_view`.
fn compact_view(t: &[char]) -> SecurityTextView {
    let mut contextual = Marks::new(contextual_ignorable_offsets(t));
    let mut compact = Marks::new(compact_gap_offsets(t));
    let mut spacing = Marks::new(letter_spacing_gap_offsets(t));
    let mut instruction = Marks::new(instruction_gap_offsets(t));
    let (mut out, mut offsets) = (String::new(), Vec::new());
    for (off, &c) in t.iter().enumerate() {
        let flags = [
            contextual.hit(off),
            compact.hit(off),
            spacing.hit(off),
            instruction.hit(off),
        ];
        if is_ignored(c) || c == '\u{fffd}' || flags.iter().any(|&f| f) {
            continue;
        }
        emit(&mut out, &mut offsets, c, off);
    }
    finish("compact", out, offsets)
}

/// `normalized_security_view` as a plain text (used by the prohibition grammar).
#[must_use]
pub fn normalized_security_view(text: &str) -> SecurityTextView {
    let t: Vec<char> = text.chars().collect();
    normalized_view(&t)
}

/// The derived views of `text` (everything but the raw view), in `security_text_views` order.
#[must_use]
pub fn derived_views(text: &str) -> Vec<SecurityTextView> {
    let t: Vec<char> = text.chars().collect();
    let has_spacing = !letter_spacing_runs(&t, true).is_empty();
    let has_obfuscated = !instruction_matches(&t, true).is_empty();
    if text.is_ascii() && !t.iter().any(|&c| is_ignored(c)) && !has_spacing && !has_obfuscated {
        return Vec::new();
    }
    // `_requires_normalized_security_view` is only a shortcut: whenever it says no, the normalized
    // view equals the raw text and would be dropped as a duplicate below.
    let mut candidates = vec![normalized_view(&t)];
    if t.contains(&'\u{fffd}')
        || !compact_gap_offsets(&t).is_empty()
        || has_spacing
        || has_obfuscated
    {
        candidates.push(compact_view(&t));
    }
    if has_obfuscated {
        candidates.push(obfuscated_view(&t));
    }
    let mut unique: Vec<SecurityTextView> = Vec::new();
    for view in candidates {
        if view.text != text && unique.iter().all(|u| u.text != view.text) {
            unique.push(view);
        }
    }
    unique
}

/// `security_text_views`: the raw view followed by the distinct derived views.
#[must_use]
pub fn security_text_views(text: &str) -> Vec<SecurityTextView> {
    let mut all = vec![SecurityTextView {
        name: "raw",
        text: text.to_owned(),
        source_offsets: None,
    }];
    all.extend(derived_views(text));
    all
}

/// The derived views of one file together with the source characters they point into.
#[derive(Debug)]
pub struct FileViews {
    pub source_chars: Vec<char>,
    pub views: Vec<SecurityTextView>,
}

/// Which view the running module is scanning (`static_runner._ACTIVE_SECURITY_VIEW`).
#[derive(Clone)]
enum Active {
    Raw,
    Derived(Rc<FileViews>, usize),
}

thread_local! {
    static ACTIVE: RefCell<Option<Active>> = const { RefCell::new(None) };
}

/// Restores the previously active view when dropped.
pub struct ActiveGuard(Option<Active>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let previous = self.0.take();
        ACTIVE.with(|a| *a.borrow_mut() = previous);
    }
}

fn activate(active: Active) -> ActiveGuard {
    ActiveGuard(ACTIVE.with(|a| a.borrow_mut().replace(active)))
}

/// Marks the raw view as the one being scanned.
#[must_use]
pub fn activate_raw() -> ActiveGuard {
    activate(Active::Raw)
}

/// Marks derived view `index` of `file` as the one being scanned.
#[must_use]
pub fn activate_derived(file: &Rc<FileViews>, index: usize) -> ActiveGuard {
    activate(Active::Derived(Rc::clone(file), index))
}

/// `security_view_match_is_literal`: whether bytes `start..end` of the view being scanned are
/// unchanged from the source text (always true on the raw view).
#[must_use]
pub fn match_is_literal(text: &str, start: usize, end: usize) -> bool {
    let Some(active) = ACTIVE.with(|a| a.borrow().clone()) else {
        return false;
    };
    if start >= end
        || end > text.len()
        || !text.is_char_boundary(start)
        || !text.is_char_boundary(end)
    {
        return false;
    }
    let Active::Derived(file, index) = active else {
        return true;
    };
    let Some(offsets) = file
        .views
        .get(index)
        .and_then(|v| v.source_offsets.as_ref())
    else {
        return true;
    };
    let first = text[..start].chars().count();
    let derived = text[start..end].chars();
    let mut previous: Option<usize> = None;
    for (i, c) in derived.enumerate() {
        let Some(&src) = offsets.get(first + i) else {
            return false;
        };
        let src = src as usize;
        if previous.is_some_and(|p| src != p + 1) || file.source_chars.get(src) != Some(&c) {
            return false;
        }
        previous = Some(src);
    }
    true
}
