//! The `complete_context=True` half of `_markdown_shell_text`: pairing of inline-code backtick
//! runs, prose apostrophes, and the shell-parse pass that keeps an apostrophe inside an earlier
//! shell word. Char indices throughout.

use super::destructive::parse_shell_command_word;
use crate::matcher::Pat;
use std::collections::BTreeSet;
use std::sync::LazyLock;

/// Compiles a Python-syntax pattern; under test a pattern that fails to compile panics.
fn pat(src: &str, flags: &str) -> Pat {
    #[cfg(test)]
    assert!(
        Pat::try_new(src, flags).is_ok(),
        "pattern does not compile: {src}"
    );
    Pat::new(src, flags)
}

static CONTRACTION: LazyLock<Pat> = LazyLock::new(|| {
    pat(
        r"^(?:The|This|That|These|Those|It|They|We|You|I|A|An)[ \t]+[A-Za-z \t,]*\b(?:doesn|isn|aren|wasn|weren|don|didn|hasn|haven|hadn|can|couldn|shouldn|wouldn|won|mustn)(?P<apostrophe>')t\b[A-Za-z \t,]*[.!?]\z",
        "i",
    )
});
static WORD_APOSTROPHE: LazyLock<Pat> = LazyLock::new(|| {
    pat(
        r"(?<![\w'/.~-])[A-Za-z]++(?P<apostrophe>')(?:s|t|d|m|re|ve|ll)(?![\w'/])",
        "i",
    )
});

/// Char index inside `s` of the byte offset `byte`.
fn char_at(s: &str, byte: usize) -> usize {
    s[..byte].chars().count()
}

/// Pending backtick runs and the prose apostrophes found so far.
pub(super) struct Inline {
    complete: bool,
    word_apostrophes: bool,
    runs: Vec<(usize, usize)>,
    prose: BTreeSet<usize>,
}

impl Inline {
    pub(super) fn new(complete: bool, word_apostrophes: bool) -> Self {
        Self {
            complete,
            word_apostrophes,
            runs: Vec::new(),
            prose: BTreeSet::new(),
        }
    }

    pub(super) fn has_runs(&self) -> bool {
        !self.runs.is_empty()
    }

    /// Records the backtick runs of `text[from..to]` at absolute offset `base + index`.
    pub(super) fn add_runs(&mut self, text: &[char], from: usize, to: usize, base: usize) {
        let mut i = from;
        while i < to {
            if text[i] == '`' {
                let start = i;
                while i < to && text[i] == '`' {
                    i += 1;
                }
                self.runs.push((base + start, base + i));
            } else {
                i += 1;
            }
        }
    }

    /// `mask_inline_delimiters`: pair equal-length runs and blank both delimiters.
    pub(super) fn mask(&mut self, content: &[char], output: &mut [char]) {
        if !self.complete {
            self.runs.clear();
            return;
        }
        let runs = std::mem::take(&mut self.runs);
        let mut next_by_length: std::collections::HashMap<usize, usize> = Default::default();
        let mut closing: std::collections::HashMap<usize, usize> = Default::default();
        for index in (0..runs.len()).rev() {
            let length = runs[index].1 - runs[index].0;
            if let Some(&n) = next_by_length.get(&length) {
                closing.insert(index, n);
            }
            next_by_length.insert(length, index);
        }
        let mut index = 0;
        while index < runs.len() {
            let (start, end) = runs[index];
            let escapes = content[..start]
                .iter()
                .rev()
                .take_while(|&&c| c == '\\')
                .count();
            let Some(&close) = closing.get(&index).filter(|_| escapes % 2 == 0) else {
                index += 1;
                continue;
            };
            let (cs, ce) = runs[close];
            output[start..end].fill(' ');
            output[cs..ce].fill(' ');
            index = close + 1;
        }
    }

    /// The prose-apostrophe rules for one paragraph line (`leading` begins at `start`).
    pub(super) fn note_prose(
        &mut self,
        leading: &[char],
        start: usize,
        heading: bool,
        starts_shell_line: bool,
    ) {
        if !self.complete || heading || self.has_runs() {
            return;
        }
        let s: String = leading.iter().collect();
        if leading.len() <= 512
            && let Some(h) = CONTRACTION.find_iter(&s).first()
            && let Some((a, _)) = h.groups.get(1).copied().flatten()
        {
            self.prose.insert(start + char_at(&s, a));
        } else if self.word_apostrophes
            && s.contains('\'')
            && !s.contains(['$', '`', '\\', '"'])
            && starts_shell_line
        {
            let found: Vec<usize> = WORD_APOSTROPHE
                .find_iter(&s)
                .iter()
                .filter_map(|h| h.groups.get(1).copied().flatten())
                .map(|(a, _)| start + char_at(&s, a))
                .collect();
            if found.len() == leading.iter().filter(|&&c| c == '\'').count() {
                self.prose.extend(found);
            }
        }
    }

    /// Final projection: masks the recorded apostrophes unless an earlier shell word owns them.
    pub(super) fn finish(self, mut output: Vec<char>) -> Vec<char> {
        let Some(&last) = self.prose.iter().next_back() else {
            return output;
        };
        let projected = output.clone();
        let mut cursor = 0;
        while cursor <= last && cursor < projected.len() {
            if self.prose.contains(&cursor) {
                output[cursor] = ' ';
            } else if "'\"`$\\".contains(projected[cursor]) {
                match parse_shell_command_word(&projected, cursor, None) {
                    Ok(Some(w)) if !w.limited => {
                        cursor = (cursor + 1).max(w.end);
                        continue;
                    }
                    _ => break,
                }
            }
            cursor += 1;
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regexes_compile_and_match() {
        let s = "They don't need it.";
        assert!(!CONTRACTION.find_iter(s).is_empty());
        assert_eq!(WORD_APOSTROPHE.find_iter("the reference's end").len(), 1);
        assert!(WORD_APOSTROPHE.find_iter("r'm'").is_empty());
    }

    #[test]
    fn equal_length_runs_pair() {
        let content: Vec<char> = "a `x` b".chars().collect();
        let mut out = content.clone();
        let mut inline = Inline::new(true, false);
        inline.add_runs(&content, 0, content.len(), 0);
        inline.mask(&content, &mut out);
        assert_eq!(out.iter().collect::<String>(), "a  x  b");
    }
}
