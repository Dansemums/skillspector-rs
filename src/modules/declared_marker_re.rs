//! Constants, regexes and the char-indexed text view behind [`super::declared_marker`].

use crate::matcher::Pat;
use std::sync::LazyLock;

pub(super) const MAX_MARKER_LENGTH: usize = 16;
pub(super) const MAX_MARKER_SCOPE_CHARS: usize = 768;
pub(super) const MAX_LOOKAHEAD: usize = 8192;
pub(super) const MAX_PAYLOAD_CHARS: usize = 700;
pub(super) const MAX_ACTIVE_DIRECTIVES: usize = 8;
pub(super) const MAX_MARKER_REMOVALS: usize = 64;
pub(super) const MAX_NEGATION_PREFIX: usize = 80;
pub(super) const MAX_HEADER: usize = 256;
pub(super) const SPACING: usize = 8;

pub(super) const OPEN_QUOTES: &str = "'\"`\u{2018}\u{201c}";

pub(super) fn close_of(c: char) -> Option<char> {
    match c {
        '\'' | '"' | '`' => Some(c),
        '\u{2018}' => Some('\u{2019}'),
        '\u{201c}' => Some('\u{201d}'),
        _ => None,
    }
}

pub(super) fn is_quote(c: char) -> bool {
    matches!(
        c,
        '\'' | '"' | '`' | '\u{2018}' | '\u{2019}' | '\u{201c}' | '\u{201d}'
    )
}

pub(super) fn removal_verbs(gap: usize) -> String {
    format!(
        "remove|removing|strip|stripping|delete|deleting|drop|dropping|omit|omitting|erase|erasing|ignore|ignoring|excise|excising|take[ \\t]{{0,{gap}}}out|taking[ \\t]{{0,{gap}}}out"
    )
}

pub(super) const REPLACEMENT_VERBS: &str = "replace|replacing|substitute|substituting";

pub(super) fn prefix() -> String {
    format!(
        r"[ \t]{{1,{SPACING}}}(?:(?:(?:the|this|both|all|every|each|literal|declared|specified|following|next|invisible)[ \t]{{1,{SPACING}}}){{0,3}}(?:(?:markers?|tokens?|substrings?|strings?|text|characters?|occurrences?)(?:[ \t]{{1,{SPACING}}}of)?[ \t]{{1,{SPACING}}})?)?"
    )
}

pub(super) fn pat(src: &str) -> Pat {
    #[cfg(test)]
    assert!(
        Pat::try_new(src, "i").is_ok(),
        "pattern does not compile: {src}"
    );
    Pat::new(src, "i")
}

pub(super) fn full(src: &str) -> Pat {
    pat(&format!(r"\A(?:{src})\z"))
}

pub(super) struct Re {
    pub(super) prefilter: Pat,
    pub(super) passive_prefilter: Pat,
    pub(super) quoted_start: Pat,
    pub(super) unsupported_start: Pat,
    pub(super) passive_start: Pat,
    pub(super) passive_suffix: Pat,
    pub(super) empty_start: Pat,
    pub(super) empty_suffix: Pat,
    pub(super) fallback_verbs_full: Pat,
    pub(super) unambiguous: Pat,
    pub(super) unambiguous_full: Pat,
    pub(super) contextual: Pat,
    pub(super) paste: Pat,
    pub(super) payload_prefix: Pat,
    pub(super) payload_prefix_full: Pat,
    pub(super) explicit_prefix: Pat,
    pub(super) paste_target: Pat,
    pub(super) removal_prefix_full: Pat,
    pub(super) copy_prefix_full: Pat,
    pub(super) anaphoric: Pat,
    pub(super) shell_wrapper_full: Pat,
    pub(super) decoded_token: Pat,
    pub(super) affirmative: Pat,
    pub(super) negated: Pat,
    pub(super) forward_ref: Pat,
    pub(super) after_re: Pat,
    pub(super) gap_full: Pat,
    pub(super) then_re: Pat,
}

pub(super) static RE: LazyLock<Re> = LazyLock::new(|| {
    let removal = removal_verbs(SPACING);
    let fallback = removal_verbs(MAX_HEADER);
    let pre = prefix();
    let q = format!("[{OPEN_QUOTES}]");
    let payload_prefix = r"[ \t]*(?:(?:exactly|verbatim|literally|directly|immediately)[ \t]+){0,2}(?:(?:the|this|following|next)[ \t]+)?(?:(?:command|instruction|payload|request|shell[ \t]+command)\b[ \t]*)?(?::|=)?[ \t]*";
    let anaphoric_action = r"\b(?P<action>run|execute|invoke|issue|launch|perform|call|eval|type|submit|enter|paste)\b[ \t]+(?:it|this|that|(?:the|this|that)[ \t]+(?:result|command|instruction|payload))\b";
    Re {
        prefilter: pat(&format!(r"\b(?:{fallback}|{REPLACEMENT_VERBS})\b")),
        passive_prefilter: pat(
            r"\b(?:with|once|after)\b[^.!?\n]{0,64}\b(?:removed|stripped|deleted|dropped|omitted|erased|ignored|excised|taken[ \t]+out)\b",
        ),
        quoted_start: pat(&format!(r"\b(?:{removal})\b{pre}(?P<quote>{q})")),
        unsupported_start: pat(&format!(
            r"\b(?:{fallback})\b[^.!?\n]{{0,{MAX_HEADER}}}?(?P<quote>{q})"
        )),
        passive_start: pat(&format!(r"\b(?:with|once|after){pre}(?P<quote>{q})")),
        passive_suffix: pat(&format!(
            r"[ \t]{{1,{SPACING}}}(?:(?:the[ \t]+)?(?:markers?|tokens?|substrings?|strings?|text|characters?)[ \t]{{1,{SPACING}}})?(?:is[ \t]+)?(?:removed|stripped|deleted|dropped|omitted|erased|ignored|excised|taken[ \t]+out)\b"
        )),
        empty_start: pat(&format!(r"\b(?:{REPLACEMENT_VERBS})\b{pre}(?P<quote>{q})")),
        empty_suffix: pat(
            r#"[ \t]{1,32}with[ \t]+(?:(?:an?|the)[ \t]+)?(?:nothing\b|empty[ \t]+(?:string|text|value)\b|''|"")"#,
        ),
        fallback_verbs_full: full(&fallback),
        unambiguous: pat(r"\b(?:run|execute|invoke|issue|launch|perform|carry[ \t]+out)\b"),
        unambiguous_full: full(r"\b(?:run|execute|invoke|issue|launch|perform|carry[ \t]+out)\b"),
        contextual: pat(r"\b(?:call|eval|type|submit|enter)\b"),
        paste: pat(r"\bpaste\b"),
        payload_prefix: pat(payload_prefix),
        payload_prefix_full: full(payload_prefix),
        explicit_prefix: pat(
            r"[ \t]*(?:(?:the|this|following|next)[ \t]+)?(?:command|instruction|payload|request|shell[ \t]+command)\b[ \t]*(?::|=)?[ \t]*",
        ),
        paste_target: pat(
            r"[ \t]+into[ \t]+(?:(?:the|a)[ \t]+)?(?:terminal|shell|console|command[ \t]+prompt|bash|zsh|powershell|cmd(?:\.exe)?)\b",
        ),
        removal_prefix_full: full(
            r"[ \t]*(?:from|in)[ \t]+(?:(?:the|this|following|next)[ \t]+){0,2}(?:(?:command|instruction|payload|request)[ \t]*)?(?::|=)?[ \t]*",
        ),
        copy_prefix_full: full(
            r"[ \t]*(?:,|;)?[ \t]*(?:then[ \t]+)?copy[ \t]+(?:(?:the|this|following|next)[ \t]+)?(?:(?:command|instruction|payload|request)[ \t]*)?(?::|=)?[ \t]*",
        ),
        anaphoric: pat(anaphoric_action),
        shell_wrapper_full: full(r"(?:sudo|command|nohup)[ \t]+[^\s]*$"),
        decoded_token: pat(
            r"\b(?:run|execute|invoke|issue|launch|perform|call|eval|type|submit|enter|curl|rm|del|erase|sudo|bash|zsh|powershell)\b",
        ),
        affirmative: pat(
            r"(?:(?:\bdo[ \t]+not|\bdon't|\bnever)[ \t,]+(?:forget|fail|hesitate|neglect)(?:[ \t]+at[ \t]+all)?[ \t]+to(?:[ \t]+(?!(?:never|not|don't)\b)\w+){0,2}|(?:\bdo[ \t]+not|\bdon't|\bnever)[ \t,]+forget(?:[ \t]+that)?(?:[ \t]+you)?[ \t]+(?:must|should|shall|will|need[ \t]+to)|\bnot[ \t]+(?:only|just)(?:[ \t]+\w+){0,2}|(?:\bdo[ \t]+not|\bdon't|\bnever|\bavoid)[ \t]+(?:only|just|merely)|(?:\bdo[ \t]+not|\bdon't|\bnever)[ \t]+stop[ \t]+at)[ \t]*$",
        ),
        negated: pat(
            r"(?:(?:\bdo[ \t]+not|\bdon't|\bnever|\bavoid|\bmust[ \t]+not)(?:(?:[ \t]*,[ \t]*|[ \t]+)(?!(?:so|but|yet|then|therefore|however|instead)\b)\w+){0,8}[ \t,]*|\bnot[ \t,]*|\bnot(?:[ \t]*,[ \t]*|[ \t]+)(?:ever|directly|immediately|actually)[ \t,]*|\bnot(?:[ \t]*,[ \t]*|[ \t]+)(?:under|in)(?:[ \t]*,[ \t]*|[ \t]+)(?:any|all|these|those)(?:(?:[ \t]*,[ \t]*|[ \t]+)\w+){0,4}[ \t,]*|\bunder(?:[ \t]*,[ \t]*|[ \t]+)no(?:[ \t]*,[ \t]*|[ \t]+)(?:circumstances?|conditions?)[ \t,]*|\bin(?:[ \t]*,[ \t]*|[ \t]+)no(?:[ \t]*,[ \t]*|[ \t]+)case[ \t,]*|\brefrain(?:ing)?[ \t]+from[ \t]*)$",
        ),
        forward_ref: pat(
            r"\b(?:next|following|coming)[ \t]+(?:command|instruction|prompt|payload|request)\b",
        ),
        after_re: pat(r"\bafter(?:[ \t]+(?:this|that|it|the[ \t]+result))?[ \t]+$"),
        gap_full: full(r"[ \t]+(?:[A-Za-z-]+[ \t]+){0,2}"),
        then_re: pat(r"then\b[ \t]*"),
    }
});

/// A char-indexed view of the text with regex helpers (regexes run on bytes).
pub(super) struct Text {
    pub(super) s: String,
    pub(super) c: Vec<char>,
    pub(super) c2b: Vec<usize>,
}

#[derive(Clone, Debug)]
pub(super) struct M {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) groups: Vec<Option<(usize, usize)>>,
}

impl Text {
    pub(super) fn new(s: &str) -> Self {
        let mut c2b: Vec<usize> = s.char_indices().map(|(b, _)| b).collect();
        c2b.push(s.len());
        Self {
            s: s.to_owned(),
            c: s.chars().collect(),
            c2b,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.c.len()
    }

    pub(super) fn b2c(&self, b: usize) -> usize {
        self.c2b.partition_point(|&x| x < b)
    }

    pub(super) fn slice(&self, a: usize, b: usize) -> String {
        self.c[a.min(self.c.len())..b.min(self.c.len()).max(a.min(self.c.len()))]
            .iter()
            .collect()
    }

    pub(super) fn conv(&self, h: &crate::matcher::Hit) -> M {
        M {
            start: self.b2c(h.start),
            end: self.b2c(h.end),
            groups: h
                .groups
                .iter()
                .map(|g| g.map(|(a, b)| (self.b2c(a), self.b2c(b))))
                .collect(),
        }
    }

    pub(super) fn finditer(&self, p: &Pat, start: usize, end: usize) -> Vec<M> {
        let (s, e) = (
            self.c2b[start.min(self.len())],
            self.c2b[end.min(self.len())],
        );
        p.find_in(&self.s, s, e)
            .iter()
            .map(|h| self.conv(h))
            .collect()
    }

    pub(super) fn search(&self, p: &Pat, start: usize, end: usize) -> Option<M> {
        self.finditer(p, start, end).into_iter().next()
    }

    pub(super) fn match_at(&self, p: &Pat, pos: usize, end: usize) -> Option<M> {
        self.search(p, pos, end).filter(|m| m.start == pos)
    }

    pub(super) fn full(&self, p: &Pat, s: &str) -> bool {
        !p.find_iter(s).is_empty()
    }

    pub(super) fn find_seq(&self, needle: &[char], a: usize, b: usize) -> Option<usize> {
        let b = b.min(self.len());
        if needle.is_empty() {
            return (a <= b).then_some(a);
        }
        (a..=b.checked_sub(needle.len())?).find(|&i| self.c[i..i + needle.len()] == *needle)
    }

    pub(super) fn contains(&self, needle: &[char], a: usize, b: usize) -> bool {
        self.find_seq(needle, a, b).is_some()
    }
}
