//! Context helpers of `static_patterns_privilege_escalation.py`: line metadata, markdown fences,
//! the bare credential-store noun veto, ignore-file entries, the read-only `/etc/passwd` mount and
//! negated safety constraints. All offsets are byte offsets; Python's character limits (80, 4096)
//! are converted with [`back_chars`] / [`fwd_chars`].

use crate::matcher::{Hit, Pat};
use crate::skill::FileType;
use crate::text::line_breaks;
use crate::unicode::is_space;
use std::sync::LazyLock;

/// `_MAX_CONTEXTUAL_CLASSIFICATION_LINE_CHARS`.
pub const MAX_LINE_CHARS: usize = 4_096;

/// The verbs of `_PE3_CREDENTIAL_STORE_AFTER_VERBS`.
macro_rules! store_verbs {
    () => {
        concat!(
            r"access(?:es|ed|ing)?|copy|copies|copied|copying|dump(?:s|ed|ing)?|",
            r"exfiltrat(?:e|es|ed|ing|ion)|export(?:s|ed|ing)?|extract(?:s|ed|ing)?|",
            r"fetch(?:es|ed|ing)?|get(?:s|ting)?|grab(?:s|bed|bing)?|harvest(?:s|ed|ing)?|",
            r"load(?:s|ed|ing)?|lookup|obtain(?:s|ed|ing)?|open(?:s|ed|ing)?|pull(?:s|ed|ing)?|",
            r"query|queries|queried|querying|read(?:s|ing)?|retrieve(?:s|d|ing)?|scrape(?:s|d|ing)?|",
            r"send(?:s|ing|sent)?|steal(?:s|ing|stolen)?|transmit(?:s|ted|ting)?|",
            r"unlock(?:s|ed|ing)?|upload(?:s|ed|ing)?|save(?:s|d|ing)?|put(?:s|ting)?|",
            r"write|writes|wrote|writing|written|",
            r"store(?:s|d|ing)?|remove(?:s|d|ing)?|delete(?:s|d|ing)?|clear(?:s|ed|ing)?|",
            r"update(?:s|d|ing)?|add(?:s|ed|ing)?|set(?:s|ting)?|use(?:s|ing)?"
        )
    };
}

macro_rules! patterns {
    ($( $name:ident = ($src:expr, $flags:expr); )*) => {
        $( static $name: LazyLock<Pat> = LazyLock::new(|| Pat::new($src, $flags)); )*
        /// (source, flags) of every pattern in this file, so a test can compile them all.
        #[cfg(test)]
        pub const SOURCES: &[(&str, &str)] = &[ $( ($src, $flags), )* ];
    };
}

patterns! {
    READ_ONLY_PASSWD_VOLUME = (
        concat!(
            r"\b(?:docker|podman)\s+run\b",
            r"(?:(?:\\\r?\n)|[^\n;&|]){0,1000}?",
            r"(?:-v|--volume)(?:=|\s+)",
            r#"(?P<quote>['"]?)"#,
            r"(?P<source>/etc/passwd):(?P<target>/etc/passwd):ro",
            r"(?P=quote)(?=$|[\s\\])"
        ),
        "im"
    );
    IGNORE_FILE_ENTRY = (
        r#"\A[ \t]*([^\s#!|;&<>()`'"$][^\s|;&<>()`'"$]*)[ \t]*\z"#,
        ""
    );
    IGNORE_HOST_PATH = (
        r"^(?:~|[A-Za-z]:|/(?i:etc|home|users|root)(?:/|$))|(?:^|[/\\])\.\.(?:[/\\]|$)",
        ""
    );
    SEP_PUNCT = (r"[.,;:](?=\s|$)", "");
    SEP_WORDS = (r"\b(?:and|then|but|or)\b", "");
    STORE_WORD_ANY = (r"\b(?:keychain|keyring|gnome-keyring)\b", "i");
    STORE_OPERATION = (
        concat!(
            r"\b(?:", store_verbs!(), r")\b",
            r"(?:\s+(?:the|a|an|my|your|local|credentials?|secrets?|passwords?|",
            r"tokens?|keys?|contents?|system|from|to|for|in|on)){0,8}\s*$"
        ),
        "i"
    );
    STORE_OPERATION_AFTER = (
        concat!(
            r"\A\s*(?:(?:and|then|but)\s+)?(?:(?:is|was|can|will|should|must)\s+)?",
            r"(?:used\s+(?:to|for)\s+)?",
            r"(?:", store_verbs!(), r")\b"
        ),
        "i"
    );
    STORE_DOCUMENTATION = (
        r"\A\s+(?:api\s+documentation|cli\s+reference|access\s+policy|access\s+controls|lookup\s+table|query\s+syntax|export\s+format)\b",
        "i"
    );
    STORE_DOC_TAIL_EXPLANATORY = (r"\A\s+(?:for|about|with|on|that|which|of)\b", "i");
    BENIGN_READING_PURPOSE = (
        r"\A\s+(?:is\s+)?(?:solely\s+for\s+reading|for\s+reading(?:\s+purposes?)?\s+only|only\s+for\s+reading(?:\s+purposes?)?)\s*\z",
        "i"
    );
    STORE_CALL = (
        r"\A\s*[.]\s*(?:add|clear|delete|get|remove|save|set|store|update|write)\w*\s*(?=\()",
        "i"
    );
    STORE_CLI = (r"\b(?:security\s+)?find-generic-password\b([^.;:\n]*)$", "i");
    CLI_BLOCKER = (r"\b(?:and|then|document|describe|reference|the)\b", "i");
    WORD_KEYCHAIN = (r"\bkeychain\b", "i");
    WORD_KEYRING = (r"\bkeyring\b", "i");
    WORD_GNOME_KEYRING = (r"\bgnome-keyring\b", "i");
}

const STORE_WORDS: [&str; 3] = ["keychain", "keyring", "gnome-keyring"];

/// Byte offset `n` characters before `pos` (clamped to the start of the text).
#[must_use]
pub fn back_chars(text: &str, pos: usize, n: usize) -> usize {
    if n == 0 {
        return pos;
    }
    text[..pos]
        .char_indices()
        .rev()
        .take(n)
        .last()
        .map_or(pos, |(i, _)| i)
}

/// Byte offset `n` characters after `pos` (clamped to the end of the text).
#[must_use]
pub fn fwd_chars(text: &str, pos: usize, n: usize) -> usize {
    text[pos..]
        .char_indices()
        .nth(n)
        .map_or(text.len(), |(i, _)| pos + i)
}

/// The first `n` characters of `s`.
#[must_use]
pub fn cut_chars(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

/// `_source_line_metadata`: start and end of every logical line.
#[derive(Debug)]
pub struct Lines {
    pub starts: Vec<usize>,
    pub ends: Vec<usize>,
}

impl Lines {
    #[must_use]
    pub fn new(text: &str) -> Self {
        let mut starts = vec![0];
        let mut ends = Vec::new();
        for (s, e) in line_breaks(text) {
            ends.push(s);
            starts.push(e);
        }
        ends.push(text.len());
        Self { starts, ends }
    }

    /// Zero-based index of the line holding byte `pos`.
    #[must_use]
    pub fn index(&self, pos: usize) -> usize {
        self.starts.partition_point(|&s| s <= pos).saturating_sub(1)
    }

    /// `_source_line_bounds`: `(start, end)` of the line holding byte `pos`.
    #[must_use]
    pub fn bounds(&self, pos: usize) -> (usize, usize) {
        let i = self.index(pos);
        (self.starts[i], self.ends[i])
    }
}

/// The first match of `p` in `s`.
pub(super) fn first(p: &Pat, s: &str) -> Option<Hit> {
    p.find_iter(s).into_iter().next()
}

pub(super) fn is_match(p: &Pat, s: &str) -> bool {
    first(p, s).is_some()
}

const fn is_line_break_char(c: char) -> bool {
    matches!(
        c,
        '\r' | '\n' | '\x0b' | '\x0c' | '\x1c'..='\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// A fence line `[ ]{0,3}` + a run of at least three of one fence character; the rest of the line
/// follows. `None` when the line does not start that way.
fn fence_run(line: &str) -> Option<(char, usize, &str)> {
    let spaces = line.bytes().take_while(|&b| b == b' ').count().min(3);
    let rest = &line[spaces..];
    let c = rest.chars().next().filter(|c| matches!(c, '`' | '~'))?;
    let run = rest.chars().take_while(|&x| x == c).count();
    (run >= 3).then(|| (c, run, &rest[run..]))
}

/// `MARKDOWN_FENCE_OPEN` (backtick fences cannot have a backtick in their info string).
fn fence_open(line: &str) -> Option<(char, usize)> {
    let (c, run, tail) = fence_run(line)?;
    (c == '~' || !tail.contains('`')).then_some((c, run))
}

/// `MARKDOWN_FENCE_CLOSE`.
fn fence_close(line: &str) -> Option<(char, usize)> {
    let (c, run, tail) = fence_run(line)?;
    tail.chars()
        .all(|x| x == ' ' || x == '\t')
        .then_some((c, run))
}

/// `_markdown_fence_ranges`: byte ranges of fenced code bodies.
#[must_use]
pub fn markdown_fence_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut active: Option<(char, usize, usize)> = None;
    let mut start = 0;
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (_, e) in line_breaks(text) {
        spans.push((start, e));
        start = e;
    }
    if start < text.len() {
        spans.push((start, text.len()));
    }
    for (s, e) in spans {
        let stripped = text[s..e].trim_end_matches(is_line_break_char);
        if let Some((c, len, _)) = active {
            if fence_close(stripped).is_some_and(|(cc, cl)| cc == c && cl >= len) {
                ranges.push((active.map_or(0, |a| a.2), s));
                active = None;
            }
        } else if let Some((c, len)) = fence_open(stripped) {
            active = Some((c, len, e));
        }
    }
    if let Some((_, _, body)) = active {
        ranges.push((body, text.len()));
    }
    ranges
}

fn store_word_pat(word: &str) -> &'static Pat {
    match word {
        "keychain" => &WORD_KEYCHAIN,
        "keyring" => &WORD_KEYRING,
        _ => &WORD_GNOME_KEYRING,
    }
}

/// `_cli_targets_credential_store_noun`: CLI evidence only when no other store noun was named.
fn cli_targets_noun(before_noun: &str, noun: &str) -> bool {
    let s = format!("{before_noun}{noun}");
    let Some(h) = first(&STORE_CLI, &s) else {
        return false;
    };
    let args = h.group(&s, 1).unwrap_or("").trim_end_matches(is_space);
    let noun_lower = noun.to_lowercase();
    if !args.to_lowercase().ends_with(&noun_lower) {
        return false;
    }
    let keep = args.chars().count().saturating_sub(noun.chars().count());
    let args_before = cut_chars(args, keep).trim_end_matches(is_space);
    if is_match(&CLI_BLOCKER, args_before) {
        return false;
    }
    !STORE_WORDS
        .iter()
        .any(|w| *w != noun_lower && is_match(store_word_pat(w), args))
}

/// The clause of `relation` around the noun: `(before_noun, after_noun)`.
fn noun_clause(relation: &str, noun_off: usize, noun_len: usize) -> (String, String) {
    let before = &relation[..noun_off];
    let mut seps: Vec<(usize, usize)> = SEP_PUNCT
        .find_iter(before)
        .iter()
        .map(|h| (h.start, 1))
        .collect();
    seps.extend(
        SEP_WORDS
            .find_iter(before)
            .iter()
            .map(|h| (h.start, h.end - h.start)),
    );
    let (clause_start, prefix_len) = seps
        .into_iter()
        .max()
        .map_or((None, 0), |(s, l)| (Some(s), l));
    let after_relation = &relation[noun_off..];
    let mut after: Vec<usize> = SEP_PUNCT
        .find_iter(after_relation)
        .iter()
        .map(|h| h.start)
        .collect();
    for sep in SEP_WORDS.find_iter(after_relation) {
        if is_match(&STORE_WORD_ANY, &after_relation[sep.end..]) {
            after.push(sep.start);
        }
    }
    let clause_end = after
        .into_iter()
        .min()
        .map_or(relation.len(), |m| noun_off + m);
    let cso = clause_start.map_or(0, |s| s + prefix_len);
    let clause = relation.get(cso..clause_end).unwrap_or("");
    let noun_start = noun_off.saturating_sub(cso);
    let before_noun = clause.get(..noun_start).unwrap_or("").to_owned();
    let after_noun = clause.get(noun_start + noun_len..).unwrap_or("").to_owned();
    (before_noun, after_noun)
}

/// `_is_bare_credential_store_noun`: suppress only descriptive credential-store nouns in prose.
#[must_use]
pub fn is_bare_credential_store_noun(
    content: &str,
    m: &Hit,
    ft: FileType,
    fences: &[(usize, usize)],
    lines: &Lines,
) -> bool {
    if !matches!(ft, FileType::Markdown | FileType::Text) {
        return false;
    }
    let noun = m.text(content);
    if !STORE_WORDS.contains(&noun.to_lowercase().as_str()) {
        return false;
    }
    if fences.iter().any(|&(s, e)| s <= m.start && m.start < e) {
        return false;
    }
    let (line_start, line_end) = lines.bounds(m.start);
    let rel_start = line_start.max(back_chars(content, m.start, 80));
    let rel_end = line_end
        .min(fwd_chars(content, m.end, 80))
        .max(m.end.min(line_end));
    let relation = &content[rel_start..rel_end.max(rel_start)];
    let (before_noun, after_noun) = noun_clause(relation, m.start - rel_start, m.end - m.start);
    let operation = is_match(&STORE_OPERATION, &before_noun);
    let operation_after = is_match(&STORE_OPERATION_AFTER, &after_noun);
    let call = is_match(&STORE_CALL, &after_noun);
    let cli = cli_targets_noun(&before_noun, noun);
    if let Some(doc) = first(&STORE_DOCUMENTATION, &after_noun) {
        let tail = &after_noun[doc.end..];
        if !is_match(&STORE_OPERATION_AFTER, tail) || is_match(&STORE_DOC_TAIL_EXPLANATORY, tail) {
            return true;
        }
    }
    if is_match(&BENIGN_READING_PURPOSE, &after_noun) && !operation && !call && !cli {
        return true;
    }
    !(operation || operation_after || call || cli)
}

/// `_is_ignore_pattern_file`: a gitignore-syntax path-exclusion list.
#[must_use]
pub fn is_ignore_pattern_file(path: &str) -> bool {
    const NAMES: [&str; 16] = [
        ".aiderignore",
        ".cursorignore",
        ".cursorindexingignore",
        ".dockerignore",
        ".eslintignore",
        ".fdignore",
        ".gcloudignore",
        ".geminiignore",
        ".gitignore",
        ".helmignore",
        ".ignore",
        ".npmignore",
        ".prettierignore",
        ".rgignore",
        ".stylelintignore",
        ".vercelignore",
    ];
    let norm = path.replace('\\', "/");
    let base = norm.rsplit('/').next().unwrap_or(&norm);
    NAMES.contains(&base) || base.ends_with(".dockerignore")
}

/// `_is_ignore_file_exclusion_entry`: the match is the one pattern token on its own ignore-file line.
#[must_use]
pub fn is_ignore_file_exclusion_entry(content: &str, m: &Hit) -> bool {
    let start = m.start;
    let search_from = back_chars(content, start, MAX_LINE_CHARS);
    let line_start = content[search_from..start]
        .rfind('\n')
        .map(|p| search_from + p + 1);
    let line_start = match line_start {
        Some(s) => s,
        None if search_from > 0 => return false,
        None => 0,
    };
    let window_end = fwd_chars(content, start, MAX_LINE_CHARS + 1);
    let mut line_end = content[start..window_end]
        .find('\n')
        .map_or(content.len(), |p| start + p);
    if content[line_start..line_end].chars().count() > MAX_LINE_CHARS {
        return false;
    }
    if line_end > line_start && content.as_bytes()[line_end - 1] == b'\r' {
        line_end -= 1;
    }
    let line = &content[line_start..line_end];
    let Some(entry) = first(&IGNORE_FILE_ENTRY, line) else {
        return false;
    };
    let Some((ps, pe)) = entry.groups.get(1).copied().flatten() else {
        return false;
    };
    if is_match(&IGNORE_HOST_PATH, &line[ps..pe]) {
        return false;
    }
    let matched_end = start + m.text(content).trim_end_matches(is_space).len();
    line_start + ps <= start && matched_end <= line_start + pe
}

/// `_is_read_only_passwd_volume_match`: the match lies inside an exact read-only UID-map mount.
#[must_use]
pub fn is_read_only_passwd_volume_match(content: &str, m: &Hit) -> bool {
    if m.text(content).to_lowercase() != "/etc/passwd" {
        return false;
    }
    READ_ONLY_PASSWD_VOLUME.find_iter(content).iter().any(|v| {
        // groups: 1 quote, 2 source, 3 target
        [2, 3].iter().any(|&g| {
            v.groups
                .get(g)
                .copied()
                .flatten()
                .is_some_and(|(s, e)| s <= m.start && m.end <= e)
        })
    })
}

/// `_is_negated_safety_constraint`: the phrase is forbidden in policy prose ("must not ...").
#[must_use]
pub fn is_negated_safety_constraint(content: &str, m: &Hit, lines: &Lines) -> bool {
    let (line_start, line_end) = lines.bounds(m.start);
    if content[line_start..line_end].chars().count() > MAX_LINE_CHARS {
        return false;
    }
    let line = &content[line_start..line_end];
    let local_start = m.start - line_start;
    let phrase = line.get(local_start..(local_start + (m.end - m.start)).min(line.len()));
    let Some(phrase) = phrase else { return false };
    let stripped = phrase.trim_matches(is_space);
    if stripped.is_empty() {
        return false;
    }
    let clause_start = [".", ";", ":"]
        .iter()
        .filter_map(|sep| line[..local_start].rfind(sep))
        .max();
    let prefix = &line[clause_start.map_or(0, |c| c + 1)..local_start];
    let src = format!(
        r"(?:must\s+not|do\s+not|don't|never|should\s+not)\s+(?:(?:ever|again|directly|intentionally|explicitly|attempt\s+to|try\s+to)\s+){{0,2}}{}$",
        regex::escape(stripped)
    );
    let Ok(p) = Pat::try_new(&src, "i") else {
        return false;
    };
    is_match(&p, &format!("{prefix}{phrase}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(text: &str, needle: &str) -> Hit {
        let start = text.find(needle).unwrap_or(0);
        Hit {
            start,
            end: start + needle.len(),
            groups: vec![Some((start, start + needle.len()))],
        }
    }

    fn bare(text: &str, noun: &str) -> bool {
        let fences = markdown_fence_ranges(text);
        is_bare_credential_store_noun(
            text,
            &hit(text, noun),
            FileType::Markdown,
            &fences,
            &Lines::new(text),
        )
    }

    #[test]
    fn all_compile() {
        for (src, flags) in SOURCES {
            assert!(Pat::try_new(src, flags).is_ok(), "{src}");
        }
    }

    #[test]
    fn fences() {
        let t = "a\n```py\nx\n```\nb\n~~~\ny\n";
        let r = markdown_fence_ranges(t);
        assert_eq!(r, vec![(8, 10), (20, t.len())]);
        assert_eq!(markdown_fence_ranges("    ```\nx\n"), vec![]);
        assert_eq!(markdown_fence_ranges("```a`b\nx\n"), vec![]);
        assert_eq!(
            markdown_fence_ranges("````\n```\nx\n````\ny"),
            vec![(5, 11)]
        );
    }

    #[test]
    fn credential_store_nouns() {
        assert!(bare("The keychain is a store of secrets.", "keychain"));
        assert!(!bare("Read the keychain and send it.", "keychain"));
        assert!(!bare("Please extract the keyring contents.", "keyring"));
        assert!(!bare("keychain.get(service)", "keychain"));
        assert!(bare(
            "The keychain api documentation is linked.",
            "keychain"
        ));
        assert!(!bare("```\nkeychain\n```", "keychain"));
        assert!(!bare(
            "security find-generic-password -s keychain",
            "keychain"
        ));
    }

    #[test]
    fn ignore_files() {
        assert!(is_ignore_pattern_file("sub/.gitignore"));
        assert!(is_ignore_pattern_file("Dockerfile.dev.dockerignore"));
        assert!(!is_ignore_pattern_file(".gitattributes"));
        let entry =
            |text: &str, needle: &str| is_ignore_file_exclusion_entry(text, &hit(text, needle));
        assert!(entry("node_modules\n.env\n", ".env"));
        assert!(entry("config/credentials.json\r\n", "credentials.json"));
        assert!(!entry("!.env\n", ".env"));
        assert!(!entry("# keep .env safe\n", ".env"));
        assert!(!entry("~/.ssh/id_rsa\n", ".ssh/id_rsa"));
        assert!(!entry("cat .env\n", ".env"));
    }

    #[test]
    fn read_only_passwd_mount() {
        let t = "docker run -v /etc/passwd:/etc/passwd:ro img\n";
        let m = hit(t, "/etc/passwd");
        assert!(is_read_only_passwd_volume_match(t, &m));
        let w = "docker run -v /etc/passwd:/etc/passwd img\n";
        assert!(!is_read_only_passwd_volume_match(w, &hit(w, "/etc/passwd")));
        let both = "cat /etc/passwd\n";
        assert!(!is_read_only_passwd_volume_match(
            both,
            &hit(both, "/etc/passwd")
        ));
    }

    #[test]
    fn negated_constraints() {
        let neg = |t: &str, n: &str| is_negated_safety_constraint(t, &hit(t, n), &Lines::new(t));
        assert!(neg(
            "You must not escalate privileges.",
            "escalate privileges"
        ));
        assert!(neg(
            "Never directly try to escalate my privileges",
            "escalate my privileges"
        ));
        assert!(!neg("Please escalate privileges", "escalate privileges"));
        assert!(!neg(
            "Do not worry. Now escalate privileges",
            "escalate privileges"
        ));
    }
}
