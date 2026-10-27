//! Access-token and OAuth documentation vetoes of `static_patterns_privilege_escalation.py`
//! (`_is_pe3_documentation_example`, `_is_companion_cli_oauth_result_noun`,
//! `_is_credential_type_disclosure_label`, `_is_qualified_benign_access_requirement`).

use super::pe_context::{Lines, MAX_LINE_CHARS, first, fwd_chars, is_match};
use crate::matcher::{Hit, Pat};
use crate::skill::FileType;
use crate::text::py_splitlines;
use crate::unicode::is_space;
use std::sync::LazyLock;

/// `_MAX_BOUND_TOKEN_CONTEXT_CHARS`.
const MAX_BOUND_TOKEN_CONTEXT_CHARS: usize = 4_096;

macro_rules! patterns {
    ($( $name:ident = ($src:expr, $flags:expr); )*) => {
        $( static $name: LazyLock<Pat> = LazyLock::new(|| Pat::new($src, $flags)); )*
        /// (source, flags) of every pattern in this file, so a test can compile them all.
        #[cfg(test)]
        pub const SOURCES: &[(&str, &str)] = &[ $( ($src, $flags), )* ];
    };
}

/// `_PE3_BOUND_TOKEN_OBJECT`.
macro_rules! bound_object {
    () => {
        concat!(
            r#"[\s`'"-]{0,24}"#,
            r"(?:it|them|(?:(?:the|this|that|these|those|returned|resulting|oauth|oidc|",
            r"access|refresh|bearer|api)\s+){0,5}tokens?|",
            r"(?:(?:this|that|the\s+(?:returned|resulting))\s+value))\b"
        )
    };
}

/// Characters that end a sentence-like clause in the bound-token windows.
macro_rules! clause_stop {
    () => {
        r"[^.!?;\r\n\x0b\f\x1c-\x1e\x85\u2028\u2029]"
    };
}

patterns! {
    CREDENTIAL_TYPE_FIELD = (
        r"\A[ \t]*\*\*Credential\s+Type\(s\):\*\*[ \t]*(\[[^\r\n]*\])[ \t]*(?:<br\s*/?>)?[ \t]*\z",
        "i"
    );
    CREDENTIAL_TYPE_NOUN = (r"\Aaccess[ \t]+(?:credentials?|secrets?|tokens?)\z", "i");
    SAFE_ACCESS_TOKEN_NAVIGATION = (
        r"(?:^|>|\b(?:navigate|go)\s+to\s+)\s*settings\s*>\s*(?:ci/cd\s*>\s*)?(access\s+tokens?)\s*[`.)]*\s*$",
        "i"
    );
    TOKEN_ACTION_CONTEXT = (
        concat!(
            r"\b(?:steal(?:s|ing|en)?|exfiltrat(?:e|es|ed|ing|ion)|dump(?:s|ed|ing)?|",
            r"harvest(?:s|ed|ing)?|scrap(?:e|es|ed|ing)|upload(?:s|ed|ing)?|",
            r"transmit(?:s|ted|ting)?|send(?:s|ing)?|sent|cop(?:y|ies|ied|ying)|",
            r"extract(?:s|ed|ing|ion)?|forward(?:s|ed|ing)?|leak(?:s|ed|ing)?|",
            r"share(?:s|d|ing)?|expose(?:s|d|ing)?|log(?:s|ged|ging)?|",
            r"print(?:s|ed|ing)?|write(?:s|written|writing)?|publish(?:es|ed|ing)?|",
            r"display(?:s|ed|ing)?|giv(?:e|es|ing|en)|reveal(?:s|ed|ing)?|",
            r"email(?:s|ed|ing)?|include(?:s|d|ing)?)\b",
            r"|\bpost(?:s|ed|ing)?\b[^\n]{0,80}",
            r"\b(?:it|them|(?:the\s+)?(?:access|refresh|bearer|api)[ _-]?tokens?)\b",
            r"[^\n]{0,40}\bto\b",
            r"|\b(?:read(?:s|ing)?|open(?:s|ed|ing)?|load(?:s|ed|ing)?)\b[^\n]{0,80}",
            r"\b(?:access|refresh|bearer|api)[ _-]?tokens?\b"
        ),
        "i"
    );
    BOUND_TOKEN_TRANSFER = (
        concat!(
            r"\b(?:past(?:e|es|ed|ing)|submit(?:s|ted|ting)?|attach(?:es|ed|ing)?|",
            r"relay(?:s|ed|ing)?|deliver(?:s|ed|ing)?|put(?:s|ting)?|",
            r"pass(?:es|ed|ing)?|enter(?:s|ed|ing)?|insert(?:s|ed|ing)?|",
            r"post(?:s|ed|ing)?)\b",
            bound_object!(),
            clause_stop!(), r"{0,96}?",
            r"\b(?:to|into|onto|through|via|in|on|with|as|at|under|for)\b(?=\s+\S)"
        ),
        "i"
    );
    BOUND_TOKEN_RETENTION = (
        concat!(
            r"\b(?:stor(?:e|es|ed|ing)|sav(?:e|es|ed|ing)|export(?:s|ed|ing)?|",
            r"persist(?:s|ed|ing)?|cach(?:e|es|ed|ing)|retain(?:s|ed|ing)?|",
            r"keep(?:s|ing)?|kept)\b",
            bound_object!(),
            r"(?:(?=\s*(?:[.!?;]|$|\r\n|[\r\n\x0b\f\x1c-\x1e\x85\u2028\u2029]))|",
            clause_stop!(), r"{0,96}?",
            r"\b(?:to|into|onto|through|via|in|on|with|as|at|under|for)\b(?=\s+\S))"
        ),
        "i"
    );
    TOKEN_SENSITIVE_SOURCE = (
        concat!(
            r"(?<![\w.-])(?:\.ssh|\.aws)(?:[/\\]|$)",
            r"|(?<![\w.-])\.env(?:\.[\w-]+)?\b",
            r"|/etc/(?:passwd|shadow)\b",
            r"|\b(?:tokens?\.json|credentials?|secrets?)\b[^\n]{0,80}",
            r"\b(?:read|open|load|copy|upload|transmit)\b"
        ),
        "i"
    );
    ACCESS_TOKEN_DIRECTIVE_PREFIX = (
        concat!(
            r"\b(?:please|always|silently|then|next|must|should|shall|can|could|will|may|to)\s*$",
            r"|\b(?:need(?:s)?|try|attempt)\s+to\s*$",
            r"|^\s*(?:the\s+|an?\s+)?(?:\w+[ -]+){0,2}",
            r"(?:agents?|assistants?|tools?|skills?|scripts?|users?|clients?|applications?|",
            r"attackers?|we|you|they|i)\s*$",
            r"|^\s*(?:go|navigate)\b.*[,;]\s*$"
        ),
        "i"
    );
    ACCESS_TOKEN_NOUN_SUFFIX = (
        concat!(
            r"\A\s*(?:$|[|,.;:)]|(?:are|were|is|was|expire\w*|remain\w*|contain\w*|",
            r"include\w*|provide\w*|represent\w*|identify\w*|authenticate\w*|authorize\w*|",
            r"issued|returned|accepted|rejected|revoked|stored|used|tied|associated)\b)"
        ),
        "i"
    );
    OAUTH_PROTOCOL_CONTEXT = (
        r"\b(?:oauth(?:\s*2(?:\.\d+)?)?|openid\s+connect|oidc|authorization\s+code|refresh[ _-]?tokens?|bearer[ _-]?tokens?)\b",
        "i"
    );
    COMPANION_CLI_CONTEXT = (
        r"\b(?:companion\s+cli|command[- ]line\s+(?:client|tool)|cli(?:'s)?|[a-z][\w.-]*(?:ctl|-cli)(?:'s)?)\b",
        "i"
    );
    OAUTH_RESULT_CONTEXT = (
        concat!(
            r"\b(return(?:s|ed)?|issu(?:e|es|ed)|provid(?:e|es|ed)|yield(?:s|ed)?)",
            r"\s+(?:an?|the)\s+(?:(?:oauth|oidc|bearer|short-lived|",
            r"temporary|new|provider-specific)\s+){0,3}$"
        ),
        "i"
    );
    OAUTH_OWNER_BRIDGE = (
        concat!(
            "\\A(?:['\u{2019}]s)?(?:\\s+(?:sign[- ]?in|login|flow|authentication|authorization|",
            r"token|code|exchange|command|client|process|request|operation|helper)){0,4}\s*\z"
        ),
        "i"
    );
    OAUTH_CAUSATIVE_PREFIX = (
        concat!(
            r"\b(?:have|has|had|make|makes|made|let|lets|cause|causes|caused|",
            r"force|forces|forced|ask|asks|asked|tell|tells|told|instruct|instructs|",
            r"instructed|get|gets|got|request|requests|require|requires|command|commands|",
            r"direct|directs|order|orders|prompt|prompts|ensure|confirm|verify|check|",
            r"configure|use|please|must|should|shall|need|needs|can|could|may|will|would)\b"
        ),
        "i"
    );
    OAUTH_RESULT_SUFFIX = (
        concat!(
            r#"\A\s*(?:and\s+(?:an?\s+|the\s+)?(?:short-lived\s+)?refresh[ _-]?token)?"#,
            r#"\s*[`'".,;:)]*\s*\z"#
        ),
        "i"
    );
    MARKDOWN_LINE_PREFIX = (r"\A\s*(?:(?:[-*+>#]|\d+[.)])\s*)*", "");
}

const DOCUMENTATION_DIRS: [&str; 10] = [
    "docs",
    "doc",
    "documentation",
    "procedures",
    "procedure",
    "references",
    "reference",
    "examples",
    "example",
    "guides",
];
const BARE_RESULT_VERBS: [&str; 4] = ["return", "issue", "provide", "yield"];
const BENIGN_ACCESS_REQUIREMENT_ROWS: [&str; 2] = [
    "| GTL access credential | Runner-gated job start |",
    "| GTL access credential | Runner-gated job create/start/monitor/collect |",
];

/// Whether `OAUTH_PROTOCOL_CONTEXT` occurs in `text` (decides the companion explanation).
#[must_use]
pub fn has_oauth_protocol_context(text: &str) -> bool {
    is_match(&OAUTH_PROTOCOL_CONTEXT, text)
}

fn is_doc_type(ft: FileType) -> bool {
    matches!(ft, FileType::Markdown | FileType::Text)
}

/// `_has_bound_token_transfer`: a transfer or retention instruction bound to this token.
fn has_bound_token_transfer(content: &str, m: &Hit, lines: &Lines) -> bool {
    let li = lines.index(m.start);
    let last = (li + 3).min(lines.ends.len() - 1);
    let window_end = lines.ends[last].min(fwd_chars(content, m.end, MAX_BOUND_TOKEN_CONTEXT_CHARS));
    let window_start = lines.starts[li];
    let Some(window) = content.get(window_start..window_end) else {
        return false;
    };
    let (ms, me) = (m.start - window_start, m.end - window_start);
    [&BOUND_TOKEN_TRANSFER, &BOUND_TOKEN_RETENTION]
        .iter()
        .any(|p| {
            p.find_iter(window)
                .iter()
                .any(|t| (t.start <= ms && ms < t.end) || t.start >= me)
        })
}

fn line_too_long(content: &str, start: usize, end: usize) -> bool {
    content[start..end].chars().count() > MAX_LINE_CHARS
}

/// `rfind` of any of `.;:` before the end of `s`, as a position after the separator.
fn after_last_of(s: &str, marks: &[char]) -> usize {
    s.rfind(marks).map_or(0, |i| i + 1)
}

/// `_is_access_token_documentation_noun`.
fn is_access_token_documentation_noun(
    content: &str,
    m: &Hit,
    path: &str,
    lines: &Lines,
    context: &str,
) -> bool {
    let matched = m.text(content).to_lowercase();
    if matched != "access token" && matched != "access tokens" {
        return false;
    }
    let (ls, le) = lines.bounds(m.start);
    if line_too_long(content, ls, le) {
        return false;
    }
    let line = &content[ls..le];
    let lower_path = path.replace('\\', "/").to_lowercase();
    if !lower_path
        .split('/')
        .any(|part| DOCUMENTATION_DIRS.contains(&part))
    {
        return false;
    }
    if is_match(&TOKEN_ACTION_CONTEXT, context)
        || is_match(&TOKEN_SENSITIVE_SOURCE, context)
        || has_bound_token_transfer(content, m, lines)
    {
        return false;
    }
    let (rs, re) = (m.start - ls, m.end - ls);
    let before = &line[..rs];
    let prefix = match first(&MARKDOWN_LINE_PREFIX, before) {
        Some(h) => &before[h.end..],
        None => before,
    };
    let suffix = &line[re..];
    let cell_prefix = prefix.rsplit('|').next().unwrap_or(prefix);
    let clause_prefix = &cell_prefix[after_last_of(cell_prefix, &['.', ';', ':'])..];
    if is_match(&ACCESS_TOKEN_DIRECTIVE_PREFIX, cell_prefix)
        || is_match(&ACCESS_TOKEN_DIRECTIVE_PREFIX, clause_prefix)
    {
        return false;
    }
    if matched == "access token" {
        return true;
    }
    if clause_prefix.trim_matches(is_space).is_empty() {
        return is_match(&ACCESS_TOKEN_NOUN_SUFFIX, suffix);
    }
    true
}

/// `_is_pe3_documentation_example`: reviewed, position-bound access-token documentation forms.
#[must_use]
pub fn is_pe3_documentation_example(
    content: &str,
    m: &Hit,
    ft: FileType,
    path: &str,
    lines: &Lines,
    context: &str,
) -> bool {
    if !is_doc_type(ft) {
        return false;
    }
    let matched = m.text(content).to_lowercase();
    if matched != "access token" && matched != "access tokens" {
        return false;
    }
    let (ls, le) = lines.bounds(m.start);
    if line_too_long(content, ls, le) {
        return false;
    }
    let line = &content[ls..le];
    if let Some(nav) = first(&SAFE_ACCESS_TOKEN_NAVIGATION, line)
        && nav.groups.get(1).copied().flatten() == Some((m.start - ls, m.end - ls))
    {
        return true;
    }
    is_access_token_documentation_noun(content, m, path, lines, context)
}

/// `_is_companion_cli_oauth_result_noun`: one directly owned singular OAuth result in CLI docs.
#[must_use]
pub fn is_companion_cli_oauth_result_noun(
    content: &str,
    m: &Hit,
    ft: FileType,
    lines: &Lines,
    context: &str,
) -> bool {
    if !is_doc_type(ft) || m.text(content).to_lowercase() != "access token" {
        return false;
    }
    let (ls, le) = lines.bounds(m.start);
    if line_too_long(content, ls, le) {
        return false;
    }
    let line = &content[ls..le];
    let prefix = &line[..m.start - ls];
    let clause_prefix = &prefix[after_last_of(prefix, &['.', ';', ':', '|'])..];
    let (Some(cli), Some(oauth), Some(result)) = (
        first(&COMPANION_CLI_CONTEXT, clause_prefix),
        first(&OAUTH_PROTOCOL_CONTEXT, clause_prefix),
        first(&OAUTH_RESULT_CONTEXT, clause_prefix),
    ) else {
        return false;
    };
    let owner_end = cli.end.max(oauth.end);
    if result.start < owner_end {
        return false;
    }
    let bridge = &clause_prefix[owner_end..result.start];
    let suffix = &line[m.end - ls..];
    let verb = result.group(clause_prefix, 1).unwrap_or("").to_lowercase();
    if is_match(&OAUTH_CAUSATIVE_PREFIX, &clause_prefix[..cli.start])
        || BARE_RESULT_VERBS.contains(&verb.as_str())
        || !is_match(&OAUTH_OWNER_BRIDGE, bridge)
        || !is_match(&OAUTH_RESULT_SUFFIX, suffix)
    {
        return false;
    }
    !(is_match(&TOKEN_ACTION_CONTEXT, context)
        || is_match(&TOKEN_SENSITIVE_SOURCE, context)
        || has_bound_token_transfer(content, m, lines))
}

/// `_is_credential_type_disclosure_label`: an access-credential noun inside a skill-card field.
#[must_use]
pub fn is_credential_type_disclosure_label(
    content: &str,
    m: &Hit,
    ft: FileType,
    lines: &Lines,
) -> bool {
    if ft != FileType::Markdown || !is_match(&CREDENTIAL_TYPE_NOUN, m.text(content)) {
        return false;
    }
    let (ls, le) = lines.bounds(m.start);
    if line_too_long(content, ls, le) {
        return false;
    }
    let line = &content[ls..le];
    let Some(field) = first(&CREDENTIAL_TYPE_FIELD, line) else {
        return false;
    };
    let Some((vs, ve)) = field.groups.get(1).copied().flatten() else {
        return false;
    };
    if !(ls + vs <= m.start && m.start < m.end && m.end <= ls + ve) {
        return false;
    }
    let value = &line[vs..ve];
    !(is_match(&TOKEN_ACTION_CONTEXT, value) || is_match(&TOKEN_SENSITIVE_SOURCE, value))
}

/// `_is_qualified_benign_access_requirement`: the reviewed GTL requirement row in its exact table.
#[must_use]
pub fn is_qualified_benign_access_requirement(
    content: &str,
    m: &Hit,
    ft: FileType,
    lines: &Lines,
) -> bool {
    if ft != FileType::Markdown || m.text(content) != "access credential" {
        return false;
    }
    let all = py_splitlines(content);
    let row = lines.index(m.start);
    let Some(row_text) = all.get(row) else {
        return false;
    };
    if !BENIGN_ACCESS_REQUIREMENT_ROWS.contains(&row_text.trim_matches(is_space)) {
        return false;
    }
    let mut table_start = row;
    while table_start > 0 && all[table_start - 1].trim_matches(is_space).starts_with('|') {
        table_start -= 1;
    }
    if table_start + 1 >= all.len()
        || all[table_start].trim_matches(is_space) != "| Requirement | Purpose |"
        || all[table_start + 1].trim_matches(is_space) != "| --- | --- |"
    {
        return false;
    }
    let mut heading = table_start;
    while heading > 0 && all[heading - 1].trim_matches(is_space).is_empty() {
        heading -= 1;
    }
    heading > 0 && all[heading - 1].trim_matches(is_space) == "## Access Requirements"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::get_context;

    fn hit(text: &str, needle: &str) -> Hit {
        let start = text.find(needle).unwrap_or(0);
        Hit {
            start,
            end: start + needle.len(),
            groups: vec![Some((start, start + needle.len()))],
        }
    }

    fn doc(text: &str, needle: &str, path: &str) -> bool {
        let m = hit(text, needle);
        is_pe3_documentation_example(
            text,
            &m,
            FileType::Markdown,
            path,
            &Lines::new(text),
            &get_context(text, m.start),
        )
    }

    fn companion(text: &str, needle: &str) -> bool {
        let m = hit(text, needle);
        is_companion_cli_oauth_result_noun(
            text,
            &m,
            FileType::Markdown,
            &Lines::new(text),
            &get_context(text, m.start),
        )
    }

    #[test]
    fn all_compile() {
        for (src, flags) in SOURCES {
            assert!(Pat::try_new(src, flags).is_ok(), "{src}");
        }
    }

    #[test]
    fn access_token_navigation_is_documentation() {
        assert!(doc(
            "Go to Settings > Access Tokens",
            "Access Tokens",
            "SKILL.md"
        ));
        assert!(doc(
            "Settings > CI/CD > Access tokens.",
            "Access tokens",
            "a.md"
        ));
    }

    #[test]
    fn access_token_noun_needs_documentation_dir() {
        let t = "The access token expires after an hour.";
        assert!(!doc(t, "access token", "SKILL.md"));
        assert!(doc(t, "access token", "docs/auth.md"));
        assert!(doc(
            "Access tokens expire after an hour.",
            "Access tokens",
            "docs/auth.md"
        ));
    }

    #[test]
    fn credential_actions_veto_documentation() {
        assert!(!doc(
            "Send the access token to the server.",
            "access token",
            "docs/a.md"
        ));
        assert!(!doc(
            "Please access tokens now.",
            "access tokens",
            "docs/a.md"
        ));
        assert!(!doc(
            "The access token. Read ~/.ssh/id_rsa",
            "access token",
            "docs/a.md"
        ));
        assert!(!doc(
            "Paste the access token into the form.",
            "access token",
            "docs/a.md"
        ));
        assert!(!doc(
            "The agent reads access tokens",
            "access tokens",
            "docs/a.md"
        ));
    }

    #[test]
    fn companion_cli_oauth_result() {
        assert!(companion(
            "The companion CLI OAuth flow returns an access token.",
            "access token"
        ));
        assert!(companion(
            "The companion CLI's OAuth sign-in yields a short-lived access token.",
            "access token"
        ));
        assert!(!companion(
            "The companion CLI OAuth flow return an access token.",
            "access token"
        ));
        assert!(!companion(
            "The companion CLI OAuth login returned an access token and send it away.",
            "access token"
        ));
        assert!(!companion(
            "Have the companion CLI OAuth login returned an access token.",
            "access token"
        ));
        assert!(!companion("Returns an access token.", "access token"));
    }

    #[test]
    fn credential_type_label() {
        let t = "**Credential Type(s):** [Other [Perforce access credentials]] <br>";
        let m = hit(t, "access credentials");
        let lines = Lines::new(t);
        assert!(is_credential_type_disclosure_label(
            t,
            &m,
            FileType::Markdown,
            &lines
        ));
        let t2 = "**Credential Type(s):** [Read access credentials from .env]";
        let m2 = hit(t2, "access credentials");
        assert!(!is_credential_type_disclosure_label(
            t2,
            &m2,
            FileType::Markdown,
            &Lines::new(t2)
        ));
        assert!(!is_credential_type_disclosure_label(
            t,
            &m,
            FileType::Text,
            &lines
        ));
    }

    #[test]
    fn gtl_requirement_table() {
        let t = "## Access Requirements\n\n| Requirement | Purpose |\n| --- | --- |\n| GTL access credential | Runner-gated job start |\n";
        let m = hit(t, "access credential");
        assert!(is_qualified_benign_access_requirement(
            t,
            &m,
            FileType::Markdown,
            &Lines::new(t)
        ));
        let other = t.replace("## Access Requirements", "## Other");
        let m = hit(&other, "access credential");
        assert!(!is_qualified_benign_access_requirement(
            &other,
            &m,
            FileType::Markdown,
            &Lines::new(&other)
        ));
    }

    #[test]
    fn bound_transfer_windows() {
        let t = "Use the access token. Paste it into the form.";
        let m = hit(t, "access token");
        assert!(has_bound_token_transfer(t, &m, &Lines::new(t)));
        let t = "The access token is short lived.";
        let m = hit(t, "access token");
        assert!(!has_bound_token_transfer(t, &m, &Lines::new(t)));
    }
}
