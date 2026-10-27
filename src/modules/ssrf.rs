//! SSRF1-SSRF3 from `static_patterns_ssrf.py`.

use super::support::Rule;
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::matcher::{Hit, Pat, paragraph_matches};
use crate::pyast::PyFile;
use crate::runner::StaticModule;
use crate::skill::FileType;
use crate::text::{LineIndex, py_splitlines};
use crate::unicode::is_alnum;
use std::sync::LazyLock;

const TAG: &str = "Server-Side Request Forgery";

/// Request-issuing functions across Python and JS, used to anchor SSRF matches.
const REQ: &str = r"(?:requests|httpx|aiohttp|urllib(?:\.request)?|urllib3|session)\s*\.\s*(?:get|post|put|patch|delete|head|request|urlopen)|fetch|axios(?:\.\w+)?|XMLHttpRequest|\bcurl\b|\bwget\b";

const SSRF1_ENDPOINTS: [(&str, f32); 4] = [
    (r"169\.254\.169\.254", 0.9),
    (r"metadata\.google\.internal", 0.9),
    (r"100\.100\.100\.200", 0.85),
    (r"fd00:ec2::254", 0.85),
];
const SSRF1_PROSE: (&str, f32) = (
    r"(?:read|fetch|get|query)\s+(?:the\s+)?(?:instance\s+)?metadata\s+(?:service|endpoint|server)",
    0.6,
);

/// `REQ` with ASCII word boundaries around `curl`/`wget`: a Unicode `\b` makes the regex engine
/// fall back to a very slow search on any file with a non-ASCII character. [`unicode_boundary_ok`]
/// restores the exact Unicode semantics afterwards.
const REQ_FAST: &str = r"(?:requests|httpx|aiohttp|urllib(?:\.request)?|urllib3|session)\s*\.\s*(?:get|post|put|patch|delete|head|request|urlopen)|fetch|axios(?:\.\w+)?|XMLHttpRequest|(?-u:\b)curl(?-u:\b)|(?-u:\b)wget(?-u:\b)";

fn ssrf2_sources() -> Vec<(String, f32)> {
    vec![(
        format!(
            r#"(?:{REQ_FAST})\s*\(\s*f?['"]https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|10\.\d|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"#
        ),
        0.7,
    )]
}

fn ssrf3_sources() -> Vec<(String, f32)> {
    vec![
        (format!(r#"(?:{REQ_FAST})\s*\(\s*f['"]https?://\{{"#), 0.6),
        (r"fetch\s*\(\s*`https?://\$\{".to_owned(), 0.6),
    ]
}

const DEFENSE_CONTEXT: &str = r"\bssrf(?:[\s-]+)refusal\b|\b(?:reject(?:s|ed|ing)?|refus(?:e|es|ed|al|ing)|block(?:s|ed|ing)?|deny|denies|denied|disallow(?:s|ed|ing)?)\b[^.\n]{0,160}\b(?:ssrf|fetch|request|target|host|endpoint|address|loopback|link-local|private|metadata)\b|\b(?:ssrf|fetch|request|target|host|endpoint|address|space|loopback|link-local|private|metadata)\b[^.\n]{0,160}\b(?:is\s+|are\s+)?(?:rejected|refused|blocked|denied|disallowed)\b|\bprevent(?:s|ed|ing)?\b[^.\n]{0,80}\bssrf\b";
const DEFENSIVE_REQUEST: &str = r"\b(?:refus(?:e|es|ed|ing)\s+to|reject(?:s|ed|ing)?|block(?:s|ed|ing)?|deny|denies|denied|never|must\s+not|do\s+not|don'?t)\s+(?:attempts?\s+to\s+)?(?:fetch|get|request|access|connect|contact|curl|wget)\b";

fn compile(sources: &[(String, f32)]) -> Vec<(Pat, f32)> {
    sources
        .iter()
        .map(|(s, c)| (Pat::new(s, "im"), *c))
        .collect()
}

static SSRF1: LazyLock<Vec<(Pat, f32)>> = LazyLock::new(|| {
    SSRF1_ENDPOINTS
        .iter()
        .map(|&(s, c)| (Pat::new(s, "im"), c))
        .collect()
});
static SSRF1_PROSE_PAT: LazyLock<Pat> = LazyLock::new(|| Pat::new(SSRF1_PROSE.0, "im"));
static SSRF2: LazyLock<Vec<(Pat, f32)>> = LazyLock::new(|| compile(&ssrf2_sources()));
static SSRF3: LazyLock<Vec<(Pat, f32)>> = LazyLock::new(|| compile(&ssrf3_sources()));
static DEFENSE: LazyLock<Pat> = LazyLock::new(|| Pat::new(DEFENSE_CONTEXT, "i"));
static DEFENSIVE: LazyLock<Pat> = LazyLock::new(|| Pat::new(DEFENSIVE_REQUEST, "i"));
static ISSUER: LazyLock<Pat> = LazyLock::new(|| Pat::new(REQ, "i"));

const R_SSRF1: Rule = Rule {
    id: "SSRF1",
    message: "Cloud Metadata Access",
    severity: Severity::High,
    tag: TAG,
};
const R_SSRF2: Rule = Rule {
    id: "SSRF2",
    message: "Internal Network Request",
    severity: Severity::Medium,
    tag: TAG,
};
const R_SSRF3: Rule = Rule {
    id: "SSRF3",
    message: "Dynamic Request Target",
    severity: Severity::Medium,
    tag: TAG,
};

/// `get_context(content, start, context_lines=5)`, which only feeds the defense-prose check.
fn wide_context(text: &str, byte: usize, idx: &LineIndex) -> String {
    const LINES: usize = 5;
    const MAX: usize = 1_000;
    let lines = py_splitlines(text);
    let at = usize::try_from(idx.line(byte)).unwrap_or(1) - 1;
    let first = at.saturating_sub(LINES);
    let last = lines.len().min(at + LINES + 1);
    let Some(sel) = lines.get(first..last).filter(|s| !s.is_empty()) else {
        return String::new();
    };
    let rel = (at - first).min(sel.len() - 1);
    let line_start = text[..byte].rfind('\n').map_or(0, |p| p + 1);
    let column = text[line_start..byte]
        .chars()
        .count()
        .min(sel[rel].chars().count());
    let anchor: usize = sel[..rel]
        .iter()
        .map(|l| l.chars().count() + 1)
        .sum::<usize>()
        + column;
    let joined = sel.join("\n");
    let chars: Vec<char> = joined.chars().collect();
    if chars.len() <= MAX {
        return joined;
    }
    let start = anchor.saturating_sub(MAX / 2).min(chars.len() - MAX);
    chars[start..start + MAX].iter().collect()
}

/// `_is_defensive_reference`: the indicator documents an explicit rejection rule. A request
/// issuer on the matched line wins over nearby defensive prose.
fn is_defensive_reference(text: &str, h: &Hit, idx: &LineIndex) -> bool {
    let line_start = text[..h.start].rfind('\n').map_or(0, |p| p + 1);
    let line_end = text[h.end..].find('\n').map_or(text.len(), |p| h.end + p);
    let line = &text[line_start..line_end];
    if !DEFENSIVE.find_iter(line).is_empty() {
        return true;
    }
    if !ISSUER.find_iter(line).is_empty() {
        return false;
    }
    !DEFENSE
        .find_iter(&wide_context(text, h.start, idx))
        .is_empty()
}

/// A hit that starts with `curl`/`wget` needs a Unicode `\b` before it: the preceding character
/// must not be a word character. (The right-hand `\b` always holds: `\s*\(` follows.)
fn unicode_boundary_ok(text: &str, h: &Hit) -> bool {
    let starts_with_tool = |w: &str| {
        text[h.start..]
            .get(..w.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(w))
    };
    if !(starts_with_tool("curl") || starts_with_tool("wget")) {
        return true;
    }
    !text[..h.start]
        .chars()
        .next_back()
        .is_some_and(|c| is_alnum(c) || c == '_')
}

/// `finditer` over the ASCII-boundary pattern with the Unicode boundary check applied: a rejected
/// hit means the regex would have failed at that start, so the search resumes just after it.
fn find_requests(pat: &Pat, text: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    let mut pos = 0;
    'resume: while pos <= text.len() {
        for h in pat.find_in(text, pos, text.len()) {
            if !unicode_boundary_ok(text, &h) {
                pos = h.start + text[h.start..].chars().next().map_or(1, char::len_utf8);
                continue 'resume;
            }
            out.push(h);
        }
        break;
    }
    out
}

/// The SSRF static module.
pub struct Ssrf;

impl StaticModule for Ssrf {
    fn id(&self) -> &'static str {
        "static_patterns_ssrf"
    }

    fn analyze(
        &self,
        text: &str,
        path: &str,
        _ft: FileType,
        _py: Option<&PyFile>,
    ) -> Vec<RawFinding> {
        let idx = LineIndex::new(text);
        let mut out = Vec::new();
        let mut add = |rule: &Rule, conf: f32, h: &Hit| {
            out.push(rule.plain(conf, path, idx.line(h.start), h.text(text)));
        };
        for (pat, conf) in SSRF1.iter() {
            for h in pat.find_iter(text) {
                if !is_defensive_reference(text, &h, &idx) {
                    add(&R_SSRF1, *conf, &h);
                }
            }
        }
        for h in paragraph_matches(&SSRF1_PROSE_PAT, text) {
            if !is_defensive_reference(text, &h, &idx) {
                add(&R_SSRF1, SSRF1_PROSE.1, &h);
            }
        }
        for (rule, pats) in [(&R_SSRF2, &*SSRF2), (&R_SSRF3, &*SSRF3)] {
            for (pat, conf) in pats {
                for h in find_requests(pat, text) {
                    add(rule, *conf, &h);
                }
            }
        }
        out
    }
}

#[cfg(test)]
/// Every pattern source with its flags, for the compile test.
pub fn pattern_sources() -> Vec<(String, &'static str)> {
    let mut v: Vec<(String, &'static str)> = SSRF1_ENDPOINTS
        .iter()
        .map(|(s, _)| ((*s).to_owned(), "im"))
        .collect();
    v.push((SSRF1_PROSE.0.to_owned(), "im"));
    v.extend(
        ssrf2_sources()
            .into_iter()
            .chain(ssrf3_sources())
            .map(|(s, _)| (s, "im")),
    );
    v.extend([
        (DEFENSE_CONTEXT.to_owned(), "i"),
        (DEFENSIVE_REQUEST.to_owned(), "i"),
        (REQ.to_owned(), "i"),
    ]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str) -> Vec<RawFinding> {
        Ssrf.analyze(text, "a.md", FileType::Markdown, None)
    }

    fn ids(f: &[RawFinding]) -> Vec<&'static str> {
        f.iter().map(|f| f.rule_id).collect()
    }

    #[test]
    fn all_patterns_compile() {
        for (src, flags) in pattern_sources() {
            assert!(Pat::try_new(&src, flags).is_ok(), "{src}");
        }
    }

    #[test]
    fn ssrf1_metadata_endpoint() {
        assert_eq!(
            ids(&run("curl http://169.254.169.254/latest/meta-data/")),
            ["SSRF1"]
        );
        assert_eq!(ids(&run("Then fetch the metadata service.")), ["SSRF1"]);
    }

    #[test]
    fn ssrf1_defensive_reference_is_skipped() {
        assert!(run("Never fetch 169.254.169.254.").is_empty());
        // "Requests" (plural) is not the word "request": SkillSpector reports this one
        assert_eq!(
            ids(&run(
                "SSRF protection:\nRequests to 169.254.169.254 are blocked.\n"
            )),
            ["SSRF1"]
        );
    }

    #[test]
    fn ssrf2_internal_request() {
        let f = run("data = urllib.request.urlopen('http://localhost:8080/x')");
        assert_eq!(ids(&f), ["SSRF2"]);
        assert_eq!(
            f[0].matched_text.as_deref(),
            Some("urllib.request.urlopen('http://localhost")
        );
        assert_eq!(
            ids(&run("requests.get(\"http://192.168.1.5/\")")),
            ["SSRF2"]
        );
        assert!(run("requests.get('http://example.com/')").is_empty());
    }

    #[test]
    fn curl_needs_a_unicode_word_boundary() {
        assert_eq!(ids(&run("curl('http://localhost/x')")), ["SSRF2"]);
        assert!(run("\u{e9}curl('http://localhost/x')").is_empty());
        assert!(run("_curl('http://localhost/x')").is_empty());
        assert_eq!(ids(&run("a-wget ('http://localhost/x')")), ["SSRF2"]);
    }

    #[test]
    fn ssrf3_dynamic_target() {
        assert_eq!(ids(&run("requests.get(f'http://{host}/x')")), ["SSRF3"]);
        assert_eq!(ids(&run("fetch(`https://${host}/x`)")), ["SSRF3"]);
    }
}
