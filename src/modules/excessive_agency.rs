//! EA1-EA4 from `static_patterns_excessive_agency.py` (EA5 lives in [`super::model_selection`]).
//!
//! Prose patterns run per paragraph; EA2 prose hits are dropped when a direct prohibition governs
//! them or when they restate an approval requirement.

use super::model_selection;
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::matcher::{Pat, paragraph_matches};
use crate::prohibition::{AllowedTail, Options, is_directly_prohibited};
use crate::pyast::PyFile;
use crate::runner::StaticModule;
use crate::skill::FileType;
use crate::text::{LineIndex, get_context};
use std::sync::LazyLock;

const CATEGORY_TAG: &str = "Excessive Agency";
const FLAGS: &str = "im";

/// `(source, confidence, is_prose)`.
type Entry = (&'static str, f32, bool);

/// One rule: id, message, severity and its pattern table.
struct Rule {
    id: &'static str,
    message: &'static str,
    severity: Severity,
    entries: &'static [Entry],
}

const EA1: Rule = Rule {
    id: "EA1",
    message: "Unrestricted Tool Access",
    severity: Severity::Medium,
    entries: &[
        (
            r#"(?:tools?|permissions?)\s*:[ \t]*\[?[ \t]*['\"]?\*(?!\*|\w)['\"]?[ \t]*\]?"#,
            0.85,
            false,
        ),
        (
            r#"tools?\s*:\s*\[\s*['\"]shell['\"].*?['\"](?:file_write|network|http)['\"]"#,
            0.7,
            false,
        ),
        (
            r"(?:allow|grant|enable)\s+(?:access\s+to\s+)?(?:all|any|every)\s+tools?",
            0.8,
            true,
        ),
        (
            r"(?:no|without)\s+(?:tool|permission|access|capability)\s+(?:restrictions?|constraints?|limitations?)",
            0.75,
            true,
        ),
        (
            r"(?:call|invoke|use|execute)\s+(?:any|all|every)\s+(?:available\s+)?tools?",
            0.8,
            true,
        ),
        (
            r"(?:unrestricted|unlimited|unconstrained)\s+(?:tool|function|api)\s+(?:access|use|calls?)",
            0.85,
            true,
        ),
        (
            r"(?:can|may|should)\s+(?:freely|always)\s+(?:use|call|invoke)\s+(?:any|all)\s+(?:tools?|functions?|apis?)",
            0.75,
            true,
        ),
        (
            r"(?:grant|give)\s+(?:full|complete|total)\s+(?:tool|function|api)\s+access",
            0.85,
            true,
        ),
        (
            r"(?:execute|run)\s+(?:arbitrary|any)\s+(?:commands?|code|scripts?)",
            0.8,
            true,
        ),
        (
            r"(?:no\s+)?(?:tool\s+)?(?:allow|block|deny)\s*(?:list|listing)\s*(?:is\s+)?(?:empty|disabled|off)",
            0.7,
            true,
        ),
    ],
};

const EA2: Rule = Rule {
    id: "EA2",
    message: "Autonomous Decision Making",
    severity: Severity::Medium,
    entries: &[
        (
            r"(?:auto[_-]?approve|auto[_-]?confirm|auto[_-]?execute|auto[_-]?deploy)",
            0.85,
            false,
        ),
        (r"(?:--auto-?approve|--no-?confirm)\b", 0.65, false),
        (
            r"(?:without|no)\s+(?:asking|confirmation|approval|consent|verification|checking)",
            0.75,
            true,
        ),
        (
            r"(?:auto(?:matically)?|autonomously)\s+(?:execute|run|perform|delete|remove|modify|send|deploy)",
            0.8,
            true,
        ),
        (
            r"(?:skip|bypass|disable)\s+(?:user\s+)?(?:confirmation|approval|consent|verification|prompt)",
            0.85,
            true,
        ),
        (
            r"(?:do\s+not|don't|never)\s+(?:ask|prompt|confirm|verify|check)\s+(?:the\s+)?(?:user|before)",
            0.8,
            true,
        ),
        (
            r"(?:proceed|continue|execute)\s+without\s+(?:waiting|asking)\s+(?:for\s+)?(?:user|human|permission)",
            0.8,
            true,
        ),
        (
            r"(?:assume|presume)\s+(?:user\s+)?(?:consent|approval|permission)",
            0.7,
            true,
        ),
        (
            r"(?:if|when)\s+(?:unsure|uncertain).*?(?:proceed|continue|execute)\s+(?:anyway|regardless)",
            0.75,
            true,
        ),
    ],
};

const EA3: Rule = Rule {
    id: "EA3",
    message: "Scope Creep",
    severity: Severity::Low,
    entries: &[
        (
            r"(?:also|additionally|furthermore)\s+(?:perform|execute|run|do|handle|manage)\s+(?:any|all|other)",
            0.65,
            true,
        ),
        (
            r"(?:while\s+you(?:'re|\s+are)\s+at\s+it|in\s+addition|on\s+top\s+of\s+that)\s*[,.]?\s*(?:also\s+)?(?:do|perform|execute|run)",
            0.7,
            true,
        ),
        (
            r"(?:extend|expand|broaden)\s+(?:your|the\s+)?(?:scope|functionality|capabilities|responsibilities)",
            0.75,
            true,
        ),
        (
            r"(?:not\s+limited\s+to|beyond\s+(?:the\s+)?(?:scope|stated|described|documented))",
            0.7,
            true,
        ),
        (
            r"(?:take\s+over|assume\s+control\s+of|manage)\s+(?:all|any|every)\s+(?:aspect|part|area)",
            0.75,
            true,
        ),
        (
            r"(?:you\s+(?:can|should|must)\s+)?(?:handle|manage)\s+(?:everything|anything|all\s+tasks?)",
            0.7,
            true,
        ),
        (
            r"(?:act\s+as|become|serve\s+as)\s+(?:a\s+)?(?:general[- ]purpose|universal|all[- ]in[- ]one|omniscient)",
            0.65,
            true,
        ),
        (
            r"(?:you\s+are\s+)?(?:responsible\s+for|in\s+charge\s+of)\s+(?:everything|all\s+(?:systems?|operations?|tasks?))",
            0.7,
            true,
        ),
    ],
};

const EA4: Rule = Rule {
    id: "EA4",
    message: "Unbounded Resource Access",
    severity: Severity::Medium,
    entries: &[
        (
            r#"max[_-]?retries?\s*=\s*(?:None|0|float\s*\(\s*['\"]inf['\"]|math\.inf|infinity)"#,
            0.8,
            false,
        ),
        (
            r#"timeout\s*=\s*(?:None|0|float\s*\(\s*['\"]inf['\"]|math\.inf)"#,
            0.75,
            false,
        ),
        (
            r"(?:unlimited|infinite|unbounded|no\s+limit(?:s)?(?:\s+on)?)\s+(?:api\s+)?(?:calls?|requests?|queries?|invocations?)",
            0.8,
            true,
        ),
        (
            r"(?:no|without)\s+(?:rate\s+)?limit(?:s|ing)?\s+(?:on|for|when)\s+(?:api|tool|request|query)",
            0.7,
            true,
        ),
        (
            r"(?:no|without)\s+(?:timeout|budget|quota|cap|ceiling)\s+(?:on|for|when)\s+(?:api|tool|request|execution)",
            0.7,
            true,
        ),
        (
            r"(?:loop|iterate|repeat)\s+(?:indefinitely|forever|infinitely|endlessly)",
            0.75,
            true,
        ),
        (
            r"(?:retry|attempt)\s+(?:indefinitely|forever|without\s+limit|unlimited\s+times)",
            0.75,
            true,
        ),
        (
            r"(?:allocate|consume|use)\s+(?:as\s+much|unlimited|unbounded)\s+(?:memory|storage|disk|compute|cpu|gpu)",
            0.8,
            true,
        ),
        (
            r"(?:no|without)\s+(?:resource\s+)?(?:constraints?|limits?|quotas?|budgets?)\s+(?:on|for|when)\s+(?:api|tool|execution|request|compute)",
            0.7,
            true,
        ),
    ],
};

const RULES: [&Rule; 4] = [&EA1, &EA2, &EA3, &EA4];

const APPROVAL_OBJECT: &str = r"(?:(?:new|additional|external)\s+)?(?:dependencies|changes|files|commands|deployments|purchases|requests|actions)";
const PROHIBITED_ACTION_OBJECT: &str =
    r"(?:(?:all|any|new)\s+)?(?:files|commands|changes|requests|messages|dependencies)";
const APPROVAL_SOURCES: [(&str, &str); 3] = [
    (
        r"\b(?P<action>(?:add|install|introduce|make|delete|remove|modify|run|execute|send)\s+OBJ|deploy)\s+$",
        "i",
    ),
    (r"\bno\s+(?P<object>OBJ)\s+$", "i"),
    (PROHIBITED_ACTION_OBJECT, "i"),
];

static COMPILED: LazyLock<Vec<Vec<Pat>>> = LazyLock::new(|| {
    RULES
        .iter()
        .map(|r| r.entries.iter().map(|e| Pat::new(e.0, FLAGS)).collect())
        .collect()
});

struct Approval {
    action: Pat,
    constraint: Pat,
    tail: AllowedTail,
}

static APPROVAL: LazyLock<Approval> = LazyLock::new(|| Approval {
    action: Pat::new(&APPROVAL_SOURCES[0].0.replace("OBJ", APPROVAL_OBJECT), "i"),
    constraint: Pat::new(&APPROVAL_SOURCES[1].0.replace("OBJ", APPROVAL_OBJECT), "i"),
    tail: AllowedTail::new(PROHIBITED_ACTION_OBJECT, "i"),
});

fn cut_chars(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

/// `_requires_approval`: a local requirement for approval, without negating other actions.
fn requires_approval(content: &str, start: usize, end: usize) -> bool {
    if !content[start..end].to_lowercase().starts_with("without") {
        return false;
    }
    let prefix_start = content[..start]
        .char_indices()
        .rev()
        .nth(159)
        .map_or(0, |(i, _)| i);
    let prefix = &content[prefix_start..start];
    let opts = Options::default();
    if let Some(a) = APPROVAL.action.find_iter(prefix).first() {
        return is_directly_prohibited(content, prefix_start + a.start, end, &opts);
    }
    let Some(c) = APPROVAL.constraint.find_iter(prefix).into_iter().next() else {
        return false;
    };
    let Some(Some((object_start, _))) = c.groups.get(1) else {
        return false;
    };
    is_directly_prohibited(content, prefix_start + object_start, end, &opts)
}

fn finding(
    rule: &Rule,
    conf: f32,
    path: &str,
    text: &str,
    idx: &LineIndex,
    at: (usize, usize),
) -> RawFinding {
    let full = &text[at.0..at.1];
    let mut f = RawFinding::new(
        rule.id,
        rule.message,
        rule.severity,
        conf,
        path,
        idx.line(at.0),
    );
    f.tags = vec![CATEGORY_TAG.to_owned()];
    f.context = Some(get_context(text, at.0));
    f.matched_text = Some(cut_chars(full, 200).to_owned());
    f.fingerprint_text = Some(full.to_owned());
    f
}

/// EA1-EA4 for one text.
fn analyze_patterns(text: &str, path: &str) -> Vec<RawFinding> {
    let idx = LineIndex::new(text);
    let mut out = Vec::new();
    let ea2_opts = Options {
        allowed_tail: Some(&APPROVAL.tail),
        ..Options::default()
    };
    for (rule, pats) in RULES.iter().zip(COMPILED.iter()) {
        for (entry, pat) in rule.entries.iter().zip(pats) {
            let prose = entry.2 || rule.id == "EA3";
            let hits = if prose {
                paragraph_matches(pat, text)
            } else {
                pat.find_iter(text)
            };
            for h in hits {
                if rule.id == "EA2"
                    && prose
                    && (is_directly_prohibited(text, h.start, h.end, &ea2_opts)
                        || requires_approval(text, h.start, h.end))
                {
                    continue;
                }
                out.push(finding(rule, entry.1, path, text, &idx, (h.start, h.end)));
            }
        }
    }
    out
}

/// `static_patterns_excessive_agency`.
pub struct ExcessiveAgency;

impl StaticModule for ExcessiveAgency {
    fn id(&self) -> &'static str {
        "static_patterns_excessive_agency"
    }

    fn analyze(
        &self,
        text: &str,
        path: &str,
        _ft: FileType,
        _py: Option<&PyFile>,
    ) -> Vec<RawFinding> {
        let mut out = analyze_patterns(text, path);
        out.extend(model_selection::ea5_findings(text, path));
        out
    }
}

#[cfg(test)]
/// Every pattern source (with its flags) of EA1-EA5, so tests can compile them all.
pub fn pattern_sources() -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = RULES
        .iter()
        .flat_map(|r| r.entries.iter().map(|e| (e.0.to_owned(), FLAGS)))
        .collect();
    out.extend(APPROVAL_SOURCES.iter().map(|(s, f)| ((*s).to_owned(), *f)));
    out.extend(model_selection::pattern_sources());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(text: &str, rule: &str) -> Vec<(u32, String)> {
        analyze_patterns(text, "SKILL.md")
            .into_iter()
            .filter(|f| f.rule_id == rule)
            .map(|f| (f.start_line, f.matched_text.unwrap_or_default()))
            .collect()
    }

    #[test]
    fn all_regexes_compile() {
        for (src, flags) in pattern_sources() {
            let src = src.replace("OBJ", APPROVAL_OBJECT);
            Pat::try_new(&src, flags).unwrap_or_else(|e| panic!("{e}"));
        }
    }

    #[test]
    fn ea1_wildcard_stays_on_one_line_and_is_a_standalone_token() {
        for c in [
            "For each tool:\n\n**Input Schema:**\n",
            "tools:\n*\n",
            "**API Coverage vs. Workflow Tools:**\n",
            "Tools: **Read**, **Write**\n",
        ] {
            assert!(ids(c, "EA1").is_empty(), "{c:?}");
        }
        for c in [
            "tools: \"*\"\n",
            "tools: [*]\n",
            "permissions: '*'\n",
            "tools: *\n",
        ] {
            assert_eq!(ids(c, "EA1").len(), 1, "{c:?}");
        }
    }

    #[test]
    fn approval_requirements_are_not_ea2() {
        for c in [
            "[Stack version, naming conventions, no new dependencies without asking]",
            "- [Stack version, naming conventions, no new dependencies without asking]\n- Only make changes directly requested. Do not add features, abstractions, or files beyond what was asked.",
            "No changes without approval.",
            "Do not add new dependencies without asking.",
            "Never deploy without approval.",
            "You must not delete files without confirmation.",
            "Do not automatically delete files.",
            "Never skip user confirmation.",
            "Do not assume consent.",
        ] {
            assert!(ids(c, "EA2").is_empty(), "{c:?}");
        }
    }

    #[test]
    fn affirmative_bypasses_remain_ea2() {
        for c in [
            "Add new dependencies without asking.",
            "Deploy without approval.",
            "Do not ask the user before deploying.",
            "Never confirm before deleting files.",
            "Do not hesitate to deploy without approval.",
            "Never fail to automatically delete files.",
            "No new dependencies; deploy without asking.",
            "No changes are necessary; execute without confirmation.",
            "Do not modify files, but deploy without approval.",
            "Do not modify files then deploy without approval.",
            "Do not run commands; use --auto-approve.",
            "No new dependencies without asking, but deploy without approval.",
            "Do not skip user confirmation; automatically delete files.",
            "Do not deploy without approval twice; do it once.",
            "Do not automatically delete files locally; do it remotely.",
            "Never bypass user approval? Actually yes, do it.",
        ] {
            assert!(!ids(c, "EA2").is_empty(), "{c:?}");
        }
    }

    #[test]
    fn mixed_approval_requirement_keeps_the_operative_location() {
        let got = ids(
            "No new dependencies without asking.\nDeploy without approval.",
            "EA2",
        );
        assert!(!got.is_empty());
        assert!(
            got.iter()
                .all(|(line, text)| *line == 2 && text == "without approval")
        );
    }

    #[test]
    fn ea3_ea4_basics() {
        assert_eq!(ids("Also perform any task.", "EA3").len(), 1);
        assert_eq!(ids("timeout = None", "EA4").len(), 1);
        assert_eq!(ids("Loop forever.", "EA4").len(), 1);
    }
}
