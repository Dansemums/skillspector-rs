//! AS1-AS3 from `static_patterns_agent_snooping.py`: reading agent config directories (AS1), MCP
//! config files (AS2) and other installed skills (AS3).
//!
//! AS3 skips exact path references to the skill being scanned, so the module carries the skill's
//! identity. `StaticModule` has no access to the skill, so it is registered as an [`Analyzer`] that
//! builds the module per skill and runs it through the static runner.

use super::common::{Head, hit_finding, is_directly_prohibited};
use crate::analyzer::Analyzer;
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::matcher::{Pat, paragraph_matches};
use crate::pyast::PyFile;
use crate::runner::{StaticModule, run_static};
use crate::skill::{FileType, Skill};
use crate::text::LineIndex;
use crate::unicode::is_space;
use std::sync::LazyLock;

const TAG: &str = "Agent Snooping";

const AS3_SKILL_PATH: &str = r"skills?/(?P<skill_name>(?!CURRENT)[A-Z][A-Za-z0-9_-]+)/SKILL\.md";

/// (source, confidence, prose). Prose patterns match inside paragraphs and honour prohibitions.
type Rule = (&'static str, f32, bool);

const AS1: [Rule; 7] = [
    (
        r#"open\s*\(\s*['"]?\.(?:claude|codex|gemini|continue)/"#,
        0.9,
        false,
    ),
    (
        r#"(?:Path|pathlib\.Path)\s*\(\s*['"]?\.(?:claude|codex|gemini|continue)/"#,
        0.9,
        false,
    ),
    (
        r#"os\.path\.(?:join|exists|isfile)\s*\(\s*['"]?\.(?:claude|codex|gemini|continue)"#,
        0.85,
        false,
    ),
    (
        r"(?:cat|less|head|tail|grep|find)\s+[^|&;\n]*~?/?\.(claude|codex|gemini)/",
        0.85,
        false,
    ),
    (
        r"~?/\.(?:claude|codex|gemini|continue)/(?:config|settings?|preferences?|credentials?)(?:\.(?:json|yaml|yml|toml))?",
        0.9,
        false,
    ),
    (
        r"(?:read|load|open|access|fetch)\s+(?:the\s+)?(?:agent|claude|codex|gemini)\s+(?:config|configuration|settings?)\s+(?:from|at|in)\s+~?/?\.(?:claude|codex|gemini)",
        0.9,
        true,
    ),
    (
        r"(?:read|access|inspect|examine|retrieve)\s+(?:the\s+)?(?:agent|assistant)\s+(?:config(?:uration)?|settings?|preferences?)\s+(?:file|directory|folder)",
        0.8,
        true,
    ),
];

const AS2: [Rule; 7] = [
    (
        r#"open\s*\(\s*['"][^'"]*mcp(?:_config)?\.json['"]"#,
        0.95,
        false,
    ),
    (
        r#"(?:Path|pathlib\.Path)\s*\(\s*['"][^'"]*mcp(?:_config)?\.json['"]"#,
        0.9,
        false,
    ),
    (
        r"(?:cat|less|head|grep)\s+[^|&;\n]*mcp(?:_config)?\.json",
        0.9,
        false,
    ),
    (
        r"\.(?:claude|codex|gemini)/mcp(?:_config)?\.json",
        0.95,
        false,
    ),
    (
        r"mcp(?:_config)?\.json.*?(?:api_?key|token|secret|url|endpoint)",
        0.9,
        false,
    ),
    (
        r"(?:read|access|load|inspect)\s+(?:the\s+)?mcp(?:\.json|_config)?\s+(?:file|config(?:uration)?|settings?)",
        0.9,
        true,
    ),
    (
        r"(?:list|enumerate|discover)\s+(?:all\s+)?(?:available\s+)?mcp\s+(?:servers?|tools?|services?)",
        0.8,
        true,
    ),
];

const AS3: [Rule; 7] = [
    (
        r"(?:os\.listdir|os\.scandir|glob\.glob|Path\.iterdir)\s*\([^)]*\.(?:claude|codex|gemini)/skills?",
        0.9,
        false,
    ),
    (
        r"(?<![\w-])g?(?:ls|find|dir)\s+[^|&;\n]*\.(?:claude|codex|gemini)/skills?",
        0.85,
        false,
    ),
    (
        r#"open\s*\(\s*['"][^'"]*SKILL\.md['"].*?\bother\b"#,
        0.85,
        false,
    ),
    (AS3_SKILL_PATH, 0.8, false),
    (
        r"(?:read|access|inspect|enumerate)\s+(?:all\s+)?(?:installed|available|other)\s+skills?(?:\s+in\s+(?:the\s+)?(?:skills?|agent)\s+(?:directory|folder))?",
        0.85,
        true,
    ),
    (
        r"(?:list|discover|find|enumerate|identify)\s+(?:all\s+)?(?:other|installed|available)\s+(?:skills?|agents?|tools?)\s+(?:in\s+)?(?:the\s+)?(?:\.(?:claude|codex|gemini)|\$HOME)",
        0.85,
        true,
    ),
    (
        r"(?:read|access|load)\s+(?:the\s+)?(?:SKILL|skill)\.md\s+(?:file\s+)?(?:of|from|for)\s+(?:another|other|different|all)\s+(?:skill|agent|tool)",
        0.9,
        true,
    ),
];

fn compile(rules: &[Rule]) -> Vec<Pat> {
    rules.iter().map(|r| Pat::new(r.0, "im")).collect()
}

static AS1_PATS: LazyLock<Vec<Pat>> = LazyLock::new(|| compile(&AS1));
static AS2_PATS: LazyLock<Vec<Pat>> = LazyLock::new(|| compile(&AS2));
static AS3_PATS: LazyLock<Vec<Pat>> = LazyLock::new(|| compile(&AS3));
static AS3_PATH_FULL: LazyLock<Pat> = LazyLock::new(|| Pat::new(AS3_SKILL_PATH, "i"));

/// `_is_current_skill_path_reference`: the whole match is `skills/<name>/SKILL.md` for this skill.
fn names_current_skill(matched: &str, current: &[String]) -> bool {
    if current.is_empty() {
        return false;
    }
    let Some(hit) = AS3_PATH_FULL.find_iter(matched).into_iter().next() else {
        return false;
    };
    if hit.start != 0 || hit.end != matched.len() {
        return false;
    }
    hit.group(matched, 1)
        .map(|n| n.trim_matches(is_space))
        .is_some_and(|n| !n.is_empty() && current.iter().any(|c| c == n))
}

fn head(rule: &'static str, message: &'static str, severity: Severity) -> Head<'static> {
    Head {
        rule,
        message,
        severity,
        tag: TAG,
    }
}

/// AS1-AS3 for one skill identity.
#[derive(Debug, Default)]
pub struct AgentSnooping {
    current: Vec<String>,
}

impl AgentSnooping {
    /// The module for a skill named `current` (`_current_skill_identifiers`).
    #[must_use]
    pub fn for_skill(skill: &Skill) -> Self {
        Self {
            current: current_identifiers(skill),
        }
    }
}

/// `_current_skill_identifiers`: the folder name, unless the manifest name disagrees.
fn current_identifiers(skill: &Skill) -> Vec<String> {
    let path_id = skill
        .root
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.trim_matches(is_space))
        .filter(|n| !n.is_empty());
    let Some(path_id) = path_id else {
        return Vec::new();
    };
    let manifest_id = skill
        .manifest
        .as_ref()
        .and_then(|m| m.name.as_deref())
        .map(|n| n.trim_matches(is_space))
        .filter(|n| !n.is_empty());
    if manifest_id.is_some_and(|m| m != path_id) {
        return Vec::new();
    }
    vec![path_id.to_owned()]
}

impl StaticModule for AgentSnooping {
    fn id(&self) -> &'static str {
        "static_patterns_agent_snooping"
    }

    fn analyze(
        &self,
        text: &str,
        path: &str,
        _ft: FileType,
        _py: Option<&PyFile>,
    ) -> Vec<RawFinding> {
        let index = LineIndex::new(text);
        let mut out = Vec::new();
        let groups: [(Head<'_>, &[Rule], &[Pat]); 3] = [
            (
                head("AS1", "Agent Config Directory Access", Severity::High),
                &AS1,
                &AS1_PATS,
            ),
            (
                head("AS2", "MCP Config Access", Severity::High),
                &AS2,
                &AS2_PATS,
            ),
            (
                head("AS3", "Skill Enumeration", Severity::Medium),
                &AS3,
                &AS3_PATS,
            ),
        ];
        for (h, rules, pats) in groups {
            let id = h.rule;
            for (rule, pat) in rules.iter().zip(pats) {
                let hits = if rule.2 {
                    paragraph_matches(pat, text)
                } else {
                    pat.find_iter(text)
                };
                for hit in &hits {
                    // AS1 and AS2 prose are not subject to prohibitions in the Python source.
                    if id == "AS3" && rule.2 && is_directly_prohibited(text, hit.start, hit.end) {
                        continue;
                    }
                    // A derived view only skips a reference that is unchanged from the source text.
                    if id == "AS3"
                        && names_current_skill(hit.text(text), &self.current)
                        && crate::views::match_is_literal(text, hit.start, hit.end)
                    {
                        continue;
                    }
                    out.push(hit_finding(&h, rule.1, path, text, hit, &index));
                }
            }
        }
        out
    }
}

/// Registers [`AgentSnooping`] with the skill's identity.
pub struct AgentSnoopingAnalyzer;

impl Analyzer for AgentSnoopingAnalyzer {
    fn id(&self) -> &'static str {
        "static_patterns_agent_snooping"
    }

    fn run(&self, skill: &Skill) -> Vec<RawFinding> {
        run_static(skill, &[&AgentSnooping::for_skill(skill)])
    }
}

#[cfg(test)]
/// Every pattern with its flags, so tests can compile them all.
pub fn all_patterns() -> Vec<&'static str> {
    [AS1.as_slice(), AS2.as_slice(), AS3.as_slice()]
        .concat()
        .iter()
        .map(|r| r.0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(files: &[(&str, &str)], root: &str) -> Vec<RawFinding> {
        let mut skill = Skill::from_memory(
            files
                .iter()
                .map(|(n, t)| ((*n).to_owned(), t.as_bytes().to_vec()))
                .collect(),
        );
        skill.root = root.into();
        AgentSnoopingAnalyzer.run(&skill)
    }

    #[test]
    fn all_patterns_compile() {
        for p in all_patterns() {
            assert!(Pat::try_new(p, "im").is_ok(), "{p}");
        }
    }

    #[test]
    fn config_and_mcp_access() {
        let f = scan(
            &[(
                "a.py",
                "x = open('.claude/settings.json')\nopen('mcp.json')\n",
            )],
            "/x/s",
        );
        let ids: Vec<_> = f.iter().map(|f| (f.rule_id, f.start_line)).collect();
        assert!(ids.contains(&("AS1", 1)));
        assert!(ids.contains(&("AS2", 2)));
    }

    #[test]
    fn current_skill_path_is_excluded_other_is_flagged() {
        let text = "See skills/Alpha-Skill/SKILL.md and skills/Other-Skill/SKILL.md\n";
        let f = scan(&[("a.md", text)], "/x/Alpha-Skill");
        let hits: Vec<_> = f.iter().filter(|f| f.rule_id == "AS3").collect();
        assert_eq!(hits.len(), 1);
        assert!(
            hits[0]
                .matched_text
                .as_deref()
                .is_some_and(|t| t.contains("Other"))
        );
    }

    #[test]
    fn manifest_disagreement_clears_identity() {
        let files = [(
            "SKILL.md",
            "---\nname: Beta\ndescription: d\n---\nskills/Alpha/SKILL.md\n",
        )];
        let f = scan(&files, "/x/Alpha");
        assert_eq!(f.iter().filter(|f| f.rule_id == "AS3").count(), 1);
    }

    #[test]
    fn ls_skills_directory_and_prose() {
        let f = scan(&[("a.sh", "ls ~/.claude/skills\n")], "/x/s");
        assert!(f.iter().any(|f| f.rule_id == "AS3"));
        let f = scan(
            &[("a.md", "Please enumerate all other skills now.\n")],
            "/x/s",
        );
        assert!(f.iter().any(|f| f.rule_id == "AS3"));
    }

    #[test]
    fn enumeration_operations_and_standard_installation() {
        for op in ["ls", "find", "dir", "gls", "gfind", "/usr/local/bin/gls"] {
            let f = scan(&[("a.md", &format!("{op} ~/.claude/skills"))], "/x/s");
            assert!(f.iter().any(|f| f.rule_id == "AS3"), "{op}");
        }
        let f = scan(
            &[("a.md", "cat ~/.claude/skills/other-skill/SKILL.md")],
            "/x/s",
        );
        assert!(f.iter().any(|f| f.rule_id == "AS3"));
        for agent in ["claude", "codex", "gemini"] {
            let t = format!(
                "mkdir -p ~/.{agent}/skills/prompt-master\ngit clone https://github.com/nidhinjs/prompt-master.git ~/.{agent}/skills/prompt-master\n"
            );
            assert!(scan(&[("install.sh", &t)], "/x/s").is_empty(), "{agent}");
        }
        for prefix in ["mkdir", "mydir", "my-dir"] {
            assert!(
                scan(
                    &[("a.sh", &format!("{prefix} -p ~/.claude/skills"))],
                    "/x/s"
                )
                .is_empty()
            );
        }
    }

    #[test]
    fn unknown_or_mismatched_identity_flags_every_reference() {
        let text = "skills/example-skill/SKILL.md\nskills/different-skill/SKILL.md";
        // No usable folder name: nothing is excluded.
        assert_eq!(
            scan(&[("a.md", text)], "")
                .iter()
                .filter(|f| f.rule_id == "AS3")
                .count(),
            2
        );
        // A matching folder name excludes only itself.
        let f = scan(&[("a.md", text)], "/tmp/example-skill");
        assert_eq!(f.iter().filter(|f| f.rule_id == "AS3").count(), 1);
    }
}
