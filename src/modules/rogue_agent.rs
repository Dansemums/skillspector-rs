//! RA1-RA2 from `static_patterns_rogue_agent.py`: skill self-modification (RA1) and unauthorised
//! persistence (RA2). A `self-update` of a documented signed companion CLI is reported as a
//! low-severity "Signed Companion CLI Update", which changes the message, severity and group key.

use super::common::{Head, hit_finding, is_directly_prohibited};
use super::rogue_agent_ctx::{
    Lines, STANDARD_SKILL_MKDIR, hidden_directory_write_pattern, is_negated_safety_constraint,
    is_signed_companion_cli_update, unsafe_skill_install_context,
};
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::matcher::{Hit, Pat, paragraph_matches};
use crate::pyast::PyFile;
use crate::runner::StaticModule;
use crate::skill::FileType;
use crate::text::LineIndex;
use std::sync::LazyLock;

const TAG: &str = "Rogue Agent";

/// (source, confidence, prose).
type Rule = (&'static str, f32, bool);

const RA1: [Rule; 12] = [
    (r#"open\s*\(\s*__file__\s*,\s*['"]w"#, 0.95, false),
    (
        r"(?:Path|pathlib)\s*\(\s*__file__\s*\)\s*\.\s*write_text",
        0.95,
        false,
    ),
    (
        r"(?:self[_-]?modify|self[_-]?update|self[_-]?rewrite|self[_-]?patch|self[_-]?evolve)",
        0.9,
        false,
    ),
    (
        r#"open\s*\(\s*['"](?:SKILL\.md|skill\.md)['"].*?['"]w"#,
        0.9,
        false,
    ),
    (
        r"(?:write|modify|edit|update|overwrite|patch)\s+(?:this\s+)?(?:skill(?:'s)?|SKILL\.md|skill\.md)",
        0.85,
        true,
    ),
    (
        r"(?:modify|edit|change|rewrite|update|alter)\s+(?:your\s+own|its\s+own|this\s+skill(?:'s)?)\s+(?:code|source|file|script|config|configuration|instructions?|rules?)",
        0.9,
        true,
    ),
    (
        r"(?:rewrite|replace|overwrite)\s+(?:the\s+)?(?:current|existing|original)\s+(?:code|script|file|config|skill)",
        0.85,
        true,
    ),
    (
        r"(?:append|add|inject|insert)\s+(?:code|instructions?|rules?)\s+(?:to|into)\s+(?:this|the\s+current|your\s+own)\s+(?:file|skill|script)",
        0.85,
        true,
    ),
    (
        r"(?:generate|create|write)\s+(?:new|updated|replacement)\s+(?:code|version)\s+(?:for|of)\s+(?:this|itself|the\s+skill)",
        0.8,
        true,
    ),
    (
        r"(?:update|modify|change|edit)\s+(?:the\s+)?(?:config|configuration|settings|parameters)\s+(?:of\s+)?(?:this|the\s+current)\s+(?:skill|agent|tool)",
        0.75,
        true,
    ),
    (
        r"(?:disable|remove|delete|bypass)\s+(?:the\s+)?(?:safety|security|guard|protection|constraint)\s+(?:check|rule|mechanism|feature)",
        0.9,
        true,
    ),
    (
        r"(?:comment\s+out|remove)\s+(?:the\s+)?(?:validation|verification|check|guard|assertion)",
        0.7,
        true,
    ),
];

const RA2_CODE: [(&str, f32); 5] = [
    (r"crontab\s+(?:-[el]|.*?>>?\s*/)", 0.85),
    (
        r"(?:systemd|systemctl|launchd|launchctl|init\.d)\s+.*?(?:enable|install|register|create)",
        0.8,
    ),
    (r"(?:nohup|disown|setsid)\s+", 0.65),
    (r"(?:HKEY_|RegOpenKey|RegSetValue|reg\s+add)\s+", 0.8),
    (
        r"(?:defaults\s+write|(?<![a-z])plist|launchctl\s+load)",
        0.75,
    ),
];
const RA2_HIDDEN_CONFIDENCE: f32 = 0.6;

const RA2_PROSE: [(&str, f32); 11] = [
    (
        r"(?:add|create|install|register)\s+(?:a\s+)?(?:cron\s+)?(?:job|task|entry)\s+(?:for|to|that)",
        0.8,
    ),
    (
        r"(?:schedule|register)\s+(?:a\s+)?(?:recurring|periodic|repeated|daily|hourly)\s+(?:task|job|command|script)",
        0.8,
    ),
    (
        r"(?:add|write|append|install)\s+(?:to|into)\s+(?:~/)?\.(?:bashrc|zshrc|profile|bash_profile|login|cshrc)",
        0.9,
    ),
    (
        r"(?:add|register|install)\s+(?:as\s+)?(?:a\s+)?(?:startup|boot|autostart|login)\s+(?:script|service|daemon|task|item)",
        0.85,
    ),
    (
        r"(?:create|install|register|add)\s+(?:a\s+)?(?:systemd\s+)?(?:service|daemon|agent)\s+(?:file|unit)",
        0.8,
    ),
    (
        r"(?:save|write|persist|store|dump)\s+(?:the\s+)?(?:state|session|context|data)\s+(?:to|in)\s+(?:a\s+)?(?:file|disk|database|storage)",
        0.6,
    ),
    (
        r"(?:restore|load|read|resume)\s+(?:the\s+)?(?:previous|saved|persisted|stored)\s+(?:state|session|context|data)",
        0.55,
    ),
    (
        r"(?:persist|maintain|keep|preserve)\s+(?:state|data|context|session)\s+(?:across|between|through)\s+(?:sessions?|restarts?|reboots?|invocations?)",
        0.75,
    ),
    (
        r"(?:create|make|write)\s+(?:a\s+)?(?:hidden|dot)\s+(?:file|directory|folder)",
        0.65,
    ),
    (
        r"(?:start|launch|spawn|fork)\s+(?:a\s+)?(?:background|daemon|detached)\s+(?:process|service|worker|task)",
        0.7,
    ),
    (
        r"(?:run|execute)\s+(?:in\s+the\s+)?background\s+(?:and\s+)?(?:detach|persist|survive)",
        0.75,
    ),
];

fn pats<'a>(srcs: impl Iterator<Item = &'a str>) -> Vec<Pat> {
    srcs.map(|s| Pat::new(s, "im")).collect()
}

static RA1_PATS: LazyLock<Vec<Pat>> = LazyLock::new(|| pats(RA1.iter().map(|r| r.0)));
static RA2_CODE_PATS: LazyLock<Vec<Pat>> = LazyLock::new(|| pats(RA2_CODE.iter().map(|r| r.0)));
static RA2_PROSE_PATS: LazyLock<Vec<Pat>> = LazyLock::new(|| pats(RA2_PROSE.iter().map(|r| r.0)));
static HIDDEN_DIR: LazyLock<Pat> =
    LazyLock::new(|| Pat::new(&hidden_directory_write_pattern(), "im"));

/// RA1-RA2.
pub struct RogueAgent;

impl RogueAgent {
    fn ra1(
        text: &str,
        path: &str,
        ft: FileType,
        index: &LineIndex,
        lines: &Lines,
    ) -> Vec<RawFinding> {
        let mut out = Vec::new();
        for (rule, pat) in RA1.iter().zip(RA1_PATS.iter()) {
            let hits = if rule.2 {
                paragraph_matches(pat, text)
            } else {
                pat.find_iter(text)
            };
            for hit in &hits {
                if is_negated_safety_constraint(text, hit.start, hit.end, lines) {
                    continue;
                }
                let companion = matches!(ft, FileType::Markdown | FileType::Text)
                    && is_signed_companion_cli_update(text, hit.start, hit.end, lines);
                let head = Head {
                    rule: "RA1",
                    message: if companion {
                        "Signed Companion CLI Update"
                    } else {
                        "Self-Modification"
                    },
                    severity: if companion {
                        Severity::Low
                    } else {
                        Severity::High
                    },
                    tag: TAG,
                };
                let conf = if companion { rule.1.min(0.15) } else { rule.1 };
                let mut f = hit_finding(&head, conf, path, text, hit, index);
                if companion {
                    f.tags.extend([
                        "contextual-triage".to_owned(),
                        "likely-benign-context".to_owned(),
                    ]);
                    f.remediation = Some(
                        "No skill self-modification change is indicated by this match. Keep signature verification mandatory and identify the companion CLI explicitly."
                            .to_owned(),
                    );
                    f.explanation = Some(
                        "The matched phrase is a signed self-update subcommand for a documented companion CLI; it does not direct the skill or agent to rewrite itself."
                            .to_owned(),
                    );
                    // The runner records the exact source start for this finding.
                    f.start_column = Some(index.col_chars(text, hit.start));
                }
                out.push(f);
            }
        }
        out
    }

    /// The hit to report for a hidden-directory write, or `None` when it is a plain skills `mkdir`.
    fn hidden_dir_hit(text: &str, hit: &Hit, lines: &Lines) -> Option<Hit> {
        let (line_start, line_end) = lines.bounds(hit.start);
        let line = &text[line_start..line_end];
        let Some(mkdir) = STANDARD_SKILL_MKDIR.find_iter(line).into_iter().next() else {
            return Some(hit.clone());
        };
        let target = mkdir.group(line, 2).unwrap_or("");
        unsafe_skill_install_context(text, line_start, target, lines).map(|(s, e)| Hit {
            start: s,
            end: e,
            groups: vec![Some((s, e))],
        })
    }

    fn ra2(text: &str, path: &str, index: &LineIndex, lines: &Lines) -> Vec<RawFinding> {
        let mut out = Vec::new();
        let head = Head {
            rule: "RA2",
            message: "Session Persistence",
            severity: Severity::Medium,
            tag: TAG,
        };
        let mut push = |hit: &Hit, conf: f32| {
            out.push(hit_finding(&head, conf, path, text, hit, index));
        };
        for (rule, pat) in RA2_CODE.iter().zip(RA2_CODE_PATS.iter()) {
            for hit in pat.find_iter(text) {
                push(&hit, rule.1);
            }
        }
        // Declaration order: the hidden-directory pattern sits between the second and third code rules.
        for hit in HIDDEN_DIR.find_iter(text) {
            if let Some(h) = Self::hidden_dir_hit(text, &hit, lines) {
                push(&h, RA2_HIDDEN_CONFIDENCE);
            }
        }
        for (rule, pat) in RA2_PROSE.iter().zip(RA2_PROSE_PATS.iter()) {
            for hit in paragraph_matches(pat, text) {
                if !is_directly_prohibited(text, hit.start, hit.end) {
                    push(&hit, rule.1);
                }
            }
        }
        out
    }
}

impl StaticModule for RogueAgent {
    fn id(&self) -> &'static str {
        "static_patterns_rogue_agent"
    }

    fn analyze(
        &self,
        text: &str,
        path: &str,
        ft: FileType,
        _py: Option<&PyFile>,
    ) -> Vec<RawFinding> {
        let index = LineIndex::new(text);
        let lines = Lines::new(text);
        let mut out = Self::ra1(text, path, ft, &index, &lines);
        out.extend(Self::ra2(text, path, &index, &lines));
        out
    }
}

#[cfg(test)]
/// Every pattern with its flags, so tests can compile them all.
pub fn all_patterns() -> Vec<String> {
    let mut v: Vec<String> = RA1.iter().map(|r| r.0.to_owned()).collect();
    v.extend(RA2_CODE.iter().map(|r| r.0.to_owned()));
    v.extend(RA2_PROSE.iter().map(|r| r.0.to_owned()));
    v.push(hidden_directory_write_pattern());
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skill::Skill;

    fn scan(name: &str, text: &str) -> Vec<RawFinding> {
        let skill = Skill::from_memory(vec![(name.to_owned(), text.as_bytes().to_vec())]);
        crate::runner::run_static(&skill, &[&RogueAgent])
    }

    #[test]
    fn all_patterns_compile() {
        for p in all_patterns() {
            assert!(Pat::try_new(&p, "im").is_ok(), "{p}");
        }
        for (p, flags) in super::super::rogue_agent_ctx::all_patterns() {
            assert!(Pat::try_new(&p, flags).is_ok(), "{p}");
        }
    }

    #[test]
    fn negated_constraint_is_not_flagged() {
        assert!(scan("a.md", "You must not modify this skill.\n").is_empty());
        let f = scan("a.md", "Please modify this skill now.\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "RA1");
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn signed_companion_update_is_low() {
        let t = "Use `acme-cli self-update --verify-signature` to install a signed CLI release.\n";
        let f = scan("a.md", t);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].message, "Signed Companion CLI Update");
        assert_eq!(f[0].severity, Severity::Low);
        assert!(f[0].tags.iter().any(|t| t == "likely-benign-context"));
        // Negated release, and a protected subject, keep the finding high.
        let neg = "Run `acme-cli self-update --verify-signature` but not a signed CLI release.\n";
        assert_eq!(scan("a.md", neg)[0].severity, Severity::High);
        let own = "Run `skill self-update --verify-signature` for a signed release.\n";
        assert_eq!(scan("a.md", own)[0].severity, Severity::High);
        assert_eq!(scan("a.py", t)[0].severity, Severity::High);
    }

    #[test]
    fn standard_skill_mkdir_is_exempt_but_writers_nearby_are_not() {
        assert!(scan("a.sh", "mkdir -p ~/.claude/skills/foo\n").is_empty());
        let t = "mkdir -p ~/.claude/skills/foo\ncp x ~/.claude/skills/foo/x\n";
        assert_eq!(
            scan("a.sh", t)
                .iter()
                .filter(|f| f.rule_id == "RA2")
                .count(),
            1
        );
        let clone = "mkdir -p ~/.claude/skills/foo\ngit clone https://example.com/r.git ~/.claude/skills/foo\n";
        assert!(scan("a.sh", clone).is_empty());
        assert_eq!(scan("a.sh", "mkdir ~/.hidden\n").len(), 1);
    }

    #[test]
    fn persistence_patterns() {
        let f = scan("a.sh", "crontab -e\nnohup ./run &\n");
        assert_eq!(f.iter().filter(|f| f.rule_id == "RA2").count(), 2);
        assert!(scan("a.md", "relationshipList\n").is_empty());
    }

    fn ra(text: &str, name: &str) -> Vec<RawFinding> {
        let skill = Skill::from_memory(vec![(name.to_owned(), text.as_bytes().to_vec())]);
        crate::runner::run_static(&skill, &[&RogueAgent])
    }

    fn ra_lines(text: &str, name: &str) -> Vec<(&'static str, u32)> {
        ra(text, name)
            .iter()
            .map(|f| (f.rule_id, f.start_line))
            .collect()
    }

    fn ra1(text: &str) -> Vec<RawFinding> {
        ra(text, "SKILL.md")
            .into_iter()
            .filter(|f| f.rule_id == "RA1")
            .collect()
    }

    fn high_only(text: &str) -> bool {
        let f = ra1(text);
        f.len() == 1
            && f[0].severity == Severity::High
            && !f[0].tags.iter().any(|t| t == "likely-benign-context")
    }

    #[test]
    fn standard_installation_is_not_persistence() {
        for agent in ["claude", "codex", "gemini"] {
            for target in ["", "/prompt-master"] {
                let t = format!(
                    "mkdir -p ~/.{agent}/skills{target}\ngit clone https://github.com/nidhinjs/prompt-master.git ~/.{agent}/skills/prompt-master\n"
                );
                assert!(ra(&t, "install.sh").is_empty(), "{t}");
            }
        }
        for t in [
            "mkdir ~/.claude/skills",
            "mkdir --parents ~/.claude/skills/",
            "mkdir -p -- ~/.claude/skills/prompt-master",
            "  mkdir -p \"~/.claude/skills/prompt-master\"  ",
            "mkdir -p ~/.claude/skills/helper\n\ngit clone https://example.test/helper.git $HOME/.claude/skills/helper\n",
            "mkdir -p ~/.claude/skills/helper\n\ngit clone https://example.test/helper.git ${HOME}/.claude/skills/helper/sub-skill\n",
            "mkdir -p ~/.claude/skills/helper\n\ngit clone https://example.test/helper.git /home/alice/.claude/skills/helper\n",
            "mkdir -p ~/.claude/skills/payload\ncp -r /tmp/payload /tmp/output\n",
        ] {
            assert!(ra(t, "README.md").is_empty(), "{t}");
        }
        for prose in [
            "Install into your Claude Code skills directory:",
            "The skill is free ($0).",
        ] {
            let t = format!(
                "## Installation\n\n{prose}\n\n```sh\nmkdir -p ~/.claude/skills\ngit clone https://github.com/example/helper.git ~/.claude/skills/helper\n```\n"
            );
            assert!(ra(&t, "SKILL.md").is_empty(), "{t}");
        }
        for prefix in ["mkdir", "mydir", "my-dir"] {
            assert!(ra(&format!("{prefix} -p ~/.claude/skills"), "a.sh").is_empty());
        }
    }

    #[test]
    fn hidden_writes_and_composition_remain_reported() {
        for t in [
            "mkdir -p ~/.hidden-agent",
            "mkdir -p ~/.claude/skills-other",
            "mkdir -p ~/.claude/skills/../../.hidden-agent",
            "mkdir -p ~/.claude/skills/.hidden-agent",
            "mkdir -p ~/.claude/skills /tmp/.hidden-agent",
            "mkdir -p ~/.claude/skills && crontab -e",
            "write ~/.claude/skills/agent/state.json",
            "mkdir \\\n    ~/.hidden-agent",
            "mkdir -p \\\r\n    ~/.hidden-agent",
        ] {
            assert!(ra(t, "README.md").iter().any(|f| f.rule_id == "RA2"), "{t}");
        }
        assert!(
            ra(
                "mkdir -p build && cp agent.desktop ~/.config/autostart/",
                "README.md"
            )
            .is_empty()
        );
        for sep in ["\n", "\r\n", "\r", "\u{2028}"] {
            let t = format!("mkdir -p ~/.claude/skills{sep}write ~/.hidden-agent/state.json{sep}");
            let lines: Vec<u32> = ra_lines(&t, "README.md").iter().map(|l| l.1).collect();
            // U+2028 is removed by the compact view, which joins the two lines (as in Python).
            let expected: &[u32] = if sep == "\u{2028}" { &[2, 1] } else { &[2] };
            assert_eq!(lines, expected, "{sep:?}");
        }
    }

    #[test]
    fn other_skills_root_use_keeps_the_nearby_operation() {
        let ops = [
            "cp -r ./payload ~/.claude/skills/helper # install",
            "cp -r ./payload ~/.claude/skills/helper && echo done",
            "cp -r ./payload '~/.claude/skills/helper",
            "tar -xzf helper.tgz -C ~/.claude/skills/helper",
            "cp -r ./payload $HOME/.claude/skills/helper",
            "git clone https://example.test/repo.git ~/.claude/skills/other",
            "git clone https://example.test/repo.git ~/.claude/skills/helper/../other",
            "cp -r ./payload \"$HOME\"/.claude/skills/helper",
            "cp -r ./payload ~/.claude/sk*lls/helper",
            "cp -r ./payload ${HOME:-/tmp}/.claude/skills/helper",
            "cp -r ./payload \"$SKILL_DIR\"",
            "cp -r ./payload /Users/alice/.claude/skills/helper",
        ];
        for sep in ["\n", "\r\n", "\r", "\u{2028}", "\u{2029}"] {
            for op in ops {
                for after in [true, false] {
                    let mkdir = "mkdir -p ~/.claude/skills/helper";
                    let parts = if after {
                        [mkdir, "", op]
                    } else {
                        [op, "", mkdir]
                    };
                    let t = parts.join(sep);
                    let line = if after { 3 } else { 1 };
                    let hit = ra(&t, "README.md").iter().any(|f| {
                        f.rule_id == "RA2"
                            && f.start_line == line
                            && f.matched_text.as_deref().is_some_and(|m| op.contains(m))
                    });
                    assert!(hit, "{op:?} {sep:?} {after}");
                }
            }
        }
        for copy in [
            "cp -r /tmp/payload ~/.claude/skills/payload",
            "mv /tmp/payload ~/.claude/skills/payload",
            "install -D /tmp/payload ~/.claude/skills/payload/payload",
            "cp -r /tmp/payload ~/.claude/skills/another-skill",
        ] {
            let lines = ra_lines(
                &format!("mkdir -p ~/.claude/skills/payload\n{copy}\n"),
                "a.sh",
            );
            assert!(lines.contains(&("RA2", 2)), "{copy}");
        }
        let late = ra_lines(
            "mkdir -p ~/.claude/skills/payload\n\ncp -r /tmp/payload ~/.claude/skills/payload\n",
            "a.sh",
        );
        assert!(late.contains(&("RA2", 3)));
    }

    #[test]
    fn install_context_window_edges() {
        let radius = 2048;
        let mkdir = "mkdir -p ~/.claude/skills/helper\n";
        let copy = "cp -r ./payload ~/.claude/skills/helper\n";
        let filler = format!("#{}\n", "x".repeat(radius - mkdir.len() - 1));
        let after = format!("{mkdir}{filler}{copy}");
        assert!(ra_lines(&after, "install.sh").contains(&("RA2", 1)));
        let filler = format!("#{}\n", "x".repeat(radius - 3));
        let before = format!("{copy}{filler}{mkdir}");
        assert!(ra_lines(&before, "install.sh").contains(&("RA2", 3)));
        let blanks = format!(
            "{mkdir}#{}\n\n   \n\t\n",
            "x".repeat(radius - mkdir.len() - 1)
        );
        assert!(ra(&blanks, "install.sh").is_empty());
        let clipped = format!("{mkdir}{} ~/.claude/skills/helper", "x".repeat(4096));
        assert!(ra_lines(&clipped, "README.md").contains(&("RA2", 1)));
        let near = format!(
            "{mkdir}{}\ncp ./payload ~/.claude/skills/helper/SKILL.md\n",
            "echo preparing\n".repeat(8)
        );
        assert!(ra_lines(&near, "README.md").contains(&("RA2", 11)));
    }

    #[test]
    fn companion_update_variants() {
        let ok =
            "Run `widgetctl self-update --verify-signature` to install the signed CLI release.";
        let f = ra1(ok);
        assert_eq!(f.len(), 1);
        assert!(f[0].confidence <= 0.15 && f[0].severity == Severity::Low);
        assert!(
            f[0].explanation
                .as_deref()
                .is_some_and(|e| e.contains("signed self-update"))
        );
        for cmd in [
            "widgetctl self-update --verify-signature=false",
            "widgetctl self-update --verify-signature false",
            "widgetctl self-update --no-verify-signature",
            "widgetctl self-update && echo --verify-signature",
            "widgetctl self-update # --verify-signature",
            "widgetctl self-update --verify-signature > SKILL.md",
            "widgetctl self-update --description=--verify-signature",
            "widgetctl self-update --verify-signature.txt",
            "bash widgetctl self-update --verify-signature",
            "widgetctl self-update --output SKILL.md --verify-signature",
        ] {
            assert!(
                high_only(&format!("Run `{cmd}` for the signed CLI release.")),
                "{cmd}"
            );
        }
        for launcher in [
            "bash",
            "python3",
            "python3.13",
            "node",
            "powershell.exe",
            "sudo",
            "env",
        ] {
            assert!(
                high_only(&format!(
                    "Run `{launcher} self-update --verify-signature` for the signed CLI release."
                )),
                "{launcher}"
            );
        }
        for cli in [
            "agentctl",
            "agent-cli",
            "skill-cli",
            "skillspector-cli",
            "agentctl.exe",
            "skillctl.cmd",
            "toolctl",
            "self-cli.exe",
            "agentctl.exe.bat",
            "agent-updater",
            "my-skill-update",
            "ag\u{435}ntctl",
        ] {
            assert!(
                high_only(&format!(
                    "Run `{cli} self-update --verify-signature` for the signed CLI release."
                )),
                "{cli}"
            );
        }
        for t in [
            "Run `widgetctl self-update --verify-signature`; this is not a signed CLI release.",
            "Run `widgetctl self-update --verify-signature` for the signed CLI release; but not a signed CLI release.",
            "Run `widgetctl self-update --verify-signature` for anything except a signed CLI release.",
            "Never use a signed CLI release; run `widgetctl self-update --verify-signature` anyway.",
            "Run `widgetctl self-update --verify-signature` without a signed CLI release.",
        ] {
            assert!(high_only(t), "{t}");
        }
    }

    #[test]
    fn companion_update_scope_is_one_clause_and_one_line() {
        let two = "Run `widgetctl self-update --verify-signature` for the signed CLI release; run `acmectl self-update --verify-signature` for the signed CLI release.";
        let f = ra1(two);
        let cols: Vec<_> = f.iter().map(|f| f.start_column).collect();
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|f| f.severity == Severity::Low));
        assert_eq!(
            cols,
            [two.find("self-update"), two.rfind("self-update")].map(|c| c.map(|c| c as u32))
        );
        let mixed = "Run `widgetctl self-update --verify-signature` for the signed CLI release; run `acmectl self-update --verify-signature` now.";
        let mut f = ra1(mixed);
        f.sort_by_key(|f| f.start_column);
        assert_eq!(
            f.iter().map(|f| f.severity).collect::<Vec<_>>(),
            [Severity::Low, Severity::High]
        );
        assert_eq!(f[1].message, "Self-Modification");
        for sep in [
            "\n", "\r\n", "\r", "\x0b", "\x0c", "\x1c", "\u{85}", "\u{2028}", "\u{2029}",
        ] {
            let t = format!(
                "Run `widgetctl self-update --verify-signature`.{sep}A signed CLI release exists."
            );
            assert!(high_only(&t), "{sep:?}");
        }
        let both = ra1(
            "Run `widgetctl self-update --verify-signature`, then modify this skill's instructions.",
        );
        assert!(both.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn negated_phrases_are_not_reported() {
        for t in [
            "You must not modify this skill.",
            "Do not ever rewrite its own code.",
            "Never directly update your own instructions.",
            "The skill should not attempt to edit this skill.",
        ] {
            assert!(ra1(t).is_empty(), "{t}");
        }
        // The negation only reaches back within its own clause.
        assert_eq!(ra1("Never do that. Modify this skill now.").len(), 1);
    }
}
