//! LP1-LP4 (`mcp_least_privilege`): declared `permissions` / `allowed-tools` against the
//! capabilities the executable files use.

use crate::analyzer::Analyzer;
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::matcher::Pat;
use crate::modules::concealed_executable::is_executable_content;
use crate::skill::{Skill, SourceFile};
use std::collections::BTreeSet;
use std::sync::LazyLock;

const CATEGORY: &str = "MCP Least Privilege";
const WINDOW: usize = 64 * 1024;
const OVERLAP: usize = 4096;
const MATCH_CHARS: usize = 4096;
const MODE_CHARS: usize = 64;

/// Compiles a Python-syntax pattern; under test a pattern that fails to compile panics.
fn pat(src: &str, flags: &str) -> Pat {
    #[cfg(test)]
    assert!(
        Pat::try_new(src, flags).is_ok(),
        "pattern does not compile: {src}"
    );
    Pat::new(src, flags)
}

/// Capability -> patterns, in Python's dict order.
static CAPABILITY_PATTERNS: LazyLock<Vec<(&'static str, Vec<Pat>)>> = LazyLock::new(|| {
    let open_r = format!(r#"open\s*\([^)]{{0,{MATCH_CHARS}}}['"]r['"]"#);
    let open_r2 = format!(r#"open\s*\([^)]{{0,{MATCH_CHARS}}}['"][^'"]{{0,{MODE_CHARS}}}r['"]"#);
    let open_w = format!(r#"open\s*\([^)]{{0,{MATCH_CHARS}}}['"][wa]['"]"#);
    let open_w2 = format!(r#"open\s*\([^)]{{0,{MATCH_CHARS}}}['"][^'"]{{0,{MODE_CHARS}}}[wa]['"]"#);
    let table: Vec<(&str, Vec<String>)> = vec![
        (
            "shell",
            [
                r"subprocess",
                r"Popen",
                r"os\.system",
                r"os\.popen",
                r"os\.exec",
                r"\bcurl\b",
                r"\bwget\b",
                r"\bchmod\b",
            ]
            .map(String::from)
            .to_vec(),
        ),
        (
            "network",
            [
                r"\bhttpx\b",
                r"\brequests\b",
                r"\burllib\b",
                r"\baiohttp\b",
                r"socket\.connect",
                r"fetch\(",
                r"XMLHttpRequest",
            ]
            .map(String::from)
            .to_vec(),
        ),
        (
            "file_read",
            vec![
                open_r,
                open_r2,
                r"\.read_text\(".into(),
                r"\.read_bytes\(".into(),
                r"os\.listdir".into(),
                r"os\.walk".into(),
                r"glob\.glob".into(),
            ],
        ),
        (
            "file_write",
            vec![
                open_w,
                open_w2,
                r"\.write_text\(".into(),
                r"\.write_bytes\(".into(),
                r"shutil\.copy".into(),
                r"os\.rename".into(),
                r"os\.mkdir".into(),
            ],
        ),
        (
            "env",
            [
                r"os\.environ",
                r"os\.getenv",
                r"process\.env",
                r"\bdotenv\b",
            ]
            .map(String::from)
            .to_vec(),
        ),
        (
            "mcp",
            [r"create_session", r"MCPClient", r"mcp\.client"]
                .map(String::from)
                .to_vec(),
        ),
    ];
    table
        .into_iter()
        .map(|(cap, pats)| (cap, pats.iter().map(|p| pat(p, "i")).collect()))
        .collect()
});

/// Permission keyword -> capability, in Python's dict order (first match wins).
const PERM_TO_CAPABILITY: [(&str, &str); 19] = [
    ("bash", "shell"),
    ("shell", "shell"),
    ("terminal", "shell"),
    ("command", "shell"),
    ("network", "network"),
    ("http", "network"),
    ("fetch", "network"),
    ("api", "network"),
    ("read", "file_read"),
    ("fs_read", "file_read"),
    ("file_read", "file_read"),
    ("write", "file_write"),
    ("fs_write", "file_write"),
    ("file_write", "file_write"),
    ("env", "env"),
    ("environment", "env"),
    ("mcp", "mcp"),
    ("tools", "mcp"),
    ("tool_use", "mcp"),
];

static PERMISSION_PATTERNS: LazyLock<Vec<(&'static str, Pat)>> = LazyLock::new(|| {
    PERM_TO_CAPABILITY
        .iter()
        .map(|(kw, cap)| (*cap, pat(&format!(r"\b{}\b", regex::escape(kw)), "i")))
        .collect()
});

const TOOL_TO_CAPABILITY: [(&str, &str); 14] = [
    ("bash", "shell"),
    ("execute", "shell"),
    ("terminal", "shell"),
    ("read", "file_read"),
    ("glob", "file_read"),
    ("ls", "file_read"),
    ("write", "file_write"),
    ("edit", "file_write"),
    ("multiedit", "file_write"),
    ("notebookedit", "file_write"),
    ("webfetch", "network"),
    ("websearch", "network"),
    ("fetch", "network"),
    ("env", "env"),
];

const WILDCARDS: [&str; 4] = ["*", "all", "full", "any"];

/// The LP1-LP4 detector.
pub struct LeastPrivilege;

/// `content[start:start+WINDOW]` for each window start, by characters.
fn windows(text: &str) -> Vec<&str> {
    let bounds: Vec<usize> = text
        .char_indices()
        .map(|(b, _)| b)
        .chain([text.len()])
        .collect();
    let chars = bounds.len() - 1;
    let step = WINDOW - OVERLAP;
    let mut out = Vec::new();
    let mut start = 0;
    loop {
        out.push(&text[bounds[start.min(chars)]..bounds[(start + WINDOW).min(chars)]]);
        if start + WINDOW >= chars {
            return out;
        }
        start += step;
    }
}

fn detect_capabilities(text: &str) -> BTreeSet<&'static str> {
    let mut found = BTreeSet::new();
    for window in windows(text) {
        for (cap, pats) in CAPABILITY_PATTERNS.iter() {
            if !found.contains(cap)
                && pats
                    .iter()
                    .any(|p| !p.find_in(window, 0, window.len()).is_empty())
            {
                found.insert(*cap);
            }
        }
    }
    found
}

fn permission_category(permission: &str) -> Option<&'static str> {
    PERMISSION_PATTERNS.iter().find_map(|(cap, pat)| {
        windows(permission)
            .iter()
            .any(|w| !pat.find_iter(w).is_empty())
            .then_some(*cap)
    })
}

/// `allowed_tool_grant_name`: the tool name of a complete grant.
fn grant_name(entry: &str) -> Option<&str> {
    let entry = entry.trim_matches(crate::unicode::is_space);
    let head: String = entry.chars().take(65).collect();
    let paren = head.find('(');
    if paren.is_none() && entry.chars().count() > 64 {
        return None;
    }
    let name = paren.map_or(entry, |i| &entry[..i]);
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_*.-".contains(c));
    if !valid {
        return None;
    }
    let Some(i) = paren else { return Some(name) };
    let inner = entry
        .strip_suffix(')')
        .map(|e| &e[i + 1..])
        .filter(|_| entry.len() > i + 1)?;
    inner
        .chars()
        .any(|c| !crate::unicode::is_space(c))
        .then_some(name)
}

fn is_test_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let stem = name
        .rsplit_once('.')
        .filter(|(s, _)| !s.is_empty())
        .map_or(name, |(s, _)| s);
    name.starts_with("test_") || stem.ends_with("_test")
}

fn is_wildcard(p: &str) -> bool {
    p.chars().count() <= 16
        && WILDCARDS.contains(
            &p.trim_matches(crate::unicode::is_space)
                .to_lowercase()
                .as_str(),
        )
}

fn text_of(f: &SourceFile) -> &str {
    if f.cached && !(f.binary && !f.readable_binary) {
        &f.text
    } else {
        ""
    }
}

fn lp(
    id: &'static str,
    message: String,
    sev: Severity,
    conf: f32,
    file: &str,
    explanation: String,
    remediation: String,
) -> RawFinding {
    let mut r = RawFinding::new(id, message.clone(), sev, conf, file, 1);
    r.category = Some(CATEGORY.to_owned());
    r.tags = vec!["ASI02".to_owned()];
    r.pattern = Some(message);
    r.explanation = Some(explanation);
    r.remediation = Some(remediation);
    r
}

impl Analyzer for LeastPrivilege {
    fn id(&self) -> &'static str {
        "mcp_least_privilege"
    }

    fn run(&self, skill: &Skill) -> Vec<RawFinding> {
        let Some(manifest) = &skill.manifest else {
            return Vec::new();
        };
        let executables: Vec<&SourceFile> = skill
            .files
            .iter()
            .filter(|f| is_executable_content(f))
            .collect();
        if executables.is_empty() {
            return Vec::new();
        }
        let permissions = &manifest.permissions;
        let allowed = &manifest.allowed_tools;
        let mut file_caps: Vec<(&str, BTreeSet<&'static str>)> = Vec::new();
        let mut all_caps: BTreeSet<&'static str> = BTreeSet::new();
        for f in &executables {
            let caps = detect_capabilities(text_of(f));
            if !caps.is_empty() {
                all_caps.extend(&caps);
                file_caps.push((&f.rel, caps));
            }
        }
        let mut out = Vec::new();
        let wildcard = permissions.iter().any(|p| is_wildcard(p));
        if wildcard {
            out.push(lp("LP2", "Permission list contains a wildcard entry ('*', 'all', 'full', or 'any'), granting blanket access with no least-privilege boundary.".into(), Severity::Medium, 0.9, "SKILL.md",
                "Wildcard permissions disable permission-based security controls entirely. Specify only the permissions the skill actually requires.".into(),
                "Replace '*'/'all'/'full'/'any' with an explicit list of required permissions. Request only the minimum access needed.".into()));
        }
        if permissions.is_empty() && allowed.is_empty() && !all_caps.is_empty() {
            let names = all_caps.iter().copied().collect::<Vec<_>>().join(", ");
            out.push(lp("LP3", format!("Skill declares no tool scope ('permissions' or 'allowed-tools') but code capabilities were detected: {names}."), Severity::Medium, 0.7, "SKILL.md",
                "Without declared permissions the skill's intent is opaque and cannot be validated.".into(),
                "Clarify the skill's intended tool scope and review how the host runtime enforces it; runtime permissions are unknown unless separately verified. For Claude Code / Agent Skills SKILL.md, 'allowed-tools' records preapproved tools, not a permission ceiling; add a tool only when it is independently approved as necessary, not to silence this finding. For MCP server manifests, use a 'permissions' list naming the required capabilities.".into()));
        }
        if permissions.is_empty() && allowed.is_empty() {
            return out;
        }
        let mut declared: BTreeSet<&str> = permissions
            .iter()
            .filter_map(|p| permission_category(p))
            .collect();
        declared.extend(
            allowed
                .iter()
                .filter_map(|t| grant_name(t))
                .filter_map(|n| {
                    TOOL_TO_CAPABILITY
                        .iter()
                        .find(|(k, _)| *k == n.to_lowercase())
                        .map(|(_, c)| *c)
                }),
        );
        if !wildcard {
            let (mut in_tests, mut in_code): (BTreeSet<&str>, BTreeSet<&str>) =
                (BTreeSet::new(), BTreeSet::new());
            for (path, caps) in &file_caps {
                if is_test_file(path) {
                    in_tests.extend(caps.iter().copied());
                } else {
                    in_code.extend(caps.iter().copied());
                }
            }
            for cap in all_caps.iter().filter(|c| !declared.contains(**c)) {
                let primary = file_caps
                    .iter()
                    .find(|(_, caps)| caps.contains(cap))
                    .map_or("SKILL.md", |(p, _)| *p);
                let test_only = in_tests.contains(cap) && !in_code.contains(cap);
                let (explanation, remediation) = if allowed.is_empty() {
                    (
                        format!(
                            "The skill uses '{cap}' capability that is not covered by the declared MCP 'permissions' list. Review the server's actual authorization policy; runtime permissions are unknown unless separately verified."
                        ),
                        format!(
                            "Add the '{cap}' capability to the MCP server manifest's 'permissions' list, or remove the code that requires it."
                        ),
                    )
                } else {
                    (
                        format!(
                            "The skill uses '{cap}' capability that is not covered by the declared 'allowed-tools' preapproval. Review the host runtime's actual enforcement policy; runtime permissions are unknown unless separately verified, and this declaration alone does not establish a permission ceiling."
                        ),
                        format!(
                            "Review whether the '{cap}' capability is required and whether the host runtime policy permits it; runtime permissions are unknown unless separately verified. Remove code that does not need the capability; do not broaden 'allowed-tools' preapproval solely to silence this finding."
                        ),
                    )
                };
                out.push(lp("LP1", format!("Code capability '{cap}' detected in {primary} but not covered by declared permissions."), Severity::High, if test_only { 0.55 } else { 0.75 }, primary, explanation, remediation));
            }
        }
        for p in permissions.iter().filter(|p| !is_wildcard(p)) {
            let Some(cat) = permission_category(p).filter(|c| !all_caps.contains(c)) else {
                continue;
            };
            let shown = if p.chars().count() <= 512 {
                p.clone()
            } else {
                format!("{}…", p.chars().take(511).collect::<String>())
            };
            out.push(lp("LP4", format!("Permission '{shown}' is declared but no corresponding code capability ({cat}) was detected."), Severity::Low, 0.65, "SKILL.md",
                "Declared permissions with no matching code capability may indicate removed functionality or pre-staging for future abuse.".into(),
                format!("Remove the '{shown}' permission if the corresponding capability is no longer used.")));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(manifest: &str, files: &[(&str, &str)]) -> Vec<RawFinding> {
        let mut all = vec![(
            "SKILL.md".to_owned(),
            format!("---\n{manifest}\n---\nbody\n").into_bytes(),
        )];
        all.extend(
            files
                .iter()
                .map(|(p, t)| ((*p).to_owned(), t.as_bytes().to_vec())),
        );
        LeastPrivilege.run(&Skill::from_memory(all))
    }

    #[test]
    fn undeclared_capability_is_lp3() {
        let f = run("name: x", &[("a.py", "import subprocess\n")]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "LP3");
        assert!(f[0].message.ends_with("detected: shell."));
    }

    #[test]
    fn declared_but_unused_and_uncovered() {
        let f = run(
            "name: x\npermissions: [network]",
            &[("a.py", "import subprocess\n")],
        );
        let ids: Vec<&str> = f.iter().map(|x| x.rule_id).collect();
        assert_eq!(ids, ["LP1", "LP4"]);
        assert_eq!(f[0].file, "a.py");
    }

    #[test]
    fn wildcard_and_allowed_tools() {
        assert_eq!(
            run(
                "name: x\npermissions: ['*']",
                &[("a.py", "import subprocess\n")]
            )[0]
            .rule_id,
            "LP2"
        );
        assert!(
            run(
                "name: x\nallowed-tools: Bash(git:*)",
                &[("a.py", "import subprocess\n")]
            )
            .is_empty()
        );
    }

    #[test]
    fn grants() {
        assert_eq!(grant_name("Bash(echo '(')"), Some("Bash"));
        assert_eq!(grant_name("Bash()"), None);
        assert_eq!(grant_name("Bash(notes"), None);
        assert_eq!(grant_name("Read"), Some("Read"));
        assert!(
            is_test_file("lib/test_x.py") && is_test_file("x_test.py") && !is_test_file("x.py")
        );
    }

    #[test]
    fn malformed_grants_name_no_tool() {
        for g in [
            "Bash(",
            "Bash(notes",
            "Bash()",
            "Bash( )",
            "Bash(echo '('",
            "Bash(echo ')'",
            "Bash)",
            "(Bash)",
            "Bash (git:*)",
            "Read(./docs Bash(notes).md",
        ] {
            assert_eq!(grant_name(g), None, "{g}");
        }
        for g in [
            "Bash(echo '(')",
            "Bash(echo ')')",
            "Bash(notes).md)",
            "Bash(a)(b)",
            "Read(./docs Bash(notes).md)",
        ] {
            assert!(grant_name(g).is_some(), "{g}");
        }
    }

    #[test]
    fn scoped_grant_covers_shell_but_nested_one_does_not() {
        let code = [("skill.py", "import subprocess\n")];
        assert!(
            run("name: x\nallowed-tools: Bash(git status:*) Read", &code)
                .iter()
                .all(|f| f.rule_id != "LP1")
        );
        let f = run("name: x\nallowed-tools: Read(./docs Bash(notes).md)", &code);
        assert!(
            f.iter()
                .any(|x| x.rule_id == "LP1" && x.message.contains("'shell'"))
        );
    }

    #[test]
    fn test_file_capabilities_have_reduced_confidence() {
        let f = run(
            "name: x\npermissions: [read]",
            &[("test_a.py", "import httpx\n")],
        );
        assert_eq!(
            f.iter().find(|x| x.rule_id == "LP1").map(|x| x.confidence),
            Some(0.55)
        );
    }

    #[test]
    fn permission_keywords_match_case_insensitively() {
        assert_eq!(permission_category("BASH access"), Some("shell"));
        assert_eq!(permission_category("nothing"), None);
    }

    #[test]
    fn patterns_compile() {
        assert_eq!(CAPABILITY_PATTERNS.len(), 6);
        assert_eq!(PERMISSION_PATTERNS.len(), 19);
        assert!(detect_capabilities("open('f', 'r')").contains("file_read"));
    }
}
