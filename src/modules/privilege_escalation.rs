//! PE1-PE5 from `static_patterns_privilege_escalation.py`: excessive permissions, sudo/root,
//! credential access, Docker socket and privileged containers.
//!
//! The veto helpers live in [`super::pe_context`] and [`super::pe_token`].

use super::pe_context::{
    Lines, cut_chars, is_bare_credential_store_noun, is_ignore_file_exclusion_entry,
    is_ignore_pattern_file, is_negated_safety_constraint, is_read_only_passwd_volume_match,
    markdown_fence_ranges,
};
use super::pe_token::{
    has_oauth_protocol_context, is_companion_cli_oauth_result_noun,
    is_credential_type_disclosure_label, is_pe3_documentation_example,
    is_qualified_benign_access_requirement,
};
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::matcher::{Hit, Pat, paragraph_matches};
use crate::pyast::PyFile;
use crate::runner::StaticModule;
use crate::skill::FileType;
use crate::text::{is_reference_material, py_splitlines};
use std::collections::BTreeMap;
use std::sync::LazyLock;

const CATEGORY: &str = "Privilege Escalation";
const MAX_CONTEXT_CHARS: usize = 1_000;
const DOC_TAGS: [&str; 2] = ["contextual-triage", "likely-benign-context"];

/// A pattern and its confidence.
type Rule = (&'static str, f32);

pub const PE1_CODE: &[Rule] = &[
    (r#"permissions?\s*:\s*\[?\s*['"]?\*['"]?\s*\]?"#, 0.8),
    (
        r"permissions?\s*:.*?(?:shell_execute|file_write|network).*?(?:shell_execute|file_write|network)",
        0.6,
    ),
];
pub const PE1_PROSE: &[Rule] = &[
    (
        r"(?:request|require|need)s?\s+(?:full|all|complete)\s+(?:access|permissions?)",
        0.7,
    ),
    (
        r"(?:grant|give|allow)\s+(?:me\s+)?(?:full|all|complete)\s+(?:access|permissions?)",
        0.75,
    ),
    (
        r"(?:also\s+)?(?:need|require)s?\s+(?:write|execute|admin)\s+(?:access|permissions?)\s+(?:for|to)\s+(?:read|view|display)",
        0.7,
    ),
    (
        r"(?:escalate|elevate|upgrade)\s+(?:my\s+)?(?:permissions?|privileges?|access)",
        0.8,
    ),
    (
        r"(?:bypass|skip|ignore)\s+(?:permission|access)\s+(?:check|validation|restriction)",
        0.85,
    ),
];
pub const PE2_CODE: &[Rule] = &[
    (r"sudo\s+(?!-v|-l|--version|--list)", 0.7),
    (r"sudo\s+-[isSE]", 0.8),
    (r"sudo\s+su\b", 0.9),
    (r"su\s+-\s*$|su\s+root", 0.8),
    (r"doas\s+", 0.7),
    (r"pkexec\s+", 0.75),
    (r"chmod\s+[ugo]*[+-=]*s", 0.85),
    (
        r#"chmod\s+(?:-[\w=-]*[ \t]+)*["']?[+=]?0*[2-7][0-7]{3}["']?(?![0-9\w])"#,
        0.8,
    ),
];
pub const PE2_PROSE: &[Rule] = &[
    (r"(?:run|execute)\s+(?:as|with)\s+root", 0.8),
    (
        r"(?:requires?|needs?)\s+root\s+(?:access|privileges?|permissions?)",
        0.6,
    ),
    (
        r"(?:edit|modify|write|change)\s+(?:/etc/|system)\s+(?:files?|config)",
        0.6,
    ),
    (
        r"(?:run|execute)\s+(?:this|the)\s+(?:script|command)\s+(?:as|with)\s+(?:sudo|root|admin)",
        0.7,
    ),
    (
        r"(?:you\s+)?(?:will\s+)?need\s+(?:to\s+)?(?:use\s+)?sudo",
        0.5,
    ),
];
pub const PE3_CODE: &[Rule] = &[
    (
        r"~?/?\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts)",
        0.9,
    ),
    (r"(?:home|HOME)/\w+/\.ssh/", 0.9),
    (r#"Path\s*\.\s*home\s*\(\s*\)\s*/\s*['"]\.ssh['"]"#, 0.9),
    (r"~?/?\.aws/credentials", 0.9),
    (r"~?/?\.aws/config", 0.7),
    (r"(?:home|HOME)/\w+/\.aws/", 0.9),
    (r"~?/?\.config/gcloud/", 0.8),
    (r"application_default_credentials\.json", 0.8),
    (r"~?/?\.azure/", 0.7),
    (r"accessTokens\.json", 0.8),
    (r"~?/?\.kube/config", 0.8),
    (r"kubeconfig", 0.6),
    (r"~?/?\.docker/config\.json", 0.7),
    (r"~?/?\.npmrc", 0.7),
    (r"~?/?\.git-credentials", 0.9),
    (r"~?/?\.netrc", 0.8),
    (r"/etc/passwd", 0.6),
    (r"/etc/shadow", 0.95),
    (
        r"(?:password|credentials?|secrets?)\.(?:txt|json|yaml|yml|env)",
        0.7,
    ),
    (
        r"(?:access_token|refresh_token|bearer_token|api_token)\.txt",
        0.8,
    ),
    (
        r#"(?<!\w)\.env(?:\.local|\.production|\.development)?(?:\s|$|['"])"#,
        0.6,
    ),
    (r"(?:keychain|keyring|gnome-keyring)", 0.7),
    (
        r"(?:Chrome|Firefox|Safari)/.*?(?:Cookies|Login Data|key4\.db)",
        0.8,
    ),
];
pub const PE3_PROSE: &[Rule] = &[
    (r"read\s+(?:the\s+)?(?:ssh|private)\s+key", 0.8),
    (
        r"access\s+(?:the\s+)?(?:credentials?|secrets?|tokens?)",
        0.7,
    ),
    (r"(?:extract|copy|get)\s+(?:api\s+)?keys?\s+from", 0.7),
];
pub const PE4: &[Rule] = &[
    (r"/var/run/docker\.sock", 0.9),
    (r"docker\.from_env\(\)", 0.85),
    (r"\bDockerClient\s*\(", 0.85),
    (r"http\+unix://.*docker\.sock", 0.9),
];
pub const PE5: &[Rule] = &[
    (r"--privileged", 0.8),
    (r#"(?:-v|--volume)['",\s=]+/:"#, 0.85),
    (
        r"--cap-add[=\s]+(?:SYS_ADMIN|ALL|SYS_PTRACE|NET_ADMIN)",
        0.85,
    ),
    (r"--(?:pid|net|network|ipc|uts)[=\s]+host", 0.8),
    (r"--device[=\s]+/dev/", 0.7),
    (r"--security-opt[=\s]+\S*unconfined", 0.85),
    (r"\bnsenter\b", 0.9),
    (r"/sys/fs/cgroup/.*release_agent", 0.95),
    (r"/proc/\d+/ns/", 0.85),
    (r#"\bunshare\b['",\s]+--(?:user|mount|pid)"#, 0.85),
];

/// A compiled rule: `(pattern, confidence, is_prose)`.
type Compiled = (Pat, f32, bool);

fn compile(code: &[Rule], prose: &[Rule]) -> Vec<Compiled> {
    let one = |rules: &[Rule], is_prose: bool| -> Vec<Compiled> {
        rules
            .iter()
            .map(|&(src, conf)| (Pat::new(src, "im"), conf, is_prose))
            .collect()
    };
    let mut all = one(code, false);
    all.extend(one(prose, true));
    all
}

static PE1: LazyLock<Vec<Compiled>> = LazyLock::new(|| compile(PE1_CODE, PE1_PROSE));
static PE2: LazyLock<Vec<Compiled>> = LazyLock::new(|| compile(PE2_CODE, PE2_PROSE));
static PE3: LazyLock<Vec<Compiled>> = LazyLock::new(|| compile(PE3_CODE, PE3_PROSE));
static PE4_RE: LazyLock<Vec<Compiled>> = LazyLock::new(|| compile(PE4, &[]));
static PE5_RE: LazyLock<Vec<Compiled>> = LazyLock::new(|| compile(PE5, &[]));

const DOCUMENTATION_INDICATORS: [&str; 10] = [
    "example:",
    "for example",
    "e.g.",
    "such as",
    "documentation",
    "# warning:",
    "# note:",
    "**warning**",
    "**note**",
    "```",
];

/// `_is_documentation_example`.
#[must_use]
pub fn is_documentation_example(context: &str, ft: FileType) -> bool {
    if !matches!(ft, FileType::Markdown | FileType::Text) {
        return false;
    }
    let lower = context.to_lowercase();
    DOCUMENTATION_INDICATORS.iter().any(|i| lower.contains(i))
}

/// `get_context_from_lines`: three lines either side of 1-based `lineno`, bounded to 1000 chars
/// around the anchor.
#[must_use]
pub fn context_from_lines(lines: &[&str], lineno: usize, column: usize) -> String {
    let start = lineno.saturating_sub(4);
    let end = lines.len().min(lineno + 3);
    let Some(selected) = lines.get(start..end).filter(|s| !s.is_empty()) else {
        return String::new();
    };
    let relative = lineno.saturating_sub(1 + start).min(selected.len() - 1);
    let column = column.min(selected[relative].chars().count());
    let anchor: usize = selected[..relative]
        .iter()
        .map(|l| l.chars().count() + 1)
        .sum::<usize>()
        + column;
    let joined = selected.join("\n");
    let chars: Vec<char> = joined.chars().collect();
    if chars.len() <= MAX_CONTEXT_CHARS {
        return joined;
    }
    let slice_start = anchor
        .saturating_sub(MAX_CONTEXT_CHARS / 2)
        .min(chars.len() - MAX_CONTEXT_CHARS);
    chars[slice_start..slice_start + MAX_CONTEXT_CHARS]
        .iter()
        .collect()
}

/// Everything one `analyze` call shares between rules.
struct Scan<'a> {
    text: &'a str,
    path: &'a str,
    ft: FileType,
    lines: Lines,
    content_lines: Vec<&'a str>,
}

impl Scan<'_> {
    fn line(&self, offset: usize) -> u32 {
        u32::try_from(self.lines.index(offset) + 1).unwrap_or(u32::MAX)
    }

    fn context(&self, offset: usize) -> String {
        let idx = self.lines.index(offset);
        let column = self.text[self.lines.starts[idx]..offset].chars().count();
        context_from_lines(&self.content_lines, idx + 1, column)
    }

    fn base(
        &self,
        rule: &'static str,
        (message, severity, confidence): (&str, Severity, f32),
        m: &Hit,
        tags: Vec<String>,
        context: String,
    ) -> RawFinding {
        let full = m.text(self.text);
        let mut f = RawFinding::new(
            rule,
            message,
            severity,
            confidence,
            self.path,
            self.line(m.start),
        );
        f.category = Some(CATEGORY.to_owned());
        f.tags = tags;
        f.context = Some(context);
        f.matched_text = Some(cut_chars(full, 200).to_owned());
        f.fingerprint_text = Some(full.to_owned());
        f
    }
}

fn tags(doc: bool) -> Vec<String> {
    let mut t = vec![CATEGORY.to_owned()];
    if doc {
        t.extend(DOC_TAGS.iter().map(|s| (*s).to_owned()));
    }
    t
}

fn hits(rule: &Compiled, text: &str) -> Vec<Hit> {
    if rule.2 {
        paragraph_matches(&rule.0, text)
    } else {
        rule.0.find_iter(text)
    }
}

fn simple_rule(
    scan: &Scan<'_>,
    rules: &[Compiled],
    id: &'static str,
    message: &str,
    severity: Severity,
    tag_docs: bool,
) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for rule in rules {
        for m in hits(rule, scan.text) {
            let context = scan.context(m.start);
            let doc = tag_docs && is_documentation_example(&context, scan.ft);
            out.push(scan.base(id, (message, severity, rule.1), &m, tags(doc), context));
        }
    }
    out
}

/// The best finding per line (`pe4_best` / `pe5_best`), ties keep the first.
fn best_per_line(
    scan: &Scan<'_>,
    rules: &[Compiled],
    id: &'static str,
    message: &str,
    reference_tag: bool,
) -> Vec<RawFinding> {
    let mut best: BTreeMap<u32, RawFinding> = BTreeMap::new();
    for rule in rules {
        for m in rule.0.find_iter(scan.text) {
            let line = scan.line(m.start);
            let context = scan.context(m.start);
            let doc = reference_tag || is_documentation_example(&context, scan.ft);
            if best.get(&line).is_some_and(|b| b.confidence >= rule.1) {
                continue;
            }
            let f = scan.base(
                id,
                (message, Severity::High, rule.1),
                &m,
                tags(doc),
                context,
            );
            best.insert(line, f);
        }
    }
    best.into_values().collect()
}

const OAUTH_EXPLANATION: &str = "The matched phrase names an OAuth access-token value in documentation; no instruction to read, copy, or transmit stored credentials was matched.";
const LABEL_EXPLANATION: &str = "The matched phrase is an access-token label in documentation; no instruction to read, copy, or transmit stored credentials was matched.";
const OAUTH_REMEDIATION: &str = "No credential-access change is indicated by this match. Keep the OAuth flow and token scope explicit, and review separately if the skill reads or transmits stored tokens.";

fn credential_findings(scan: &Scan<'_>) -> Vec<RawFinding> {
    let doc_type = matches!(scan.ft, FileType::Markdown | FileType::Text);
    let fences = if doc_type {
        markdown_fence_ranges(scan.text)
    } else {
        Vec::new()
    };
    let ignore_file = is_ignore_pattern_file(scan.path);
    let mut out = Vec::new();
    for rule in PE3.iter() {
        for m in hits(rule, scan.text) {
            if is_bare_credential_store_noun(scan.text, &m, scan.ft, &fences, &scan.lines)
                || (ignore_file && is_ignore_file_exclusion_entry(scan.text, &m))
                || is_credential_type_disclosure_label(scan.text, &m, scan.ft, &scan.lines)
            {
                continue;
            }
            let context = scan.context(m.start);
            let token_doc = is_pe3_documentation_example(
                scan.text,
                &m,
                scan.ft,
                scan.path,
                &scan.lines,
                &context,
            );
            let companion =
                is_companion_cli_oauth_result_noun(scan.text, &m, scan.ft, &scan.lines, &context);
            let contextual = token_doc
                || companion
                || is_qualified_benign_access_requirement(scan.text, &m, scan.ft, &scan.lines)
                || is_read_only_passwd_volume_match(scan.text, &m)
                || is_negated_safety_constraint(scan.text, &m, &scan.lines);
            let mut f = if companion {
                scan.base(
                    "PE3",
                    ("OAuth Token Documentation", Severity::Low, rule.1.min(0.15)),
                    &m,
                    tags(contextual),
                    context.clone(),
                )
            } else {
                scan.base(
                    "PE3",
                    ("Credential Access", Severity::High, rule.1),
                    &m,
                    tags(contextual),
                    context.clone(),
                )
            };
            if companion {
                f.remediation = Some(OAUTH_REMEDIATION.to_owned());
                f.explanation = Some(
                    if has_oauth_protocol_context(&context) {
                        OAUTH_EXPLANATION
                    } else {
                        LABEL_EXPLANATION
                    }
                    .to_owned(),
                );
            }
            out.push(f);
        }
    }
    out
}

/// The PE1-PE5 static module.
pub struct PrivilegeEscalation;

impl StaticModule for PrivilegeEscalation {
    fn id(&self) -> &'static str {
        "static_patterns_privilege_escalation"
    }

    fn uses_python_source_type(&self) -> bool {
        true
    }

    fn analyze(
        &self,
        text: &str,
        path: &str,
        ft: FileType,
        _py: Option<&PyFile>,
    ) -> Vec<RawFinding> {
        let scan = Scan {
            text,
            path,
            ft,
            lines: Lines::new(text),
            content_lines: py_splitlines(text),
        };
        let mut out = simple_rule(
            &scan,
            &PE1,
            "PE1",
            "Excessive Permissions",
            Severity::Low,
            false,
        );
        out.extend(simple_rule(
            &scan,
            &PE2,
            "PE2",
            "Sudo/Root Execution",
            Severity::Medium,
            true,
        ));
        out.extend(credential_findings(&scan));
        out.extend(best_per_line(
            &scan,
            &PE4_RE,
            "PE4",
            "Docker Socket Access",
            false,
        ));
        out.extend(best_per_line(
            &scan,
            &PE5_RE,
            "PE5",
            "Privileged Container / Container Escape",
            is_reference_material(path, ft),
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str, path: &str) -> Vec<RawFinding> {
        let ft = FileType::from_path(path);
        PrivilegeEscalation.analyze(text, path, ft, None)
    }

    fn ids(text: &str, path: &str) -> Vec<(&'static str, u32)> {
        run(text, path)
            .iter()
            .map(|f| (f.rule_id, f.start_line))
            .collect()
    }

    #[test]
    fn all_compile() {
        for rules in [
            PE1_CODE, PE1_PROSE, PE2_CODE, PE2_PROSE, PE3_CODE, PE3_PROSE, PE4, PE5,
        ] {
            for (src, _) in rules {
                assert!(Pat::try_new(src, "im").is_ok(), "{src}");
            }
        }
        assert!(super::super::pe_context::SOURCES.len() > 10);
    }

    #[test]
    fn chmod_modes() {
        let hit = |s: &str| ids(s, "a.sh").iter().any(|(i, _)| *i == "PE2");
        assert!(hit("chmod 4755 /bin/x"));
        assert!(hit("chmod -R 2755 dir"));
        assert!(hit("chmod u+s /bin/x"));
        assert!(!hit("chmod 755 /bin/x"));
        assert!(!hit("chmod 644 f"));
        assert!(!hit("chmod 47554 f"));
        assert!(hit("chmod \"6755\" f"));
    }

    #[test]
    fn sudo_and_prose() {
        assert_eq!(ids("sudo apt install x", "a.sh"), [("PE2", 1)]);
        assert!(ids("sudo -l", "a.sh").is_empty());
        assert_eq!(ids("Please run as root\n", "a.md"), [("PE2", 1)]);
        let doc = run("For example:\nsudo make\n", "a.md");
        assert!(doc[0].tags.iter().any(|t| t == "likely-benign-context"));
    }

    #[test]
    fn credential_paths() {
        assert_eq!(ids("cat ~/.ssh/id_rsa", "a.sh"), [("PE3", 1)]);
        assert_eq!(ids("cat /etc/shadow\nx", "a.sh"), [("PE3", 1)]);
        assert!(ids(".env\n", ".gitignore").is_empty());
        assert_eq!(ids("cp a .env\n", "a.sh"), [("PE3", 1)]);
    }

    #[test]
    fn credential_store_noun_in_prose_is_not_flagged() {
        assert!(ids("The keychain is a store of secrets.", "a.md").is_empty());
        assert_eq!(ids("Read the keychain.", "a.md"), [("PE3", 1)]);
        assert_eq!(ids("keychain.get(x)", "a.py"), [("PE3", 1)]);
    }

    #[test]
    fn negated_constraint_is_tagged() {
        let f = run("You must never access credentials.\n", "a.md");
        assert_eq!(f.len(), 1);
        assert!(f[0].tags.iter().any(|t| t == "contextual-triage"));
    }

    #[test]
    fn oauth_companion_variant() {
        let f = run(
            "The companion CLI OAuth flow returns an access token.\n",
            "docs/a.md",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].message, "OAuth Token Documentation");
        assert_eq!(f[0].severity, Severity::Low);
        assert!(f[0].confidence <= 0.15);
    }

    #[test]
    fn docker_findings_keep_best_per_line() {
        let f = run(
            "DockerClient(base_url='http+unix://var/run/docker.sock')\n",
            "a.py",
        );
        let pe4: Vec<_> = f.iter().filter(|f| f.rule_id == "PE4").collect();
        assert_eq!(pe4.len(), 1);
        assert!((pe4[0].confidence - 0.9).abs() < 1e-6);
        let g = run("docker run --privileged --cap-add=SYS_ADMIN x\n", "a.sh");
        let pe5: Vec<_> = g.iter().filter(|f| f.rule_id == "PE5").collect();
        assert_eq!(pe5.len(), 1);
        assert!((pe5[0].confidence - 0.85).abs() < 1e-6);
        let r = run("docker run --privileged x\n", "references/a.md");
        assert!(r[0].tags.iter().any(|t| t == "likely-benign-context"));
    }

    #[test]
    fn documentation_example_context() {
        assert!(is_documentation_example(
            "see e.g. this",
            FileType::Markdown
        ));
        assert!(!is_documentation_example("see e.g. this", FileType::Shell));
    }

    #[test]
    fn context_window_is_bounded() {
        let long = "x".repeat(2_000);
        let lines = ["a", long.as_str(), "b"];
        assert_eq!(context_from_lines(&lines, 1, 0).chars().count(), 1_000);
        assert_eq!(context_from_lines(&["a", "b"], 2, 0), "a\nb");
        assert_eq!(context_from_lines(&[], 1, 0), "");
    }
}
