//! OH1-OH3 from `static_patterns_output_handling.py`: unvalidated model output reaching a sink,
//! output crossing contexts, unbounded output.

use super::common::{Head, cut_chars, hit_finding};
use super::oh_js::is_regexp_literal_exec;
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::matcher::{Pat, paragraph_matches};
use crate::pyast::ast::{Expr, ExprCall, Keyword, Ranged, Stmt, StmtExpr};
use crate::pyast::{
    Node, PyFile, get_complete_source_segment, resolve_call_name, resolve_dynamic_import_call, walk,
};
use crate::runner::StaticModule;
use crate::skill::FileType;
use crate::text::LineIndex;
use std::cell::OnceCell;
use std::sync::LazyLock;

const TAG: &str = "Output Handling";
const OUTPUT_NAMES: [&str; 7] = [
    "answer",
    "completion",
    "generated",
    "output",
    "reply",
    "response",
    "result",
];
/// `_SUBPROCESS_EXECUTION_KEYWORDS`, sorted by name as `sorted(_SUBPROCESS_CALLS)`.
const SUBPROCESS_CALLS: [(&str, &[&str]); 7] = [
    ("Popen", &["args", "executable"]),
    ("call", &["args", "executable"]),
    ("check_call", &["args", "executable"]),
    ("check_output", &["args", "input", "executable"]),
    ("getoutput", &["cmd"]),
    ("getstatusoutput", &["cmd"]),
    ("run", &["args", "input", "executable"]),
];
const FALLBACK_MAX_CHARS: usize = 1_000;
const EXEC_OUTPUT: &str =
    r"exec\s*\(\s*(?:response|output|result|answer|completion|reply|generated)";

type Rule = (&'static str, f32);

pub const OH1_CODE: [Rule; 10] = [
    (EXEC_OUTPUT, 0.9),
    (
        r"eval\s*\(\s*(?:response|output|result|answer|completion|reply|generated)",
        0.9,
    ),
    (
        r"os\.system\s*\(\s*(?:response|output|result|answer|completion)",
        0.85,
    ),
    (
        r"os\.popen\s*\(\s*(?:response|output|result|answer|completion)",
        0.85,
    ),
    (
        r"innerHTML\s*=\s*(?:response|output|result|answer|completion)",
        0.8,
    ),
    (
        r"document\.write\s*\(\s*(?:response|output|result|answer|completion)",
        0.8,
    ),
    (
        r"\.html\s*\(\s*(?:response|output|result|answer|completion)",
        0.7,
    ),
    (r"dangerouslySetInnerHTML\s*=\s*\{", 0.65),
    (
        r#"(?:execute|cursor\.execute|query)\s*\([^)]*(?:\+|%|\.format|f['\"])\s*.*?(?:response|output|result)"#,
        0.85,
    ),
    (
        r#"f['\"](?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\{(?:response|output|result)"#,
        0.9,
    ),
];
pub const OH1_PROSE: [Rule; 3] = [
    (
        r"(?:run|execute|shell)\s+(?:the\s+)?(?:generated|model|llm|ai)\s+(?:output|response|code|command)",
        0.8,
    ),
    (
        r"(?:pipe|pass|feed)\s+(?:the\s+)?(?:output|response|result)\s+(?:directly\s+)?(?:to|into)\s+(?:the\s+)?(?:shell|terminal|command|interpreter)",
        0.85,
    ),
    (
        r"(?:use|insert|embed)\s+(?:the\s+)?(?:raw|unfiltered|unescaped|unsanitized)\s+(?:output|response)",
        0.8,
    ),
];
pub const OH2: [Rule; 6] = [
    (
        r"(?:pass|forward|relay|send|pipe)\s+(?:the\s+)?(?:output|response|result)\s+(?:from\s+\w+\s+)?(?:to|into)\s+(?:another|different|separate|external)\s+(?:context|agent|service|system|session)",
        0.75,
    ),
    (
        r"(?:share|transfer|propagate)\s+(?:the\s+)?(?:output|response|context|state)\s+(?:across|between|to\s+other)\s+(?:sessions?|contexts?|agents?|services?)",
        0.75,
    ),
    (
        r"(?:inject|insert|embed)\s+(?:the\s+)?(?:output|response)\s+(?:from\s+\w+\s+)?(?:into|as)\s+(?:the\s+)?(?:system\s+prompt|instructions?|context)",
        0.85,
    ),
    (
        r"(?:use|include)\s+(?:the\s+)?(?:previous|other|external)\s+(?:agent|model|llm)(?:'s)?\s+(?:output|response)\s+(?:as|in|for)\s+(?:input|context|prompt)",
        0.8,
    ),
    (
        r"(?:cross[_-]?context|cross[_-]?session|cross[_-]?agent)\s+(?:output|data|state)\s+(?:sharing|transfer|flow)",
        0.8,
    ),
    (
        r"(?:take|use)\s+(?:the\s+)?(?:output|result)\s+(?:and\s+)?(?:run|execute|eval)\s+(?:it\s+)?(?:in|on|against)\s+(?:a\s+)?(?:different|another|new)\s+(?:environment|context|system)",
        0.8,
    ),
];
pub const OH3_CODE: [Rule; 2] = [
    (
        r#"max[_-]?tokens?\s*=\s*(?:None|float\s*\(\s*['\"]inf['\"]|math\.inf|999999|1000000)"#,
        0.8,
    ),
    (
        r#"max[_-]?(?:output[_-]?)?length\s*=\s*(?:None|0|-1|float\s*\(\s*['\"]inf)"#,
        0.75,
    ),
];
pub const OH3_PROSE: [Rule; 7] = [
    (
        r"(?:no|without|disable)\s+(?:output\s+)?(?:length|size|token)\s+(?:limit|cap|maximum|restriction)",
        0.75,
    ),
    (
        r"(?:generate|produce|output)\s+(?:as\s+much|unlimited|unbounded|infinite)\s+(?:text|content|output|tokens?)",
        0.8,
    ),
    (
        r"(?:no|without)\s+(?:output\s+)?(?:truncation|trimming|cutting)",
        0.6,
    ),
    (
        r"(?:repeat|loop|generate)\s+(?:the\s+)?(?:output|response)\s+(?:indefinitely|forever|continuously|endlessly)",
        0.8,
    ),
    (
        r"(?:keep|continue)\s+(?:generating|producing|outputting)\s+(?:until|unless)\s+(?:stopped|killed|interrupted)",
        0.75,
    ),
    (
        r"(?:stream|emit)\s+(?:output|tokens?|response)\s+(?:without\s+(?:limit|bound|end))",
        0.75,
    ),
    (
        r"(?:flood|spam|fill)\s+(?:the\s+)?(?:output|log|console|terminal|channel)",
        0.8,
    ),
];

/// `_SUBPROCESS_FALLBACK_PATTERN`.
fn fallback_source() -> String {
    let calls: Vec<&str> = SUBPROCESS_CALLS.iter().map(|c| c.0).collect();
    format!(
        r#"\bsubprocess\s*\.\s*(?:{})\s*\([^)]{{0,{FALLBACK_MAX_CHARS}}}?(?<![-\w'"])(?:{})(?!\w)"#,
        calls.join("|"),
        OUTPUT_NAMES.join("|"),
    )
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Plain,
    Prose,
}

struct Compiled {
    pat: Pat,
    confidence: f32,
    mode: Mode,
    is_exec: bool,
}

fn compile(rules: &[Rule], mode: Mode) -> Vec<Compiled> {
    rules
        .iter()
        .map(|&(src, confidence)| Compiled {
            pat: Pat::new(src, "im"),
            confidence,
            mode,
            is_exec: src == EXEC_OUTPUT,
        })
        .collect()
}

static OH1_RE: LazyLock<Vec<Compiled>> = LazyLock::new(|| {
    let mut v = compile(&OH1_CODE, Mode::Plain);
    v.extend(compile(&OH1_PROSE, Mode::Prose));
    v
});
static OH2_RE: LazyLock<Vec<Compiled>> = LazyLock::new(|| compile(&OH2, Mode::Prose));
static OH3_RE: LazyLock<Vec<Compiled>> = LazyLock::new(|| {
    let mut v = compile(&OH3_CODE, Mode::Plain);
    v.extend(compile(&OH3_PROSE, Mode::Prose));
    v
});
static FALLBACK_RE: LazyLock<Pat> = LazyLock::new(|| Pat::new(&fallback_source(), "i"));

/// `_contains_output_name`: a Name or Attribute under `expr` spelled like model output.
fn contains_output_name(expr: &Expr) -> bool {
    let stmt = Stmt::Expr(StmtExpr {
        range: expr.range(),
        value: Box::new(expr.clone()),
    });
    let mut found = false;
    walk(std::slice::from_ref(&stmt), |node| {
        let name = match node {
            Node::Expr(Expr::Name(n)) => n.id.as_str(),
            Node::Expr(Expr::Attribute(a)) => a.attr.as_str(),
            _ => return,
        };
        found |= OUTPUT_NAMES.contains(&crate::unicode::casefold(name).as_str());
    });
    found
}

/// `_subprocess_execution_arguments`.
fn execution_arguments<'a>(call: &'a ExprCall, keywords: &[&str]) -> Vec<&'a Expr> {
    let mut out: Vec<&Expr> = call.args.first().into_iter().collect();
    out.extend(
        call.keywords
            .iter()
            .filter(|k: &&Keyword| {
                k.arg
                    .as_ref()
                    .is_some_and(|a| keywords.contains(&a.as_str()))
            })
            .map(|k| &k.value),
    );
    out
}

fn finding(
    head: &Head<'_>,
    confidence: f32,
    path: &str,
    line: u32,
    end_line: Option<u32>,
    full: &str,
) -> RawFinding {
    let mut f = RawFinding::new(
        head.rule,
        head.message,
        head.severity,
        confidence,
        path,
        line,
    );
    f.end_line = end_line;
    f.tags = vec![head.tag.to_owned()];
    f.matched_text = Some(cut_chars(full, 200).to_owned());
    f.fingerprint_text = Some(full.to_owned());
    f
}

/// `_analyze_subprocess_fallback`.
fn subprocess_fallback(
    text: &str,
    path: &str,
    head: &Head<'_>,
    idx: &LineIndex,
) -> Vec<RawFinding> {
    FALLBACK_RE
        .find_iter(text)
        .iter()
        .map(|h| hit_finding(head, 0.85, path, text, h, idx))
        .collect()
}

/// `_analyze_python_subprocess_calls`.
fn subprocess_calls(
    text: &str,
    path: &str,
    head: &Head<'_>,
    idx: &LineIndex,
    py: Option<&PyFile>,
) -> Vec<RawFinding> {
    let parsed;
    let py = match py {
        Some(p) => p,
        None => {
            parsed = PyFile::parse(text, path);
            &parsed
        }
    };
    let Some(tree) = py.tree.as_deref() else {
        return subprocess_fallback(text, path, head, idx);
    };
    let aliases = Some(&py.import_aliases);
    let mut out = Vec::new();
    walk(tree, |node| {
        let Node::Expr(Expr::Call(call)) = node else {
            return;
        };
        let name =
            resolve_call_name(call, aliases).or_else(|| resolve_dynamic_import_call(call, aliases));
        let Some((_, method)) = name.as_deref().and_then(|n| {
            n.starts_with("subprocess.")
                .then(|| n.split_once('.'))
                .flatten()
        }) else {
            return;
        };
        let Some((_, keywords)) = SUBPROCESS_CALLS.iter().find(|c| c.0 == method) else {
            return;
        };
        let args = execution_arguments(call, keywords);
        if !args.iter().any(|a| contains_output_name(a)) {
            return;
        }
        let pos = py.pos(call.range);
        let full = get_complete_source_segment(&py.lines, pos.line, Some(pos.end_line));
        out.push(finding(
            head,
            0.95,
            path,
            pos.line,
            Some(pos.end_line),
            &full,
        ));
    });
    out
}

/// The OH1-OH3 static module.
pub struct OutputHandling;

impl StaticModule for OutputHandling {
    fn id(&self) -> &'static str {
        "static_patterns_output_handling"
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
        let idx = LineIndex::new(text);
        let head = |rule, message, severity| Head {
            rule,
            message,
            severity,
            tag: TAG,
        };
        let mut out = Vec::new();
        let chars: OnceCell<Vec<char>> = OnceCell::new();
        let oh1 = head("OH1", "Unvalidated Output Injection", Severity::High);
        let boost = matches!(
            ft,
            FileType::Python | FileType::Javascript | FileType::Shell
        );
        for c in OH1_RE.iter() {
            let confidence = if boost {
                (c.confidence + 0.1).min(1.0)
            } else {
                c.confidence
            };
            let hits = match c.mode {
                Mode::Plain => c.pat.find_iter(text),
                Mode::Prose => paragraph_matches(&c.pat, text),
            };
            for hit in hits {
                if c.is_exec {
                    let chars = chars.get_or_init(|| text.chars().collect());
                    let start = text[..hit.start].chars().count();
                    if is_regexp_literal_exec(chars, start, path, ft) {
                        continue;
                    }
                }
                out.push(hit_finding(&oh1, confidence, path, text, &hit, &idx));
            }
        }
        if ft == FileType::Python {
            out.extend(subprocess_calls(text, path, &oh1, &idx, py));
        } else {
            out.extend(subprocess_fallback(text, path, &oh1, &idx));
        }
        for (rule, message, severity, rules) in [
            ("OH2", "Cross-Context Output", Severity::Medium, &OH2_RE),
            ("OH3", "Unbounded Output", Severity::Medium, &OH3_RE),
        ] {
            let head = head(rule, message, severity);
            for c in rules.iter() {
                let hits = match c.mode {
                    Mode::Plain => c.pat.find_iter(text),
                    Mode::Prose => paragraph_matches(&c.pat, text),
                };
                for hit in hits {
                    out.push(hit_finding(&head, c.confidence, path, text, &hit, &idx));
                }
            }
        }
        out
    }
}

#[cfg(test)]
/// Every pattern source with its flags, for the compile test.
pub fn pattern_sources() -> Vec<(String, &'static str)> {
    let mut v: Vec<(String, &'static str)> =
        [&OH1_CODE[..], &OH1_PROSE, &OH2, &OH3_CODE, &OH3_PROSE]
            .iter()
            .flat_map(|rules| rules.iter().map(|r| (r.0.to_owned(), "im")))
            .collect();
    v.push((fallback_source(), "i"));
    v
}

#[cfg(test)]
mod tests;
