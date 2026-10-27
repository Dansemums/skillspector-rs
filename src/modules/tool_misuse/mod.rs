//! TM1-TM4 from `static_patterns_tool_misuse.py` (the lexical half of the `tool_misuse` node) and
//! the AST half in [`shell_truthiness`].
//!
//! Stage map: plain TM1/TM2/TM3/TM4 patterns, destructive `rm` parsing and the direct
//! `shell=True` calls are ported literally; everything that needs the Python AST is a
//! `TODO(pyast)` in [`variable_shell`] and [`shell_truthiness`].

mod candidates;
mod exhaustion;
mod patterns;
mod shell_truthiness;
mod variable_shell;

pub use exhaustion::has_bounded_parse_exhaustion;
pub use shell_truthiness::ShellTruthiness;

use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::matcher::{Pat, paragraph_matches};
use crate::pyast::PyFile;
use crate::runner::StaticModule;
use crate::skill::FileType;
use crate::text::{LineIndex, get_context, is_reference_material};
use crate::unicode::collapse_ws;
use candidates::{Candidate, tm1_candidates};
use patterns::{
    SHELL_TRUE_VALUE, TM2_PATS, TM4_PATS, Tm3Kind, compile, is_safe_cache_cleanup,
    is_safe_container_command, is_safe_dockerfile_idiom, tm3_entries,
};
use std::collections::HashMap;
use variable_shell::{VariableWindow, call_start, is_true_prefixed_name, variable_shell_matches};

const CATEGORY_TAG: &str = "Tool Misuse";
const MAX_DIRECT_SHELL_CONTEXT_CHARS: usize = 1024;
/// Private markers on a finding's evidence, stripped by `postprocess` (`cleanup_path_findings`).
const DIRECT_MARK: &str = "_tm1_lexical_direct_shell";
const VARIABLE_MARK: &str = "_tm1_variable_shell_flag";

/// The tool misuse lexical module.
pub struct ToolMisuse;

fn first_chars(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

/// `_line_containing`: the full `\n`-delimited line around a match.
fn line_containing(content: &str, start: usize, end: usize) -> &str {
    let line_start = content[..start].rfind('\n').map_or(0, |i| i + 1);
    let line_end = content[end..].find('\n').map_or(content.len(), |i| end + i);
    &content[line_start..line_end]
}

/// `_is_assigned_value`: is the expression at `start` the value of an assignment?
fn is_assigned_value(content: &str, start: usize) -> bool {
    let before = &content[..start];
    let trimmed = before.trim_end_matches([' ', '\t', '\r', '\n', '\\', '(']);
    let Some(prefix) = trimmed.strip_suffix('=') else {
        return false;
    };
    !prefix.ends_with(['=', '!', '<', '>'])
}

/// `_bounded_context`: a fixed-size window centred on a direct shell call.
fn bounded_context(content: &str, match_start: usize) -> String {
    let chars: Vec<char> = content.chars().collect();
    let at = content[..match_start].chars().count();
    let left = at.saturating_sub(MAX_DIRECT_SHELL_CONTEXT_CHARS / 2);
    let right = chars.len().min(left + MAX_DIRECT_SHELL_CONTEXT_CHARS);
    let left = right.saturating_sub(MAX_DIRECT_SHELL_CONTEXT_CHARS);
    let window: String = chars[left..right].iter().collect();
    window
        .trim_end_matches([
            '\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}',
        ])
        .to_owned()
}

/// `_classify_tm1`: severity and confidence of one candidate.
fn classify_tm1(
    context: &str,
    matched: &str,
    matched_line: &str,
    confidence: f32,
    ft: FileType,
    safe: (Option<bool>, Option<bool>),
) -> (Severity, f32) {
    let safe_context = safe.0.unwrap_or_else(|| {
        is_safe_container_command(context) || is_safe_dockerfile_idiom(context, matched)
    });
    let safe_line = safe
        .1
        .unwrap_or_else(|| is_safe_cache_cleanup(matched_line));
    if safe_context || safe_line {
        return (Severity::Low, confidence.min(0.15));
    }
    let adjusted = if matches!(
        ft,
        FileType::Python | FileType::Shell | FileType::Javascript
    ) {
        round2((f64::from(confidence) + 0.1).min(1.0))
    } else {
        confidence
    };
    (Severity::High, adjusted)
}

#[allow(clippy::cast_possible_truncation)]
fn round2(v: f64) -> f32 {
    ((v * 100.0).round() / 100.0) as f32
}

struct Scan<'a> {
    text: &'a str,
    path: &'a str,
    ft: FileType,
    index: LineIndex,
    contexts: HashMap<u32, String>,
}

impl Scan<'_> {
    fn ctx(&mut self, start: usize) -> String {
        let line = self.index.line(start);
        self.contexts
            .entry(line)
            .or_insert_with(|| get_context(self.text, start))
            .clone()
    }

    fn finding(
        &self,
        rule: &'static str,
        message: &str,
        severity: Severity,
        confidence: f32,
        start: usize,
    ) -> RawFinding {
        let mut f = RawFinding::new(
            rule,
            message,
            severity,
            confidence,
            self.path,
            self.index.line(start),
        );
        f.tags = vec![CATEGORY_TAG.to_owned()];
        f
    }
}

impl ToolMisuse {
    /// The TM1 loop of `analyze` (`_direct_shell_only=False`, `defer_variable_reconciliation=True`).
    fn tm1(scan: &mut Scan<'_>) -> Vec<RawFinding> {
        let content = scan.text;
        let windows: HashMap<(usize, usize), VariableWindow> = variable_shell_matches(content)
            .into_iter()
            .map(|w| ((w.start, w.end), w))
            .collect();
        // TODO(pyast): for Python files Python parses the module here and drops windows whose
        // binding is invisible or replaced (`invisible_variable_matches`); that runs only when the
        // reconciliation is not deferred, which the runner always requests, so it lives in
        // `variable_shell::reconcile_with_ast` (postprocess) instead.
        let shell_content = perl_shell_content(content, scan.ft);
        let mut findings: Vec<RawFinding> = Vec::new();
        let mut by_key: HashMap<(u32, String), usize> = HashMap::new();
        let mut direct_safety: HashMap<u32, (bool, bool)> = HashMap::new();
        for c in tm1_candidates(content, shell_content.as_deref()) {
            let variable = windows.get(&(c.start, c.end));
            let line = scan.index.line(c.start);
            let classification_context = scan.ctx(c.start);
            let context_text = if c.direct {
                bounded_context(content, c.start)
            } else {
                classification_context.clone()
            };
            let matched = first_chars(&c.text, 200);
            let matched_line = line_containing(content, c.start, c.end);
            let (severity, adjusted) = if c.direct {
                let safety = *direct_safety.entry(line).or_insert_with(|| {
                    (
                        is_safe_container_command(&classification_context)
                            || is_safe_dockerfile_idiom(&classification_context, matched),
                        is_safe_cache_cleanup(matched_line),
                    )
                });
                classify_tm1(
                    &classification_context,
                    matched,
                    matched_line,
                    c.confidence,
                    scan.ft,
                    (Some(safety.0), Some(safety.1)),
                )
            } else {
                classify_tm1(
                    &classification_context,
                    matched,
                    matched_line,
                    c.confidence,
                    scan.ft,
                    (None, None),
                )
            };
            let identity = if c.direct || variable.is_some() {
                &c.text
            } else {
                matched
            };
            let key = (line, collapse_ws(identity));
            if let Some(&i) = by_key.get(&key) {
                if adjusted > findings[i].confidence {
                    findings[i].confidence = adjusted;
                    findings[i].severity = severity;
                }
                continue;
            }
            let mut identity_match = c.text.clone();
            let mut f = scan.finding("TM1", "Tool Parameter Abuse", severity, adjusted, c.start);
            f.context = Some(context_text);
            if c.direct {
                identity_match = direct_identity(content, &c);
                f.evidence.insert(DIRECT_MARK.to_owned(), "1".to_owned());
            }
            if let Some(w) = variable {
                // `defer_variable_reconciliation`: without Python bindings keep only
                // call-anchored windows of true-prefixed names.
                if scan.ft != FileType::Python && !is_true_prefixed_name(&w.name) {
                    continue;
                }
                f.evidence.insert(VARIABLE_MARK.to_owned(), w.name.clone());
                if call_start(w).is_some() && w.name.to_lowercase().starts_with("true") {
                    identity_match.clone_from(&c.text);
                }
            }
            f.matched_text = Some(matched.to_owned());
            f.fingerprint_text = Some(identity_match);
            by_key.insert(key, findings.len());
            findings.push(f);
        }
        findings
    }

    fn tm2(scan: &mut Scan<'_>) -> Vec<RawFinding> {
        let mut out = Vec::new();
        for (pat, confidence, prose) in TM2_PATS.iter() {
            for hit in hits(pat, scan.text, *prose) {
                let full = &scan.text[hit.0..hit.1];
                let context = scan.ctx(hit.0);
                let matched = first_chars(full, 200);
                let (severity, adjusted) = if is_safe_dockerfile_idiom(&context, matched) {
                    (Severity::Low, confidence.min(0.15))
                } else {
                    (Severity::High, *confidence)
                };
                let mut f = scan.finding("TM2", "Chaining Abuse", severity, adjusted, hit.0);
                f.context = Some(context);
                f.matched_text = Some(matched.to_owned());
                f.fingerprint_text = Some(full.to_owned());
                out.push(f);
            }
        }
        out
    }

    fn tm3(scan: &mut Scan<'_>) -> Vec<RawFinding> {
        let mut out = Vec::new();
        for entry in tm3_entries(scan.ft == FileType::Shell) {
            let pat = compile(&entry.source);
            for hit in hits(&pat, scan.text, entry.kind == Tm3Kind::Prose) {
                if entry.kind == Tm3Kind::UmaskCall && is_assigned_value(scan.text, hit.0) {
                    continue;
                }
                let full = &scan.text[hit.0..hit.1];
                let mut f = scan.finding(
                    "TM3",
                    "Unsafe Defaults",
                    Severity::Medium,
                    entry.confidence,
                    hit.0,
                );
                f.context = Some(scan.ctx(hit.0));
                f.matched_text = Some(first_chars(full, 200).to_owned());
                f.fingerprint_text = Some(full.to_owned());
                out.push(f);
            }
        }
        out
    }

    fn tm4(scan: &mut Scan<'_>) -> Vec<RawFinding> {
        let reference = is_reference_material(scan.path, scan.ft);
        let mut out = Vec::new();
        for (pat, confidence) in TM4_PATS.iter() {
            for hit in pat.find_iter(scan.text) {
                let full = hit.text(scan.text);
                let mut f = scan.finding(
                    "TM4",
                    "Privileged Kubernetes Workload",
                    Severity::High,
                    *confidence,
                    hit.start,
                );
                if reference {
                    f.tags.extend([
                        "contextual-triage".to_owned(),
                        "likely-benign-context".to_owned(),
                    ]);
                }
                f.context = Some(scan.ctx(hit.start));
                f.matched_text = Some(first_chars(full, 200).to_owned());
                f.fingerprint_text = Some(full.to_owned());
                out.push(f);
            }
        }
        out
    }
}

/// `re.finditer` or `iter_paragraph_matches`, as `(start, end)`.
fn hits(pat: &Pat, text: &str, prose: bool) -> Vec<(usize, usize)> {
    let found = if prose {
        paragraph_matches(pat, text)
    } else {
        pat.find_iter(text)
    };
    found.into_iter().map(|h| (h.start, h.end)).collect()
}

/// The text a direct `shell=True` call is fingerprinted from (`canonical_match`).
fn direct_identity(content: &str, c: &Candidate) -> String {
    let canonical_start = c
        .alternate_start
        .filter(|&a| a < c.start)
        .unwrap_or(c.start);
    let shell_end = c.anchor.and_then(|a| {
        SHELL_TRUE_VALUE
            .find_in(content, a, content.len())
            .into_iter()
            .find(|h| h.start == a)
            .map(|h| h.end)
    });
    match shell_end {
        Some(end) => content[canonical_start..end].to_owned(),
        None => match (&c.alternate_text, c.alternate_start) {
            (Some(t), Some(a)) if a < c.start => t.clone(),
            _ => c.text.clone(),
        },
    }
}

/// `_perl_literal_print_shell_text` for Perl files.
fn perl_shell_content(content: &str, ft: FileType) -> Option<String> {
    // TODO(perl): projection of printed Perl literals (offsets preserved); only changes which
    // `rm` commands inside `print "..."` are parsed as shell. Not needed by the golden corpus.
    let _ = (content, ft);
    None
}

impl StaticModule for ToolMisuse {
    fn id(&self) -> &'static str {
        "static_patterns_tool_misuse"
    }

    fn uses_python_ast(&self) -> bool {
        // POSTPROCESS_USES_PYTHON_AST: the module wants the parse and the Python source type.
        true
    }

    /// Only `POSTPROCESS_USES_PYTHON_AST` is set in Python, so the lexical scan covers every view.
    fn runs_derived_views(&self) -> bool {
        true
    }

    fn analyze(
        &self,
        text: &str,
        path: &str,
        ft: FileType,
        _py: Option<&PyFile>,
    ) -> Vec<RawFinding> {
        let mut scan = Scan {
            text,
            path,
            ft,
            index: LineIndex::new(text),
            contexts: HashMap::new(),
        };
        let mut out = Self::tm1(&mut scan);
        out.extend(Self::tm2(&mut scan));
        out.extend(Self::tm3(&mut scan));
        out.extend(Self::tm4(&mut scan));
        out
    }

    /// `postprocess_path_findings`: reconcile, coalesce direct calls and drop private state.
    fn postprocess(
        &self,
        _text: &str,
        findings: Vec<RawFinding>,
        py: Option<&PyFile>,
    ) -> Vec<RawFinding> {
        // TODO(pyast): `_bound_direct_replays` and `direct_literal_metadata` rebind direct calls to
        // AST call spans; the coalescing of lexical owners against AST-bound findings is in
        // `coalesce` below minus the bound half.
        let findings = variable_shell::reconcile_with_ast(findings, py);
        let mut seen: std::collections::HashSet<(String, u32, Option<String>)> =
            std::collections::HashSet::new();
        let mut out = Vec::new();
        for mut f in findings {
            let direct = f.evidence.contains_key(DIRECT_MARK);
            f.evidence.remove(DIRECT_MARK);
            f.evidence.remove(VARIABLE_MARK);
            if f.rule_id == "TM1"
                && direct
                && !seen.insert((f.file.clone(), f.start_line, f.fingerprint()))
            {
                continue;
            }
            out.push(f);
        }
        out
    }
}

#[cfg(test)]
mod tests;
