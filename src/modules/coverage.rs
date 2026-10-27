//! AE1: a `SKILL.md` reference that resolves to a bundled file whose inspection was incomplete
//! (`finalize_inspection_ledger._reference_coverage_findings`).
//!
//! A target is incomplete when it is a binary artifact (`classify_artifact(referenced=True)`), when
//! the tool-misuse parser hit its span limit on it (`static_parse_limit`), or when declared-marker
//! reconstruction could not be evaluated (`obfuscated_instruction_text`).
//!
//! Not ported: `runtime_limit` rows of the LLM meta stage (a run-time accident of the golden
//! corpus), ledger/status validation (every ledger is complete here), size-limit AE7 (files are
//! only cut at 16 MiB) and the passive-PNG exemption.

use super::coverage_refs::{Reference, resolve_references};
use crate::analyzer::Analyzer;
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::modules::tool_misuse::has_bounded_parse_exhaustion;
use crate::skill::{Skill, SourceFile};
use serde_json::{Value, json};
use std::collections::HashSet;

const STATIC_PARSE_LIMIT: &str =
    "A security-relevant expression exceeded a bounded static parser's span limit.";
const OBFUSCATED: &str =
    "Obfuscated instruction text could not be fully evaluated by the deterministic layer.";
const BINARY: &str = "Binary content cannot be inspected as text.";

/// The static analyzers that run over text artifacts, in the order Python lists them.
const STATIC_ANALYZERS: [&str; 13] = [
    "static_patterns_agent_snooping",
    "static_patterns_anti_refusal",
    "static_patterns_deserialization",
    "static_patterns_excessive_agency",
    "static_patterns_harmful_content",
    "static_patterns_memory_poisoning",
    "static_patterns_privilege_escalation",
    "static_patterns_prompt_injection",
    "static_patterns_rogue_agent",
    "static_patterns_ssrf",
    "static_patterns_supply_chain",
    "static_patterns_system_prompt_leakage",
    "static_patterns_tool_misuse",
];

/// The AE1 detector.
pub struct ReferenceCoverage;

/// Why one target is incomplete, as the ledger rows AE1 evidence copies.
fn reasons(f: &SourceFile) -> Vec<Value> {
    let mut rows = Vec::new();
    if f.binary && !f.readable_binary {
        rows.push(json!({"reason_code": "binary_content", "message": BINARY, "phase": "artifact", "analyzers": []}));
        return rows;
    }
    if !f.cached {
        return rows;
    }
    if marker_projection_limited(f) {
        for a in STATIC_ANALYZERS {
            rows.push(json!({"reason_code": "obfuscated_instruction_text", "message": OBFUSCATED, "phase": "static", "analyzers": [a]}));
        }
    }
    if parse_limited(f) {
        rows.push(json!({"reason_code": "static_parse_limit", "message": STATIC_PARSE_LIMIT, "phase": "static", "analyzers": ["static_patterns_tool_misuse"]}));
    }
    rows
}

/// The tool-misuse parser's `has_bounded_parse_exhaustion` over the file as a whole.
/// Python and Perl complete-context readings are not ported and count as within bounds.
fn parse_limited(f: &SourceFile) -> bool {
    !(f.binary && !f.readable_binary)
        && has_bounded_parse_exhaustion(&f.text, f.file_type, true).unwrap_or(false)
}

/// Declared-marker reconstruction could not be fully evaluated.
fn marker_projection_limited(f: &SourceFile) -> bool {
    super::declared_marker::marker_projection_limited(&f.text)
}

fn remediation(rows: &[Value]) -> String {
    let has = |code: &str| rows.iter().any(|r| r["reason_code"] == code);
    let mut actions: Vec<&str> = Vec::new();
    if has("static_parse_limit") {
        actions.push("Review the reported expression and analyzer's parsing limitation; correct the scanner if it misinterprets valid source, then rerun the scan.");
    }
    if has("binary_content") {
        actions.push("Provide inspectable source or analysis support for the referenced format.");
    }
    let distinct: HashSet<&str> = rows
        .iter()
        .filter_map(|r| r["reason_code"].as_str())
        .collect();
    if actions.is_empty() || distinct.len() > 1 {
        actions
            .push("Review the target's analysis-completeness ledger and resolve all limitations.");
    }
    actions
        .push("Keep required references; incomplete analysis is not proof of malicious evasion.");
    actions.join(" ")
}

fn finding(r: &Reference, source: &str, rows: &[Value]) -> RawFinding {
    let mut f = RawFinding::new(
        "AE1",
        "Referenced artifact was not completely inspected",
        Severity::High,
        1.0,
        source,
        r.line,
    );
    f.category = Some("analysis-evasion".to_owned());
    f.pattern = Some("Incomplete referenced artifact analysis".to_owned());
    f.tags = ["coverage", "reference", "target-disposition:partial"]
        .map(str::to_owned)
        .to_vec();
    f.matched_text = Some(r.target.clone());
    f.context = Some(r.evidence.clone());
    f.remediation = Some(remediation(rows));
    let evidence = [
        ("target_path", json!(r.target)),
        ("target_disposition", json!("partial")),
        ("reasons", Value::Array(rows.to_vec())),
    ];
    f.evidence = evidence
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_string()))
        .collect();
    f
}

impl Analyzer for ReferenceCoverage {
    fn id(&self) -> &'static str {
        "reference_coverage"
    }

    fn run(&self, skill: &Skill) -> Vec<RawFinding> {
        let Some(primary) = ["SKILL.md", "skill.md"]
            .into_iter()
            .find_map(|n| skill.files.iter().find(|f| f.rel == n && f.cached))
        else {
            return Vec::new();
        };
        let known: Vec<&str> = skill.files.iter().map(|f| f.rel.as_str()).collect();
        let mut seen: HashSet<(u32, String)> = HashSet::new();
        let mut out = Vec::new();
        for r in resolve_references(&primary.rel, &primary.text, &known) {
            let Some(target) = skill.files.iter().find(|f| f.rel == r.target) else {
                continue;
            };
            let rows = reasons(target);
            if rows.is_empty() || !seen.insert((r.line, r.target.clone())) {
                continue;
            }
            out.push(finding(&r, &primary.rel, &rows));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(files: &[(&str, &[u8])]) -> Vec<RawFinding> {
        let all = files
            .iter()
            .map(|(p, b)| ((*p).to_owned(), b.to_vec()))
            .collect();
        ReferenceCoverage.run(&Skill::from_memory(all))
    }

    #[test]
    fn binary_reference_is_incomplete() {
        let f = run(&[
            ("SKILL.md", b"# s\nsee [data](assets/blob.bin)\n"),
            ("assets/blob.bin", b"\x7fELF\x00\x01\x02\x03"),
        ]);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].rule_id, f[0].start_line), ("AE1", 2));
        assert!(f[0].tags.contains(&"target-disposition:partial".to_owned()));
        assert!(f[0].evidence["reasons"].contains("binary_content"));
    }

    #[test]
    fn text_reference_is_complete() {
        let f = run(&[
            ("SKILL.md", b"[a](refs/a.md)\n"),
            ("refs/a.md", b"plain text\n"),
        ]);
        assert!(f.is_empty());
    }

    #[test]
    fn unparseable_destructive_command_hits_the_parse_limit() {
        let many = (0..9).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        let script = format!("rm -rf {{{many}}}/x\n");
        let f = run(&[
            ("SKILL.md", b"run `scripts/clean.sh`\n"),
            ("scripts/clean.sh", script.as_bytes()),
        ]);
        assert_eq!(f.len(), 1);
        assert!(f[0].evidence["reasons"].contains("static_parse_limit"));
        assert!(
            f[0].remediation
                .as_deref()
                .is_some_and(|r| r.contains("parsing limitation"))
        );
    }

    #[test]
    fn same_target_on_one_line_is_reported_once() {
        let f = run(&[
            ("SKILL.md", b"[a](x.bin) and [b](x.bin)\n"),
            ("x.bin", b"MZ\x00\x00\x00\x00\x00\x00\x00"),
        ]);
        assert_eq!(f.len(), 1);
    }
}
