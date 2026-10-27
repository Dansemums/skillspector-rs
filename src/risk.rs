//! SkillSpector's risk verdict (`_compute_risk_score` in `nodes/report.py`).
//!
//! Each finding scores `points(severity) * weight(n) * confidence`, where `n` counts the finding
//! among those of the same rule (weights 1.0, 0.5, 0.25; later ones are ignored). Findings in
//! executable files are multiplied by 1.3. A few findings put a floor of 51 under the score.
//!
//! Not ported: the BH2/BH3 floors (those analyzers do not exist here yet) and the baseline.

use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::modules::concealed_executable::is_executable_content;
use crate::skill::Skill;
use serde::Serialize;
use std::collections::HashMap;

const MAX_OCCURRENCES_PER_RULE: usize = 3;
const DIMINISHING_WEIGHTS: [f32; MAX_OCCURRENCES_PER_RULE] = [1.0, 0.5, 0.25];
const EXECUTABLE_MULTIPLIER: f32 = 1.3;
const BLOCKING_FLOOR: u32 = 51;
const MAX_SCORE: u32 = 100;

/// The overall verdict for one skill.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Risk {
    /// 0 (nothing found) to 100.
    pub score: u32,
    /// Band of the score: `LOW` (0-20), `MEDIUM` (21-50), `HIGH` (51-80) or `CRITICAL` (81-100).
    pub severity: Severity,
    /// `SAFE`, `CAUTION` or `DO_NOT_INSTALL`.
    pub recommendation: &'static str,
    /// Worst severity among the findings, or `None` when there are none. It can be higher than
    /// `severity`, because the score is weighted by confidence.
    pub max_issue_severity: Option<Severity>,
}

fn points(s: Severity) -> f32 {
    match s {
        Severity::Critical => 50.0,
        Severity::High => 25.0,
        Severity::Medium => 10.0,
        Severity::Low => 5.0,
    }
}

fn rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    }
}

fn band(score: u32) -> (Severity, &'static str) {
    match score {
        81.. => (Severity::Critical, "DO_NOT_INSTALL"),
        51.. => (Severity::High, "DO_NOT_INSTALL"),
        21.. => (Severity::Medium, "CAUTION"),
        _ => (Severity::Low, "SAFE"),
    }
}

fn evidence_true(f: &RawFinding, key: &str) -> bool {
    f.evidence.get(key).is_some_and(|v| v == "true")
}

fn floor(f: &RawFinding) -> u32 {
    let blocks = f.rule_id == "SC8"
        || (f.rule_id == "SC9"
            && (evidence_true(f, "excluded_from_analysis")
                || evidence_true(f, "partially_analyzed_executable")));
    if blocks { BLOCKING_FLOOR } else { 0 }
}

/// Scores the raw (not yet grouped) findings of one skill.
pub(crate) fn assess(findings: &[RawFinding], skill: &Skill) -> Risk {
    let executable: HashMap<&str, bool> = skill
        .files
        .iter()
        .map(|f| (f.rel.as_str(), is_executable_content(f)))
        .collect();
    let mut scored: Vec<&RawFinding> = findings
        .iter()
        .filter(|f| f.confidence.clamp(0.0, 1.0) > 0.0)
        .collect();
    scored.sort_by_key(|f| (f.rule_id, rank(f.severity))); // stable, like Python's sorted()
    let mut seen: HashMap<&str, usize> = HashMap::new();
    let mut total = 0.0_f32;
    for f in &scored {
        let n = seen.entry(f.rule_id).or_default();
        let weight = DIMINISHING_WEIGHTS.get(*n).copied();
        *n += 1;
        let Some(weight) = weight else { continue };
        let mut part = points(f.severity) * weight * f.confidence.clamp(0.0, 1.0);
        if executable.get(f.file.as_str()).copied().unwrap_or(false) {
            part *= EXECUTABLE_MULTIPLIER;
        }
        total += part;
    }
    let floor = scored.iter().map(|f| floor(f)).max().unwrap_or(0);
    // `as u32` truncates toward zero, like Python's int().
    let score = MAX_SCORE.min(floor.max(total as u32));
    let (severity, recommendation) = band(score);
    Risk {
        score,
        severity,
        recommendation,
        max_issue_severity: findings.iter().map(|f| f.severity).max(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(id: &'static str, sev: Severity, conf: f32, file: &str) -> RawFinding {
        let mut r = RawFinding::new(id, "m", sev, conf, file, 1);
        r.confidence = conf;
        r
    }

    fn skill() -> Skill {
        Skill::from_memory(vec![
            ("a.md".to_owned(), b"x".to_vec()),
            ("run.py".to_owned(), b"x".to_vec()),
        ])
    }

    #[test]
    fn nothing_found_is_safe() {
        let r = assess(&[], &skill());
        assert_eq!(
            (r.score, r.recommendation, r.max_issue_severity),
            (0, "SAFE", None)
        );
    }

    #[test]
    fn repeats_of_one_rule_diminish_and_stop_after_three() {
        let f: Vec<_> = (0..5)
            .map(|_| raw("X1", Severity::High, 1.0, "a.md"))
            .collect();
        assert_eq!(assess(&f, &skill()).score, 43); // 25 + 12.5 + 6.25
    }

    #[test]
    fn executable_files_weigh_more_and_confidence_scales() {
        assert_eq!(
            assess(&[raw("X1", Severity::High, 0.5, "run.py")], &skill()).score,
            16
        );
        assert_eq!(
            assess(&[raw("X1", Severity::High, 0.5, "a.md")], &skill()).score,
            12
        );
    }

    #[test]
    fn score_is_capped_and_sc8_blocks() {
        let f: Vec<_> = ["A", "B", "C"]
            .iter()
            .map(|i| raw(i, Severity::Critical, 1.0, "a.md"))
            .collect();
        let r = assess(&f, &skill());
        assert_eq!((r.score, r.recommendation), (100, "DO_NOT_INSTALL"));
        let r = assess(&[raw("SC8", Severity::Low, 0.1, "a.md")], &skill());
        assert_eq!((r.score, r.severity), (51, Severity::High));
    }
}
