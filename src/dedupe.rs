//! `nodes/deduplicate.py` plus `report._expand_occurrences`: one [`Issue`] per occurrence of each
//! group of equivalent findings.
//!
//! Group key: `(rule_id, fingerprint, classification)`. Within a group occurrences are unique on
//! `(file, start_line, end_line, start_column, end_column)`, so two matches on one line count twice
//! only when their columns or end lines differ. Findings without a fingerprint never group.

use crate::finding::RawFinding;
use crate::issue::{Issue, Severity};
use std::collections::{HashMap, HashSet};

/// The fields that must agree before two findings can share a representative.
pub type ClassKey = (
    String,
    Severity,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<String>,
    Vec<(String, String)>,
);

/// `classification_metadata_key`, ignoring the given (view-origin) tags.
#[must_use]
pub fn classification_key(f: &RawFinding, ignored_tags: &[&str]) -> ClassKey {
    let mut tags: Vec<String> = f
        .tags
        .iter()
        .filter(|t| !ignored_tags.contains(&t.as_str()))
        .cloned()
        .collect();
    tags.sort();
    (
        f.message.clone(),
        f.severity,
        f.category.clone(),
        f.pattern.clone(),
        f.explanation.clone(),
        f.remediation.clone(),
        tags,
        f.evidence
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    )
}

type Location = (String, u32, Option<u32>, Option<u32>, Option<u32>);

fn location(f: &RawFinding) -> Location {
    (
        f.file.clone(),
        f.start_line,
        f.end_line,
        f.start_column,
        f.end_column,
    )
}

/// Best representative: most severe, then most confident.
fn is_better(a: &RawFinding, b: &RawFinding) -> bool {
    (a.severity, a.confidence) > (b.severity, b.confidence)
}

fn to_issue(rep: &RawFinding, loc: &Location) -> Issue {
    Issue {
        id: rep.rule_id.to_owned(),
        category: rep
            .category
            .clone()
            .or_else(|| rep.tags.first().cloned())
            .unwrap_or_default(),
        pattern: rep.pattern.clone().unwrap_or_else(|| rep.message.clone()),
        severity: rep.severity,
        confidence: rep.confidence,
        file: loc.0.clone(),
        start_line: Some(loc.1),
        finding: rep
            .matched_text
            .as_deref()
            .map(|t| t.chars().take(200).collect())
            .unwrap_or_default(),
    }
}

/// Groups, de-duplicates and expands findings into the issues SkillSpector reports.
#[must_use]
pub fn finalize(findings: Vec<RawFinding>) -> Vec<Issue> {
    type GroupKey = (&'static str, String, ClassKey);
    let mut index: HashMap<GroupKey, usize> = HashMap::new();
    let mut groups: Vec<Vec<RawFinding>> = Vec::new();
    let mut issues = Vec::new();
    for f in findings {
        let Some(fp) = f.fingerprint() else {
            let loc = location(&f);
            issues.push(to_issue(&f, &loc));
            continue;
        };
        let key = (f.rule_id, fp, classification_key(&f, &[]));
        let slot = *index.entry(key).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[slot].push(f);
    }
    for group in groups {
        let mut rep = &group[0];
        for f in &group[1..] {
            if is_better(f, rep) {
                rep = f;
            }
        }
        let mut seen: HashSet<Location> = HashSet::new();
        for f in &group {
            let loc = location(f);
            if seen.insert(loc.clone()) {
                issues.push(to_issue(rep, &loc));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(rule: &'static str, line: u32, col: Option<u32>, text: &str) -> RawFinding {
        let mut f = RawFinding::new(rule, "m", Severity::Low, 0.5, "a.md", line);
        f.start_column = col;
        f.matched_text = Some(text.into());
        f
    }

    #[test]
    fn same_line_different_columns_count_twice_identical_once() {
        let two = finalize(vec![
            raw("X1", 3, Some(0), "npx a"),
            raw("X1", 3, Some(20), "npx a"),
        ]);
        assert_eq!(two.len(), 2);
        let one = finalize(vec![
            raw("X1", 3, Some(5), "npx a"),
            raw("X1", 3, Some(5), "npx   a"),
        ]);
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn different_text_or_classification_stay_apart() {
        assert_eq!(
            finalize(vec![raw("X1", 1, None, "a"), raw("X1", 1, None, "b")]).len(),
            2
        );
        let mut other = raw("X1", 1, None, "a");
        other.message = "different".into();
        assert_eq!(finalize(vec![raw("X1", 1, None, "a"), other]).len(), 2);
        assert_eq!(
            finalize(vec![raw("X1", 1, None, "a"), raw("X2", 1, None, "a")]).len(),
            2
        );
    }

    #[test]
    fn no_fingerprint_never_groups() {
        let mut a = raw("X1", 1, None, "");
        a.matched_text = None;
        assert_eq!(finalize(vec![a.clone(), a]).len(), 2);
    }

    #[test]
    fn representative_is_most_severe_then_confident() {
        let mut hi = raw("X1", 2, None, "a");
        hi.confidence = 0.9;
        let issues = finalize(vec![raw("X1", 1, None, "a"), hi]);
        assert_eq!(issues.len(), 2);
        assert!(
            issues
                .iter()
                .all(|i| (i.confidence - 0.9).abs() < f32::EPSILON)
        );
    }
}
