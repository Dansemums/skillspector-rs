//! The finding an analyzer emits before de-duplication (`AnalyzerFinding` / `Finding`).

use crate::issue::Severity;
use std::collections::BTreeMap;

/// One match, located but not yet grouped.
#[derive(Clone, Debug, PartialEq)]
pub struct RawFinding {
    pub rule_id: &'static str,
    pub message: String,
    pub severity: Severity,
    pub confidence: f32,
    pub file: String,
    pub start_line: u32,
    pub end_line: Option<u32>,
    /// Zero-based character column.
    pub start_column: Option<u32>,
    pub end_column: Option<u32>,
    pub tags: Vec<String>,
    /// The surrounding lines (`context`); PE3 documentation tagging reads it.
    pub context: Option<String>,
    pub matched_text: Option<String>,
    /// The text the fingerprint is built from when it is not `matched_text`
    /// (`complete_match` / `compute_match_fingerprint`).
    pub fingerprint_text: Option<String>,
    pub evidence: BTreeMap<String, String>,
    pub category: Option<String>,
    pub pattern: Option<String>,
    pub explanation: Option<String>,
    pub remediation: Option<String>,
}

impl RawFinding {
    /// A finding with only the required fields set.
    #[must_use]
    pub fn new(
        rule_id: &'static str,
        message: impl Into<String>,
        severity: Severity,
        confidence: f32,
        file: &str,
        start_line: u32,
    ) -> Self {
        Self {
            rule_id,
            message: message.into(),
            severity,
            confidence,
            file: file.to_owned(),
            start_line,
            end_line: None,
            start_column: None,
            end_column: None,
            tags: Vec::new(),
            context: None,
            matched_text: None,
            fingerprint_text: None,
            evidence: BTreeMap::new(),
            category: None,
            pattern: None,
            explanation: None,
            remediation: None,
        }
    }

    /// `Finding.fingerprint()` without the hash: the whitespace-normalised text the rule matched,
    /// or `None` when the finding has nothing to group on (each such finding stays alone).
    #[must_use]
    pub fn fingerprint(&self) -> Option<String> {
        let text = match (&self.fingerprint_text, &self.matched_text) {
            (Some(t), _) => t.as_str(),
            (None, Some(t)) if !t.is_empty() => t.as_str(),
            _ => return None,
        };
        Some(crate::unicode::collapse_ws(text))
    }
}
