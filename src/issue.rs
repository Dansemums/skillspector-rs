//! One finding, shaped like an entry of SkillSpector's JSON `issues` array.

use serde::{Deserialize, Serialize};

/// SkillSpector's severity labels, ordered from least to most severe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Informational or low-impact.
    Low,
    /// Worth reviewing.
    Medium,
    /// Likely harmful.
    High,
    /// Clearly malicious or dangerous.
    Critical,
}

impl Severity {
    /// Parses a label such as `"HIGH"`; unknown labels count as `Low`.
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        match label.to_ascii_uppercase().as_str() {
            "CRITICAL" => Self::Critical,
            "HIGH" => Self::High,
            "MEDIUM" => Self::Medium,
            _ => Self::Low,
        }
    }
}

/// A finding in one file of one skill.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Issue {
    /// Pattern id, e.g. `SC2`.
    pub id: String,
    /// Rule category, e.g. `Supply Chain`.
    pub category: String,
    /// Human-readable rule name.
    pub pattern: String,
    /// How serious the finding is.
    pub severity: Severity,
    /// Rule confidence from 0.0 to 1.0.
    pub confidence: f32,
    /// Path relative to the skill folder, with `/` separators.
    pub file: String,
    /// 1-based line, when the finding has one.
    pub start_line: Option<u32>,
    /// The matched text.
    pub finding: String,
}
