//! AE4 (`artifact_integrity._text_signals`): format controls or ASCII/Greek/Cyrillic mixed-script
//! tokens in a text artifact. Reported at line 1.
//!
//! Not ported: AE2/AE3/AE5/AE6 (no golden finding) and the readable-binary projection.

use crate::analyzer::Analyzer;
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::skill::{Skill, SourceFile};
use crate::unicode::{category, is_alnum, is_alpha};

/// The AE4 detector.
pub struct ArtifactIntegrity;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    Cyrillic,
    Greek,
}

/// `"CYRILLIC" in unicodedata.name(c)` / `"GREEK" in ...` for an alphabetic non-ASCII character
/// (code-point blocks instead of the name table; Coptic letters are not Greek).
fn script_of(c: char) -> Option<Script> {
    match u32::from(c) {
        0x0400..=0x052F
        | 0x1C80..=0x1C88
        | 0x1D2B
        | 0x1D78
        | 0xA640..=0xA69F
        | 0x1E030..=0x1E08F => Some(Script::Cyrillic),
        0x0370..=0x03E1 | 0x03F0..=0x03FF | 0x1D26..=0x1D2A | 0x1D66..=0x1D6A | 0x1F00..=0x1FFF => {
            Some(Script::Greek)
        }
        _ => None,
    }
}

/// `(format_density, mixed_script)` of `text`.
fn signals(text: &str) -> (f64, bool) {
    let (mut ignored, mut total) = (0usize, 0usize);
    let (mut mixed, mut latin, mut others) = (false, false, 0u8);
    let mut seen: Vec<Script> = Vec::new();
    for c in text.chars() {
        total += 1;
        if c == '\u{ad}' || (matches!(category(c), "Cf" | "Cc") && !matches!(c, '\n' | '\r' | '\t'))
        {
            ignored += 1;
        }
        if c.is_ascii() && is_alpha(c) {
            latin = true;
        } else if is_alpha(c) {
            if let Some(s) = script_of(c)
                && !seen.contains(&s)
            {
                seen.push(s);
                others += 1;
            }
        } else if is_alnum(c) || c == '_' || c == '-' {
            // continues the token
        } else {
            mixed |= latin && others > 0;
            latin = false;
            seen.clear();
            others = 0;
        }
    }
    mixed |= latin && others > 0;
    #[allow(clippy::cast_precision_loss)]
    let density = if total == 0 {
        0.0
    } else {
        ignored as f64 / total as f64
    };
    (density, mixed)
}

fn flagged(f: &SourceFile) -> bool {
    if !f.cached || f.binary {
        return false;
    }
    let (density, mixed) = signals(&f.text);
    density >= 0.01 || mixed
}

impl Analyzer for ArtifactIntegrity {
    fn id(&self) -> &'static str {
        "artifact_integrity"
    }

    fn run(&self, skill: &Skill) -> Vec<RawFinding> {
        skill
            .files
            .iter()
            .filter(|f| flagged(f))
            .map(|f| {
                let mut r = RawFinding::new(
                    "AE4",
                    "Suspicious Unicode normalization or mixed-script content",
                    Severity::Medium,
                    0.8,
                    &f.rel,
                    1,
                );
                r.category = Some("analysis-evasion".to_owned());
                r.tags = vec!["artifact-integrity".to_owned()];
                r
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_script_token_is_flagged() {
        assert!(signals("pаssword").1); // Cyrillic a inside a Latin token
        assert!(!signals("hello привет").1);
    }

    #[test]
    fn format_controls_raise_density() {
        let s = format!("a{}b", "\u{200b}".repeat(3));
        assert!(signals(&s).0 >= 0.01);
        assert!(signals("plain text\n\t").0 == 0.0);
    }
}
