//! Contextual filters the static runner applies to converted findings
//! (`static_runner._convert_analyzer_finding`): EA3 license boilerplate and PE3 `.env` docs.

use crate::finding::RawFinding;
use crate::matcher::Pat;
use crate::skill::FileType;
use crate::text::py_splitlines;
use crate::unicode::{casefold, collapse_ws};
use std::sync::LazyLock;

/// `(canonical lines, line offset of the only suppressible line)`.
const LICENSE_RANGES: [(&[&str], usize); 7] = [
    (
        &[
            "\"source\" form shall mean the preferred form for making modifications,",
            "including but not limited to software source code, documentation",
            "source, and configuration files.",
        ],
        1,
    ),
    (
        &[
            "transformation or translation of a source form, including but",
            "not limited to compiled object code, generated documentation,",
            "and conversions to other media types.",
        ],
        1,
    ),
    (
        &[
            "the copyright owner. For the purposes of this definition, \"submitted\"",
            "means any form of electronic, verbal, or written communication sent",
            "to the Licensor or its representatives, including but not limited to",
            "communication on electronic mailing lists, source code control systems,",
        ],
        2,
    ),
    (
        &[
            "result of this License or out of the use or inability to use the",
            "Work (including but not limited to damages for loss of goodwill,",
            "work stoppage, computer failure or malfunction, or any and all",
        ],
        1,
    ),
    (
        &[
            "the software is provided \"as is\", without warranty of any kind, express or",
            "implied, including but not limited to the warranties of merchantability,",
            "fitness for a particular purpose and NONINFRINGEMENT. in no event shall the",
        ],
        1,
    ),
    (
        &[
            "this software is provided by the copyright holders and contributors \"as is\"",
            "and any express or implied warranties, including, but not limited to, the",
            "implied warranties of merchantability and fitness for a particular purpose are",
        ],
        1,
    ),
    (
        &[
            "the font software is provided \"as is\", without warranty of any kind,",
            "express or implied, including but not limited to any warranties of",
            "merchantability, fitness for a particular purpose and noninfringement",
        ],
        1,
    ),
];

static LICENSE_BASENAME: LazyLock<Pat> = LazyLock::new(|| {
    Pat::new(
        r"\A(?:license|licenses|copying|notice|notices|(?:[^/]*[._-])?ofl)(?:[._-].*)?\Z",
        "",
    )
});

fn normalize_license_line(line: &str) -> String {
    collapse_ws(&casefold(line))
}

/// `_is_license_basename`.
#[must_use]
pub fn is_license_basename(path: &str, ft: FileType) -> bool {
    if !matches!(ft, FileType::Markdown | FileType::Text | FileType::Other) {
        return false;
    }
    let norm = path.replace('\\', "/");
    let base = norm.rsplit('/').next().unwrap_or(&norm);
    if ft == FileType::Other
        && let Some((_, suffix)) = base.rsplit_once('.')
        && casefold(&format!(".{suffix}")) != ".lesser"
    {
        return false;
    }
    !LICENSE_BASENAME.find_iter(&casefold(base)).is_empty()
}

/// Normalised lines of a license file, built once per file.
#[must_use]
pub fn normalized_license_lines(text: &str) -> Vec<String> {
    py_splitlines(text)
        .into_iter()
        .map(normalize_license_line)
        .collect()
}

/// `_is_license_boilerplate_in_normalized_lines`.
#[must_use]
pub fn is_license_boilerplate(lines: &[String], start_line: u32) -> bool {
    let Ok(line) = usize::try_from(start_line) else {
        return false;
    };
    if line < 1 || line > lines.len() {
        return false;
    }
    LICENSE_RANGES.iter().any(|(canonical, offset)| {
        let Some(range_start) = line.checked_sub(offset + 1) else {
            return false;
        };
        let Some(window) = lines.get(range_start..range_start + canonical.len()) else {
            return false;
        };
        window
            .iter()
            .zip(canonical.iter())
            .all(|(have, want)| *have == normalize_license_line(want))
    })
}

static PE3_PATTERNS: LazyLock<[Pat; 3]> = LazyLock::new(|| {
    [
        Pat::new(
            r"\A(?:[-*]\s*)?(?:cp|copy|mv|rename)\s+\.env\.(?:example|sample|template)\s+(?:to\s+)?\.env(?:\s+(?:before\s+(?:running|starting)(?:\s+the\s+app)?|for\s+local\s+development))?[.:]?\Z",
            "i",
        ),
        Pat::new(
            r"\A(?:create|configure|set\s+up|make|add)\s+(?:an?\s+|the\s+)?\.env(?:\s+file)?(?:\s+in\s+the\s+project\s+root)?(?:\s+with\s+(?:your\s+)?api\s+keys?|\s+for\s+(?:local\s+)?(?:development|testing))?[.:]?\Z",
            "i",
        ),
        Pat::new(
            r"\A(?:install|use)\s+(?:python-)?dotenv\s+to\s+load\s+(?:the\s+)?\.env\s+file[.:]?\Z",
            "i",
        ),
    ]
});

/// `_is_env_file_reference_in_docs` with the file's lines passed in.
#[must_use]
pub fn is_env_file_reference_in_docs(
    f: &RawFinding,
    ft: FileType,
    path: &str,
    lines: &[&str],
) -> bool {
    if f.rule_id != "PE3" || !matches!(ft, FileType::Markdown | FileType::Text) {
        return false;
    }
    if path.replace('\\', "/").to_lowercase().ends_with("skill.md") {
        return false;
    }
    if f.context.as_deref().is_none_or(str::is_empty) {
        return false;
    }
    let Some(line) = usize::try_from(f.start_line)
        .ok()
        .and_then(|l| l.checked_sub(1))
        .and_then(|i| lines.get(i))
    else {
        return false;
    };
    let normalized = line.replace('`', "");
    let normalized = normalized.trim_matches(crate::unicode::is_space);
    PE3_PATTERNS
        .iter()
        .any(|p| !p.find_iter(normalized).is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issue::Severity;

    #[test]
    fn license_names() {
        assert!(is_license_basename("LICENSE", FileType::Other));
        assert!(is_license_basename("sub/LICENSE.md", FileType::Markdown));
        assert!(is_license_basename("Font-OFL.txt", FileType::Text));
        assert!(!is_license_basename("LICENSE.py", FileType::Python));
        assert!(!is_license_basename("LICENSE.pdf", FileType::Other));
        assert!(is_license_basename("COPYING.LESSER", FileType::Other));
        assert!(!is_license_basename("readme.md", FileType::Markdown));
    }

    #[test]
    fn license_boilerplate_line() {
        let text = "x\n\"Source\" form shall mean the preferred form for making modifications,\n\
                    including but not limited to software source code, documentation\n\
                    source, and configuration files.\ny";
        let lines = normalized_license_lines(text);
        assert!(is_license_boilerplate(&lines, 3));
        assert!(!is_license_boilerplate(&lines, 2));
        assert!(!is_license_boilerplate(&lines, 99));
    }

    #[test]
    fn pe3_env_docs() {
        let mut f = RawFinding::new("PE3", "m", Severity::Low, 0.5, "docs/a.md", 2);
        f.context = Some("ctx".into());
        let lines = ["x", "- `cp .env.example .env`"];
        assert!(is_env_file_reference_in_docs(
            &f,
            FileType::Markdown,
            "docs/a.md",
            &lines
        ));
        assert!(!is_env_file_reference_in_docs(
            &f,
            FileType::Markdown,
            "SKILL.md",
            &lines
        ));
        assert!(!is_env_file_reference_in_docs(
            &f,
            FileType::Python,
            "a.py",
            &lines
        ));
        f.start_line = 1;
        assert!(!is_env_file_reference_in_docs(
            &f,
            FileType::Markdown,
            "docs/a.md",
            &lines
        ));
    }
}
