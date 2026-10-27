//! SC9 (`_analyze_concealed_executables`) over the component metadata `build_context` derives:
//! executables under hidden path segments (`_build_component_metadata`) and binary executables
//! outside text coverage (`_mark_unanalyzed_executables`).
//!
//! Not ported: ZIP-family nested members, executables in excluded directories, referenced-but-
//! uninspected artifacts and read-limit failures; none occurs with the corpus layout this crate scans.
//! TODO: a hidden `*.d.ts` file that is declaration-only is exempt in Python
//! (`_looks_like_typescript_declaration`); here every such file counts as executable.

use crate::analyzer::Analyzer;
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::skill::{Skill, SourceFile};
use serde_json::{Value, json};

const CATEGORY: &str = "Supply Chain";

const EXECUTABLE_SUFFIXES: [&str; 41] = [
    ".app", ".bash", ".bat", ".bin", ".cmd", ".com", ".cjs", ".class", ".cts", ".dll", ".dex",
    ".dylib", ".exe", ".go", ".js", ".jsx", ".luac", ".mjs", ".msi", ".mts", ".php", ".php3",
    ".php4", ".php5", ".pl", ".phtml", ".ps1", ".py", ".pyw", ".pyc", ".pyo", ".rb", ".rake",
    ".rs", ".sh", ".so", ".svg", ".ts", ".tsx", ".wasm", ".zsh",
];

const BINARY_EXECUTABLE_MAGICS: [&[u8]; 11] = [
    b"MZ",
    b"\x7fELF",
    b"\x00asm",
    b"\x1bLua",
    b"\xfe\xed\xfa",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
];

/// The SC9 detector; a whole-skill analyzer because it reads file metadata, not text.
pub struct ConcealedExecutable;

/// `Path(path).suffix.lower()`.
fn suffix(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => name[i..].to_lowercase(),
        _ => String::new(),
    }
}

fn has_dex_magic(d: &[u8]) -> bool {
    d.len() >= 8 && d.starts_with(b"dex\n") && d[4..7].iter().all(u8::is_ascii_digit) && d[7] == 0
}

fn has_binary_executable_magic(d: &[u8]) -> bool {
    has_dex_magic(d) || BINARY_EXECUTABLE_MAGICS.iter().any(|m| d.starts_with(m))
}

/// `is_executable_content` (the declaration-file exemption is a TODO, see the module doc).
pub(crate) fn is_executable_content(f: &SourceFile) -> bool {
    let s = suffix(&f.rel);
    EXECUTABLE_SUFFIXES.contains(&s.as_str())
        || f.bytes.starts_with(b"#!")
        || has_binary_executable_magic(&f.bytes)
        || f.executable
}

fn is_hidden(path: &str) -> bool {
    path.replace('\\', "/")
        .split('/')
        .any(|p| !p.is_empty() && p.starts_with('.'))
}

fn compatible_interpreters(suffix: &str) -> &'static [&'static str] {
    match suffix {
        ".bash" => &["bash"],
        ".cjs" => &["node", "nodejs", "bun"],
        ".js" | ".jsx" | ".mjs" => &["node", "nodejs", "bun", "deno"],
        ".php" => &["php"],
        ".pl" => &["perl"],
        ".ps1" => &["pwsh", "powershell"],
        ".py" => &["python", "python2", "python3", "pypy", "pypy3"],
        ".rb" => &["ruby"],
        ".sh" => &["sh", "bash", "dash", "ksh", "zsh"],
        ".ts" | ".tsx" => &["node", "nodejs", "bun", "deno", "tsx"],
        ".zsh" => &["zsh"],
        _ => &[],
    }
}

/// `_is_conventional_skill_script`: a visible script of `.agents/skills/<name>/` or
/// `.claude/skills/<name>/` whose skill folder has a `SKILL.md`.
fn is_conventional_skill_script(skill: &Skill, f: &SourceFile) -> bool {
    let norm = f.rel.replace('\\', "/");
    let parts: Vec<&str> = norm.split('/').collect();
    if parts.len() < 4 || parts[1] != "skills" || !matches!(parts[0], ".agents" | ".claude") {
        return false;
    }
    if parts[2].is_empty()
        || parts[2].starts_with('.')
        || parts[3..].iter().any(|p| p.starts_with('.'))
    {
        return false;
    }
    let ext = suffix(parts[parts.len() - 1]);
    let allowed = compatible_interpreters(&ext);
    if allowed.is_empty() || has_binary_executable_magic(&f.bytes) {
        return false;
    }
    if f.bytes.starts_with(b"#!") {
        let first = f
            .bytes
            .split(|b| matches!(b, b'\n' | b'\r'))
            .next()
            .unwrap_or(&[]);
        // shortcut: whitespace split instead of shlex.split; differs only for quoted shebang words.
        let Ok(line) = std::str::from_utf8(&first[2..]) else {
            return false;
        };
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(first_token) = tokens.first() else {
            return false;
        };
        let base = |t: &str| t.rsplit('/').next().unwrap_or(t).to_owned();
        let mut interp = base(first_token);
        if interp == "env" {
            interp = tokens[1..]
                .iter()
                .find(|t| !t.starts_with('-') && !t.contains('='))
                .map_or_else(String::new, |t| base(t));
        }
        let interp = interp
            .strip_suffix(".exe")
            .unwrap_or(&interp)
            .to_lowercase();
        if interp.is_empty() || !allowed.contains(&interp.as_str()) {
            return false;
        }
    }
    let root = parts[..3].join("/");
    ["SKILL.md", "skill.md"]
        .iter()
        .any(|m| skill.files.iter().any(|g| g.rel == format!("{root}/{m}")))
}

struct Component {
    reasons: Vec<&'static str>,
    excluded_from_analysis: bool,
    partially_analyzed: bool,
    inherited: Option<&'static str>,
}

/// The concealed-executable state of one file, or `None` when it raises no SC9.
fn component(skill: &Skill, f: &SourceFile) -> Option<Component> {
    if !is_executable_content(f) {
        return None;
    }
    let mut c = Component {
        reasons: Vec::new(),
        excluded_from_analysis: false,
        partially_analyzed: false,
        inherited: None,
    };
    if is_hidden(&f.rel) && !is_conventional_skill_script(skill, f) {
        c.reasons.push("hidden_artifact");
    }
    if f.binary {
        let reason = if f.readable_binary {
            "binary_executable_text"
        } else {
            "binary_content"
        };
        c.excluded_from_analysis = !f.readable_binary;
        c.partially_analyzed = f.readable_binary;
        c.inherited = Some(reason);
        c.reasons.push(reason);
    }
    (!c.reasons.is_empty()).then_some(c)
}

fn finding(f: &SourceFile, c: &Component) -> RawFinding {
    let message = if c.partially_analyzed {
        "Readable text was inspected, but binary executable behavior was not analyzed."
    } else if c.excluded_from_analysis {
        "Executable content is excluded from analysis."
    } else {
        "Executable content is concealed inside a document, hidden, or disguised artifact."
    };
    let explanation = if c.partially_analyzed {
        "Text-based checks covered the readable projection, but they cannot establish the behavior of the binary executable."
    } else if c.excluded_from_analysis {
        "An executable artifact remains available under the skill install path but its content is outside analyzer coverage."
    } else {
        "An executable nested in a document or hidden/disguised artifact can evade ordinary extension-based review while still being available to the skill at runtime."
    };
    let mut r = RawFinding::new("SC9", message, Severity::High, 1.0, &f.rel, 1);
    r.category = Some(CATEGORY.to_owned());
    r.pattern = Some("Concealed Executable Artifact".to_owned());
    r.explanation = Some(explanation.to_owned());
    r.remediation = Some(
        "Review the artifact provenance and the reason executable content is packaged in this location; keep executable files explicit and directly reviewable."
            .to_owned(),
    );
    r.tags = ["supply-chain", "concealed-executable", "local-only"]
        .map(str::to_owned)
        .to_vec();
    r.matched_text = Some(f.rel.clone());
    let evidence: [(&str, Value); 14] = [
        ("outer_path", json!(f.rel)),
        ("nested_path", json!(f.rel)),
        ("container_type", json!("filesystem")),
        ("container_ancestry", json!(["filesystem"])),
        ("container_depth", json!(0)),
        ("concealment", json!(c.reasons[0])),
        ("concealment_reasons", json!(c.reasons)),
        ("local_only", json!(true)),
        ("referenced", json!(false)),
        ("excluded_from_analysis", json!(c.excluded_from_analysis)),
        ("partially_analyzed_executable", json!(c.partially_analyzed)),
        ("excluded_inspection_incomplete", json!(false)),
        ("inherited_exclusion_reason", json!(c.inherited)),
        ("inspection_limitation_reason", Value::Null),
    ];
    r.evidence = evidence
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_string()))
        .collect();
    r
}

impl Analyzer for ConcealedExecutable {
    fn id(&self) -> &'static str {
        "static_patterns_supply_chain_concealed_executable"
    }

    fn run(&self, skill: &Skill) -> Vec<RawFinding> {
        skill
            .files
            .iter()
            .filter_map(|f| component(skill, f).map(|c| finding(f, &c)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(files: &[(&str, &[u8])]) -> Vec<RawFinding> {
        let skill = Skill::from_memory(
            files
                .iter()
                .map(|(p, b)| ((*p).to_owned(), b.to_vec()))
                .collect(),
        );
        ConcealedExecutable.run(&skill)
    }

    #[test]
    fn hidden_executables_are_flagged() {
        let f = run(&[
            (".hidden/lib/a.py", b"x = 1\n"),
            (".hidden/readme.md", b"text\n"),
            ("lib/b.py", b"x = 1\n"),
            ("SKILL.md", b"# s\n"),
            (".hidden/icon.svg", b"<svg/>"),
        ]);
        let files: Vec<&str> = f.iter().map(|x| x.file.as_str()).collect();
        assert_eq!(files, [".hidden/icon.svg", ".hidden/lib/a.py"]);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].evidence["concealment"], "\"hidden_artifact\"");
    }

    #[test]
    fn conventional_skill_scripts_are_exempt() {
        let f = run(&[
            (".claude/skills/demo/SKILL.md", b"# s\n"),
            (
                ".claude/skills/demo/run.py",
                b"#!/usr/bin/env python3\nprint(1)\n",
            ),
            (".claude/skills/demo/bad.py", b"#!/bin/sh\n"),
            (".agents/skills/none/run.py", b"print(1)\n"),
        ]);
        let files: Vec<&str> = f.iter().map(|x| x.file.as_str()).collect();
        assert_eq!(
            files,
            [".agents/skills/none/run.py", ".claude/skills/demo/bad.py"]
        );
    }

    #[test]
    fn binary_executables_are_excluded_from_analysis() {
        let f = run(&[("bin/tool", b"\x7fELF\x02\x01\x01\x00rest")]);
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].message,
            "Executable content is excluded from analysis."
        );
        assert_eq!(
            f[0].evidence["inherited_exclusion_reason"],
            "\"binary_content\""
        );
    }

    #[test]
    fn suffixes() {
        assert_eq!(suffix("a/b.PY"), ".py");
        assert_eq!(suffix(".bashrc"), "");
        assert_eq!(suffix("dir.d/file"), "");
    }
}
