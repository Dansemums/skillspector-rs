//! A skill folder read into memory once, so every analyzer sees the same text.
//! Port of the parts of SkillSpector's `build_context` that decide what each analyzer sees.

use crate::manifest::{Manifest, parse_manifest};
use crate::pysource::{classify_python_source, decode_python_source};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Folders no agent reads, skipped like the app's own scan and SkillSpector's copy do.
const SKIP_DIRS: [&str; 9] = [
    "node_modules",
    ".git",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    "site-packages",
    ".tox",
    ".pytest_cache",
];

/// `MAX_ANALYZABLE_FILE_BYTES`: longer files are cut.
const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;

/// `static_runner.FILE_TYPES` plus `other`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileType {
    Markdown,
    Python,
    Shell,
    Powershell,
    Json,
    Yaml,
    Toml,
    Text,
    Javascript,
    Typescript,
    Ruby,
    Perl,
    Go,
    Rust,
    Other,
}

impl FileType {
    /// `_infer_file_type`: by the text after the last `.` of the whole path.
    #[must_use]
    pub fn from_path(path: &str) -> Self {
        let Some(idx) = path.rfind('.') else {
            return Self::Other;
        };
        match path[idx..].to_lowercase().as_str() {
            ".md" | ".markdown" => Self::Markdown,
            ".py" | ".pyw" => Self::Python,
            ".sh" | ".bash" | ".zsh" => Self::Shell,
            ".ps1" => Self::Powershell,
            ".json" => Self::Json,
            ".yaml" | ".yml" => Self::Yaml,
            ".toml" => Self::Toml,
            ".txt" => Self::Text,
            ".js" => Self::Javascript,
            ".ts" => Self::Typescript,
            ".rb" => Self::Ruby,
            ".pl" => Self::Perl,
            ".go" => Self::Go,
            ".rs" => Self::Rust,
            _ => Self::Other,
        }
    }

    /// The lowercase name SkillSpector uses, e.g. `markdown`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::Python => "python",
            Self::Shell => "shell",
            Self::Powershell => "powershell",
            Self::Json => "json",
            Self::Yaml => "yaml",
            Self::Toml => "toml",
            Self::Text => "text",
            Self::Javascript => "javascript",
            Self::Typescript => "typescript",
            Self::Ruby => "ruby",
            Self::Perl => "perl",
            Self::Go => "go",
            Self::Rust => "rust",
            Self::Other => "other",
        }
    }
}

/// `PythonSourceClassification`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PySource {
    Python,
    Ambiguous,
    NonPython,
}

/// One readable file of a skill.
#[derive(Debug)]
pub struct SourceFile {
    /// Path relative to the skill folder, `/`-separated.
    pub rel: String,
    /// The text SkillSpector's `local_file_cache` holds: lossy UTF-8, or the PEP 263 decoded source
    /// (universal newlines) for Python files.
    pub text: String,
    /// Raw bytes (cut at 16 MiB).
    pub bytes: Vec<u8>,
    /// Type from the extension.
    pub file_type: FileType,
    pub py: PySource,
    /// `content_kind == binary` (scanned only when `readable_binary`).
    pub binary: bool,
    /// Binary with a readable header (MZ, GIF, PDF) that still gets scanned.
    pub readable_binary: bool,
    pub executable: bool,
    /// False when a Python file failed to decode: SkillSpector drops it from its cache entirely.
    pub cached: bool,
}

impl SourceFile {
    /// A copy whose text is cut to at most `max` bytes (on a character boundary), or `None` when
    /// the text already fits. Used to bound the work of the lexical modules on huge files.
    #[must_use]
    pub fn text_cut_at(&self, max: usize) -> Option<SourceFile> {
        if self.text.len() <= max {
            return None;
        }
        let mut end = max;
        while !self.text.is_char_boundary(end) {
            end -= 1;
        }
        Some(SourceFile {
            rel: self.rel.clone(),
            text: self.text[..end].to_owned(),
            bytes: self.bytes[..self.bytes.len().min(end)].to_vec(),
            ..*self
        })
    }

    /// `_effective_module_file_type`: scripts that are Python by shebang count as Python only for
    /// modules that opt in.
    #[must_use]
    pub fn effective_type(&self, uses_python_source: bool) -> FileType {
        if uses_python_source && self.py != PySource::NonPython {
            FileType::Python
        } else {
            self.file_type
        }
    }
}

/// A skill folder: its files, in a stable order, and its parsed manifest.
#[derive(Debug)]
pub struct Skill {
    pub root: PathBuf,
    pub files: Vec<SourceFile>,
    pub manifest: Option<Manifest>,
}

const BINARY_MAGIC: [&[u8]; 10] = [
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"PK\x03\x04",
    b"\x7fELF",
    b"MZ",
    b"\x00asm",
    b"\x1bLua",
    b"%PDF-",
];

fn has_dex_magic(d: &[u8]) -> bool {
    d.len() >= 8 && d.starts_with(b"dex\n") && d[4..7].iter().all(u8::is_ascii_digit) && d[7] == 0
}

/// `binary_instruction_view(...).text` is non-empty: a run of 8+ characters outside C0/C1 controls.
fn has_printable_run(s: &str) -> bool {
    let bad = |c: char| matches!(c, '\0'..='\x08' | '\x0b' | '\x0c' | '\x0e'..='\x1f' | '\x7f'..='\u{9f}' | '\u{fffd}');
    let mut run = 0;
    for c in s.chars() {
        run = if bad(c) { 0 } else { run + 1 };
        if run >= 8 {
            return true;
        }
    }
    false
}

/// `artifacts.classify_artifact`: `(binary, readable_binary)`.
fn classify_artifact(data: &[u8]) -> (bool, bool) {
    let has_magic = has_dex_magic(data) || BINARY_MAGIC.iter().any(|m| data.starts_with(m));
    let strict = std::str::from_utf8(data).ok();
    let lossy = String::from_utf8_lossy(data);
    let readable = data.starts_with(b"MZ")
        || data.starts_with(b"GIF87a")
        || data.starts_with(b"GIF89a")
        || data.starts_with(b"%PDF-");
    let readable = readable && has_printable_run(&lossy);
    let binary = if has_magic {
        true
    } else if strict.is_some() || data.is_empty() {
        false
    } else {
        let total = lossy.chars().count().max(1);
        let printable = lossy
            .chars()
            .filter(|&c| crate::unicode::is_printable(c) || matches!(c, '\n' | '\r' | '\t'))
            .count();
        let repl = lossy.chars().filter(|&c| c == '\u{fffd}').count();
        #[allow(clippy::cast_precision_loss)]
        let (p, r) = (printable as f64 / total as f64, repl as f64 / total as f64);
        !(p >= 0.85 && r <= 0.10)
    };
    (binary, readable)
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

fn build_file(rel: String, mut bytes: Vec<u8>, executable: bool) -> SourceFile {
    bytes.truncate(MAX_FILE_BYTES);
    let (binary, readable_binary) = classify_artifact(&bytes);
    let py = classify_python_source(&rel, &bytes);
    let (text, cached) = if py == PySource::NonPython {
        (String::from_utf8_lossy(&bytes).into_owned(), true)
    } else {
        match decode_python_source(&bytes) {
            Some(t) => (t, true),
            None => (String::new(), false),
        }
    };
    let file_type = FileType::from_path(&rel);
    SourceFile {
        rel,
        text,
        bytes,
        file_type,
        py,
        binary,
        readable_binary,
        executable,
        cached,
    }
}

/// Reads at most [`MAX_FILE_BYTES`] of a file, so a multi-gigabyte file cannot exhaust memory.
fn read_capped(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_FILE_BYTES as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

impl Skill {
    /// Reads every regular file under `root`, following links. Each file is read up to 16 MiB;
    /// unreadable entries, devices, FIFOs and link loops are skipped.
    ///
    /// # Errors
    /// Fails when `root` is not a readable directory.
    pub fn read(root: &Path) -> std::io::Result<Self> {
        std::fs::read_dir(root)?;
        let mut files: Vec<SourceFile> = WalkDir::new(root)
            .follow_links(true)
            .into_iter()
            .filter_entry(|e| {
                !(e.file_type().is_dir() && SKIP_DIRS.iter().any(|d| e.file_name() == *d))
            })
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .filter_map(|e| {
                let rel = e
                    .path()
                    .strip_prefix(root)
                    .ok()?
                    .to_string_lossy()
                    .replace('\\', "/");
                let bytes = read_capped(e.path())?;
                Some(build_file(rel, bytes, is_executable(e.path())))
            })
            .collect();
        files.sort_by(|a, b| a.rel.cmp(&b.rel));
        let manifest = parse_manifest(&files);
        Ok(Self {
            root: root.to_path_buf(),
            files,
            manifest,
        })
    }

    /// Builds a skill from in-memory files, for tests and callers that already have the bytes.
    #[must_use]
    pub fn from_memory(files: Vec<(String, Vec<u8>)>) -> Self {
        let mut files: Vec<SourceFile> = files
            .into_iter()
            .map(|(rel, b)| build_file(rel, b, false))
            .collect();
        files.sort_by(|a, b| a.rel.cmp(&b.rel));
        let manifest = parse_manifest(&files);
        Self {
            root: PathBuf::new(),
            files,
            manifest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_type_uses_last_dot_of_path() {
        assert_eq!(FileType::from_path("a/b.MD"), FileType::Markdown);
        assert_eq!(FileType::from_path("dir.d/file"), FileType::Other);
        assert_eq!(FileType::from_path("x.rs"), FileType::Rust);
    }

    #[test]
    fn binary_classification() {
        assert_eq!(classify_artifact(b"\x89PNG\r\n\x1a\nrest"), (true, false));
        assert_eq!(classify_artifact(b"hello"), (false, false));
        assert_eq!(classify_artifact(b""), (false, false));
        assert_eq!(
            classify_artifact(b"MZ\x90\x00 a readable string here"),
            (true, true)
        );
        assert_eq!(
            classify_artifact(b"\xff\x00\x01\x02\x03\x04"),
            (true, false)
        );
        let mut almost_text = b"plain text that is mostly fine ".repeat(10);
        almost_text.push(0xff);
        assert_eq!(classify_artifact(&almost_text), (false, false));
    }

    #[test]
    fn effective_type_follows_shebang() {
        let f = build_file(
            "run".into(),
            b"#!/usr/bin/env python3\nprint(1)\n".to_vec(),
            true,
        );
        assert_eq!(f.py, PySource::Python);
        assert_eq!(f.effective_type(true), FileType::Python);
        assert_eq!(f.effective_type(false), FileType::Other);
        let s = build_file("run.sh".into(), b"#!/bin/sh\n".to_vec(), true);
        assert_eq!(s.effective_type(true), FileType::Shell);
    }

    #[test]
    fn python_files_use_decoded_source() {
        let f = build_file("a.py".into(), b"x = 1\r\ny = 2\rz".to_vec(), false);
        assert_eq!(f.text, "x = 1\ny = 2\nz");
        let bad = build_file("b.py".into(), b"x = '\xff'".to_vec(), false);
        assert!(!bad.cached);
    }
}
