//! `static_runner.py`, minimum that preserves output: run each module over each file, give every
//! finding its column, apply the contextual filters, drop exact duplicates.
//!
//! Lexical modules run over the raw text and every derived security view ([`crate::views`]);
//! AST modules run over the raw text only. Files that are only scanned through the binary
//! printable-text view (`readable_binary`) are skipped for now.

use crate::dedupe::classification_key;
use crate::filters::{
    is_env_file_reference_in_docs, is_license_basename, is_license_boilerplate,
    normalized_license_lines,
};
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::pyast::PyFile;
use crate::skill::{FileType, Skill, SourceFile};
use crate::text::{LineIndex, py_splitlines};
use crate::views::{self, FileViews, RawCoords};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// Tags that mark which view a finding came from; they do not separate duplicates.
/// Size guard: the lexical (regex) modules look at no more than this many bytes of one file (cut on a
/// character boundary). SkillSpector windows large files and enforces time budgets instead; this
/// keeps worst-case time bounded without a clock. Python files are still parsed whole, up to
/// `pyast::MAX_SOURCE_CHARS`, and YARA/rug-pull see the full file.
pub(crate) const MAX_ANALYZED_TEXT_BYTES: usize = 1024 * 1024;

const VIEW_ORIGIN_TAGS: [&str; 2] = ["normalized-view", "declared-marker-view"];

/// One static pattern module (`static_patterns_*`).
pub trait StaticModule: Sync {
    /// SkillSpector's `ANALYZER_ID`.
    #[allow(dead_code)] // part of the trait for parity with SkillSpector's ANALYZER_ID
    fn id(&self) -> &'static str;

    /// `USES_PYTHON_AST`: the module wants a parsed tree for Python files.
    fn uses_python_ast(&self) -> bool {
        false
    }

    /// Whether the module also scans the derived security views. False exactly for modules whose
    /// Python `USES_PYTHON_AST` is set (they scan the raw text once); `tool_misuse` only sets
    /// `POSTPROCESS_USES_PYTHON_AST`, so it overrides this.
    fn runs_derived_views(&self) -> bool {
        !self.uses_python_ast()
    }

    /// `USES_PYTHON_SOURCE_TYPE`: shebang scripts count as `python` for this module.
    fn uses_python_source_type(&self) -> bool {
        self.uses_python_ast()
    }

    /// Findings in one text view of one file. Offsets are the module's business; findings carry lines.
    fn analyze(&self, text: &str, path: &str, ft: FileType, py: Option<&PyFile>)
    -> Vec<RawFinding>;

    /// `postprocess_path_findings`: reconcile findings after every view has run.
    fn postprocess(
        &self,
        _text: &str,
        findings: Vec<RawFinding>,
        _py: Option<&PyFile>,
    ) -> Vec<RawFinding> {
        findings
    }
}

/// `_OccurrenceColumnResolver`: gives each finding the column of its matched text, walking repeated
/// identical previews along their line so same-line repeats get distinct columns.
struct ColumnResolver<'a> {
    text: &'a str,
    index: LineIndex,
    next: HashMap<(u32, &'static str, String), usize>,
}

impl<'a> ColumnResolver<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            index: LineIndex::new(text),
            next: HashMap::new(),
        }
    }

    fn assign(&mut self, f: &mut RawFinding) {
        let Some(matched) = f.matched_text.as_deref().filter(|m| !m.is_empty()) else {
            return;
        };
        if f.start_column.is_some() || f.start_line < 1 {
            return;
        }
        let line = usize::try_from(f.start_line).unwrap_or(usize::MAX);
        if line > self.index.len() {
            return;
        }
        let line_start = self.index.line_start(f.start_line);
        let line_end = if line < self.index.len() {
            self.index.line_start(f.start_line + 1)
        } else {
            self.text.len()
        };
        let key = (f.start_line, f.rule_id, matched.to_owned());
        let search_start = self.next.get(&key).copied().unwrap_or(line_start);
        // Python limit: line_end + len(matched) characters, clipped to the text.
        let limit = self.text[line_end.min(self.text.len())..]
            .char_indices()
            .nth(matched.chars().count())
            .map_or(self.text.len(), |(i, _)| line_end + i);
        let Some(hay) = self.text.get(search_start.min(limit)..limit) else {
            return;
        };
        let Some(rel) = hay.find(matched) else { return };
        let at = search_start + rel;
        if at < line_start || at >= line_end {
            return;
        }
        f.start_column = Some(self.index.col_chars(self.text, at));
        self.next.insert(key, at + matched.len().max(1));
    }
}

type ViewKey = (
    &'static str,
    String,
    u32,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<String>,
    crate::dedupe::ClassKey,
);

type ScopeKey = (
    &'static str,
    String,
    u32,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<String>,
);

/// `_view_finding_key`.
fn view_key(f: &RawFinding) -> ViewKey {
    (
        f.rule_id,
        f.file.clone(),
        f.start_line,
        f.end_line,
        f.start_column,
        f.end_column,
        f.fingerprint(),
        classification_key(f, &VIEW_ORIGIN_TAGS),
    )
}

/// `_view_scope_key`: a mapped column identifies the exact raw occurrence on its own.
fn scope_key(f: &RawFinding) -> ScopeKey {
    let fingerprint = if f.start_column.is_some() {
        None
    } else {
        f.fingerprint()
    };
    (
        f.rule_id,
        f.file.clone(),
        f.start_line,
        f.end_line,
        f.start_column,
        f.end_column,
        fingerprint,
    )
}

/// `_view_finding_strength`: smaller is stronger (severity rank, then higher confidence).
fn strength(f: &RawFinding) -> (u8, f64) {
    let rank = match f.severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    };
    (rank, -f64::from(f.confidence))
}

fn is_stronger(a: (u8, f64), b: (u8, f64)) -> bool {
    a.0 < b.0 || (a.0 == b.0 && a.1 < b.1)
}

fn tagged(f: &RawFinding, tag: &str) -> bool {
    f.tags.iter().any(|t| t == tag)
}

/// `_deduplicate_view_findings`: drop findings equal on location, fingerprint and class, and
/// derived-view findings that a raw finding of the same occurrence already covers.
fn dedupe_view_findings(findings: Vec<RawFinding>) -> Vec<RawFinding> {
    let raw_keys: HashSet<ViewKey> = findings
        .iter()
        .filter(|f| !tagged(f, "normalized-view"))
        .map(view_key)
        .collect();
    let mut raw_strength = HashMap::new();
    for f in findings
        .iter()
        .filter(|f| !tagged(f, "normalized-view") && !tagged(f, "contextual-triage"))
    {
        let s = strength(f);
        let slot = raw_strength.entry(scope_key(f)).or_insert(s);
        if is_stronger(s, *slot) {
            *slot = s;
        }
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for f in findings {
        let key = view_key(&f);
        let derived = tagged(&f, "normalized-view");
        if derived && raw_keys.contains(&key) {
            continue;
        }
        if derived
            && tagged(&f, "contextual-triage")
            && raw_strength
                .get(&scope_key(&f))
                .is_some_and(|&r| !is_stronger(strength(&f), r))
        {
            continue;
        }
        if seen.insert(key) {
            out.push(f);
        }
    }
    out
}

/// Runs one module over one text view: columns, contextual filters, view tag.
fn scan_view(
    file: &SourceFile,
    module: &dyn StaticModule,
    ft: FileType,
    text: &str,
    py: Option<&PyFile>,
) -> Vec<RawFinding> {
    let path_type = FileType::from_path(&file.rel);
    let license = is_license_basename(&file.rel, path_type).then(|| normalized_license_lines(text));
    let lines = py_splitlines(text);
    let mut resolver = ColumnResolver::new(text);
    let mut out = Vec::new();
    for mut f in module.analyze(text, &file.rel, ft, py) {
        resolver.assign(&mut f);
        if f.rule_id == "EA3"
            && license
                .as_ref()
                .is_some_and(|l| is_license_boilerplate(l, f.start_line))
        {
            continue;
        }
        if is_env_file_reference_in_docs(&f, ft, &file.rel, &lines) {
            for tag in ["contextual-triage", "likely-benign-context"] {
                if !f.tags.iter().any(|t| t == tag) {
                    f.tags.push(tag.to_owned());
                }
            }
        }
        out.push(f);
    }
    out
}

/// Runs one module over one file: the raw view, then (lexical modules) every derived view.
fn scan_file(
    file: &SourceFile,
    module: &dyn StaticModule,
    py: Option<&PyFile>,
    derived: Option<&Rc<FileViews>>,
) -> Vec<RawFinding> {
    let text = file.text.as_str();
    let ft = file.effective_type(module.uses_python_source_type());
    let mut out = {
        let _active = views::activate_raw();
        scan_view(file, module, ft, text, py)
    };
    if module.runs_derived_views()
        && let Some(fv) = derived
    {
        let raw = RawCoords::new(text);
        let mut seen: HashSet<ViewKey> = out.iter().map(view_key).collect();
        for (i, view) in fv.views.iter().enumerate() {
            let _active = views::activate_derived(fv, i);
            let mut found = scan_view(file, module, ft, &view.text, None);
            for f in &mut found {
                f.tags.push("normalized-view".to_owned());
            }
            views::restore_source_lines(&mut found, view, &raw);
            out.extend(found.into_iter().filter(|f| seen.insert(view_key(f))));
        }
    }
    module.postprocess(text, dedupe_view_findings(out), py)
}

/// The derived security views of a file, shared by every module that scans it.
fn file_views(file: &SourceFile) -> Option<Rc<FileViews>> {
    let derived = views::derived_views(&file.text);
    (!derived.is_empty()).then(|| {
        Rc::new(FileViews {
            source_chars: file.text.chars().collect(),
            views: derived,
        })
    })
}

/// Runs every module over every scannable file of `skill`. AST modules share one parse per file.
#[must_use]
pub fn run_static(skill: &Skill, modules: &[&dyn StaticModule]) -> Vec<RawFinding> {
    let any_ast = modules.iter().any(|m| m.uses_python_ast());
    let cap = |f: &SourceFile| f.text_cut_at(MAX_ANALYZED_TEXT_BYTES);
    skill
        .files
        .iter()
        .filter(|f| f.cached && !f.binary && !f.readable_binary)
        .flat_map(|f| {
            let py = if any_ast { PyFile::for_file(f) } else { None };
            let capped = cap(f);
            let f = capped.as_ref().unwrap_or(f);
            let derived = file_views(f);
            modules
                .iter()
                .flat_map(|m| {
                    scan_file(
                        f,
                        *m,
                        if m.uses_python_ast() {
                            py.as_ref()
                        } else {
                            None
                        },
                        derived.as_ref(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issue::Severity;

    struct Words;
    impl StaticModule for Words {
        fn id(&self) -> &'static str {
            "words"
        }
        fn analyze(
            &self,
            text: &str,
            path: &str,
            _ft: FileType,
            _py: Option<&PyFile>,
        ) -> Vec<RawFinding> {
            let idx = LineIndex::new(text);
            text.match_indices("foo")
                .map(|(i, m)| {
                    let mut f = RawFinding::new("W1", "msg", Severity::Low, 0.5, path, idx.line(i));
                    f.matched_text = Some(m.to_owned());
                    f
                })
                .collect()
        }
    }

    fn run(text: &str, path: &str) -> Vec<RawFinding> {
        let skill = Skill::from_memory(vec![(path.to_owned(), text.as_bytes().to_vec())]);
        run_static(&skill, &[&Words])
    }

    #[test]
    fn repeated_same_line_matches_get_distinct_columns() {
        let f = run("a foo foo\n\u{e9}foo", "a.md");
        let cols: Vec<_> = f.iter().map(|f| (f.start_line, f.start_column)).collect();
        assert_eq!(cols, [(1, Some(2)), (1, Some(6)), (2, Some(1))]);
    }

    #[test]
    fn columns_after_unusual_breaks() {
        let f = run("x\x1cfoo\u{2028}  foo", "a.md");
        let cols: Vec<_> = f.iter().map(|f| (f.start_line, f.start_column)).collect();
        assert_eq!(cols, [(2, Some(0)), (3, Some(2))]);
    }

    #[test]
    fn binary_and_undecodable_files_are_skipped() {
        assert!(run("foo", "a.png").len() == 1); // text content is text whatever the extension
        let skill = Skill::from_memory(vec![
            ("x.bin".into(), b"\x89PNG\r\n\x1a\nfoo".to_vec()),
            ("b.py".into(), b"foo \xff".to_vec()),
        ]);
        assert!(run_static(&skill, &[&Words]).is_empty());
    }

    #[test]
    fn derived_view_findings_map_back_to_the_source() {
        // The raw "foo" is found once; the zero-width spelling only in the normalized view.
        let f = run("foo f\u{200b}oo\n\u{ff46}oo", "a.md");
        let got: Vec<_> = f
            .iter()
            .map(|f| (f.start_line, f.start_column, f.tags.clone()))
            .collect();
        let tag = vec!["normalized-view".to_owned()];
        assert_eq!(
            got,
            [
                (1, Some(0), vec![]),
                (1, Some(4), tag.clone()),
                (2, Some(0), tag)
            ]
        );
    }

    #[test]
    fn pe3_docs_are_tagged() {
        struct Pe3;
        impl StaticModule for Pe3 {
            fn id(&self) -> &'static str {
                "pe3"
            }
            fn analyze(
                &self,
                _t: &str,
                path: &str,
                _ft: FileType,
                _py: Option<&PyFile>,
            ) -> Vec<RawFinding> {
                let mut f = RawFinding::new("PE3", "m", Severity::Low, 0.5, path, 1);
                f.context = Some("c".into());
                vec![f]
            }
        }
        let skill =
            Skill::from_memory(vec![("docs/a.md".into(), b"cp .env.example .env".to_vec())]);
        let f = run_static(&skill, &[&Pe3]);
        assert_eq!(f[0].tags, ["contextual-triage", "likely-benign-context"]);
    }
}
