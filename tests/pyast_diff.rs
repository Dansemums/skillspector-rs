//! Differential test against SkillSpector's own AST layer: `tools/pyast_probe.py` dumps, per Python
//! file, whether `ast.parse` succeeds, the import aliases and every `ast.Call` with its position and
//! `resolve_call_name`. This test reproduces that data with `skillspector_rs::pyast`.
//!
//! Needs private data: run `tools/pyast_probe.py` (see tools/README.md) and point
//! `SKILLSPECTOR_RS_PRIVATE_DATA` at the directory holding `pyast_probe.json`; without it the test skips.

use serde_json::Value;
use skillspector_rs::pyast::{self, PyFile, resolve_call_name};
use skillspector_rs::skill::{PySource, Skill};
use std::collections::BTreeMap;
use std::path::Path;

/// Adversarial files where rustpython-parser 0.4 and CPython 3.13 legitimately disagree and cannot be
/// reconciled after the fact (see `tools/pyast_adv_gen.py`). Anything else must match exactly.
const KNOWN_GAPS: [(&str, &str); 9] = [
    (
        "fstring_312.py",
        "PEP 701 f-string (same quote nested, backslash in field): rustpython rejects",
    ),
    (
        "nested_fstr_quotes.py",
        "PEP 701 f-string: rustpython rejects",
    ),
    ("pep701.py", "PEP 701 f-string: rustpython rejects"),
    (
        "bare_star_kw.py",
        "`def f(*, **k)`: bare `*` is not represented in rustpython's AST",
    ),
    (
        "dup_args.py",
        "duplicate parameter: CPython only fails later (symtable), rustpython at parse",
    ),
    ("dup_kwonly.py", "duplicate keyword-only parameter: same"),
    (
        "kwarg_dup.py",
        "repeated keyword argument: CPython only fails in the compiler",
    ),
    (
        "zwj_ident.py",
        "ZWJ inside an identifier: CPython accepts, rustpython rejects",
    ),
    (
        "s_pow_5k.py",
        "CPython raises MemoryError (parser stack), which SkillSpector does not catch",
    ),
];

fn known_gap(rel: &str) -> bool {
    KNOWN_GAPS.iter().any(|(name, _)| *name == rel)
}

type CallRow = (u32, u32, u32, u32, Option<u32>, Option<u32>, Option<String>);

struct Observed {
    parse_ok: bool,
    aliases: BTreeMap<String, String>,
    calls: Vec<CallRow>,
}

fn observe(py: &PyFile) -> Observed {
    let mut calls: Vec<CallRow> = Vec::new();
    if let Some(tree) = &py.tree {
        for c in pyast::calls(tree) {
            let r = pyast::ast::Ranged::range(c);
            let (p, cp) = (py.pos(r), py.char_pos(r));
            let name = resolve_call_name(c, Some(&py.import_aliases));
            calls.push((
                p.line, p.col, p.end_line, p.end_col, cp.col, cp.end_col, name,
            ));
        }
    }
    calls.sort_by(|a, b| {
        let key = |r: &CallRow| {
            (
                (r.0, r.1, r.2, r.3, r.4, r.5),
                r.6.clone().unwrap_or_default(),
            )
        };
        key(a).cmp(&key(b))
    });
    Observed {
        parse_ok: py.is_parseable(),
        aliases: py
            .import_aliases
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        calls,
    }
}

fn expected(v: &Value) -> Observed {
    let n = |x: &Value| x.as_u64().map(|n| u32::try_from(n).unwrap_or(u32::MAX));
    let calls = v["calls"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|c| {
                    (
                        n(&c[0]).unwrap_or(0),
                        n(&c[1]).unwrap_or(0),
                        n(&c[2]).unwrap_or(0),
                        n(&c[3]).unwrap_or(0),
                        n(&c[4]),
                        n(&c[5]),
                        c[6].as_str().map(str::to_owned),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let aliases = v["aliases"]
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_owned()))
                .collect()
        })
        .unwrap_or_default();
    Observed {
        parse_ok: v["parse_ok"].as_bool().unwrap_or(false),
        aliases,
        calls,
    }
}

fn first_call_diff(a: &[CallRow], b: &[CallRow]) -> String {
    let at = a
        .iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()));
    format!(
        "python {:?} vs rust {:?} (counts {} vs {})",
        a.get(at),
        b.get(at),
        a.len(),
        b.len()
    )
}

#[test]
fn matches_skillspector_ast_layer() {
    let path = std::env::var_os("SKILLSPECTOR_RS_PRIVATE_DATA")
        .map(|d| std::path::Path::new(&d).join("pyast_probe.json"));
    let Some(raw) = path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()) else {
        eprintln!(
            "SKIPPED: set SKILLSPECTOR_RS_PRIVATE_DATA to a directory holding pyast_probe.json (tools/README.md)"
        );
        return;
    };
    let probe: Value = serde_json::from_str(&raw).expect("probe json");
    let (mut files, mut calls, mut diffs, mut known) = (0usize, 0usize, Vec::new(), Vec::new());
    for (dir, per_file) in probe.as_object().expect("object") {
        let skill = Skill::read(Path::new(dir)).expect("read skill");
        let mut rust: BTreeMap<&str, &skillspector_rs::skill::SourceFile> = BTreeMap::new();
        for f in skill
            .files
            .iter()
            .filter(|f| f.cached && f.py != PySource::NonPython)
        {
            rust.insert(f.rel.as_str(), f);
        }
        let want_files = per_file.as_object().expect("files");
        let skipped = |v: &Value| v.get("skipped").is_some();
        for rel in want_files.keys() {
            if !rust.contains_key(rel.as_str()) {
                diffs.push(format!(
                    "{dir}/{rel}: python-only file (classification/decoding)"
                ));
            }
        }
        for (rel, f) in &rust {
            let Some(want) = want_files.get(*rel) else {
                diffs.push(format!(
                    "{dir}/{rel}: rust-only file (classification/decoding)"
                ));
                continue;
            };
            let got = PyFile::for_file(f);
            if skipped(want) {
                if got.is_some() {
                    diffs.push(format!("{dir}/{rel}: should be skipped as too large"));
                }
                continue;
            }
            let Some(got) = got else {
                diffs.push(format!("{dir}/{rel}: rust declined to parse"));
                continue;
            };
            let (g, w) = (observe(&got), expected(want));
            files += 1;
            calls += w.calls.len();
            let diffs = if known_gap(rel) {
                &mut known
            } else {
                &mut diffs
            };
            if g.parse_ok != w.parse_ok {
                diffs.push(format!(
                    "{dir}/{rel}: parse_ok python={} rust={}",
                    w.parse_ok, g.parse_ok
                ));
            } else if g.aliases != w.aliases {
                diffs.push(format!(
                    "{dir}/{rel}: aliases differ {:?} vs {:?}",
                    w.aliases, g.aliases
                ));
            } else if g.calls != w.calls {
                diffs.push(format!(
                    "{dir}/{rel}: calls differ: {}",
                    first_call_diff(&w.calls, &g.calls)
                ));
            }
        }
    }
    eprintln!(
        "compared {files} files, {calls} calls, {} differences ({} known gaps)",
        diffs.len(),
        known.len()
    );
    for d in &known {
        eprintln!("KNOWN {d}");
    }
    for d in &diffs {
        eprintln!("DIFF {d}");
    }
    assert!(diffs.is_empty(), "{} differences", diffs.len());
}
