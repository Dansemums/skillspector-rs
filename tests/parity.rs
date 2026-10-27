//! Parity with the reference SkillSpector (`--no-llm`) on the public fixtures.
//!
//! `tests/fixtures/golden.json` maps each fixture folder to the findings the Python tool reports
//! (see `tools/make_golden.py`). Every fixture is scanned with the library and compared as a multiset
//! of `(rule id, file, start line)`. Differences listed in `tests/fixtures/KNOWN_DIFFERENCES.md` (and in
//! `ALLOWED` below) may differ for the listed rule ids; everything else must match exactly.

use serde::Deserialize;
use skillspector_rs::scan_skill;
use std::collections::BTreeMap;
use std::path::Path;

/// `(fixture, rule id)` pairs that may differ; each is explained in KNOWN_DIFFERENCES.md.
const ALLOWED: &[(&str, &str)] = &[
    ("malicious_skill", "P5"),
    ("mcp_poisoned_tool", "TP1"),
    ("mcp_poisoned_tool", "TP2"),
    ("mcp_poisoned_tool", "TP3"),
    ("oms", "SC3"),
    ("ssd/ssd4_narrative_deception", "TR2"),
];

#[derive(Deserialize)]
struct Golden {
    id: String,
    file: Option<String>,
    start_line: Option<u32>,
}

type Key = (String, String, Option<u32>);

fn multiset(keys: impl IntoIterator<Item = Key>) -> BTreeMap<Key, usize> {
    let mut m = BTreeMap::new();
    for k in keys {
        *m.entry(k).or_insert(0) += 1;
    }
    m
}

#[test]
fn matches_reference_on_public_fixtures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let raw = std::fs::read_to_string(root.join("golden.json")).expect("golden.json");
    let golden: BTreeMap<String, Vec<Golden>> = serde_json::from_str(&raw).expect("golden json");
    assert!(golden.len() >= 60, "golden.json shrank: {}", golden.len());

    let (mut want_total, mut matched, mut report) = (0usize, 0usize, Vec::new());
    for (name, want) in &golden {
        let got = scan_skill(&root.join(name)).expect("scan fixture");
        let want = multiset(want.iter().map(|g| {
            (
                g.id.clone(),
                g.file.clone().unwrap_or_default(),
                g.start_line,
            )
        }));
        let got = multiset(
            got.iter()
                .map(|i| (i.id.clone(), i.file.clone(), i.start_line)),
        );
        want_total += want.values().sum::<usize>();
        let mut diffs = Vec::new();
        // Without the `yara` feature the YR* rules are not available.
        let allowed = |k: &Key| {
            ALLOWED.contains(&(name.as_str(), k.0.as_str()))
                || (!cfg!(feature = "yara") && k.0.starts_with("YR"))
        };
        for (k, w) in want.iter().filter(|(k, _)| !allowed(k)) {
            let g = got.get(k).copied().unwrap_or(0);
            matched += w.min(&g);
            if g < *w {
                diffs.push(format!("  missing {k:?} x{}", w - g));
            }
        }
        for (k, g) in got.iter().filter(|(k, _)| !allowed(k)) {
            let w = want.get(k).copied().unwrap_or(0);
            if w < *g {
                diffs.push(format!("  extra   {k:?} x{}", g - w));
            }
        }
        if !diffs.is_empty() {
            report.push(format!("{name}:\n{}", diffs.join("\n")));
        }
    }
    assert!(
        report.is_empty(),
        "{} fixtures differ from golden ({matched}/{want_total} matched):\n{}",
        report.len(),
        report.join("\n")
    );
}
