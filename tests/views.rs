//! Differential test: the security views must equal Python's `security_text_views` exactly.
//!
//! The expectation file comes from `tools/views_probe.py` (default path below, override with
//! `SKILLSPECTOR_RS_PRIVATE_DATA`). Every text file of the skill folders it names is read from disk again.

use serde_json::Value;
use skillspector_rs::views::{SecurityTextView, security_text_views};

/// File name inside `$SKILLSPECTOR_RS_PRIVATE_DATA` (see tools/README.md).
const GOLDEN_FILE: &str = "views_golden.json";
const MAX_CHARS: usize = 300_000;

type Expected = Vec<(String, String, Option<Vec<u32>>)>;

fn expected_views(v: &Value) -> Expected {
    v.as_array()
        .map(|views| {
            views
                .iter()
                .map(|e| {
                    let name = e[0].as_str().unwrap_or_default().to_owned();
                    let text = e[1].as_str().unwrap_or_default().to_owned();
                    let offsets = e[2].as_array().map(|a| {
                        a.iter()
                            .map(|n| {
                                u32::try_from(n.as_u64().unwrap_or(u64::MAX)).unwrap_or(u32::MAX)
                            })
                            .collect()
                    });
                    (name, text, offsets)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn actual_views(text: &str) -> Expected {
    security_text_views(text)
        .into_iter()
        .filter(|v: &SecurityTextView| v.name != "raw")
        .map(|v| (v.name.to_owned(), v.text, v.source_offsets))
        .collect()
}

fn describe(want: &Expected, got: &Expected) -> String {
    let names = |e: &Expected| e.iter().map(|v| v.0.clone()).collect::<Vec<_>>();
    if names(want) != names(got) {
        return format!(
            "view names differ: want {:?}, got {:?}",
            names(want),
            names(got)
        );
    }
    for (w, g) in want.iter().zip(got) {
        if w.1 != g.1 {
            return format!(
                "view {} text differs: want {:?}, got {:?}",
                w.0,
                w.1.chars().take(80).collect::<String>(),
                g.1.chars().take(80).collect::<String>()
            );
        }
        if w.2 != g.2 {
            return format!("view {} source offsets differ", w.0);
        }
    }
    "equal".to_owned()
}

#[test]
fn views_match_python() {
    let path = std::env::var_os("SKILLSPECTOR_RS_PRIVATE_DATA")
        .map(|d| std::path::Path::new(&d).join(GOLDEN_FILE));
    let Some(raw) = path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()) else {
        eprintln!(
            "SKIPPED: set SKILLSPECTOR_RS_PRIVATE_DATA to a directory holding {GOLDEN_FILE} (tools/README.md)"
        );
        return;
    };
    let golden: Value = serde_json::from_str(&raw).expect("golden file is JSON");
    let mut failures = Vec::new();
    let (mut files, mut strings) = (0usize, 0usize);

    for (file, want) in golden["files"].as_object().expect("files object") {
        let Ok(bytes) = std::fs::read(file) else {
            eprintln!("SKIPPED file (unreadable): {file}");
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        if text.chars().count() > MAX_CHARS {
            continue;
        }
        files += 1;
        let (want, got) = (expected_views(want), actual_views(&text));
        if want != got {
            failures.push(format!("{file}: {}", describe(&want, &got)));
        }
    }
    for case in golden["strings"].as_array().expect("strings array") {
        let text = case["text"].as_str().expect("text");
        strings += 1;
        let (want, got) = (expected_views(&case["views"]), actual_views(text));
        if want != got {
            failures.push(format!("string {text:?}: {}", describe(&want, &got)));
        }
    }
    eprintln!(
        "compared {files} files and {strings} strings, {} differences",
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} differences, first:\n{}",
        failures.len(),
        failures
            .iter()
            .take(15)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
