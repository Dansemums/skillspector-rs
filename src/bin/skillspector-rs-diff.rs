//! Compares this crate's findings with a golden file made by the Python SkillSpector.
//!
//! Usage: `skillspector-rs-diff golden.json [--ids SC2,P1] [--limit N]`
//! The golden file maps a skill folder to SkillSpector's `issues` array. A finding matches on
//! (file, id, start_line). Exit code 1 when anything differs.

use rayon::prelude::*;
use serde::Deserialize;
use skillspector_rs::issue::Issue;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

#[derive(Deserialize)]
struct GoldenLocation {
    file: Option<String>,
    start_line: Option<u32>,
}

#[derive(Deserialize)]
struct GoldenIssue {
    id: String,
    location: GoldenLocation,
}

type Key = (String, String, Option<u32>);

fn key_of(i: &Issue) -> Key {
    (i.file.clone(), i.id.clone(), i.start_line)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(golden_path) = args.first() else {
        eprintln!("usage: skillspector-rs-diff golden.json [--ids A,B] [--limit N]");
        return ExitCode::from(2);
    };
    let ids: Option<Vec<&str>> = args
        .iter()
        .position(|a| a == "--ids")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.split(',').collect());
    let limit: usize = args
        .iter()
        .position(|a| a == "--limit")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let wanted = |id: &str| ids.as_ref().is_none_or(|v| v.contains(&id));

    let golden: BTreeMap<String, Vec<GoldenIssue>> = match std::fs::read_to_string(golden_path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
    {
        Ok(g) => g,
        Err(e) => {
            eprintln!("cannot read {golden_path}: {e}");
            return ExitCode::from(2);
        }
    };

    let started = std::time::Instant::now();
    let results: Vec<(&String, Result<Vec<Issue>, String>)> = golden
        .par_iter()
        .map(|(dir, _)| {
            (
                dir,
                skillspector_rs::scan_skill(Path::new(dir)).map_err(|e| e.to_string()),
            )
        })
        .collect();
    let elapsed = started.elapsed();

    let (mut want_total, mut got_total, mut matched) = (0usize, 0usize, 0usize);
    let mut per_id: BTreeMap<String, [usize; 3]> = BTreeMap::new(); // golden, matched, extra
    let mut samples: Vec<String> = Vec::new();
    let mut errors = 0usize;
    for (dir, result) in &results {
        let got = match result {
            Ok(g) => g,
            Err(e) => {
                errors += 1;
                eprintln!("error scanning {dir}: {e}");
                continue;
            }
        };
        let mut remaining: BTreeMap<Key, usize> = BTreeMap::new();
        for i in got.iter().filter(|i| wanted(&i.id)) {
            *remaining.entry(key_of(i)).or_default() += 1;
            got_total += 1;
        }
        for g in golden[*dir].iter().filter(|g| wanted(&g.id)) {
            want_total += 1;
            let k = (
                g.location.file.clone().unwrap_or_default(),
                g.id.clone(),
                g.location.start_line,
            );
            let slot = per_id.entry(g.id.clone()).or_default();
            slot[0] += 1;
            match remaining.get_mut(&k) {
                Some(n) if *n > 0 => {
                    *n -= 1;
                    matched += 1;
                    slot[1] += 1;
                }
                _ => {
                    if samples.len() < limit {
                        samples.push(format!("missing  {} {} {:?}  in {dir}", k.1, k.0, k.2));
                    }
                }
            }
        }
        for (k, n) in remaining.into_iter().filter(|(_, n)| *n > 0) {
            per_id.entry(k.1.clone()).or_default()[2] += n;
            if samples.len() < limit {
                samples.push(format!("extra    {} {} {:?}  in {dir}", k.1, k.0, k.2));
            }
        }
    }
    println!(
        "{:<8} {:>7} {:>8} {:>6}",
        "id", "golden", "matched", "extra"
    );
    for (id, [g, m, x]) in &per_id {
        println!("{id:<8} {g:>7} {m:>8} {x:>6}");
    }
    for s in &samples {
        println!("{s}");
    }
    println!(
        "skills {}  golden {want_total}  rust {got_total}  matched {matched}  errors {errors}  scan {:.2}s",
        golden.len(),
        elapsed.as_secs_f64()
    );
    if matched == want_total && got_total == want_total && errors == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
