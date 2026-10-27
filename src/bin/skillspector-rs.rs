//! `skillspector-rs`: scan AI agent skill folders for security problems. Headless, local, no network.
//!
//! Usage: `skillspector-rs scan [--recursive] [--format text|json|sarif] [--fail-on low|medium|high|critical] PATH...`

use rayon::prelude::*;
use serde_json::json;
use skillspector_rs::Risk;
use skillspector_rs::issue::{Issue, Severity};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: skillspector-rs scan [--recursive] [--format text|json|sarif] [--fail-on low|medium|high|critical] PATH...";

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Text,
    Json,
    Sarif,
}

struct Args {
    format: Format,
    recursive: bool,
    fail_on: Option<Severity>,
    paths: Vec<PathBuf>,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut it = args.iter();
    if it.next().map(String::as_str) != Some("scan") {
        return Err(USAGE.into());
    }
    let mut parsed = Args {
        format: Format::Text,
        recursive: false,
        fail_on: None,
        paths: Vec::new(),
    };
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--recursive" | "-r" => parsed.recursive = true,
            "--format" | "-f" => {
                parsed.format = match it.next().map(String::as_str) {
                    Some("text") => Format::Text,
                    Some("json") => Format::Json,
                    Some("sarif") => Format::Sarif,
                    other => return Err(format!("unknown format {other:?}\n{USAGE}")),
                }
            }
            "--fail-on" => {
                parsed.fail_on = match it.next().map(|s| s.to_ascii_lowercase()).as_deref() {
                    Some("low") => Some(Severity::Low),
                    Some("medium") => Some(Severity::Medium),
                    Some("high") => Some(Severity::High),
                    Some("critical") => Some(Severity::Critical),
                    other => return Err(format!("unknown severity {other:?}\n{USAGE}")),
                }
            }
            flag if flag.starts_with('-') => return Err(format!("unknown option {flag}\n{USAGE}")),
            path => parsed.paths.push(PathBuf::from(path)),
        }
    }
    if parsed.paths.is_empty() {
        return Err(USAGE.into());
    }
    Ok(parsed)
}

/// With `--recursive`, every folder under a path that holds a SKILL.md is its own skill.
fn skill_dirs(paths: &[PathBuf], recursive: bool) -> Vec<PathBuf> {
    if !recursive {
        return paths.to_vec();
    }
    let mut dirs: Vec<PathBuf> = paths
        .iter()
        .flat_map(|p| {
            walkdir::WalkDir::new(p)
                .follow_links(true)
                .into_iter()
                .filter_map(Result::ok)
        })
        .filter(|e| e.file_type().is_file() && e.file_name().eq_ignore_ascii_case("SKILL.md"))
        .filter_map(|e| e.path().parent().map(Path::to_path_buf))
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
}

fn label(s: Severity) -> &'static str {
    match s {
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

/// One scanned skill folder: its findings and overall verdict.
type Scanned = (PathBuf, Vec<Issue>, Risk);

fn render_text(results: &[Scanned]) -> String {
    let mut out = String::new();
    for (dir, issues, risk) in results {
        if issues.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "\n{} (risk {}/100, {})\n",
            dir.display(),
            risk.score,
            risk.recommendation
        ));
        for i in issues {
            let line = i.start_line.map_or(String::new(), |l| format!(":{l}"));
            let found = if i.finding.is_empty() {
                String::new()
            } else {
                format!(": {}", i.finding)
            };
            out.push_str(&format!(
                "  [{}] {} {} {}{line}{found}\n",
                label(i.severity),
                i.id,
                i.pattern,
                i.file
            ));
        }
    }
    let total: usize = results.iter().map(|(_, i, _)| i.len()).sum();
    out.push_str(&format!(
        "\n{} skills scanned, {total} findings\n",
        results.len()
    ));
    out
}

fn render_json(results: &[Scanned]) -> Result<String, serde_json::Error> {
    let skills: Vec<_> = results
        .iter()
        .map(|(d, i, r)| {
            json!({
                "skill": d,
                "risk_assessment": {
                    "score": r.score,
                    "severity": r.severity,
                    "recommendation": r.recommendation,
                    "max_issue_severity": r.max_issue_severity.map_or(json!("NONE"), |s| json!(s)),
                },
                "issues": i,
            })
        })
        .collect();
    serde_json::to_string_pretty(
        &json!({ "tool": "skillspector-rs", "version": env!("CARGO_PKG_VERSION"), "skills": skills }),
    )
}

fn render_sarif(results: &[Scanned]) -> Result<String, serde_json::Error> {
    let items: Vec<_> = results
        .iter()
        .flat_map(|(dir, issues, _)| {
            issues.iter().map(move |i| {
                json!({
                    "ruleId": i.id,
                    "level": sarif_level(i.severity),
                    "message": { "text": if i.finding.is_empty() { i.pattern.clone() } else { format!("{}: {}", i.pattern, i.finding) } },
                    "locations": [{ "physicalLocation": {
                        "artifactLocation": { "uri": dir.join(&i.file).to_string_lossy() },
                        "region": { "startLine": i.start_line.unwrap_or(1) }
                    }}]
                })
            })
        })
        .collect();
    let log = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{ "tool": { "driver": { "name": "skillspector-rs", "version": env!("CARGO_PKG_VERSION") } }, "results": items }]
    });
    serde_json::to_string_pretty(&log)
}

/// Writes the report in one go; a closed pipe (`| head`) is not an error.
fn write_stdout(report: String) -> Result<(), String> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let newline: &[u8] = if report.ends_with('\n') { b"" } else { b"\n" };
    match out
        .write_all(report.as_bytes())
        .and_then(|()| out.write_all(newline))
    {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(e.to_string()),
        _ => Ok(()),
    }
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|a| a == "--version" || a == "-V") {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if raw.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let args = match parse(&raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let dirs = skill_dirs(&args.paths, args.recursive);
    let scanned: Vec<_> = dirs
        .par_iter()
        .map(|d| {
            (
                d.clone(),
                skillspector_rs::scan_skill_with_risk(d).map_err(|e| e.to_string()),
            )
        })
        .collect();
    let mut results = Vec::with_capacity(scanned.len());
    let mut failed = false;
    for (dir, r) in scanned {
        match r {
            Ok((issues, risk)) => results.push((dir, issues, risk)),
            Err(e) => {
                eprintln!("error: {}: {e}", dir.display());
                failed = true;
            }
        }
    }
    let rendered = match args.format {
        Format::Text => Ok(render_text(&results)),
        Format::Json => render_json(&results),
        Format::Sarif => render_sarif(&results),
    };
    if let Err(e) = rendered.map_err(|e| e.to_string()).and_then(write_stdout) {
        eprintln!("error: could not write the report: {e}");
        return ExitCode::from(2);
    }
    let tripped = args.fail_on.is_some_and(|min| {
        results
            .iter()
            .flat_map(|(_, i, _)| i)
            .any(|i| i.severity >= min)
    });
    if failed {
        ExitCode::from(2)
    } else if tripped {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
