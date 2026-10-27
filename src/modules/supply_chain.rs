//! SC1, SC2, SC3 and SC7 from `static_patterns_supply_chain.analyze` (lines 2134-2340).
//!
//! SC4 (live OSV lookups), SC5/SC6 (dependency tables), SC8 (shipped bytecode), the trigger rules
//! and SC10 are not ported; SC9 is [`super::concealed_executable`].

use super::common::cut_chars;
use super::supply_chain_sc2::{
    CharView, interpreter_reads_stdin_as_data, is_safe_supply_chain_pattern,
    is_warned_internal_installer,
};
use super::supply_chain_sc3::{
    COMPILED as SC3, decoded_literal_xor_calls, decoded_shell_literal_payloads,
};
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::matcher::{Hit, Pat, paragraph_matches};
use crate::pyast::PyFile;
use crate::runner::StaticModule;
use crate::shell_tokens::sc2_shell_command_ranges;
use crate::skill::FileType;
use crate::text::LineIndex;
use std::cell::OnceCell;
use std::sync::LazyLock;

const CATEGORY: &str = "Supply Chain";

type Rule = (&'static str, f32);

pub const SC1_CODE: &[Rule] = &[
    (r"^[a-zA-Z][a-zA-Z0-9_-]*\s*$", 0.6),
    (r"^[a-zA-Z][a-zA-Z0-9_-]*\s*>=\s*[\d.]+\s*$", 0.5),
    (r"^[a-zA-Z][a-zA-Z0-9_-]*\s*==\s*\*\s*$", 0.7),
    (r#""[^"]+"\s*:\s*"(?:\*|latest)""#, 0.7),
    (r#""[^"]+"\s*:\s*"\^[\d.]+""#, 0.4),
];
pub const SC1_PROSE: &[Rule] = &[
    (
        r"install\s+(?:the\s+)?latest\s+(?:version\s+)?(?:of\s+)?(?:all\s+)?(?:packages?|dependencies)",
        0.6,
    ),
    (
        r"(?:don't|do\s+not)\s+(?:pin|lock|specify)\s+(?:package\s+)?versions?",
        0.7,
    ),
];
pub const SC2_CODE: &[Rule] = &[
    (r"curl\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh", 0.9),
    (r"wget\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh", 0.9),
    (
        r"curl\s+[^|]*\|\s*(?:sudo\s+)?(?:python|python3|node|ruby|perl)",
        0.9,
    ),
    (
        r"wget\s+[^|]*\|\s*(?:sudo\s+)?(?:python|python3|node|ruby|perl)",
        0.9,
    ),
    (r"curl\s+[^&]*-o\s+\S+\s*&&\s*(?:sudo\s+)?(?:ba)?sh", 0.8),
    (r"wget\s+[^&]*-O\s+\S+\s*&&\s*(?:sudo\s+)?(?:ba)?sh", 0.8),
    (
        r"exec\s*\(\s*(?:urllib|requests|httpx)\.[^)]+\.(?:read|text|content)",
        0.95,
    ),
    (
        r"eval\s*\(\s*(?:urllib|requests|httpx)\.[^)]+\.(?:read|text|content)",
        0.95,
    ),
    (r"eval\s*\(\s*(?:await\s+)?fetch\s*\(", 0.9),
    (r"new\s+Function\s*\([^)]*fetch\s*\(", 0.9),
    (r"subprocess\.[^(]+\([^)]*(?:curl|wget)\s+https?://", 0.8),
];
pub const SC2_PROSE: &[Rule] = &[
    (r"download\s+and\s+(?:run|execute)\s+(?:the\s+)?script", 0.7),
    (
        r"run\s+(?:this|the)\s+(?:following\s+)?(?:curl|wget)\s+command",
        0.6,
    ),
];
/// The first six SC2 code patterns are matched only inside proved shell command ranges.
const SC2_SHELL_COUNT: usize = 6;
pub const SC7: &[Rule] = &[
    (r"--disable-content-trust\b(?!=false)", 0.85),
    (r"DOCKER_CONTENT_TRUST\s*=\s*0", 0.85),
    (r"--insecure-registry", 0.8),
];

const DEPENDENCY_FILE_NAMES: [&str; 5] = [
    "requirements",
    "package.json",
    "pyproject.toml",
    "setup.py",
    "pipfile",
];

struct Compiled {
    sc1_code: Vec<Pat>,
    sc1_prose: Vec<Pat>,
    sc2_code: Vec<Pat>,
    sc2_prose: Vec<Pat>,
    sc7: Vec<Pat>,
}

fn compile(rules: &[Rule], flags: &str) -> Vec<Pat> {
    rules.iter().map(|(s, _)| Pat::new(s, flags)).collect()
}

static C: LazyLock<Compiled> = LazyLock::new(|| Compiled {
    sc1_code: compile(SC1_CODE, "m"),
    sc1_prose: compile(SC1_PROSE, "m"),
    sc2_code: compile(SC2_CODE, "im"),
    sc2_prose: compile(SC2_PROSE, "im"),
    sc7: compile(SC7, "im"),
});

/// SC1-SC3 and SC7.
pub struct SupplyChain;

/// `_iter_sc2_shell_matches`: matches anchored at proved command ranges, or legacy scanning from
/// the first open-ended range.
fn iter_sc2_shell_matches(pat: &Pat, text: &str, ranges: &[(usize, Option<usize>)]) -> Vec<Hit> {
    let mut covered = 0;
    let mut out = Vec::new();
    for &(start, end) in ranges {
        let Some(end) = end else {
            out.extend(pat.find_in(text, start.max(covered), text.len()));
            return out;
        };
        if start < covered {
            continue;
        }
        if let Some(hit) = pat
            .find_in(text, start, end)
            .into_iter()
            .next()
            .filter(|h| h.start == start)
        {
            covered = hit.end;
            out.push(hit);
        }
    }
    out
}

fn base(
    rule: &'static str,
    message: &str,
    sev: Severity,
    conf: f32,
    path: &str,
    line: u32,
) -> RawFinding {
    let mut f = RawFinding::new(rule, message, sev, conf, path, line);
    f.tags = vec![CATEGORY.to_owned()];
    f
}

fn with_match(mut f: RawFinding, full: &str, complete: bool) -> RawFinding {
    f.matched_text = Some(cut_chars(full, 200).to_owned());
    if complete {
        f.fingerprint_text = Some(full.to_owned());
    }
    f
}

fn sc1(text: &str, path: &str, index: &LineIndex, out: &mut Vec<RawFinding>) {
    let lower = path.to_lowercase();
    if !DEPENDENCY_FILE_NAMES.iter().any(|n| lower.contains(n)) {
        return;
    }
    let groups = [
        (SC1_CODE, &C.sc1_code, false),
        (SC1_PROSE, &C.sc1_prose, true),
    ];
    for (rules, pats, prose) in groups {
        for ((_, conf), pat) in rules.iter().zip(pats) {
            let hits = if prose {
                paragraph_matches(pat, text)
            } else {
                pat.find_iter(text)
            };
            for hit in hits {
                let f = base(
                    "SC1",
                    "Unpinned Dependencies",
                    Severity::Low,
                    *conf,
                    path,
                    index.line(hit.start),
                );
                out.push(with_match(f, hit.text(text), true));
            }
        }
    }
}

fn sc2_finding(
    text: &str,
    path: &str,
    ft: FileType,
    conf: f32,
    hit: &Hit,
    index: &LineIndex,
    view: &OnceCell<CharView>,
) -> RawFinding {
    let mt = hit.text(text);
    let warned = is_warned_internal_installer(text, hit, ft, index);
    let consumer =
        interpreter_reads_stdin_as_data(view.get_or_init(|| CharView::new(text)), hit.start);
    let (adj, sev) = if is_safe_supply_chain_pattern(mt) || consumer {
        (conf.min(0.15), Severity::Low)
    } else {
        (conf, Severity::High)
    };
    let (message, remediation, explanation) = if warned {
        (
            "Warned Pipe-to-Shell Installer",
            Some(
                "Keep the warning adjacent to this command. Prefer a checksum, signature, or \
                 inspect-before-execute flow instead of piping fetched content directly to a shell.",
            ),
            Some(
                "The matched documentation explicitly warns that an internal installer is fetched \
                 and piped directly to a shell. The warning provides context, but the command still \
                 executes remote code without an inspection step.",
            ),
        )
    } else if consumer {
        (
            "Inline Program Reads Download as Data",
            Some(
                "Prefer structured data formats and validate the fetched content before using it \
                 in a program.",
            ),
            Some(
                "The fetched content is parsed as data by the interpreter program supplied on the \
                 command line; the download is not executed as a script.",
            ),
        )
    } else {
        ("External Script Fetching", None, None)
    };
    let mut f = base("SC2", message, sev, adj, path, index.line(hit.start));
    f.remediation = remediation.map(str::to_owned);
    f.explanation = explanation.map(str::to_owned);
    if warned {
        f.tags
            .extend(["contextual-triage", "explicit-risk-warning"].map(str::to_owned));
    }
    if consumer {
        f.tags.push("data-only-stdin-consumer".to_owned());
    }
    with_match(f, mt, true)
}

/// Decoded payloads that still look like a fetch: the first matching SC2 pattern decides confidence.
fn decoded_fetch(command: &str, path: &str, line: u32) -> Option<RawFinding> {
    let c = &*C;
    let rules = SC2_CODE.iter().chain(SC2_PROSE);
    let pats = c.sc2_code.iter().chain(&c.sc2_prose);
    rules.zip(pats).find_map(|((_, conf), pat)| {
        (!pat.find_iter(command).is_empty()).then(|| {
            let f = base(
                "SC2",
                "External Script Fetching",
                Severity::High,
                *conf,
                path,
                line,
            );
            with_match(f, command, false)
        })
    })
}

fn sc2(text: &str, path: &str, ft: FileType, index: &LineIndex, out: &mut Vec<RawFinding>) {
    let Ok(ranges) = sc2_shell_command_ranges(text, ft) else {
        return;
    };
    let view = OnceCell::new();
    let c = &*C;
    let all = SC2_CODE
        .iter()
        .chain(SC2_PROSE)
        .zip(c.sc2_code.iter().chain(&c.sc2_prose));
    for (i, ((_, conf), pat)) in all.enumerate() {
        let hits = if i < SC2_SHELL_COUNT {
            iter_sc2_shell_matches(pat, text, &ranges)
        } else if i >= SC2_CODE.len() {
            paragraph_matches(pat, text)
        } else {
            pat.find_iter(text)
        };
        out.extend(
            hits.iter()
                .map(|hit| sc2_finding(text, path, ft, *conf, hit, index, &view)),
        );
    }
    if ft == FileType::Python {
        for (line, command) in decoded_literal_xor_calls(text, index) {
            out.extend(decoded_fetch(&command, path, line));
        }
    }
}

fn sc3(text: &str, path: &str, ft: FileType, index: &LineIndex, out: &mut Vec<RawFinding>) {
    let s3 = &*SC3;
    let has_decoder = !s3.decode_command.find_iter(text).is_empty();
    if has_decoder {
        for (start, command) in decoded_shell_literal_payloads(text) {
            out.extend(decoded_fetch(&command, path, index.line(start)));
        }
    }
    let applies = matches!(
        ft,
        FileType::Python
            | FileType::Javascript
            | FileType::Shell
            | FileType::Perl
            | FileType::Other
    );
    let shell_rules = super::supply_chain_sc3::shell_patterns();
    let mut sets: Vec<(Vec<f32>, &Vec<Pat>, bool)> = Vec::new();
    if applies {
        sets.push((
            super::supply_chain_sc3::SC3_CODE
                .iter()
                .map(|r| r.1)
                .collect(),
            &s3.code,
            false,
        ));
        sets.push((
            super::supply_chain_sc3::SC3_PROSE
                .iter()
                .map(|r| r.1)
                .collect(),
            &s3.prose,
            true,
        ));
    }
    if has_decoder {
        sets.push((shell_rules.iter().map(|r| r.1).collect(), &s3.shell, false));
    }
    // `SC3_PATTERNS` is code then prose; the prose rule only runs where code rules do.
    for (confs, pats, prose) in sets {
        for (conf, pat) in confs.iter().zip(pats) {
            let hits = if prose {
                paragraph_matches(pat, text)
            } else {
                pat.find_iter(text)
            };
            for hit in hits {
                let f = base(
                    "SC3",
                    "Obfuscated Code",
                    Severity::High,
                    *conf,
                    path,
                    index.line(hit.start),
                );
                out.push(with_match(f, hit.text(text), true));
            }
        }
    }
}

fn sc7(text: &str, path: &str, index: &LineIndex, out: &mut Vec<RawFinding>) {
    for ((_, conf), pat) in SC7.iter().zip(&C.sc7) {
        for hit in pat.find_iter(text) {
            let f = base(
                "SC7",
                "Untrusted Container Image",
                Severity::High,
                *conf,
                path,
                index.line(hit.start),
            );
            out.push(with_match(f, hit.text(text), true));
        }
    }
}

impl StaticModule for SupplyChain {
    fn id(&self) -> &'static str {
        "static_patterns_supply_chain"
    }

    fn uses_python_source_type(&self) -> bool {
        true
    }

    fn analyze(
        &self,
        text: &str,
        path: &str,
        ft: FileType,
        _py: Option<&PyFile>,
    ) -> Vec<RawFinding> {
        let index = LineIndex::new(text);
        let mut out = Vec::new();
        sc1(text, path, &index, &mut out);
        sc2(text, path, ft, &index, &mut out);
        sc3(text, path, ft, &index, &mut out);
        sc7(text, path, &index, &mut out);
        out
    }
}

#[cfg(test)]
/// Every pattern of the module as `(source, flags)`, for the compile test.
pub fn all_patterns() -> Vec<(String, &'static str)> {
    let mut v: Vec<(String, &'static str)> = Vec::new();
    v.extend(
        SC1_CODE
            .iter()
            .chain(SC1_PROSE)
            .map(|(s, _)| ((*s).to_owned(), "m")),
    );
    v.extend(
        SC2_CODE
            .iter()
            .chain(SC2_PROSE)
            .chain(SC7)
            .map(|(s, _)| ((*s).to_owned(), "im")),
    );
    v.extend(super::supply_chain_sc3::all_sources());
    v.extend(
        super::supply_chain_sc2::PATTERNS
            .iter()
            .map(|(s, f)| ((*s).to_owned(), *f)),
    );
    v
}
