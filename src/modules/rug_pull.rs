//! RP1-RP3 from `mcp_rug_pull.py`: unpinned MCP servers and images, manifest pre-staging and an
//! unpinned skill version. Scans every cached file (binary-classified ones too) and `str(manifest)`.
//! The previous-manifest comparison needs a second manifest the CLI never supplies and is not ported.

use crate::analyzer::Analyzer;
use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::manifest::Manifest;
use crate::matcher::{Hit, Pat};
use crate::skill::Skill;
use crate::unicode::is_space;
use std::sync::LazyLock;

const CATEGORY: &str = "MCP Rug Pull";
const TAG: &str = "ASI16";
/// `MAX_FINDINGS_PER_ARTIFACT` and `MAX_FINDINGS_PER_ANALYZER`.
const MAX_FINDINGS: usize = 10_000;

/// (source, flags) of every pattern, so tests can compile them all.
pub const PATTERNS: [(&str, &str); 7] = [
    (
        r"npx\s+(?:-+\w+\s+)*((?:@?[a-zA-Z][\w.-]*/)?[a-zA-Z][\w.-]*)",
        "i",
    ),
    (
        r"(?:uvx|uv\s+tool\s+run)\s+(?:-+\w+\s+)*([a-zA-Z][\w.-]*)",
        "i",
    ),
    (r"pip\d?\s+install\s+(?:-+\w+\s+)*([a-zA-Z][\w.-]*)", "i"),
    (r"docker\s+(?:pull|run|create)\s+\S+", "i"),
    (r"@[\d.]+\b|==[\d.]+|:[\d.]+|@sha256:", ""),
    (r#""permissions?"\s*:\s*\[[^\]]*\]"#, "i"),
    (
        r"(?:add|grant|request|require)\s+(?:new|additional|extra|more)\s+(?:permissions?|tools?|access)",
        "i",
    ),
];

static COMPILED: LazyLock<Vec<Pat>> =
    LazyLock::new(|| PATTERNS.iter().map(|(s, f)| Pat::new(s, f)).collect());
const NPX: usize = 0;
const UVX: usize = 1;
const PIP: usize = 2;
const DOCKER: usize = 3;
const PIN: usize = 4;
const PERMISSIONS_JSON: usize = 5;
const PERMISSIONS_PROSE: usize = 6;

fn cut_chars(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

fn has_pin(s: &str) -> bool {
    !COMPILED[PIN].find_iter(s).is_empty()
}

/// `_operand_has_version_pin`: only the operand's own token counts.
fn operand_has_pin(remainder: &str) -> bool {
    has_pin(remainder.split(is_space).next().unwrap_or(""))
}

fn finding(
    rule: &'static str,
    msg: String,
    sev: Severity,
    conf: f32,
    file: &str,
    line: u32,
    full: &str,
) -> RawFinding {
    let mut f = RawFinding::new(rule, msg, sev, conf, file, line);
    f.category = Some(CATEGORY.into());
    f.tags = vec![TAG.into()];
    f.matched_text = Some(cut_chars(full, 200).to_owned());
    f.fingerprint_text = Some(full.to_owned());
    f
}

struct Sink {
    out: Vec<RawFinding>,
    per_file: usize,
    full: bool,
}

impl Sink {
    /// Mirrors `_RugPullBudget.emit`: past the cap the analysis stops with what it has.
    fn emit(&mut self, mut f: RawFinding, explanation: &str, remediation: &str) {
        self.per_file += 1;
        if self.per_file > MAX_FINDINGS || self.out.len() >= MAX_FINDINGS {
            self.full = true;
            return;
        }
        f.explanation = Some(explanation.into());
        f.remediation = Some(remediation.into());
        self.out.push(f);
    }
}

fn scan_text(sink: &mut Sink, file: &str, text: &str) {
    let newlines: Vec<usize> = text.match_indices('\n').map(|(i, _)| i).collect();
    let line_of =
        |pos: usize| u32::try_from(newlines.partition_point(|&n| n < pos) + 1).unwrap_or(u32::MAX);
    let unpinned = |h: &Hit, full: &str| {
        let end = text[h.end..].find('\n').map_or(text.len(), |i| h.end + i);
        let remainder = cut_chars(&text[h.end..end], 256);
        !(has_pin(full) || operand_has_pin(remainder))
    };
    for h in COMPILED[NPX].find_iter(text) {
        let full = h.text(text);
        if sink.full || !unpinned(&h, full) {
            continue;
        }
        let msg = format!(
            "MCP server referenced without pinned version: '{}'.",
            cut_chars(full.trim_matches(is_space), 200)
        );
        let f = finding(
            "RP1",
            msg,
            Severity::Medium,
            0.70,
            file,
            line_of(h.start),
            full,
        );
        sink.emit(
            f,
            "npx commands without a version suffix (e.g. @1.0.0) create a rug-pull risk if the upstream server is compromised and publishes a malicious update.",
            "Pin the version: npx @scope/server@1.2.3",
        );
    }
    for h in COMPILED[UVX].find_iter(text) {
        let full = h.text(text);
        if sink.full || !unpinned(&h, full) {
            continue;
        }
        let msg = format!(
            "MCP server referenced without pinned version: '{}'.",
            cut_chars(full.trim_matches(is_space), 200)
        );
        let f = finding(
            "RP1",
            msg,
            Severity::Medium,
            0.65,
            file,
            line_of(h.start),
            full,
        );
        sink.emit(
            f,
            "uvx/uv tool run commands without ==version create a rug-pull risk.",
            "Pin the version: uvx package-name==1.2.3",
        );
    }
    for h in COMPILED[PIP].find_iter(text) {
        let full = h.text(text);
        if sink.full || !unpinned(&h, full) {
            continue;
        }
        if !h
            .group(text, 1)
            .unwrap_or("")
            .to_lowercase()
            .contains("mcp")
        {
            continue;
        }
        let msg = format!(
            "MCP server dependency without pinned version: '{}'.",
            cut_chars(full.trim_matches(is_space), 200)
        );
        let f = finding(
            "RP1",
            msg,
            Severity::Low,
            0.60,
            file,
            line_of(h.start),
            full,
        );
        sink.emit(
            f,
            "pip install without ==version installs the latest release, which could include malicious changes.",
            "Pin the version: pip install package==1.2.3",
        );
    }
    for h in COMPILED[DOCKER].find_iter(text) {
        let full = h.text(text);
        if sink.full || has_pin(full) {
            continue;
        }
        let msg = format!(
            "Docker image referenced without tag or digest: '{}'.",
            cut_chars(full, 80)
        );
        let f = finding(
            "RP1",
            msg,
            Severity::Medium,
            0.75,
            file,
            line_of(h.start),
            full,
        );
        sink.emit(
            f,
            "Docker image references without a specific tag (:latest is implicit) or digest (@sha256:...) can be silently replaced by a malicious image.",
            "Pin the image: image:tag or image@sha256:abc123",
        );
    }
}

fn scan_manifest(sink: &mut Sink, m: &Manifest) {
    let file = "SKILL.md";
    sink.per_file = 0;
    let text = m.text.as_str();
    for h in COMPILED[NPX].find_iter(text) {
        let full = h.text(text);
        let msg = format!(
            "Manifest references MCP server without version pin: '{}'.",
            cut_chars(full.trim_matches(is_space), 200)
        );
        let f = finding("RP1", msg, Severity::Medium, 0.70, file, 1, full);
        sink.emit(
            f,
            "MCP server references in the skill manifest without version pinning are a rug-pull risk.",
            "Always pin MCP server versions in manifest references.",
        );
    }
    for (idx, conf) in [(PERMISSIONS_JSON, 0.60), (PERMISSIONS_PROSE, 0.70)] {
        for h in COMPILED[idx].find_iter(text) {
            let f = finding(
                "RP2",
                "Manifest language suggests future permission expansion.".into(),
                Severity::Low,
                conf,
                file,
                1,
                h.text(text),
            );
            sink.emit(
                f,
                "Language in the manifest suggests the skill may request additional permissions or tools in future versions. This is a pre-staging indicator for rug-pull attacks.",
                "Review the skill's stated permissions. Consider pinning to a specific version and auditing updates.",
            );
        }
    }
    let Some(version) = m
        .version
        .as_deref()
        .map(|v| v.trim_matches(is_space))
        .filter(|_| m.version.as_deref().is_some_and(|v| !v.is_empty()))
    else {
        return;
    };
    let preview = cut_chars(version, 200);
    let (msg, conf, why, fix) = if matches!(version, "*" | "latest" | "any") {
        (
            format!("Skill version is unpinned: '{preview}'."),
            0.80,
            "An unpinned version allows automatic updates to any future version, creating a rug-pull risk.",
            "Pin to a specific version (e.g. '1.2.3').",
        )
    } else if version.starts_with(">=") || version.starts_with('^') {
        (
            format!("Skill version constraint may be too broad: '{preview}'."),
            if version.starts_with(">=") {
                0.40
            } else {
                0.50
            },
            "Broad version constraints allow automatic major-version updates, which could silently introduce malicious changes.",
            "Pin to a specific version or narrow the range.",
        )
    } else {
        return;
    };
    let mut f = finding("RP3", msg, Severity::Low, conf, file, 1, version);
    f.matched_text = Some(preview.to_owned());
    sink.emit(f, why, fix);
}

/// The `mcp_rug_pull` analyzer.
pub struct RugPull;

impl Analyzer for RugPull {
    fn id(&self) -> &'static str {
        "mcp_rug_pull"
    }

    fn run(&self, skill: &Skill) -> Vec<RawFinding> {
        let mut sink = Sink {
            out: Vec::new(),
            per_file: 0,
            full: false,
        };
        for file in skill.files.iter().filter(|f| f.cached) {
            sink.per_file = 0;
            scan_text(&mut sink, &file.rel, &file.text);
            if sink.full {
                return sink.out;
            }
        }
        if let Some(m) = &skill.manifest {
            scan_manifest(&mut sink, m);
        }
        sink.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(files: &[(&str, &str)]) -> Vec<(String, &'static str, u32, String)> {
        let skill = Skill::from_memory(
            files
                .iter()
                .map(|(n, t)| ((*n).to_owned(), t.as_bytes().to_vec()))
                .collect(),
        );
        RugPull
            .run(&skill)
            .into_iter()
            .map(|f| (f.file, f.rule_id, f.start_line, f.message))
            .collect()
    }

    #[test]
    fn all_compile() {
        for (src, flags) in PATTERNS {
            assert!(Pat::try_new(src, flags).is_ok(), "{src}");
        }
    }

    #[test]
    fn rp1_npx_pin_rules() {
        let hits = run(&[(
            "a.md",
            "npx playwright test\nnpx @scope/pkg@1.2.3 x\nnpx foo@2\nnpx bar --yes\nnpx -y baz@latest\n",
        )]);
        let lines: Vec<u32> = hits.iter().map(|h| h.2).collect();
        assert_eq!(lines, [1, 4, 5]); // `baz@latest`: the pin must be a version number
        assert_eq!(
            hits[0].3,
            "MCP server referenced without pinned version: 'npx playwright'."
        );
    }

    #[test]
    fn rp1_other_commands() {
        let hits = run(&[(
            "a.sh",
            "uvx tool\nuvx tool==1.0\npip install mcp-server\npip install requests\npip install mcp==1\ndocker run nginx\ndocker run nginx:1.2\n",
        )]);
        let lines: Vec<u32> = hits.iter().map(|h| h.2).collect();
        assert_eq!(lines, [1, 3, 6]);
    }

    #[test]
    fn line_numbers_count_only_newline() {
        let hits = run(&[("a.md", "x\rnpx foo\u{2028}\nnpx bar")]);
        assert_eq!(hits.iter().map(|h| h.2).collect::<Vec<_>>(), [1, 2]);
    }

    #[test]
    fn manifest_checks() {
        let md = "---\nname: x\nversion: latest\ndescription: it will request additional permissions, run npx thing\n---\nbody\n";
        let hits = run(&[("SKILL.md", md)]);
        let ids: Vec<_> = hits.iter().map(|h| h.1).collect();
        assert_eq!(ids, ["RP1", "RP1", "RP2", "RP3"]); // body line and manifest text
        assert_eq!(hits.iter().map(|h| h.2).collect::<Vec<_>>(), [4, 1, 1, 1]);
        let caret = run(&[("SKILL.md", "---\nversion: ^1.2\n---\n")]);
        assert_eq!(
            caret.iter().map(|h| h.3.as_str()).collect::<Vec<_>>(),
            ["Skill version constraint may be too broad: '^1.2'."]
        );
        assert!(run(&[("SKILL.md", "---\nversion: 1.2.3\n---\n")]).is_empty());
    }

    #[test]
    fn binary_files_are_scanned() {
        let skill = Skill::from_memory(vec![(
            "x.bin".into(),
            b"\x89PNG\r\n\x1a\n npx evil ".to_vec(),
        )]);
        assert_eq!(RugPull.run(&skill).len(), 1);
    }
}
