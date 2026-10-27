# skillspector-rs

[![CI](https://github.com/Dansemums/skillspector-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Dansemums/skillspector-rs/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.95+](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](#install)
[![crates.io](https://img.shields.io/badge/crates.io-not%20published%20yet-lightgrey.svg)](#install)

**An optimized Rust port of [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) with the agent / LLM
features stripped.** It ports the deterministic static analysis only: regex patterns, YARA rules, Python AST
checks, taint tracking and normalized text views. The LLM semantic analyzers and the meta analyzer are **not
included yet** (see the [roadmap](#roadmap--todo)). One binary, no Python, no network, no API keys, and a
library. Findings aim for parity with upstream v2.12.0 run with `--no-llm`.

> Independent, unofficial port. Not affiliated with or endorsed by NVIDIA. See [NOTICE](NOTICE).

It scans folders that contain AI agent skills (a `SKILL.md` plus scripts, for Claude Code, Codex, Cursor,
Gemini and similar tools) and reports prompt injection, data exfiltration, privilege escalation, supply
chain tricks, dangerous tool use and more, with rule ids, severities and line numbers that match upstream.

## Why

The upstream tool is a Python pipeline that is built around LLM calls. Its deterministic half is useful on
its own (CI gates, pre-commit hooks, bulk audits of installed skills) but starts a Python runtime per run.
This port runs that half natively.

Measured with the release build on an Apple M1 Pro (8 cores, 16 GB, macOS 26). Numbers vary with hardware,
disk cache and load; the 1000-skill range below is the spread of seven runs on a busy laptop.

| What | skillspector-rs | Python SkillSpector `--no-llm` |
|---|---|---|
| 60 skills (`tests/fixtures`), `--recursive` | 0.5 to 0.7 s | not measured as a batch |
| 1000 skill folders (the 60 fixtures copied round-robin), `--recursive` | 2.9 to 8.3 s, median 4.7 s | not measured |
| one skill (`malicious_skill`) | 0.23 to 0.3 s including start-up | 13 s wall (5.5 s CPU) |

The Python number is one cold run of `skillspector scan <folder> --no-llm`, dominated by start-up and imports.
Do not extrapolate it to a batch; a batch comparison was not measured. On a private set of 865 real skill
folders the port took about 25 s (`skillspector-rs-diff`, varies by run).

## Quick start

```bash
git clone https://github.com/Dansemums/skillspector-rs && cd skillspector-rs
cargo install --path . --bin skillspector-rs             # installs `skillspector-rs`
skillspector-rs scan ./my-skill                          # one skill
skillspector-rs scan --recursive ~/.claude/skills --fail-on high   # every skill below a folder; exit 1 on HIGH or worse
```

Real output (`skillspector-rs scan tests/fixtures/malicious_skill`):

```text
tests/fixtures/malicious_skill
  [MEDIUM] LP3 Skill declares no tool scope ('permissions' or 'allowed-tools') but code capabilities were detected: env, network. SKILL.md:1
  [HIGH] E2 Env Variable Harvesting scripts/helper.py:15: os.environ.items()
  [MEDIUM] E1 External Transmission scripts/helper.py:21: requests.post("https://
  [MEDIUM] E1 External Transmission scripts/helper.py:21: requests.post("https://api.skill-metrics.io/env", json=
  [MEDIUM] E1 External Transmission scripts/helper.py:21: https://api.skill-metrics.io/

1 skills scanned, 5 findings
```

### Usage

```text
skillspector-rs scan [--recursive|-r] [--format text|json|sarif] [--fail-on low|medium|high|critical] PATH...
```

* Without `--recursive`, every `PATH` is one skill. With it, every folder below `PATH` that holds a
  `SKILL.md` is a skill.
* Exit codes: `0` clean (or below `--fail-on`), `1` a finding at or above `--fail-on`, `2` usage or I/O error.
* `--format json` prints `{tool, version, skills: [{skill, risk_assessment, issues}]}`; `--format sarif` prints SARIF 2.1.0.
* `risk_assessment` is SkillSpector's verdict: `score` (0-100, confidence-weighted, diminishing per rule),
  `severity` band, `recommendation` and `max_issue_severity`. In the library: `scan_skill_with_risk`.
  `score`, `severity` and `max_issue_severity` matched SkillSpector on 80 of 80 skills tested; `recommendation`
  can read `SAFE` where SkillSpector says `CAUTION`, because it also downgrades when its inspection ledger
  (not ported) marks the analysis incomplete, for example for a file reference that matches no bundled file.

JSON (one issue shown):

```json
{
  "tool": "skillspector-rs",
  "version": "0.1.0",
  "skills": [
    {
      "skill": "tests/fixtures/malicious_skill",
      "issues": [
        {
          "id": "E2",
          "category": "Data Exfiltration",
          "pattern": "Env Variable Harvesting",
          "severity": "HIGH",
          "confidence": 0.699999988079071,
          "file": "scripts/helper.py",
          "start_line": 15,
          "finding": "os.environ.items()"
        }
      ]
    }
  ]
}
```

SARIF (one result shown):

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "skillspector-rs", "version": "0.1.0" } },
    "results": [{
      "ruleId": "E2",
      "level": "error",
      "message": { "text": "Env Variable Harvesting: os.environ.items()" },
      "locations": [{ "physicalLocation": {
        "artifactLocation": { "uri": "tests/fixtures/malicious_skill/scripts/helper.py" },
        "region": { "startLine": 15 } } }]
    }]
  }]
}
```

Severity maps to SARIF levels: LOW is `note`, MEDIUM is `warning`, HIGH and CRITICAL are `error`.

## What it detects

Rule ids are SkillSpector's. "Ported" means the rules are implemented and match upstream on the
fixtures and on the private corpus described under [Parity](#parity-with-upstream).

| Category | Rule ids | Status |
|---|---|---|
| Prompt injection (override phrases, hidden HTML comments, hidden Unicode, letter padding) | P1-P4, P9 | ported |
| System prompt leakage | P6-P8 | ported |
| Harmful content | P5 | not yet |
| Data exfiltration (network sends, env harvesting, file sweeps) | E1-E5 | ported |
| Privilege escalation (sudo, credentials, tokens, permissions) | PE1-PE5 | ported |
| Supply chain (pipe-to-shell, obfuscation, decoded payloads, concealed executables) | SC1-SC3, SC7, SC9 | ported |
| Known-vulnerable dependencies (OSV) | SC4 | not yet (needs network) |
| Trigger abuse / shadow commands | TR1-TR3 | not yet |
| Tool misuse (destructive commands, shell=True, chmod) | TM1-TM4 | ported |
| Behavioral AST (dangerous calls in Python) | AST1-AST10 | ported |
| Taint tracking (source to sink flows in Python) | TT1-TT6 | ported |
| Memory poisoning | MP1-MP3 | ported |
| SSRF | SSRF1-SSRF3 | ported |
| Output handling (model output into sinks) | OH1-OH3 | ported |
| Agent snooping (reading other agents' config) | AS1-AS3 | ported |
| Rogue agent (self-modification, skill installation) | RA1-RA2 | ported |
| Anti-refusal | AR1-AR3 | ported |
| Excessive agency and model selection | EA1-EA5 | ported |
| MCP rug pull (unpinned servers and images) | RP1-RP3 | ported |
| MCP least privilege | LP1-LP4 | ported |
| MCP tool poisoning (deterministic checks) | TP1-TP3 | not yet |
| Coverage notes and artifact integrity | AE1, AE4 | partial (AE1 time-budget notes and AE7 are not produced) |
| YARA rules (malware, webshells, miners, hack tools, skill-specific) | YR1-YR4 | ported (feature `yara`) |
| Signature bundle (OMS / Sigstore) projection | | not yet |

## Parity with upstream

Findings are compared with the Python tool on `(rule id, file, start line)`.

* **Public fixtures, run in CI:** upstream's 15 fixture folders and 28 synthetic skills (68 scannable
  folders). The reference reports 93 findings (SC4 excluded): 86 are reproduced, 7 are missing and 4 are
  extra. All 11 differences come from the analyzers listed as "not yet" above and are documented in
  [tests/fixtures/KNOWN_DIFFERENCES.md](tests/fixtures/KNOWN_DIFFERENCES.md); `tests/parity.rs` fails on any other.
* **Private corpus, measured once:** 865 real skill folders: 2777 of 2800 reference findings reproduced,
  0 extra. The 23 missing are 18 SC4 (network) and 5 time-budget notes.

Details and how to reproduce: [PARITY.md](PARITY.md). A rule change must keep `cargo test` green.

## Roadmap / TODO

The agent and LLM parts of upstream are the main thing missing. Contributions welcome.

- [ ] LLM semantic analyzers: `semantic_security_discovery`, `semantic_developer_intent`,
      `semantic_quality_policy`, and the LLM part of `mcp_tool_poisoning`
- [ ] Meta analyzer (false-positive filtering and re-scoring)
- [ ] Provider adapters (OpenAI, Anthropic, Bedrock, Ollama, ...)
- [ ] OSV dependency lookups (SC4; needs network, would be opt-in)
- [ ] Deterministic gaps found by the fixtures: harmful content (P5), tool poisoning (TP1-TP3), trigger
      analysis (TR1-TR3), OMS signature bundle projection
- [ ] Transitive references
- [ ] MCP registry mode
- [ ] Baselines and suppressions
- [ ] Time budgets and the inspection ledger (AE1 time-limit notes, AE7)

Until then, use upstream SkillSpector when you want LLM analysis.

## Use as a library

```rust
use std::path::Path;

fn main() -> std::io::Result<()> {
    for issue in skillspector_rs::scan_skill(Path::new("./my-skill"))? {
        println!("{} {:?} {}:{:?}", issue.id, issue.severity, issue.file, issue.start_line);
    }
    Ok(())
}
```

```toml
[dependencies]
skillspector-rs = { git = "https://github.com/Dansemums/skillspector-rs" }
# lighter build without the bundled YARA rules:
# skillspector-rs = { git = "...", default-features = false }
```

The public API is `scan_skill`, `scan_loaded` with `Skill`, `Issue` and `Severity`. There is no async
runtime and no network code. Scans run on a private thread pool.

## Install

```bash
cargo install --path . --bin skillspector-rs          # from a checkout
cargo install --git https://github.com/Dansemums/skillspector-rs --bin skillspector-rs
```

Minimum Rust is 1.95, which `yara-x` declares; the crate's own code needs 1.88 for let chains. Both
figures come from metadata and a build on Rust 1.96 and later, not from a test on 1.95 itself. Not on
crates.io yet.

Features: `yara` (default) runs the bundled YARA rules (YR1-YR4) through `yara-x`, which is the heaviest
dependency. `--no-default-features` builds without it and loses exactly those four rule ids.

## CI and pre-commit

GitHub Actions, uploading results to code scanning:

```yaml
- uses: actions/checkout@v4
- run: cargo install --git https://github.com/Dansemums/skillspector-rs --bin skillspector-rs
- run: skillspector-rs scan --recursive .claude/skills --format sarif > skillspector.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: skillspector.sarif
```

To fail the job instead, add a second step `skillspector-rs scan --recursive .claude/skills --fail-on high`.
Pre-commit hook (`.git/hooks/pre-commit`):

```bash
#!/bin/sh
skillspector-rs scan --recursive .claude/skills --fail-on high
```

## Safety limits

The scanner reads untrusted files, so it is bounded:

* it only reads: nothing is executed, imported or evaluated, and there are no network calls;
* each file is read up to 16 MiB; the regex modules look at the first 1 MiB of a file; Python files above
  1,000,000 characters are not parsed (as upstream);
* YARA is limited to 5 s per file and 10 s per skill (findings of a timed-out file are dropped);
* scans run on threads with a 256 MiB stack (reserved, not committed), so deeply nested input cannot
  overflow it;
* regex backtracking limits end a match search instead of failing; unreadable files, device files, FIFOs and
  symlink loops are skipped.

`tests/robustness.rs` exercises these with hostile folders. A single 1 MiB file made of nothing but
matches can still take several seconds.

## FAQ

**Is it safe to run on a malicious skill?** It never executes skill content, but it parses it, so it is
exposed to parser bugs like any tool. Report crashes or hangs, see [SECURITY.md](SECURITY.md).

**Does it execute skills or scripts?** No. **Does it use the network?** No, not even for dependency lookups.

**How does it differ from upstream?** Same rules for the deterministic part, in a native binary, without
the LLM analyzers, the meta analyzer, OSV lookups and a few deterministic analyzers listed above.

**Can I use LLM analysis?** Not yet. Use [upstream SkillSpector](https://github.com/NVIDIA/SkillSpector).

**Why do I see findings upstream's LLM run would drop?** Upstream's meta analyzer filters false positives;
without it every deterministic finding is kept, exactly like upstream's `--no-llm`.

## Relationship to upstream

Detection rules, pattern tables, rule ids, messages and heuristics are ported from NVIDIA SkillSpector
(Apache-2.0) at commit `d7338f58200a9ae2a24810cee08911ab68b107a7` (v2.12.0); function names follow the
Python source so changes can be tracked. What differs: native speed, fully offline, no LLM. What is
ported and what is not is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Parity is measured by
comparing finding ids, files and start lines with upstream's `--no-llm` output on public fixtures
(`tests/parity.rs`) and, privately, on a larger corpus. Upstream's test fixtures are included under
their Apache-2.0 license. This project is not affiliated with or endorsed by NVIDIA.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The parity-first rule: rule changes must keep `tests/parity.rs`
green. Security issues: [SECURITY.md](SECURITY.md).

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Derived from NVIDIA SkillSpector,
Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
