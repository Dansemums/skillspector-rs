# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `risk_assessment` (score, severity, recommendation, max issue severity) in JSON and text output, and
  `scan_skill_with_risk` / `scan_loaded_with_risk` / `Risk` in the library.

## [0.1.0] - 2026-10-27

Initial release: an optimized Rust port of the deterministic analysis of
[NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) v2.12.0 (commit `d7338f5`).

### Added

- `skillspector-rs` command line scanner (`scan [--recursive] [--format text|json|sarif] [--fail-on LEVEL]`).
- Library API: `scan_skill`, `scan_loaded`, `Skill`, `Issue`, `Severity`.
- Static rule modules for prompt injection, hidden Unicode and letter padding, system-prompt leakage,
  data exfiltration, privilege escalation, supply chain, tool misuse, behavioral AST, taint tracking,
  memory poisoning, SSRF, output handling, agent snooping, rogue agent, anti-refusal, excessive agency,
  MCP rug pull, least privilege, reference coverage, artifact integrity and bundled YARA rules.
- Parity tests against reference output on public fixtures (`tests/parity.rs`) and optional
  differential tests against a private corpus (`SKILLSPECTOR_RS_PRIVATE_DATA`).
- Robustness tests with hostile input (`tests/robustness.rs`).

### Not included

LLM analyzers, the meta analyzer, OSV lookups (SC4), trigger analysis, harmful-content and
tool-poisoning checks. See the roadmap in the README.

### Safety limits

- Files are read up to 16 MiB; regex-based modules look at the first 1 MiB of a file.
- YARA scanning is limited to 5 s per file and 10 s per skill.
- Scans run on threads with a 256 MiB stack so deeply nested input cannot overflow it.

[Unreleased]: https://github.com/Dansemums/skillspector-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Dansemums/skillspector-rs/releases/tag/v0.1.0
