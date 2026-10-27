# Architecture

skillspector-rs reproduces the deterministic analysis of [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)
(pinned: v2.12.0, commit `d7338f5`) in Rust. The goal is identical findings (rule id, file, start line)
to `skillspector scan --no-llm`, not a redesign. Module and function names deliberately mirror the
Python source so a change upstream can be traced to the Rust file that must follow it; each module's
`//!` header names the Python function it ports.

## Pipeline

```
folder --> Skill::read --> analyzers --> RawFinding --> dedupe::finalize --> Vec<Issue>
              |               |
              |               +-- whole-skill analyzers (analyzer::registry)
              |               +-- static pattern modules, run per file and per text view
              |                   (analyzer::static_modules + runner::run_static)
              +-- files, classification, manifest
```

1. **Read** (`skill.rs`, `manifest.rs`, `pysource.rs`). Walks the folder in lexical order, skipping
   `node_modules`, `.git`, `__pycache__`, `target`, `.venv`, `venv`, `site-packages`, `.tox`,
   `.pytest_cache`. Each file is read once (cut at 16 MiB), decoded like SkillSpector's
   `local_file_cache` (lossy UTF-8; PEP 263 aware for Python), classified (type by extension, binary vs
   text by magic bytes and printable ratio, Python by extension or shebang) and the `SKILL.md`
   frontmatter is parsed into a manifest. Unreadable entries, devices, FIFOs and link loops are skipped,
   never fatal.
2. **Analyze** (`analyzer.rs`, `runner.rs`). Whole-skill analyzers (rug pull, least privilege,
   concealed executables, reference coverage, artifact integrity, YARA) run in parallel with rayon.
   Static pattern modules implement `StaticModule`; `runner::run_static` runs every module over every
   file and over each *security text view* of it, assigns occurrence columns like
   `static_runner._OccurrenceColumnResolver`, applies the contextual filters (`filters.rs`: license text,
   env-file documentation) and drops duplicate view findings.
3. **Resource limits.** The lexical static modules see at most the first 1 MiB of a file
   (`runner::MAX_ANALYZED_TEXT_BYTES`); Python files are parsed whole up to 1,000,000 characters; YARA is
   stopped after 5 s per file and 10 s per skill; scans run on a private rayon pool whose threads have a
   256 MiB stack so deeply nested input cannot overflow it. Upstream instead windows large files and
   enforces time budgets; see the README ("Safety limits").
4. **Deduplicate** (`dedupe.rs`). Port of `deduplicate.py` plus the occurrence expansion in
   `report.py`. See below.
5. **Sort** by `(file, line, id)`.

## Module map

| Rust | SkillSpector source | Rule ids |
|---|---|---|
| `modules/prompt_injection.rs`, `prompt_hidden.rs`, `support.rs` | `static_patterns_prompt_injection.py` | P1-P4, P9 |
| `whitespace_padding.rs` | `whitespace_padding.py` | P9 (letter and whitespace padding) |
| `modules/system_prompt_leakage.rs` | `static_patterns_system_prompt_leakage.py` | P6-P8 |
| `modules/data_exfiltration.rs` + `shell_tokens/` | `static_patterns_data_exfiltration.py` | E1-E5 |
| `modules/privilege_escalation.rs`, `pe_*.rs` | `static_patterns_privilege_escalation.py` | PE1-PE5 |
| `modules/supply_chain*.rs` | `static_patterns_supply_chain.py` | SC1-SC3, SC7 |
| `modules/concealed_executable.rs` | `static_patterns_supply_chain.py` | SC9 |
| `modules/tool_misuse/` + `shell_tokens/` | `static_patterns_tool_misuse.py`, `static_python_shell_truthiness.py` | TM1-TM4 |
| `modules/behavioral_ast.rs`, `pyast*` | `behavioral_ast.py`, `python_ast.py`, `common.py` | AST1-AST10 |
| `modules/taint/` | `behavioral_taint_tracking.py` | TT1-TT6 |
| `modules/memory_poisoning.rs`, `memory_guards.rs` | `static_patterns_memory_poisoning.py` | MP1-MP3 |
| `modules/ssrf.rs` | `static_patterns_ssrf.py` | SSRF1-SSRF3 |
| `modules/output_handling.rs`, `oh_js.rs` | `static_patterns_output_handling.py` | OH1-OH3 |
| `modules/agent_snooping.rs` | `static_patterns_agent_snooping.py` | AS1-AS3 |
| `modules/rogue_agent*.rs` | `static_patterns_rogue_agent.py` | RA1-RA2 |
| `modules/anti_refusal.rs` | `static_patterns_anti_refusal.py` | AR1-AR3 |
| `modules/excessive_agency.rs`, `model_selection.rs`, `prohibition.rs` | `static_patterns_excessive_agency.py`, `prohibition_context.py` | EA1-EA5 |
| `modules/rug_pull.rs` | `mcp_rug_pull.py` | RP1-RP3 |
| `modules/least_privilege.rs` | `mcp_least_privilege.py` | LP1-LP4 |
| `modules/coverage*.rs` | `finalize_inspection_ledger`, `references.py` | AE1 |
| `modules/artifact_integrity.rs`, `declared_marker*.rs` | `artifact_integrity.py`, `security_reconstruction.py` | AE4 |
| `modules/yara.rs` + `rules/*.yar` | `static_yara.py` | YR1-YR4 |
| `views/` | `artifacts.py` (`security_text_views`) | (all text modules) |
| `matcher.rs`, `text.rs`, `unicode*.rs` | `common.py`, Python `re`/`unicodedata` semantics | |

## Offsets: bytes versus characters

Python indexes strings by code point; Rust by UTF-8 byte. Inside the port, match positions are **byte**
offsets (cheap slicing). Anywhere Python's behavior depends on a character count (windows such as
`content[start:start + 256]`, `{0,8192}` limits, columns in findings, `[:200]` truncation) the Rust code
converts explicitly (`LineIndex::col_chars`, `fwd_chars`, `back`). Slicing happens only at offsets that
came from a regex match or a `char_indices` walk, so they are always char boundaries. Findings carry
1-based **lines**; columns are in characters and only matter for deduplication.

Line numbers follow `LOGICAL_LINE_BREAK` (`\r\n`, `\r`, `\n`, `\x0b`, `\x0c`, `\x1c-\x1e`, `\x85`,
U+2028, U+2029) for the static modules, but plain `\n` for rug pull, as in the original.

## Deduplication and the group key

SkillSpector reports one issue per *occurrence* of a deduplicated finding. `dedupe.rs` groups raw
findings by `(rule id, fingerprint, classification key)`. The fingerprint is the rule id plus the matched
text with whitespace collapsed; the classification key is message, severity, category, pattern,
explanation, remediation, intent, sorted tags and evidence. Inside a group, occurrences are unique on
`(file, start_line, end_line, start_column, end_column)`. Consequently two matches on the same line count
twice if and only if their columns (or end lines) differ, which is why the column resolver and the
view-dedupe key must match upstream exactly. Any module that varies message, tags or evidence per match
changes the group and therefore the count.

## Security text views

A file is not only scanned as written. `views/` builds the derived views of `security_text_views`:

* a **normalized** view (NFKC, confusable skeleton, default-ignorable and control characters removed),
* a **compact letter** view (undoing letter spacing like `i g n o r e`),
* an **obfuscated instruction** view (a literal port of `_match_obfuscated_security_word*`).

Files that are plain ASCII without controls, letter spacing or obfuscation use the raw view only. Each
view carries a map from its offsets back to the source text, so a finding in a derived view reports the
source line (`views/restore.rs`, tagged `normalized-view`). Lexical modules run per view; AST-based
modules run once on the raw text.

## Regex engines

SkillSpector uses Python's `re` (and the third-party `regex` for two patterns). `matcher::Pat` wraps the
`regex` crate when a pattern compiles there and `fancy-regex` (lookaround, backreferences, atomic groups)
otherwise. Python's `\s` also matches `\x1c-\x1f`, so patterns are rewritten accordingly. A pattern that
fails to compile or exceeds the backtracking limit yields no matches instead of an error or panic.

## Python AST

`pyast/` wraps `rustpython-parser` 0.4 to expose what `python_ast.py` exposes: parse success, import
alias map, calls with positions, `resolve_call_name`. CPython and rustpython disagree on some inputs, so
`pyast/scan.rs` and `pyast/syntax.rs` add cheap pre-checks for inputs CPython rejects, and the remaining
gaps (PEP 701 f-strings and a handful of others) are listed in `tests/pyast_diff.rs`. Parsing runs on a
thread with a large stack so deeply nested input cannot overflow it. Files over 1,000,000 characters are
not parsed, as upstream.

## Unicode tables

Python's `str` predicates (`isalpha`, `isspace`, `isprintable`, category, NFKC/casefold) follow
Unicode 15.1.0 in Python 3.13. Rather than depending on a crate whose Unicode version drifts, the
tables are generated by `tools/gen_unicode.py` (and `gen_views_tables.py`, `gen_isdigit.py`) into
`src/unicode_tables.rs`, `src/views/tables.rs` and `src/shell_tokens/digit_table.rs`, marked
`@generated` and excluded from rustfmt. The confusable skeleton is copied from SkillSpector's own table
(Unicode 17 data).

## Shell tokenization

E1 (exfiltration), SC2 (remote execution) and TM (tool misuse) share a bounded shell tokenizer
(`shell_tokens/`, port of `_bounded_shell_tokens` and the command-range helpers, with `py_shlex.rs`
emulating `shlex` in POSIX mode) so that "which command does this `curl` belong to" is answered the
same way as upstream, including Markdown fences, inline code, JSON string spans, `printf`
substitutions and PowerShell `-replace`.

## Not ported

* LLM analyzers (`semantic_security_discovery`, `semantic_developer_intent`, `semantic_quality_policy`,
  the LLM part of `mcp_tool_poisoning`) and the meta analyzer.
* Deterministic analyzers that had no finding in the reference corpus: `static_patterns_harmful_content`
  (P5), the deterministic checks of `mcp_tool_poisoning` (TP1-TP3), trigger analysis (TR1-TR3),
  `static_patterns_deserialization`, `structured_skill_roles`, `bundled_execution_surface`, OMS
  (Sigstore/DSSE) signature projection.
* OSV dependency lookups (SC4, needs network), transitive reference resolution, MCP registry mode,
  baselines/suppressions, time budgets, the inspection ledger and finding caps.
* Windowing of very large files (upstream splits text over 256,000 characters into windows).

See [../PARITY.md](../PARITY.md) for how this affects results.
