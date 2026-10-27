# Parity with SkillSpector v2.12.0 (commit d7338f5), `--no-llm`

The goal of this port is that, for the rules it implements, it reports the same findings as the
Python tool. Findings are compared as a multiset of `(rule id, file, start line)` per skill folder.
SC4 (known-vulnerability lookups, needs network) is excluded everywhere.

## Public fixtures (reproducible, runs in CI)

`tests/fixtures/` holds the 15 fixture folders of upstream's test suite (Apache-2.0) plus 28 small
synthetic skills; 68 scannable folders in total (the upstream groups `ssd/`, `sdi/`, `sqp/` contain
several skills each). `tests/fixtures/golden.json` stores what the reference tool reports for each, and
`tests/parity.rs` compares it with the library on every run of `cargo test`; no Python is needed.

| | findings |
|---|---|
| reference (golden) | 93 |
| matched | 86 |
| missing (reference only) | 7 |
| extra (port only) | 4 |

Every difference is understood and listed in
[tests/fixtures/KNOWN_DIFFERENCES.md](tests/fixtures/KNOWN_DIFFERENCES.md); the test fails on any other:

* 7 missing: P5 (x2, harmful-content analyzer), TP1-TP3 (x4, deterministic tool-poisoning checks) and
  TR2 (x1, trigger analysis). These analyzers are not ported yet.
* 4 extra: SC3 on the `oms` fixture, a Sigstore/DSSE signature bundle that upstream decodes before
  scanning and this port does not.

Regenerate the golden with `python3.13 tools/make_golden.py` (see [tools/README.md](tools/README.md)).

## Private corpus (measured once, not reproducible from this repository)

During development the port was also checked against a private corpus of 865 real skill folders. The
figures below were measured once on that corpus and cannot be reproduced without it. The reference output was
produced per folder, alone, under the real folder name (SkillSpector skips findings that name the skill
itself), by `skillspector scan --no-llm`.

| | findings |
|---|---|
| SkillSpector (golden) | 2800 |
| this port | 2777 |
| matched | 2777 |
| extra (port only) | 0 |
| missing | 23 |

The 23 missing findings are deliberate or not reproducible:

* **SC4 (18):** osv.dev lookups, need the network; the port is offline.
* **AE1 (5):** `runtime_limit` coverage notes that SkillSpector emitted when its own time budget ran out
  on one very large skill; they depend on machine load.

The corpus happened not to contain skills that trigger the analyzers listed as not ported, so it says
little about them. Those differences only showed up with the public fixtures above.

With `SKILLSPECTOR_RS_PRIVATE_DATA` pointing at your own data, `skillspector-rs-diff golden.json`
reruns this kind of comparison (see [tools/README.md](tools/README.md)); it reports the same three
numbers plus the first differences per rule id.

## What is not ported

LLM analyzers and the meta analyzer, SC4, trigger analysis (TR1-TR3), P5, TP1-TP3, deserialization,
structured-role and bundled-execution-surface checks, OMS signature projection, transitive references,
MCP registry mode, baselines, time budgets, the inspection ledger (only its effect on `risk_assessment` is approximated: unresolved references, parser limits,
malformed manifests), finding caps and windowing of very
large files. See the roadmap in the README. A few security views with no finding on the corpus
(`prompt_injection_letter_spacing_view` and some continuity/declared-marker projections) are also
missing; heavily obfuscated skills may therefore differ.

## Deliberate deviations

* Safety limits (README, "Safety limits") bound time and memory on hostile input. They only change
  results for multi-megabyte pathological files.
* No environment-dependent behavior: results do not depend on environment variables.
