# Maintainer tools

Python helpers that regenerate checked-in data from the reference implementation. None of them is
needed to build, test or use the crate.

Requirements: Python 3.13 (the generated Unicode tables follow its `unicodedata`, Unicode 15.1.0) and a
checkout of [SkillSpector](https://github.com/NVIDIA/SkillSpector) at the commit pinned in
[NOTICE](../NOTICE) (`d7338f58200a9ae2a24810cee08911ab68b107a7`, v2.12.0).

```bash
export SKILLSPECTOR_SRC=/path/to/SkillSpector/src      # used by the scripts that import skillspector
export SKILLSPECTOR_RS_PRIVATE_DATA=$PWD/private-data           # where large local-only data lives (gitignored)
```

`_ssimport.py` is shared: when `SKILLSPECTOR_SRC` is set it puts the checkout on `sys.path` and stubs the
LLM framework imports of the package `__init__`, so no `pip install` is needed.

## Public data (checked in)

| Script | Regenerates | Notes |
|---|---|---|
| `make_golden.py` | `tests/fixtures/golden.json` | Needs the `skillspector` CLI of the pinned release on `PATH` (or `$SKILLSPECTOR_BIN`). Each fixture unit is copied alone to a temp dir under its real folder name and scanned with `skillspector scan <copy> --no-llm --format json`; direct scans of the copy give the same issues as `--recursive` for folders with a `SKILL.md`, and also work for the two upstream fixtures that are not valid skills (`mcp_registry`, `oms`). SC4 (OSV lookups) is dropped. About 3 minutes for 68 fixtures (Python start-up dominates). |
| `gen_unicode.py` | `src/unicode_tables.rs` | `python3.13 tools/gen_unicode.py > src/unicode_tables.rs` (confusables come from `$SKILLSPECTOR_SRC`). |
| `gen_views_tables.py` | `src/views/tables.rs` | `python3.13 tools/gen_views_tables.py > src/views/tables.rs` |
| `gen_isdigit.py` | `src/shell_tokens/digit_table.rs` | `python3.13 tools/gen_isdigit.py > src/shell_tokens/digit_table.rs` |
| `shell_tokens_probe.py` | `tests/data/shell_tokens_golden.json` (and the private corpus) | `--skip-corpus` writes only the small adversarial file. |
| `taint_record.py` | `tests/data/taint_corpus.json` | Replays SkillSpector's own taint unit tests (needs `pytest`). Cases over 100 kB (finding-cap stress tests) go to `$SKILLSPECTOR_RS_PRIVATE_DATA/taint_corpus_large.json` instead, which the unit test also replays when present. |

## Private data (optional, never checked in)

Some differential tests compare the port with the reference on a large corpus of real skill folders.
Point `SKILLSPECTOR_RS_PRIVATE_DATA` at a directory with the files below; each test **skips with a message**
when its file is absent.

| File in `$SKILLSPECTOR_RS_PRIVATE_DATA` | Used by | Produced by |
|---|---|---|
| `golden.json` | the other probes, `skillspector-rs-diff` | `make_corpus_golden.py DIRS.txt golden.json` (a map `folder -> SkillSpector issues`) |
| `shell_tokens_corpus.json` | `tests/shell_tokens.rs` (`corpus_matches_python`) | `shell_tokens_probe.py` |
| `views_golden.json` | `tests/views.rs` | `views_probe.py` |
| `pyast_probe.json` | `tests/pyast_diff.rs` | `pyast_probe.py pyast_probe.json golden.json [extra dirs]`; `pyast_adv_gen.py OUT_DIR` writes an adversarial Python corpus to pass as an extra dir |
| `taint_corpus_large.json` | `modules::taint` unit test | `taint_record.py` |

Run the full differential suite with `SKILLSPECTOR_RS_PRIVATE_DATA=... cargo test --release`.
