# Contributing

Thanks for helping. This project is a port: its job is to report what upstream
[SkillSpector](https://github.com/NVIDIA/SkillSpector) v2.12.0 reports with `--no-llm`, faster and offline.

## The parity-first rule

Any change to a rule, pattern, view or filter must keep `tests/parity.rs` green. If upstream and this
port disagree on a fixture, the port is wrong unless the difference is documented in
`tests/fixtures/KNOWN_DIFFERENCES.md` (and allowed in `tests/parity.rs`). Do not "improve" a rule beyond
upstream here; propose that upstream or open an issue to discuss a deliberate divergence first.

## Build and test

```bash
cargo build --release
cargo test --release            # unit, parity, robustness, doctests; the private-data tests skip
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --no-default-features -- -D warnings
cargo fmt --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

`tests/robustness.rs` scans hostile input (huge files, deep nesting, link loops, regex bait) and takes a
couple of minutes in release mode.

## Fixtures and goldens

`tests/fixtures/` holds upstream's own test fixtures (Apache-2.0, see its README) and small synthetic
skills under `synthetic/`. `tests/fixtures/golden.json` is what the reference tool reports for each of
them. To add a fixture, put a folder under `tests/fixtures/`, then regenerate the golden (needs the
Python `skillspector` of the pinned version, see [tools/README.md](tools/README.md)):

```bash
python3.13 tools/make_golden.py
cargo test --release --test parity
```

Never add real private skills as fixtures.

## Regenerating generated code

The Unicode tables are generated from Python 3.13 so they match upstream exactly:

```bash
export SKILLSPECTOR_SRC=/path/to/SkillSpector/src
python3.13 tools/gen_unicode.py > src/unicode_tables.rs
python3.13 tools/gen_views_tables.py > src/views/tables.rs
python3.13 tools/gen_isdigit.py > src/shell_tokens/digit_table.rs
```

## Differential tests on a private corpus

Some tests compare against the reference on a large private corpus and skip when it is absent. To run
them, build the data as described in [tools/README.md](tools/README.md) and set
`SKILLSPECTOR_RS_PRIVATE_DATA`. `skillspector-rs-diff golden.json` prints a rule-by-rule diff.

## Style

No `unwrap`/`expect` outside tests, no `unsafe` (the crate forbids it), small functions, `cargo fmt`
defaults. Mirror upstream names where a function ports a Python one and mention it in the doc comment.

## Commits and pull requests

Conventional commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`). Update
`CHANGELOG.md`. The pull request template has the checklist. By contributing you agree your work is
licensed under Apache-2.0.
