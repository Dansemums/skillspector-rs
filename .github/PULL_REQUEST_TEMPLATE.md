## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `cargo test --release` passes, including `tests/parity.rs` (any rule change keeps parity green)
- [ ] `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings` are clean
- [ ] New or changed behavior has a fixture under `tests/fixtures/` (and `golden.json` regenerated with
      `tools/make_golden.py`), or a unit test
- [ ] If a difference to upstream SkillSpector remains, it is listed in `tests/fixtures/KNOWN_DIFFERENCES.md`
- [ ] `CHANGELOG.md` updated under "Unreleased"
- [ ] No private skill content in fixtures or the description
