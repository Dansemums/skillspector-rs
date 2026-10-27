# Fixtures

* Everything outside `synthetic/` (`as3_self_reference`, `malicious_skill`, `mcp_*`, `oms`, `pe3_bare_keyring`,
  `safe_skill`, `sdi/`, `sqp/`, `ssd/`, `tp4_markdown_fenced_code`) is copied unchanged from the test
  fixtures of [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) (`tests/fixtures`, commit
  `d7338f58200a9ae2a24810cee08911ab68b107a7`), which is licensed under the Apache License 2.0,
  Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. See the repository `LICENSE` and `NOTICE`.
* `synthetic/` holds 28 tiny one-file skills written for this project (Apache-2.0) to exercise single
  rules.
* `golden.json` maps each fixture folder to the findings the reference SkillSpector (`--no-llm`)
  reports: `{id, file, start_line, severity}`, SC4 excluded. Regenerate with `tools/make_golden.py`.
* `KNOWN_DIFFERENCES.md` lists the rules where this port intentionally differs (not ported yet).

Some fixtures contain deliberately malicious-looking text (prompt injection, exfiltration). They are
inert data; nothing in this repository executes them.
