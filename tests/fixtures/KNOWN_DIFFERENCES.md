# Known differences on the public fixtures

`tests/parity.rs` allows exactly these `(fixture, rule)` differences. They are features that are not
ported yet (see the roadmap in the README), not rule disagreements.

| Fixture | Rule | Reference | Port | Reason |
|---|---|---|---|---|
| `malicious_skill` | P5 (x2) | reports | missing | The harmful-content analyzer (`static_patterns_harmful_content`) is not ported. |
| `mcp_poisoned_tool` | TP1, TP2, TP3 | reports | missing | The deterministic tool-poisoning checks of `mcp_tool_poisoning` are not ported. |
| `ssd/ssd4_narrative_deception` | TR2 | reports | missing | Trigger-abuse analysis (TR1-TR3, manifest `description`/`triggers`) is not ported. |
| `oms` | SC3 (x4) | none | extra | SkillSpector decodes Sigstore/DSSE signature bundles (`oms.py`) before scanning; the port does not, so base64 blobs inside the bundle look like obfuscated code. |

Everything else in `golden.json` (86 of 93 reference findings, no other extras) is reproduced exactly.
