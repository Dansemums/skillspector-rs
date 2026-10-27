"""Records every input/output of SkillSpector's own taint tests into tests/data/taint_corpus.json.

Runs tests/nodes/analyzers/test_behavioral_taint_tracking.py in-process (conftest disabled) with
`node` and `_collect_tainted` wrapped. Only plain {components, file_cache} states are kept.
"""
import json, sys
import os
import _ssimport  # noqa: F401
SRC = os.environ['SKILLSPECTOR_SRC']  # <SkillSpector checkout>/src
CHECKOUT = os.path.dirname(SRC)
MAX_CASE_BYTES = 100_000  # bigger cases (finding-cap stress tests) bloat the repo; see tools/README.md
import pytest
from skillspector.nodes.analyzers import behavioral_taint_tracking as b

cases, seen = [], set()
orig_node, orig_collect = b.node, b._collect_tainted


def node(state):
    out = orig_node(state)
    capped = b.MAX_FINDINGS_PER_ARTIFACT != 10_000 or b.MAX_FINDINGS_PER_ANALYZER != 10_000  # caps are not ported
    if not capped and set(state) <= {"components", "file_cache"} and all(len(c) < 200_000 for c in state.get("file_cache", {}).values()):
        fs = [{
            "rule": f.rule_id, "message": f.message, "line": f.start_line, "end_line": f.end_line,
            "col": f.start_column, "end_col": f.end_column, "matched": f.matched_text,
            "fp": f.fingerprint(), "evidence": f.evidence, "tags": list(f.tags), "file": f.file,
        } for f in out["findings"]]
        key = json.dumps([state["components"], state["file_cache"]], sort_keys=True)
        if key not in seen:
            seen.add(key)
            cases.append({"kind": "node", "components": state["components"], "files": state["file_cache"], "findings": fs})
    return out


def collect(tree, type_map, aliases, check_runtime=None):
    res = orig_collect(tree, type_map, aliases, check_runtime)
    code = sys._getframe(1).f_back.f_locals.get("code") if False else None
    frame = sys._getframe(1)
    while frame is not None and "code" not in frame.f_locals:
        frame = frame.f_back
    if frame is not None and isinstance(frame.f_locals.get("code"), str):
        key = "collect:" + frame.f_locals["code"]
        if key not in seen and len(frame.f_locals["code"]) < 200_000:
            seen.add(key)
            cases.append({"kind": "collect", "code": frame.f_locals["code"],
                          "tainted": {k: [v.name, v.source_call, v.lineno] for k, v in res.items()}})
    return res


b.node, b._collect_tainted = node, collect
rc = pytest.main(["-q", "-p", "no:cacheprovider", "--noconftest", "-q",
                  os.path.join(CHECKOUT, "tests/nodes/analyzers/test_behavioral_taint_tracking.py"),
                  "--rootdir", CHECKOUT, "-c", "/dev/null"])
small = [c for c in cases if len(json.dumps(c)) <= MAX_CASE_BYTES]
large = [c for c in cases if len(json.dumps(c)) > MAX_CASE_BYTES]
json.dump(small, open("tests/data/taint_corpus.json", "w"))
json.dump(large, open(os.environ.get("SKILLSPECTOR_RS_PRIVATE_DATA", "private-data") + "/taint_corpus_large.json", "w"))
print("cases", len(cases), "rc", rc)
