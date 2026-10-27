"""Dump what SkillSpector's Python AST layer sees, for the Rust differential test.

Run with Python 3.13 and SKILLSPECTOR_SRC set (see tools/README.md):
  python3.13 tools/pyast_probe.py OUT.json [GOLDEN.json] [EXTRA_DIR ...]
OUT.json is read by tests/pyast_diff.rs as $SKILLSPECTOR_RS_PRIVATE_DATA/pyast_probe.json.

For every Python (or shebang-python) file under every skill folder (keys of GOLDEN.json, default
$SKILLSPECTOR_RS_PRIVATE_DATA/golden.json, plus EXTRA_DIRs) it records: whether `ast.parse` succeeds, the import
alias map, and every `ast.Call` as
  [lineno, col_offset, end_lineno, end_col_offset, character_column(start), character_column(end),
   resolve_call_name(call, aliases)]
sorted by that tuple (name last). Columns are UTF-8 byte offsets except the two character columns,
which are SkillSpector's own `ParsedPythonFile.character_column`.
"""

import ast
import json
import os
import sys

import _ssimport  # noqa: F401
from skillspector.nodes.analyzers.common import resolve_call_name
from skillspector.python_ast import (
    MAX_PYTHON_AST_SOURCE_CHARS,
    PythonSourceClassification,
    classify_python_source,
    decode_python_source,
    parse_python_source,
)

SKIP_DIRS = {"node_modules", ".git", "__pycache__", "target", ".venv", "venv", "site-packages", ".tox", ".pytest_cache"}


def files_of(root):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=True):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.isfile(full):
                yield os.path.relpath(full, root).replace(os.sep, "/"), full


def probe_file(rel, raw):
    if classify_python_source(rel, raw) is PythonSourceClassification.NON_PYTHON:
        return None
    try:
        text = decode_python_source(raw)
    except Exception:
        return None  # SkillSpector drops undecodable Python files from its cache
    if len(text) > MAX_PYTHON_AST_SOURCE_CHARS:
        return {"skipped": "too_large"}
    try:
        parsed = parse_python_source(text, rel)
    except MemoryError:  # "Parser stack overflowed": SkillSpector itself would crash on this file
        return {"parse_ok": False, "aliases": {}, "calls": [], "crash": "MemoryError"}
    out = {"parse_ok": parsed.tree is not None, "aliases": dict(sorted(parsed.import_aliases.items())), "calls": []}
    if parsed.tree is None:
        return out
    calls = []
    for node in ast.walk(parsed.tree):
        if isinstance(node, ast.Call):
            cc = parsed.character_column(node.lineno, node.col_offset)
            ecc = parsed.character_column(node.end_lineno, node.end_col_offset)
            name = resolve_call_name(node, parsed.import_aliases)
            calls.append([node.lineno, node.col_offset, node.end_lineno, node.end_col_offset, cc, ecc, name])
    calls.sort(key=lambda c: (c[:6], c[6] or ""))
    out["calls"] = calls
    return out


def main():
    out_path = sys.argv[1]
    rest = sys.argv[2:]
    golden = rest[0] if rest and (rest[0].endswith(".json") or rest[0] == "-") else _ssimport.private_data("golden.json")
    extra = [a for a in rest if not a.endswith(".json")]
    dirs = ([] if golden == "-" else list(json.load(open(golden)))) + extra
    result = {}
    for d in dirs:
        if not os.path.isdir(d):
            continue
        per = {}
        for rel, full in sorted(files_of(d)):
            try:
                raw = open(full, "rb").read()
            except OSError:
                continue
            r = probe_file(rel, raw)
            if r is not None:
                per[rel] = r
        result[d] = per
    json.dump(result, open(out_path, "w"), ensure_ascii=False)
    n = sum(len(v) for v in result.values())
    c = sum(len(f.get("calls", [])) for v in result.values() for f in v.values())
    print(f"dirs={len(result)} files={n} calls={c}")


main()
