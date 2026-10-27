#!/usr/bin/env python3
"""Regenerate tests/fixtures/golden.json with the reference SkillSpector (`--no-llm`).

Usage: python3 tools/make_golden.py [--fixtures tests/fixtures] [--out tests/fixtures/golden.json]
                                    [--bin skillspector] [--jobs 4]

Needs the `skillspector` CLI of the pinned release (v2.12.0, commit d7338f5) on PATH or in
$SKILLSPECTOR_BIN. Every fixture unit is copied ALONE into a temp dir under its real folder name
(SkillSpector drops findings that name the skill itself, so the name matters) and scanned with
`skillspector scan <copy> --no-llm --format json`. SC4 (OSV lookups, needs network) is dropped.

A unit is a directory that directly holds a SKILL.md, or a directory with files and no SKILL.md
anywhere beneath it (the upstream registry/signature fixtures).
"""
import argparse
import concurrent.futures as cf
import json
import os
import shutil
import subprocess
import sys
import tempfile

SKIP_ID = {"SC4"}


def units(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        rel = os.path.relpath(dirpath, root)
        if rel == ".":
            continue
        has_skill = "SKILL.md" in filenames
        below = any("SKILL.md" in fs for _, _, fs in os.walk(dirpath) if _ != dirpath)
        if has_skill or (filenames and not below):
            found.append(rel.replace(os.sep, "/"))
    return found


def scan(binary, root, rel):
    with tempfile.TemporaryDirectory() as tmp:
        copy = os.path.join(tmp, os.path.basename(rel))
        shutil.copytree(os.path.join(root, rel), copy)
        out = os.path.join(tmp, "out.json")
        # exit status 1 only means "findings present"; a missing report is the real failure
        run = subprocess.run([binary, "scan", copy, "--no-llm", "--format", "json", "-o", out],
                             capture_output=True, text=True)
        if not os.path.exists(out):
            raise RuntimeError(f"{rel}: no report (exit {run.returncode}): {run.stderr[-500:]}")
        with open(out, encoding="utf-8") as fh:
            issues = json.load(fh)["issues"]
    rows = [{"id": i["id"], "file": i["location"].get("file"), "start_line": i["location"].get("start_line"),
             "severity": i["severity"]} for i in issues if i["id"] not in SKIP_ID]
    rows.sort(key=lambda r: (r["file"] or "", r["start_line"] or 0, r["id"]))
    return rel, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="tests/fixtures")
    ap.add_argument("--out", default="tests/fixtures/golden.json")
    ap.add_argument("--bin", default=os.environ.get("SKILLSPECTOR_BIN", "skillspector"))
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()
    todo = units(args.fixtures)
    with cf.ThreadPoolExecutor(args.jobs) as ex:
        golden = dict(ex.map(lambda r: scan(args.bin, args.fixtures, r), todo))
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(dict(sorted(golden.items())), fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    total = sum(len(v) for v in golden.values())
    print(f"{len(golden)} fixtures, {total} findings -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
