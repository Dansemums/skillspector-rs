#!/usr/bin/env python3
"""Build a private golden file for `skillspector-rs-diff` from a list of skill folders.

Usage: python3 tools/make_corpus_golden.py DIRS.txt OUT.json [--jobs 4] [--bin skillspector]

DIRS.txt has one skill folder per line. Output: {folder: [SkillSpector `issues`...]}, the shape
`skillspector-rs-diff` expects. Each folder is copied alone under its real name (SkillSpector drops
findings naming the skill itself) and scanned with `--no-llm`.
"""
import argparse
import concurrent.futures as cf
import json
import os
import shutil
import subprocess
import tempfile


def scan(binary, folder):
    with tempfile.TemporaryDirectory() as tmp:
        copy = os.path.join(tmp, os.path.basename(folder.rstrip("/")))
        shutil.copytree(folder, copy, symlinks=False, ignore_dangling_symlinks=True,
                        ignore=shutil.ignore_patterns("node_modules", ".git", "__pycache__", "target", ".venv", "venv"))
        out = os.path.join(tmp, "out.json")
        subprocess.run([binary, "scan", copy, "--no-llm", "--format", "json", "-o", out], capture_output=True)
        with open(out, encoding="utf-8") as fh:
            return folder, json.load(fh)["issues"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs")
    ap.add_argument("out")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--bin", default=os.environ.get("SKILLSPECTOR_BIN", "skillspector"))
    args = ap.parse_args()
    folders = [line.strip() for line in open(args.dirs, encoding="utf-8") if line.strip()]
    with cf.ThreadPoolExecutor(args.jobs) as ex:
        golden = dict(ex.map(lambda f: scan(args.bin, f), folders))
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(golden, fh)


if __name__ == "__main__":
    main()
