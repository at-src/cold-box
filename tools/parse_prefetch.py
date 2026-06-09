#!/usr/bin/env python3
"""Parse Windows prefetch (.pf) files and emit structured JSON for MCP tools.

Uses the system libscca sccainfo binary on Linux.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def _parse_sccainfo(text: str, source: str) -> dict:
    lines = [ln.rstrip() for ln in text.splitlines()]
    result: dict = {"source": source, "filenames": []}

    for ln in lines:
        if ln.startswith("\tFormat version"):
            result["format_version"] = int(ln.split(":")[-1].strip())
        elif ln.startswith("\tPrefetch hash"):
            result["prefetch_hash"] = ln.split(":")[-1].strip()
        elif ln.startswith("\tExecutable filename"):
            result["executable"] = ln.split(":")[-1].strip()
        elif ln.startswith("\tRun count"):
            result["run_count"] = int(ln.split(":")[-1].strip())
        elif ln.startswith("\tLast run time"):
            result["last_run_time"] = re.sub(r"^:\s*", "", ln.split(":", 1)[-1].strip())
        elif "\tFilename:" in ln or ln.lstrip().startswith("Filename:"):
            m = re.search(r"Filename:\s*(\d+)\s*:\s*(.+)", ln)
            if m:
                result["filenames"].append(m.group(2).strip())

    if "executable" not in result:
        raise ValueError("sccainfo output missing executable filename")
    return result


def parse_file(path: Path) -> dict:
    proc = subprocess.run(
        ["sccainfo", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"sccainfo failed on {path}")
    return _parse_sccainfo(proc.stdout, str(path))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="Prefetch .pf file(s)")
    args = parser.parse_args()

    results = []
    for raw in args.paths:
        path = Path(raw)
        if not path.is_file():
            print(f"error: not a file: {path}", file=sys.stderr)
            return 1
        try:
            results.append(parse_file(path))
        except Exception as exc:
            print(f"error parsing {path}: {exc}", file=sys.stderr)
            return 1

    payload = results[0] if len(results) == 1 else results
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
