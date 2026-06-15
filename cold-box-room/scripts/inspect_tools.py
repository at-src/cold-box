#!/usr/bin/env python3
"""Inspect every SIFT tool — run fixture/version probes and refresh manifest status."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cold_box_room.tools.verify import REPORT_PATH, verify_all_tools  # noqa: E402


def main() -> int:
    print("Inspecting all catalog tools (fixtures + version probes)...")
    payload = verify_all_tools(include_unavailable=True)
    counts = payload["counts"]
    print(f"verified_at: {payload['verified_at']}")
    print(
        f"ok={counts.get('ok', 0)} "
        f"bad={counts.get('bad', 0)} "
        f"not_tested={counts.get('not_tested', 0)} "
        f"unavailable={counts.get('unavailable', 0)}"
    )
    print(f"report: {REPORT_PATH}")

    bad = [
        (v["tool_id"], v["name"], v["detail"])
        for v in payload["results"].values()
        if v.get("status") == "bad"
    ]
    if bad:
        print(f"\nBAD tools ({len(bad)}) — marked do-not-use in manifest:")
        for tool_id, name, detail in sorted(bad)[:50]:
            print(f"  {tool_id} {name}: {detail[:120]}")
        if len(bad) > 50:
            print(f"  ... and {len(bad) - 50} more")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
