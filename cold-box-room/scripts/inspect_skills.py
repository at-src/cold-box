#!/usr/bin/env python3
"""Inspect every skill script — run against Terry USB in an isolated verify workspace."""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

EVIDENCE = Path("/evidence/unseen-terry-usb/terry-work-usb-2009-12-11.E01")
REPORT_PATH = ROOT / "tools" / "skill_inspection_report.json"
VERIFY_ROOT = ROOT / "e2e-runs" / "skill-inspect-workspace"


def _prepare_workspace() -> tuple[str, str]:
    case_id = "skill-inspect"
    from cold_box_room.e2e.workspace import force_remove_tree

    if VERIFY_ROOT.exists():
        force_remove_tree(VERIFY_ROOT)
    os.environ["COLD_BOX_R1_STAGING"] = str(VERIFY_ROOT / "r1-staging")
    os.environ["COLD_BOX_R2_SANDBOX"] = str(VERIFY_ROOT / "r2-sandbox")
    os.environ["COLD_BOX_ROOM_RECORDS"] = str(VERIFY_ROOT / "records")
    os.environ.setdefault("COLD_BOX_ROOM_STRICT", "0")
    os.environ.setdefault("COLD_BOX_R1_STAT_ONLY", "1")
    if not EVIDENCE.is_file():
        raise FileNotFoundError(f"Evidence missing: {EVIDENCE}")
    from cold_box_room.r1.intake import intake_case
    from cold_box_room.testing.hallway import bootstrap_case_to_room3

    intake_case(case_id, source=EVIDENCE)
    bootstrap_case_to_room3(case_id)
    return case_id, EVIDENCE.name


def main() -> int:
    from cold_box_room.skills.registry import list_skills
    from cold_box_room.skills.skill_runner import run_skill_script

    case_id, relpath = _prepare_workspace()
    skills = list_skills(runnable_only=True)
    print(f"Inspecting {len(skills)} skills on {relpath} ...")

    rows: list[dict] = []
    counts = {"success": 0, "failed": 0, "not_runnable": 0}

    for skill in skills:
        start = time.monotonic()
        try:
            result = run_skill_script(
                case_id=case_id,
                skill_ref=skill.skill_id,
                input_relpath=relpath,
                journal_id=skill.journal_id,
            )
        except Exception as exc:
            result = {"ok": False, "error": str(exc)}
        elapsed = round((time.monotonic() - start) * 1000, 1)

        if result.get("ok"):
            outcome = "success"
        elif result.get("reference_only"):
            outcome = "not_runnable"
        else:
            err = str(result.get("error") or "")
            if "reference-only" in err or "no harness script" in err:
                outcome = "not_runnable"
            else:
                outcome = "failed"
        counts[outcome] = counts.get(outcome, 0) + 1
        rows.append(
            {
                "skill_id": skill.skill_id,
                "journal_id": skill.journal_id,
                "library_slug": skill.library_slug,
                "outcome": outcome,
                "elapsed_ms": elapsed,
                "audit_count": result.get("audit_count", 0),
                "error": (result.get("error") or "")[:300],
                "traceback": (result.get("traceback") or "")[:400],
            }
        )
        mark = {"success": "OK", "failed": "FAIL", "not_runnable": "SKIP"}[outcome]
        print(f"  [{mark}] {skill.skill_id} {elapsed:7.0f}ms  {result.get('error','')[:60]}")

    payload = {
        "schema": "cold_box_room.skill_inspection_v1",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "evidence": str(EVIDENCE),
        "counts": counts,
        "results": rows,
    }
    REPORT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(
        f"\nDone: success={counts['success']} failed={counts['failed']} "
        f"not_runnable={counts['not_runnable']}"
    )
    print(f"report: {REPORT_PATH}")
    return 2 if counts["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
