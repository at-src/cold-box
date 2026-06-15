#!/usr/bin/env python3
"""Probe runnable tools through run_sift_tool using the same plans as catalog verify."""

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
REPORT_PATH = ROOT / "tools" / "harness_inspection_report.json"
WORK = ROOT / "e2e-runs" / "harness-inspect"
FIXTURES = ROOT / "cold_box_room" / "tools" / "fixtures"


def _setup() -> tuple[str, str]:
    import subprocess

    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_tool_fixtures.py")], check=True)

    case_id = "harness-inspect"
    from cold_box_room.e2e.workspace import force_remove_tree

    if WORK.exists():
        force_remove_tree(WORK)
    os.environ["COLD_BOX_R1_STAGING"] = str(WORK / "r1-staging")
    os.environ["COLD_BOX_R2_SANDBOX"] = str(WORK / "r2-sandbox")
    os.environ["COLD_BOX_ROOM_RECORDS"] = str(WORK / "records")
    os.environ.setdefault("COLD_BOX_ROOM_STRICT", "0")
    os.environ.setdefault("COLD_BOX_R1_STAT_ONLY", "1")
    if not EVIDENCE.is_file():
        raise FileNotFoundError(f"Evidence missing: {EVIDENCE}")
    from cold_box_room.r1.intake import intake_case
    from cold_box_room.testing.hallway import bootstrap_case_to_room2

    intake_case(case_id, source=EVIDENCE)
    bootstrap_case_to_room2(case_id)
    sandbox = WORK / "r2-sandbox" / case_id
    for item in FIXTURES.iterdir():
        if item.is_file():
            shutil.copy2(item, sandbox / item.name)
    return case_id, EVIDENCE.name


def main() -> int:
    from cold_box_room.r2.executor import run_sift_tool
    from cold_box_room.tools.harness_probe import (
        evaluate_probe_result,
        plan_probe,
        version_probe_args,
    )
    from cold_box_room.tools.registry import list_tools
    from cold_box_room.tools.verify import _matches, _run_cmd
    from cold_box_room.tools.verify_profiles import plan_for

    case_id, image = _setup()
    tools = [t for t in list_tools() if t.verification.agent_runnable]
    print(f"Harness-probing {len(tools)} agent-runnable tools ...")

    rows: list[dict] = []
    counts = {"ok": 0, "fail": 0, "skipped": 0, "unavailable": 0, "blocked": 0}

    for tool in tools:
        status, detail, extra, plan, input_relpath = plan_probe(tool, image_relpath=image)
        if status in {"skipped", "unavailable"}:
            counts[status] += 1
            rows.append(
                {
                    "tool_id": tool.tool_id,
                    "name": tool.name,
                    "status": status,
                    "detail": detail,
                }
            )
            continue

        start = time.monotonic()
        result: dict = {"ok": False, "exit_code": 1, "error": detail}
        timeout = min(plan.timeout or 20, tool.timeout_seconds, 60)

        if plan.mode == "version":
            import shutil

            binary = shutil.which(tool.binary) or tool.binary
            combined = ""
            exit_code = 1
            reason = "version probe failed"
            result = {"ok": False, "exit_code": exit_code, "error": reason}
            for args in version_probe_args(tool.name):
                exit_code, out, err = _run_cmd([binary, *args], timeout=timeout, cwd=FIXTURES)
                combined = out + err
                ok_v, reason = _matches(plan, exit_code, combined)
                if ok_v:
                    result = {
                        "ok": True,
                        "exit_code": exit_code,
                        "stdout_preview": out[:500],
                        "stderr_preview": err[:500],
                    }
                    break
            else:
                result = {
                    "ok": False,
                    "exit_code": exit_code,
                    "error": reason,
                    "stderr_preview": combined[:500],
                }
        else:
            try:
                result = run_sift_tool(
                    tool_id=tool.tool_id,
                    case_id=case_id,
                    input_relpath=input_relpath,
                    purpose="harness inspection",
                    why=f"Bus inspector probe for {tool.name}",
                    extra_args=extra,
                    timeout=timeout,
                )
            except Exception as exc:
                result = {"ok": False, "error": str(exc), "exit_code": -1}

        elapsed = round((time.monotonic() - start) * 1000, 1)
        ok, reason = evaluate_probe_result(plan, result)
        if ok:
            outcome = "ok"
            counts["ok"] += 1
        elif "blocked" in str(result.get("error", "")).lower() or "denied" in str(result.get("error", "")).lower():
            outcome = "blocked"
            counts["blocked"] += 1
        else:
            outcome = "fail"
            counts["fail"] += 1
            print(
                f"  [FAIL] {tool.tool_id} {tool.name}: "
                f"{(result.get('error') or reason or '')[:80]}"
            )
        rows.append(
            {
                "tool_id": tool.tool_id,
                "name": tool.name,
                "status": outcome,
                "elapsed_ms": elapsed,
                "exit_code": result.get("exit_code"),
                "detail": reason if ok else (result.get("error") or reason or "")[:200],
            }
        )

    payload = {
        "schema": "cold_box_room.harness_inspection_v2",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "results": rows,
    }
    REPORT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(
        f"ok={counts['ok']} fail={counts['fail']} skipped={counts['skipped']} "
        f"unavailable={counts['unavailable']} blocked={counts['blocked']}"
    )
    print(f"report: {REPORT_PATH}")
    return 2 if counts["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
