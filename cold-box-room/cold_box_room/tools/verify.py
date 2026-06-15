"""Run catalog tools against tiny fixtures; update manifest verification."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cold_box_room.r2.security import sanitize_extra_args
from cold_box_room.tools.registry import clear_registry_cache, list_tools, manifest_path
from cold_box_room.tools.verify_profiles import VerifyPlan, plan_for, version_argv

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
REPORT_PATH = Path(__file__).resolve().parents[2] / "tools" / "verification_report.json"


@dataclass
class VerifyResult:
    tool_id: str
    name: str
    binary: str
    status: str  # ok | bad | skip | unavailable | not_tested
    mode: str
    fixture: str = ""
    exit_code: int | None = None
    detail: str = ""
    elapsed_ms: float = 0.0


def current_host_os() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "darwin"
    return sys.platform


def _binary_available(binary: str) -> bool:
    return bool(shutil.which(binary))


def _run_cmd(cmd: list[str], *, timeout: int, cwd: Path) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd),
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except OSError as exc:
        return -2, "", str(exc)


def _build_fixture_cmd(tool, plan: VerifyPlan, fixture_path: Path) -> list[str]:
    binary = shutil.which(tool.binary)
    if not binary:
        raise FileNotFoundError(tool.binary)
    extra = sanitize_extra_args(list(plan.extra_args), tool_name=tool.name)
    cmd = [binary]
    if plan.input_last:
        if tool.input.style == "flag" and tool.input.flag:
            cmd.extend([tool.input.flag, str(fixture_path)])
        else:
            cmd.extend(extra)
            cmd.append(str(fixture_path))
        return cmd
    if tool.input.style == "flag" and tool.input.flag:
        cmd.extend([tool.input.flag, str(fixture_path)])
    elif plan.mode == "fixture":
        cmd.append(str(fixture_path))
    cmd.extend(extra)
    return cmd


def _matches(plan: VerifyPlan, exit_code: int, combined: str) -> tuple[bool, str]:
    if exit_code not in plan.accept_exit:
        return False, f"exit_code={exit_code}"
    if plan.expect_all and not all(token in combined for token in plan.expect_all):
        return False, "missing expected output"
    if plan.expect_any:
        if plan.expect_any == ("",):
            return True, "ran"
        if not any(token.lower() in combined.lower() for token in plan.expect_any if token):
            return False, "output mismatch"
    return True, "ok"


def verify_one_tool(tool) -> VerifyResult:
    plan = plan_for(tool.binary, tool.category)
    base = {
        "tool_id": tool.tool_id,
        "name": tool.name,
        "binary": tool.binary,
    }
    if not _binary_available(tool.binary):
        return VerifyResult(
            **base,
            status="unavailable",
            mode=plan.mode,
            detail="binary not on PATH for this host",
        )
    if plan.mode == "skip":
        return VerifyResult(
            **base,
            status="not_tested",
            mode="skip",
            detail=plan.skip_reason,
        )

    start = time.monotonic()
    if plan.mode == "fixture":
        fixture_path = FIXTURES_DIR / plan.fixture
        if not fixture_path.is_file():
            return VerifyResult(
                **base,
                status="not_tested",
                mode="fixture",
                fixture=plan.fixture,
                detail=f"missing fixture {plan.fixture}",
            )
        try:
            cmd = _build_fixture_cmd(tool, plan, fixture_path)
        except (ValueError, PermissionError, FileNotFoundError) as exc:
            return VerifyResult(
                **base,
                status="bad",
                mode="fixture",
                detail=str(exc),
                elapsed_ms=(time.monotonic() - start) * 1000,
            )
        code, out, err = _run_cmd(cmd, timeout=plan.timeout, cwd=FIXTURES_DIR)
        combined = out + err
        ok, reason = _matches(plan, code, combined)
        return VerifyResult(
            **base,
            status="ok" if ok else "bad",
            mode="fixture",
            fixture=plan.fixture,
            exit_code=code,
            detail=reason if ok else f"{reason}; stderr={(err or out)[:160]}",
            elapsed_ms=(time.monotonic() - start) * 1000,
        )

    binary_path = shutil.which(tool.binary)
    if not binary_path:
        return VerifyResult(
            **base,
            status="unavailable",
            mode="version",
            detail="not on PATH",
        )
    last_detail = ""
    for args in version_argv(tool.binary):
        cmd = [binary_path, *args]
        try:
            sanitize_extra_args(args, tool_name=tool.name)
        except ValueError as exc:
            last_detail = str(exc)
            continue
        code, out, err = _run_cmd(cmd, timeout=plan.timeout, cwd=FIXTURES_DIR)
        combined = out + err
        ok, reason = _matches(plan, code, combined)
        if ok:
            return VerifyResult(
                **base,
                status="ok",
                mode="version",
                exit_code=code,
                detail=reason,
                elapsed_ms=(time.monotonic() - start) * 1000,
            )
        last_detail = f"exit={code} {(err or out)[:120]}"
    return VerifyResult(
        **base,
        status="bad",
        mode="version",
        detail=last_detail or "version probe failed",
        elapsed_ms=(time.monotonic() - start) * 1000,
    )


def _manifest_status(result: VerifyResult) -> tuple[str, bool]:
    if result.status == "ok":
        return "ok", True
    if result.status == "bad":
        return "bad", False
    if result.status == "unavailable":
        return "unavailable", False
    return "not_tested", True


def apply_results_to_manifest(results: dict[str, VerifyResult]) -> dict[str, Any]:
    mp = manifest_path()
    data = json.loads(mp.read_text(encoding="utf-8"))
    by_id = {r.tool_id: r for r in results.values()}
    updated = 0
    for tool in data.get("tools", []):
        res = by_id.get(tool.get("tool_id", ""))
        if res is None:
            continue
        status, runnable = _manifest_status(res)
        tool["verification"] = {
            "status": status,
            "detail": res.detail or status,
            "runnable": runnable,
        }
        updated += 1
    mp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    clear_registry_cache()
    return {"manifest": str(mp), "updated": updated}


def verify_all_tools(*, include_unavailable: bool = True) -> dict[str, Any]:
    clear_registry_cache()
    results: dict[str, VerifyResult] = {}
    counts: dict[str, int] = {}

    for tool in list_tools():
        if tool.category == "windows_host" and not include_unavailable:
            if not _binary_available(tool.binary):
                res = VerifyResult(
                    tool_id=tool.tool_id,
                    name=tool.name,
                    binary=tool.binary,
                    status="unavailable",
                    mode="skip",
                    detail="windows host only — not installed",
                )
            else:
                res = verify_one_tool(tool)
        else:
            res = verify_one_tool(tool)
        results[tool.tool_id] = res
        counts[res.status] = counts.get(res.status, 0) + 1

    payload = {
        "schema": "cold_box_room.verification_v1",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "host_os": current_host_os(),
        "counts": counts,
        "results": {k: asdict(v) for k, v in sorted(results.items())},
    }
    REPORT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    apply_results_to_manifest(results)
    return payload
