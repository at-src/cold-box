"""Meta MCP tool — run the full cold-box agent loop from Claude Code."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from postmortem_mcp.audit_tool import run_audited_tool


def investigation_run(
    case_id: str,
    evidence_case: str,
    *,
    mode: str = "hybrid",
    max_iterations: int = 25,
    memory_relpath: str | None = None,
    from_cache: str | None = None,
    extracted_root: str | None = None,
    iteration: int = 0,
) -> dict:
    """Run the full cold-box investigation (survey→tools→verifier→findings→report).

    Use after triage or as the one-shot demo command from Claude Code.
    mode: hybrid (recommended), policy (deterministic), or llm.
    Outputs land under CASE_OUTPUT/<case_id>/ (findings.json, report.md, audit.jsonl).
    """
    mode = (mode or "hybrid").strip().lower()
    if mode not in {"hybrid", "policy", "llm"}:
        raise ValueError("mode must be hybrid, policy, or llm")

    args: dict[str, Any] = {
        "case_id": case_id,
        "evidence_case": evidence_case,
        "mode": mode,
        "max_iterations": max_iterations,
    }
    if memory_relpath:
        args["memory_relpath"] = memory_relpath
    if from_cache:
        args["from_cache"] = from_cache
    if extracted_root:
        args["extracted_root"] = extracted_root

    def execute() -> dict[str, Any]:
        cmd = [
            sys.executable,
            "-m",
            "postmortem_agent.cli",
            "run",
            "--case-id",
            case_id,
            "--evidence-case",
            evidence_case,
            "--max-iterations",
            str(max_iterations),
        ]
        if mode == "hybrid":
            cmd.append("--hybrid")
        elif mode == "llm":
            cmd.append("--llm")
        if memory_relpath:
            cmd.extend(["--memory", memory_relpath])
        if from_cache:
            cmd.extend(["--from-cache", from_cache])
        if extracted_root:
            cmd.extend(["--extracted-root", extracted_root])

        env = dict(os.environ)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        summary: dict[str, Any] = {}
        if proc.stdout.strip():
            try:
                summary = json.loads(proc.stdout)
            except json.JSONDecodeError:
                summary = {"raw_stdout": proc.stdout[-2000:]}

        out_dir = Path(env.get("CASE_OUTPUT", "/cases")) / case_id
        payload: dict[str, Any] = {
            "exit_code": proc.returncode,
            "mode": mode,
            "output_dir": str(out_dir),
            "summary": summary,
        }
        for name in ("findings.json", "report.md", "progress.jsonl", "audit.jsonl"):
            path = out_dir / name
            payload[f"has_{name.replace('.', '_')}"] = path.is_file()
        if (out_dir / "findings.json").is_file():
            findings = json.loads((out_dir / "findings.json").read_text(encoding="utf-8"))
            payload["finding_count"] = len(findings.get("findings") or [])
        if proc.returncode != 0:
            payload["stderr"] = (proc.stderr or proc.stdout or "agent run failed")[-1500:]
        return payload

    return run_audited_tool(
        case_id=case_id,
        tool="investigation_run",
        args=args,
        iteration=iteration,
        execute=execute,
    )
