"""cold-box-room hallway — Claude Code agent track.

Runs the full hallway (R1 → A → 2 → B → 3) with the `claude` CLI as the
agent.  All investigation happens through the cold-box-room MCP server;
no raw Anthropic API calls are made from this script.

Usage:
    cold-box-room-hallway-cc --case-id terry-demo --evidence /evidence/terry.E01
    cold-box-room-hallway-cc --case-id terry-demo --reuse-kitchen
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Project root — where .mcp.json and CLAUDE.md live.
REPO_ROOT = Path(__file__).resolve().parents[2]

_HALLWAY_PROMPT = """\
You are a forensic analyst. Run the full cold-box-room hallway for case: {case_id}

Complete every room in order using ONLY the cold-box-room MCP tools. \
Never run shell commands on evidence.

== ROOM A (extraction planning) ==
1. get_hallway_status(case_id="{case_id}") — confirm you are in Room A.
2. list_sandbox_files — see what evidence files are present in the sandbox.
3. list_sift_tools — browse the catalog so your plan is grounded in what's possible.
4. write_plan_a_md — draft a holistic extraction plan. \
Each step: "## Step N — title" + "**Reason:**" line. No SIFT tool IDs in the plan.
5. formalize_plan_a — validates the md and writes plan_a.py. \
If it rejects, fix the md and retry.
6. get_room_a_status — confirm ready_for_room2 is true before moving on.

== ROOM 2 (evidence extraction) ==
6. For each plan_a.py step:
   a. Pick a SIFT tool with run_sift_tool(tool_id="SIFT-###", ...). \
Record the audit_id returned — every finding must cite it.
   b. Call analyze_scratch on the output when more context helps.
   c. Call apply_plan_a_step_status with the audit_id and scratch path.
      Status must be one of: passed / fail / not_relevant / held_for_later.
7. Extend the plan with extend_plan_a_step if you discover gaps.
8. When ALL steps are resolved (no pending/held_for_later) and plan score ≥ 70%:
   call submit_layer1_writeup with findings, why, and self_score (integer 9 or 10).
   If the submit is rejected, call get_layer1_status / get_plan_a_status, fix the gaps, retry.

== ROOM B (analysis planning) ==
9. list_sandbox_files — confirm what is available from Layer 1 extractions.
10. read_layer1_tool_log — review what was actually extracted.
11. read_layer1_analyst_log — read your own Layer 1 write-up.
12. write_plan_b_md — analysis plan grounded in extracted artifacts. \
Same format as plan_a: numbered steps, title + Reason. No skill IDs in the plan.
13. formalize_plan_b — validates md and writes plan_b.py. Fix and retry if rejected.
14. get_room_b_status — confirm ready_for_room3 is true.

== ROOM 3 (analysis + final report) ==
15. For each plan_b.py step:
    a. run_skill(skill_id="SKILL-###", ...). \
Record the run_id returned.
    b. apply_plan_b_step_status with the run_id.
       Status: passed / fail / not_relevant / held_for_later.
16. If you discover a gap — missing extraction, wrong plan step — call \
return_to_room (Room A, 2, or B only; Room 1 is locked forever), fix it, \
return_to_room back to 3. Document every fix in the corrections field on submit.
17. When ALL plan_b steps are resolved and plan score ≥ 70%:
    call submit_layer2_writeup with findings, why, self_score (9 or 10), \
and corrections ("none" if no revisits).

Self-correction rules:
- If any gate rejects your submit, read the blocked_reasons, fix each one, resubmit.
- Max 3 resubmit attempts per room. After 3 failures call get_hallway_status, \
diagnose, and continue.
- cite every finding back to an audit_id (Room 2) or run_id (Room 3).

Begin now with get_hallway_status.
"""


def _find_claude() -> str:
    for candidate in [
        REPO_ROOT.parent / ".venv" / "bin" / "claude",
        Path.home() / ".local" / "bin" / "claude",
        Path("/usr/local/bin/claude"),
    ]:
        if candidate.exists():
            return str(candidate)
    return "claude"


def _run_intake(*, case_id: str, evidence: Path) -> None:
    from cold_box_room.r1.seal import strict_mode_enabled

    venv_bin = REPO_ROOT.parent / ".venv" / "bin"
    cbr = str(venv_bin / "cold-box-room") if (venv_bin / "cold-box-room").exists() else "cold-box-room"
    use_link = not strict_mode_enabled()
    mode = "link" if use_link else "copy"
    print(f"[cbr-cc] intake ({mode})  case={case_id}  evidence={evidence}", flush=True)
    intake_cmd = [cbr, "intake", "--case-id", case_id, "--source", str(evidence)]
    if use_link:
        intake_cmd.append("--link")
    subprocess.run(intake_cmd, check=True)
    print(f"[cbr-cc] r1-check --promote  case={case_id}", flush=True)
    subprocess.run(
        [cbr, "r1-check", "--case-id", case_id, "--promote"],
        check=True,
    )


def run_hallway_cc(
    *,
    case_id: str,
    evidence: Path | None = None,
    model: str | None = None,
    reuse_kitchen: bool = False,
    display: bool = False,
    display_port: int = 8765,
    ui_host: str = "127.0.0.1",
    no_open: bool = False,
    keep_sandbox: bool = False,
) -> int:
    if display:
        from cold_box_room.ui import start_ui_server

        start_ui_server(
            host=ui_host,
            port=display_port,
            open_browser=not no_open,
            case_id=case_id,
        )
        url = f"http://{ui_host}:{display_port}/?case={case_id}"
        print(f"[cbr-cc] dashboard  {url}", flush=True)
        if ui_host == "127.0.0.1":
            print(f"[cbr-cc] SSH tunnel: ssh -L {display_port}:localhost:{display_port} user@<vm-ip>", flush=True)
    if not reuse_kitchen:
        if evidence is None:
            print("[cbr-cc] --evidence is required unless --reuse-kitchen", file=sys.stderr)
            return 1
        _run_intake(case_id=case_id, evidence=evidence)

    prompt = _HALLWAY_PROMPT.format(case_id=case_id)
    claude_bin = _find_claude()

    cmd = [
        claude_bin,
        "--print",
        "--dangerously-skip-permissions",  # MCP server is the architectural guardrail
    ]
    if model:
        cmd += ["--model", model]
    cmd.append(prompt)

    env = {**os.environ}
    env.setdefault("COLD_BOX_R1_STAGING", str(REPO_ROOT / "r1-staging"))
    env.setdefault("COLD_BOX_R2_SANDBOX", str(REPO_ROOT / "r2-sandbox"))
    env.setdefault("COLD_BOX_ROOM_RECORDS", str(REPO_ROOT / "records"))
    if model:
        env["ANTHROPIC_MODEL"] = model

    print(f"[cbr-cc] launching Claude Code agent — case={case_id}", flush=True)
    result = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env)

    if not keep_sandbox:
        try:
            from cold_box_room.r2.paths import case_sandbox_dir
            sandbox = case_sandbox_dir(case_id)
            if sandbox.is_dir():
                shutil.rmtree(sandbox)
                print(f"[cbr-cc] cleanup  removed sandbox {sandbox}", flush=True)
        except Exception as exc:
            print(f"[cbr-cc] cleanup error: {exc}", flush=True)

    return result.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="cold-box-room hallway — Claude Code agent track",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cold-box-room-hallway-cc --case-id terry-demo --evidence /evidence/terry.E01
  cold-box-room-hallway-cc --case-id terry-demo --reuse-kitchen
  cold-box-room-hallway-cc --case-id terry-demo --evidence /evidence/terry.E01 --model claude-opus-4-8
""",
    )
    parser.add_argument("--case-id", required=True, help="Unique case identifier")
    parser.add_argument(
        "--evidence",
        default="",
        help="Path to evidence file (required unless --reuse-kitchen)",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Claude model override (default: inherits ANTHROPIC_MODEL or claude-sonnet-4-6)",
    )
    parser.add_argument(
        "--reuse-kitchen",
        action="store_true",
        help="Skip intake; resume agent on existing case workspace",
    )
    parser.add_argument(
        "--ui", "--display",
        dest="display",
        action="store_true",
        help="Open the live Cold Box dashboard",
    )
    parser.add_argument("--ui-port", "--display-port", dest="display_port", type=int, default=8765)
    parser.add_argument(
        "--ui-host",
        default="127.0.0.1",
        help="Host for the UI server (use 0.0.0.0 to expose on all interfaces for remote access)",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open a browser automatically (useful on headless servers)",
    )
    parser.add_argument(
        "--keep-sandbox",
        action="store_true",
        help="Keep the R2 sandbox copy after run (default: delete to reclaim disk space)",
    )
    args = parser.parse_args(argv)
    return run_hallway_cc(
        case_id=args.case_id,
        evidence=Path(args.evidence) if args.evidence else None,
        model=args.model or None,
        reuse_kitchen=args.reuse_kitchen,
        display=args.display,
        display_port=args.display_port,
        ui_host=args.ui_host,
        no_open=args.no_open,
        keep_sandbox=args.keep_sandbox,
    )


if __name__ == "__main__":
    raise SystemExit(main())
