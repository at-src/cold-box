"""Case situation briefings for Room A and Room 2 agents."""

from __future__ import annotations

import json
from typing import Any

from cold_box_room.planning.markdown import PLAN_A_SKELETON, PLAN_B_SKELETON
from cold_box_room.planning.scoring import PLAN_SCORE_MIN_PCT
from cold_box_room.r1.hallway import current_room
from cold_box_room.r1.paths import StagingError, hallway_state_path
from cold_box_room.r2.checkpoint import layer1_readonly_summary, r2_layer1_checkpoint
from cold_box_room.r2.sandbox import list_sandbox_files
from cold_box_room.room_a import get_plan_a_status, room_a_checkpoint
from cold_box_room.room_b import get_plan_b_status, room_b_checkpoint
from cold_box_room.room_3 import layer2_readonly_summary, room3_checkpoint


def _load_hallway(case_id: str) -> dict[str, Any] | None:
    path = hallway_state_path(case_id)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    return f"{size / (1024 * 1024 * 1024):.2f} GB"


def _sandbox_file_lines(case_id: str) -> list[str]:
    files = list_sandbox_files(case_id)
    if not files:
        return ["- (sandbox not materialized yet — you are before Room 2)"]
    return [
        f"- `{item['path']}` ({_format_bytes(int(item['size']))})"
        for item in files
    ]


def format_room_a_briefing(case_id: str) -> str:
    """Opening briefing for Room A — plan → formalize."""
    room = current_room(case_id)
    hallway = _load_hallway(case_id) or {}
    r1 = hallway.get("r1_checkpoint") or {}

    lines: list[str] = [
        f"## Case `{case_id}` — you are in Room {room}",
        "",
        "### Already completed — Room 1",
        "",
        "**Room 1 pass criteria:** evidence present and non-empty, then sealed read-only.",
        "",
    ]

    if r1.get("ok"):
        non_empty = r1.get("non_empty_files") or []
        file_list = ", ".join(f"`{name}`" for name in non_empty) or "(see staging record)"
        evidence_lines = [f"- `{name}`" for name in non_empty] or ["- (see staging record)"]
        lines.extend(
            [
                f"**Result: PASSED** — {file_list}",
                "",
                "**Sealed evidence (R1 table only — sandbox copies after Room A formalize):**",
                *evidence_lines,
            ]
        )
    else:
        lines.append("**Result:** R1 checkpoint not recorded (unexpected if you are in Room A).")

    lines.extend(
        [
            "",
            "**Sandbox is available.** Call `list_sandbox_files` to see the evidence, "
            "`list_sift_tools` to understand available extractions, then write your plan.",
            "",
            "### Your work — Room A (extraction planning)",
            "",
            "1. `list_sandbox_files` — see what evidence files are present.",
            "2. `list_sift_tools` — browse available SIFT tools to inform your plan.",
            "3. Write `plan_a.md` via `write_plan_a_md` — steps with title + reason only. No SIFT tool IDs.",
            "4. Call `formalize_plan_a` — validates md and produces `plan_a.py`.",
            "5. When `ready_for_room2` is true, Room A is complete.",
            "",
            "**Plan skeleton (minimum format):**",
            "```markdown",
            PLAN_A_SKELETON.format(case_id=case_id).strip(),
            "```",
            "",
        ]
    )

    if room != "A":
        lines.append(f"Warning: case is in Room {room}, not Room A.")
        return "\n".join(lines)

    try:
        status = room_a_checkpoint(case_id)
    except Exception as exc:
        lines.append(f"Room A checkpoint unavailable: {exc}")
        return "\n".join(lines)

    blocked = status.get("blocked_reasons") or []
    lines.extend(
        [
            "**Room A checkpoint status:**",
            f"- plan_formalized: {status.get('plan_formalized')}",
            f"- ready_for_room2: {status.get('ready_for_room2')}",
            f"- blocked: {blocked or 'none'}",
        ]
    )
    return "\n".join(lines)


def format_room_b_briefing(case_id: str) -> str:
    """Opening briefing for Room B — read Layer 1 → plan → formalize."""
    room = current_room(case_id)
    hallway = _load_hallway(case_id) or {}
    layer1 = hallway.get("layer1_checkpoint") or {}
    room_a = hallway.get("room_a_checkpoint") or {}

    lines: list[str] = [
        f"## Case `{case_id}` — you are in Room {room}",
        "",
        "### Already completed — Rooms 1, A, and 2",
        "",
        "**Room 1:** evidence sealed on the R1 table.",
        "**Room A:** extraction plan formalized to `plan_a.py`.",
        "**Room 2:** Layer 1 extractions + analyst log — read these before planning analysis.",
        "",
    ]

    if layer1.get("successful_extractions") is not None:
        lines.append(
            f"**Layer 1:** {layer1['successful_extractions']} successful extraction(s) on record."
        )
    if room_a.get("step_count"):
        lines.append(f"**Extraction plan:** {room_a['step_count']} step(s) in plan_a.py.")

    try:
        summary = layer1_readonly_summary(case_id)
        analyst = summary.get("analyst_log") or {}
        if analyst.get("complete"):
            lines.append(
                f"**Analyst log:** complete (self-score {summary.get('self_score')})."
            )
        else:
            lines.append("**Analyst log:** incomplete or missing — unexpected if you are in Room B.")
    except Exception as exc:
        lines.append(f"Layer 1 summary unavailable: {exc}")

    lines.extend(
        [
            "",
            "### Your work — Room B (analysis planning)",
            "",
            "1. `list_sandbox_files` — see what was extracted and is available.",
            "2. `read_layer1_tool_log` and `read_layer1_analyst_log` — understand what Layer 1 found.",
            "3. (Optional) `list_skills` / `describe_skill` to browse analysis playbooks.",
            "4. `write_plan_b_md` — numbered steps with title + reason only.",
            "5. `formalize_plan_b` — validates md and produces `plan_b.py`.",
            "6. `get_room_b_status` — confirm `ready_for_room3` is true.",
            "",
            "**Plan skeleton (minimum format):**",
            "```markdown",
            PLAN_B_SKELETON.format(case_id=case_id).strip(),
            "```",
            "",
        ]
    )

    if room != "B":
        lines.append(f"Warning: case is in Room {room}, not Room B.")
        return "\n".join(lines)

    try:
        status = room_b_checkpoint(case_id)
    except Exception as exc:
        lines.append(f"Room B checkpoint unavailable: {exc}")
        return "\n".join(lines)

    blocked = status.get("blocked_reasons") or []
    lines.extend(
        [
            "**Room B checkpoint status:**",
            f"- plan_formalized: {status.get('plan_formalized')}",
            f"- ready_for_room3: {status.get('ready_for_room3')}",
            f"- blocked: {blocked or 'none'}",
        ]
    )
    return "\n".join(lines)


def format_room3_briefing(case_id: str) -> str:
    """Opening briefing for Room 3 — Layer 1 context + plan_b execution."""
    room = current_room(case_id)
    hallway = _load_hallway(case_id) or {}
    layer1 = hallway.get("layer1_checkpoint") or {}
    room_b = hallway.get("room_b_checkpoint") or {}

    lines: list[str] = [
        f"## Case `{case_id}` — you are in Room {room}",
        "",
        "### Input context — Layer 1 (already done)",
        "",
        "Your analysis must build on Layer 1 extractions and the analyst write-up below.",
        "",
    ]

    try:
        summary = layer1_readonly_summary(case_id)
        analyst = summary.get("analyst_log") or {}
        if analyst.get("complete"):
            findings = analyst.get("findings", "")
            why = analyst.get("why", "")
            excerpt = findings[:2000] + ("…" if len(findings) > 2000 else "")
            lines.extend(
                [
                    f"**Layer 1 self-score:** {summary.get('self_score')}",
                    f"**Successful extractions:** {summary.get('successful_extractions')}",
                    "",
                    "**Layer 1 findings (excerpt):**",
                    excerpt,
                    "",
                    "**Layer 1 why (excerpt):**",
                    (why[:1200] + ("…" if len(why) > 1200 else "")),
                    "",
                ]
            )
        else:
            lines.append("**Layer 1 analyst log incomplete** — read `read_layer1_analyst_log` before analyzing.")
    except Exception as exc:
        lines.append(f"Layer 1 summary unavailable: {exc}")

    if room_b.get("step_count"):
        lines.append(f"**Analysis plan:** {room_b['step_count']} step(s) in plan_b.py.")

    lines.extend(
        [
            "",
            "### Your work — Room 3 (Layer 2 analysis)",
            "",
            "1. Read `read_layer1_tool_log` and `read_layer1_analyst_log` if you need full detail.",
            "2. Execute plan_b.py — `run_skill` per step, mark with `apply_plan_b_step_status`.",
            "3. Harness logs: `layer2_skill_log.md` (skills) + `layer2_tool_log.md` (nested SIFT) — read-only.",
            "4. `submit_layer2_writeup` → `layer2_analyst_log.md` with findings, corrections, self_score, why.",
            "5. Use `return_to_room` to fix mistakes (Room A, 2, or B only — Room 1 locked) — document in corrections.",
            "",
        ]
    )

    if room != "3":
        lines.append(f"Warning: case is in Room {room}, not Room 3.")
        return "\n".join(lines)

    try:
        status = room3_checkpoint(case_id)
        plan_status = get_plan_b_status(case_id)
    except Exception as exc:
        lines.append(f"Room 3 checkpoint unavailable: {exc}")
        return "\n".join(lines)

    blocked = status.get("blocked_reasons") or []
    plan_score = (status.get("plan_gate") or {}).get("plan_score_pct")
    lines.extend(
        [
            f"**plan_b.py steps:** {plan_status.get('step_count', 0)}",
            "",
            "**Room 3 checkpoint:**",
            f"- Successful skill runs: {status.get('successful_skill_runs')} (need ≥1)",
            f"- Plan resolved: {status.get('plan_resolved_gate')}",
            f"- Plan score: {plan_score if plan_score is not None else 'n/a'}% (need ≥ {PLAN_SCORE_MIN_PCT:g}%)",
            f"- ready_for_complete: {status.get('ready_for_complete')}",
            f"- Blocked: {blocked or 'none'}",
            f"- Prior revisits: {len(status.get('room_revisits') or [])}",
        ]
    )
    return "\n".join(lines)


def format_case_situation_briefing(case_id: str) -> str:
    """Per-case opening for Room 2 — R1/A done, sandbox inventory, Layer 1 gates."""
    room = current_room(case_id)
    if room == "A":
        return format_room_a_briefing(case_id)
    if room == "B":
        return format_room_b_briefing(case_id)
    if room == "3":
        return format_room3_briefing(case_id)

    hallway = _load_hallway(case_id) or {}
    r1 = hallway.get("r1_checkpoint") or {}
    sandbox_meta = hallway.get("r2_sandbox") or {}
    promoted_at = hallway.get("promoted_at") or ""
    room_a = hallway.get("room_a_checkpoint") or {}

    lines: list[str] = [
        f"## Case `{case_id}` — you are in Room {room}",
        "",
        "### Already completed — Rooms 1 and A",
        "",
        "**Room 1:** evidence sealed and verified on the R1 table.",
        "**Room A:** extraction plan written and formalized to `plan_a.py` — **then** sandbox materialized.",
        "",
        "**Your goal: pass Room 2 with solid extraction now, then Room B.** "
        "Mark every plan step, icat/content proof for passed steps, submit when gates pass. "
        "You may return to Room 2 later for gaps found in analysis — not to defer known work.",
        "",
    ]

    if r1.get("ok"):
        non_empty = r1.get("non_empty_files") or []
        file_list = ", ".join(f"`{name}`" for name in non_empty) or "(see sandbox)"
        lines.append(f"**R1:** {file_list} present and non-empty.")
    if room_a.get("step_count"):
        lines.append(f"**Room A plan:** {room_a['step_count']} step(s) in plan_a.py.")
    if promoted_at:
        lines.append(
            f"**Sandbox materialized (Room A → Room 2):** `{promoted_at}` — "
            "sealed R1 evidence copied into R2 workspace."
        )
    if sandbox_meta.get("file_count") is not None:
        lines.append(f"**Sandbox files:** {sandbox_meta['file_count']} copied from sealed R1.")

    lines.extend(
        [
            "",
            "**Evidence available (R2 sandbox copy — `input_relpath` relative to sandbox root):**",
            *_sandbox_file_lines(case_id),
            "",
            "### Your work — Room 2 (Layer 1 extraction)",
            "",
            "Execute plan_a.py: extract, mark each step with apply_plan_a_step_status, extend if needed.",
            "Harness appends every run to `layer1_tool_log.md`.",
            "When all steps resolved, plan score ≥ 70%, and findings are solid — submit_layer1_writeup.",
            "",
            "### Not done yet — Room B (analysis planning entrance)",
            "",
        ]
    )

    if room != "2":
        lines.append(f"Case is in Room {room}, not Room 2 — Layer 1 tools expect Room 2.")
        return "\n".join(lines)

    try:
        checkpoint = r2_layer1_checkpoint(case_id)
        plan_status = get_plan_a_status(case_id)
    except StagingError as exc:
        lines.append(f"Layer 1 checkpoint unavailable: {exc}")
        return "\n".join(lines)

    analyst = checkpoint.get("analyst_log") or {}
    blocked = checkpoint.get("blocked_reasons") or []
    plan_score = (checkpoint.get("plan_gate") or {}).get("plan_score_pct")
    lines.extend(
        [
            "**Room B pass criteria (all required — harness verifies on submit):**",
            "1. Every plan_a.py step resolved (passed/fail/not_relevant — no pending).",
            f"2. Plan score ≥ {PLAN_SCORE_MIN_PCT:g}% (passed / (passed + fail) among scoring steps).",
            "3. ≥1 successful extraction (run_sift_tool or analyze_scratch, exit 0, scratch logged).",
            "4. Complete analyst write-up via submit_layer1_writeup.",
            "5. Self-score integer 1–10, strictly > 8 (9 or 10).",
            "",
            f"**plan_a.py steps:** {plan_status.get('step_count', 0)} "
            f"(extend with extend_plan_a_step if needed)",
            "",
            "**Current Layer 1 checkpoint:**",
            f"- Plan resolved: {checkpoint.get('plan_resolved_gate')}",
            f"- Plan score: {plan_score if plan_score is not None else 'n/a'}% (need ≥ {PLAN_SCORE_MIN_PCT:g}%)",
            f"- Successful extractions: {checkpoint['successful_extractions']} (need ≥1)",
            f"- Analyst log: {'complete' if analyst.get('complete') else 'incomplete'}",
            f"- Self-score gate: {'passed' if checkpoint.get('score_gate') else 'not passed'}",
            f"- ready_for_room_b: {checkpoint['ready_for_room_b']}",
            f"- Blocked: {blocked or 'none'}",
        ]
    )
    return "\n".join(lines)
