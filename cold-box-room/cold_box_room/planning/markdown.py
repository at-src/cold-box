"""Parse and render plan_a.md / plan_b.md."""

from __future__ import annotations

import re

from cold_box_room.planning.models import PlanAttestation, PlanDocument, PlanStep

_STEP_HEADING = re.compile(
    r"^##\s+Step\s+(\d+)\s+[—\-]\s*(.+?)\s*$",
    re.MULTILINE,
)
_REASON = re.compile(r"^\*\*Reason:\*\*\s*(.+?)\s*$", re.MULTILINE)
_TOOL = re.compile(r"^\*\*Tool:\*\*\s*(.+?)\s*$", re.MULTILINE)
_PURPOSE = re.compile(r"^\*\*Purpose:\*\*\s*(.+?)\s*$", re.MULTILINE)
_TOOLS_REVIEWED = re.compile(
    r"^\*\*Tools catalog reviewed:\*\*\s*(.+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)

PLAN_A_SKELETON = """# Extraction plan — `{case_id}`

Room A — planning only. Browse the tool catalog first, then list what to extract below.
When the plan is complete, call `write_plan_a_md`, then `formalize_plan_a` (md → py).
Tool choice is Room 2 — do not list SIFT tool ids here.

## Step 1 — (what to extract)

**Reason:** (why this artifact class matters for this case)
"""

PLAN_B_SKELETON = """# Analysis plan — `{case_id}`

Room B — planning only. Read Layer 1 tool log and analyst log first, then list how you will analyze below.
When the plan is complete, call `write_plan_b_md`, then `formalize_plan_b` (md → py).
Skill/tool choice is Room 3 — do not lock specific skill script ids here.

## Step 1 — (analysis objective)

**Reason:** (why this analysis step is needed given what Layer 1 extracted)
"""


def _section_for_step(text: str, step_id: int) -> str:
    pattern = re.compile(rf"^##\s+Step\s+{step_id}\s+[—\-].*$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return ""
    start = match.start()
    next_step = re.search(r"^##\s+Step\s+\d+\s+[—\-]", text[match.end() :], re.MULTILINE)
    end = match.end() + next_step.start() if next_step else len(text)
    return text[start:end]


def parse_plan_md(text: str, *, case_id: str = "", room: str = "a") -> PlanDocument:
    attestation = PlanAttestation()
    att_m = _TOOLS_REVIEWED.search(text)
    if att_m:
        attestation.tools_catalog_reviewed = att_m.group(1).strip()

    headings = list(_STEP_HEADING.finditer(text))
    if not headings:
        raise ValueError("plan md must contain numbered ## Step N — Title sections")

    steps: list[PlanStep] = []
    for match in headings:
        step_id = int(match.group(1))
        title = match.group(2).strip()
        section = _section_for_step(text, step_id)

        reason_m = _REASON.search(section)
        if not reason_m:
            raise ValueError(f"Step {step_id} missing **Reason:** line")
        reason = reason_m.group(1).strip()
        if not reason or reason.startswith("("):
            raise ValueError(f"Step {step_id} reason is not filled in")

        tool_m = _TOOL.search(section)
        purpose_m = _PURPOSE.search(section)
        tool_raw = tool_m.group(1).strip() if tool_m else ""
        if tool_raw.startswith("SIFT-") is False and tool_raw.startswith("("):
            tool_raw = ""
        tool_id = tool_raw.split("(", 1)[0].strip() if tool_raw else ""
        if tool_id.startswith("("):
            tool_id = ""

        steps.append(
            PlanStep(
                step_id=step_id,
                title=title if not title.startswith("(") else "",
                reason=reason,
                tool_id=tool_id,
                purpose=purpose_m.group(1).strip() if purpose_m else "",
            )
        )

    steps.sort(key=lambda s: s.step_id)
    ids = [s.step_id for s in steps]
    if ids != list(range(1, len(steps) + 1)):
        raise ValueError(f"Step ids must be contiguous 1..N, got {ids}")
    for step in steps:
        if not step.title:
            raise ValueError(f"Step {step.step_id} title is not filled in")

    return PlanDocument(
        case_id=case_id,
        room=room.upper(),
        steps=steps,
        attestation=attestation,
    )


def render_plan_md(doc: PlanDocument, *, heading: str) -> str:
    lines = [
        f"# {heading} — `{doc.case_id}`",
        "",
        f"Room {doc.room} — planning only. Steps below become checkbox rows in plan_{doc.room.lower()}.py.",
        "",
    ]
    for step in doc.steps:
        lines.extend(
            [
                f"## Step {step.step_id} — {step.title}",
                "",
                f"**Reason:** {step.reason}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"
