"""Parse and render plan_a.md / plan_b.md."""

from __future__ import annotations

import re

from cold_box_room.planning.models import PlanDocument, PlanStep

# Flexible heading: ## Step N — title  OR  ## Step N: title  OR  ## Step N title
_STEP_HEADING = re.compile(
    r"^##\s*Step\s+(\d+)\s*(?:[—\-:]\s*)?(.+?)\s*$",
    re.MULTILINE,
)
# Flexible reason: **Reason:** or Reason: or **reason:** (case-insensitive, optional bold markers)
_REASON = re.compile(
    r"^\*{0,2}Reason:?\*{0,2}\s*(.+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)
_TOOL = re.compile(r"^\*{0,2}Tool:?\*{0,2}\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_PURPOSE = re.compile(r"^\*{0,2}Purpose:?\*{0,2}\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)

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


_NEXT_STEP = re.compile(r"^##\s*Step\s+\d+", re.MULTILINE)


def _section_for_step(text: str, heading_start: int, heading_end: int) -> str:
    next_match = _NEXT_STEP.search(text, heading_end)
    end = next_match.start() if next_match else len(text)
    return text[heading_start:end]


def _unwrap_placeholder(value: str) -> str:
    """Strip surrounding parentheses from placeholder text like (what to extract)."""
    v = value.strip()
    if v.startswith("(") and v.endswith(")"):
        return v[1:-1].strip()
    return v


def parse_plan_md(text: str, *, case_id: str = "", room: str = "a") -> PlanDocument:
    headings = list(_STEP_HEADING.finditer(text))
    if not headings:
        raise ValueError("plan md must contain at least one ## Step N section")

    steps: list[PlanStep] = []
    for match in headings:
        raw_id = int(match.group(1))
        title = _unwrap_placeholder(match.group(2).strip())

        section = _section_for_step(text, match.start(), match.end())

        reason_m = _REASON.search(section)
        reason = _unwrap_placeholder(reason_m.group(1).strip()) if reason_m else ""

        tool_m = _TOOL.search(section)
        purpose_m = _PURPOSE.search(section)
        tool_raw = tool_m.group(1).strip() if tool_m else ""
        tool_id = tool_raw if tool_raw.upper().startswith("SIFT-") else ""

        steps.append(
            PlanStep(
                step_id=raw_id,
                title=title,
                reason=reason,
                tool_id=tool_id,
                purpose=_unwrap_placeholder(purpose_m.group(1).strip()) if purpose_m else "",
            )
        )

    # Sort and renumber sequentially — non-contiguous IDs from the agent get fixed, not rejected.
    steps.sort(key=lambda s: s.step_id)
    for i, step in enumerate(steps, start=1):
        step.step_id = i

    return PlanDocument(
        case_id=case_id,
        room=room.upper(),
        steps=steps,
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
