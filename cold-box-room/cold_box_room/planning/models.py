"""Shared plan datatypes for Room A and Room B planning rooms.

This is not business logic — only the shapes the harness reads and writes:

- ``PlanStep`` — one extraction/analysis step (checkbox in plan_*.py)
- ``PlanDocument`` — md + py pair for a case (steps + attestation gate)
- ``STEP_STATUSES`` — same four outcomes as design.md Room 3/R4

Room A uses ``plan_a.md`` / ``plan_a.py`` (PLAN_A).
Room B will use ``plan_b.md`` / ``plan_b.py`` (PLAN_B) with the same code paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

STEP_STATUSES = frozenset(
    {"pending", "passed", "fail", "not_relevant", "held_for_later"}
)
FINAL_STATUSES = frozenset({"passed", "fail", "not_relevant"})

STATUS_SCORE_DELTA = {
    "passed": 1,
    "fail": -1,
    "not_relevant": 0,
    "held_for_later": 0,
    "pending": 0,
}


@dataclass
class PlanStep:
    """One planned step — becomes a checkbox row in plan_*.py."""

    step_id: int
    title: str
    reason: str
    tool_id: str = ""
    purpose: str = ""
    status: str = "pending"
    proof: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id,
            "title": self.title,
            "reason": self.reason,
            "tool_id": self.tool_id,
            "purpose": self.purpose,
            "status": self.status,
            "proof": dict(self.proof),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PlanStep:
        return cls(
            step_id=int(data["id"]),
            title=str(data.get("title") or "").strip(),
            reason=str(data.get("reason") or "").strip(),
            tool_id=str(data.get("tool_id") or "").strip(),
            purpose=str(data.get("purpose") or "").strip(),
            status=str(data.get("status") or "pending").strip(),
            proof=dict(data.get("proof") or {}),
        )


@dataclass
class PlanAttestation:
    """Bouncer gate — stamped into plan_*.py when agent answers YES at the door."""

    tools_catalog_reviewed: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"tools_catalog_reviewed": self.tools_catalog_reviewed}

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> PlanAttestation:
        data = data or {}
        return cls(tools_catalog_reviewed=str(data.get("tools_catalog_reviewed") or "").strip())

    def tools_gate_open(self) -> bool:
        return self.tools_catalog_reviewed.strip().lower() == "yes"


@dataclass
class PlanDocument:
    case_id: str
    room: str
    steps: list[PlanStep]
    attestation: PlanAttestation = field(default_factory=PlanAttestation)

    def to_plan_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "room": self.room.upper(),
            "version": 1,
            "attestation": self.attestation.to_dict(),
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_plan_dict(cls, data: dict[str, Any], *, room: str = "") -> PlanDocument:
        steps = [PlanStep.from_dict(row) for row in data.get("steps") or []]
        return cls(
            case_id=str(data.get("case_id") or ""),
            room=str(data.get("room") or room or "").upper(),
            steps=steps,
            attestation=PlanAttestation.from_dict(data.get("attestation")),
        )
