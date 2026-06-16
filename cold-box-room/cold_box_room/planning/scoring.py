"""Plan step scoring — used when executing plan in R2/R5."""

from __future__ import annotations

from typing import Any

from cold_box_room.planning.models import FINAL_STATUSES, PlanDocument

PLAN_SCORE_MIN_PCT = 70.0


def compute_plan_score(doc: PlanDocument) -> dict[str, Any]:
    passed = sum(1 for s in doc.steps if s.status == "passed")
    failed = sum(1 for s in doc.steps if s.status == "fail")
    held = sum(1 for s in doc.steps if s.status == "held_for_later")
    pending = sum(1 for s in doc.steps if s.status == "pending")
    not_relevant = sum(1 for s in doc.steps if s.status == "not_relevant")
    # Pool = only passed + fail. not_relevant is dropped. held/pending block submit but don't dilute score.
    pool = passed + failed
    pct = round((passed / pool) * 100, 2) if pool else 0.0
    return {
        "scoring_pool_size": pool,
        "passed_count": passed,
        "fail_count": failed,
        "not_relevant_count": not_relevant,
        "held_for_later_count": held,
        "pending_count": pending,
        "plan_score_pct": pct,
    }


def all_steps_resolved(doc: PlanDocument) -> bool:
    return all(s.status in FINAL_STATUSES for s in doc.steps)
