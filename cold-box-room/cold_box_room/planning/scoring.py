"""Plan step scoring — used when executing plan in R2/R5."""

from __future__ import annotations

from typing import Any

from cold_box_room.planning.models import FINAL_STATUSES, STATUS_SCORE_DELTA, PlanDocument

PLAN_SCORE_MIN_PCT = 70.0


def compute_plan_score(doc: PlanDocument) -> dict[str, Any]:
    scoring_steps = [s for s in doc.steps if s.status != "not_relevant"]
    pool = len(scoring_steps)
    passed = sum(1 for s in scoring_steps if s.status == "passed")
    failed = sum(1 for s in scoring_steps if s.status == "fail")
    held = sum(1 for s in scoring_steps if s.status == "held_for_later")
    pending = sum(1 for s in scoring_steps if s.status == "pending")
    net = sum(STATUS_SCORE_DELTA.get(s.status, 0) for s in scoring_steps)
    pct = round((passed / pool) * 100, 2) if pool else 0.0
    return {
        "scoring_pool_size": pool,
        "passed_count": passed,
        "fail_count": failed,
        "held_for_later_count": held,
        "pending_count": pending,
        "net_score": net,
        "plan_score_pct": pct,
        "max_net_score": pool,
        "min_net_score": -pool,
    }


def all_steps_resolved(doc: PlanDocument) -> bool:
    return all(s.status in FINAL_STATUSES for s in doc.steps)
