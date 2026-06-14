"""Shared skill-harness flag — avoids import cycles with skills package."""

from __future__ import annotations

from contextvars import ContextVar

_HARNESS_ACTIVE: ContextVar[bool] = ContextVar("cold_box_room_skill_harness", default=False)


def skill_harness_active() -> bool:
    return _HARNESS_ACTIVE.get()


def set_skill_harness_active(active: bool):
    return _HARNESS_ACTIVE.set(active)


def reset_skill_harness_active(token) -> None:
    _HARNESS_ACTIVE.reset(token)
