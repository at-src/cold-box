"""Verifier data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

RuleStatus = Literal["pass", "contradiction", "skipped"]


@dataclass
class RuleResult:
    rule_id: str
    rule_name: str
    status: RuleStatus
    detail: str
    sources: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerifyContext:
    """Inputs for deterministic verifier rules."""

    pslist_processes: list[dict[str, Any]] | None = None
    psscan_processes: list[dict[str, Any]] | None = None
    pslist_audit_id: str | None = None
    psscan_audit_id: str | None = None
    pslist_source: str | None = None
    psscan_source: str | None = None

    @classmethod
    def from_tool_payloads(
        cls,
        *,
        pslist_data: dict[str, Any] | None = None,
        psscan_data: dict[str, Any] | None = None,
        pslist_audit_id: str | None = None,
        psscan_audit_id: str | None = None,
    ) -> VerifyContext:
        return cls(
            pslist_processes=_extract_processes(pslist_data),
            psscan_processes=_extract_processes(psscan_data),
            pslist_audit_id=pslist_audit_id,
            psscan_audit_id=psscan_audit_id,
            pslist_source=(pslist_data or {}).get("source"),
            psscan_source=(psscan_data or {}).get("source"),
        )


def _extract_processes(payload: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    processes = payload.get("processes")
    if processes is None:
        processes = payload.get("rows")
    if processes is None:
        return None
    return list(processes)
