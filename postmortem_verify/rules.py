"""Verifier rule implementations."""

from __future__ import annotations

from typing import Any

from postmortem_verify.models import RuleResult, VerifyContext


def _process_ref(proc: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "process",
        "pid": proc.get("pid"),
        "name": proc.get("name"),
        "offset": proc.get("offset"),
        "ppid": proc.get("ppid"),
    }


def _audit_ref(audit_id: str | None, tool: str, source: str | None) -> dict[str, Any] | None:
    if not audit_id:
        return None
    ref: dict[str, Any] = {"type": "audit", "audit_id": audit_id, "tool": tool}
    if source:
        ref["source"] = source
    return ref


def rule_r1_hidden_process(ctx: VerifyContext) -> RuleResult:
    """R1: PID/name in psscan absent from pslist, or same PID with mismatched name."""
    if not ctx.psscan_processes:
        return RuleResult(
            rule_id="R1",
            rule_name="hidden_process",
            status="skipped",
            detail="psscan process list missing",
            sources=[],
        )
    if not ctx.pslist_processes:
        return RuleResult(
            rule_id="R1",
            rule_name="hidden_process",
            status="skipped",
            detail="pslist process list missing",
            sources=[],
        )

    pslist_by_pid = {proc["pid"]: proc for proc in ctx.pslist_processes}
    pslist_pids = set(pslist_by_pid)

    hidden: list[dict[str, Any]] = []
    for proc in ctx.psscan_processes:
        pid = proc["pid"]
        if pid not in pslist_pids:
            hidden.append({"reason": "absent_from_pslist", "process": proc})
            continue

        listed = pslist_by_pid[pid]
        if listed.get("name") != proc.get("name"):
            hidden.append(
                {
                    "reason": "name_mismatch",
                    "process": proc,
                    "pslist_process": listed,
                }
            )

    sources: list[dict[str, Any]] = []
    audit_pslist = _audit_ref(ctx.pslist_audit_id, "mem_pslist", ctx.pslist_source)
    audit_psscan = _audit_ref(ctx.psscan_audit_id, "mem_psscan", ctx.psscan_source)
    if audit_pslist:
        sources.append(audit_pslist)
    if audit_psscan:
        sources.append(audit_psscan)

    for item in hidden:
        sources.append(_process_ref(item["process"]))
        if item["reason"] == "name_mismatch":
            sources.append(_process_ref(item["pslist_process"]))

    if hidden:
        absent = sum(1 for item in hidden if item["reason"] == "absent_from_pslist")
        mismatch = sum(1 for item in hidden if item["reason"] == "name_mismatch")
        return RuleResult(
            rule_id="R1",
            rule_name="hidden_process",
            status="contradiction",
            detail=(
                f"{len(hidden)} suspicious process(es): "
                f"{absent} absent from pslist, {mismatch} name mismatch"
            ),
            sources=sources,
        )

    return RuleResult(
        rule_id="R1",
        rule_name="hidden_process",
        status="pass",
        detail=f"All {len(ctx.psscan_processes)} psscan process(es) reconcile with pslist",
        sources=sources,
    )
