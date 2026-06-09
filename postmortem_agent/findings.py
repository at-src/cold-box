"""Generic findings from verifier output and agent hypothesis."""

from __future__ import annotations

from typing import Any

from postmortem_agent.state import InvestigationState
from postmortem_report.gate import validate_findings
from postmortem_verify.models import RuleResult


def audit_ids_from_sources(sources: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for source in sources:
        aid = source.get("audit_id")
        if aid and aid not in seen:
            seen.add(aid)
            ids.append(aid)
    return ids


def build_findings(state: InvestigationState, *, partial: bool) -> list[dict[str, Any]]:
    audit_ids = state.all_audit_ids()
    findings: list[dict[str, Any]] = []
    idx = 1

    for result in state.verifier_results:
        if result.status != "contradiction":
            continue
        rule_audit = audit_ids_from_sources(result.sources)
        claim_audit = rule_audit or audit_ids
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": result.detail,
                "audit_ids": claim_audit,
                "confidence": 0.85,
                "status": "confirmed",
                "tags": [result.rule_id, result.rule_name],
            }
        )
        idx += 1

    if state.hypothesis and state.hypothesis != "Investigation not started":
        if state.self_corrected or not any(f["status"] == "confirmed" for f in findings):
            findings.append(
                {
                    "id": f"f-{idx}",
                    "claim": state.hypothesis,
                    "audit_ids": audit_ids,
                    "confidence": state.confidence,
                    "status": "confirmed" if state.confidence >= 0.5 else "inference",
                    "tags": ["hypothesis"],
                }
            )
            idx += 1

    if not findings:
        passed = [r for r in state.verifier_results if r.status == "pass"]
        if passed:
            findings.append(
                {
                    "id": "f-1",
                    "claim": state.hypothesis or passed[0].detail,
                    "audit_ids": audit_ids,
                    "confidence": state.confidence,
                    "status": "confirmed",
                    "tags": [passed[0].rule_id],
                }
            )
        elif partial:
            findings.append(
                {
                    "id": "u-0",
                    "claim": "Investigation incomplete at iteration limit",
                    "audit_ids": audit_ids,
                    "confidence": state.confidence,
                    "status": "unresolved",
                }
            )

    for uidx, item in enumerate(state.unresolved, start=1):
        findings.append(
            {
                "id": f"u-{uidx}",
                "claim": item,
                "audit_ids": audit_ids,
                "confidence": state.confidence,
                "status": "unresolved",
            }
        )

    if not findings:
        raise ValueError("no findings to emit")

    return validate_findings(findings)
