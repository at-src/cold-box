"""Incident narrative — thin adapter over the grounded synthesis layer.

Kept as a stable entry point for the loop (`append_narrative_finding`) and tests
(`build_template_narrative`). All real synthesis lives in `synthesis.py`.
"""

from __future__ import annotations

from typing import Any

from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_agent.synthesis import (
    build_incident_report,
    build_template_report,
    mitre_for_rules,
    render_report_markdown,
)


def _confirmed_findings(state: InvestigationState) -> list[dict[str, Any]]:
    return [f for f in state.findings if f.get("status") in {"confirmed", "inference"}]


def build_template_narrative(state: InvestigationState) -> dict[str, Any]:
    """Deterministic senior-analyst summary when LLM is unavailable."""
    report = build_template_report(state)
    text = render_report_markdown(report)
    if "MITRE" not in text:
        techniques = ", ".join(report.get("mitre") or []) or "techniques pending"
        text += f"\n\n## MITRE ATT&CK Techniques\n\n{techniques}"
    return {
        "text": text,
        "mitre": report.get("mitre") or mitre_for_rules(
            [r.rule_id for r in state.verifier_results if r.status == "contradiction"]
        ),
        "audit_ids": (report.get("audit_ids") or state.all_audit_ids())[:20],
        "source": "template",
        "report": report,
    }


def build_narrative(state: InvestigationState, config: AgentConfig) -> dict[str, Any]:
    report = build_incident_report(state, config)
    text = render_report_markdown(report)
    if "MITRE" not in text and report.get("mitre"):
        text += "\n\n## MITRE ATT&CK Techniques\n\n" + ", ".join(report["mitre"])
    return {
        "text": text,
        "mitre": report.get("mitre") or [],
        "audit_ids": (report.get("audit_ids") or state.all_audit_ids())[:20],
        "source": report.get("source", "template"),
        "report": report,
    }


def append_narrative_finding(
    state: InvestigationState,
    config: AgentConfig,
) -> dict[str, Any] | None:
    """Add a narrative finding (concise grounded conclusion) and return the full report payload."""
    if not state.findings:
        return None

    narrative = build_narrative(state, config)
    report = narrative.get("report") or {}
    audit_ids = narrative.get("audit_ids") or state.all_audit_ids()
    if not audit_ids:
        return None

    idx = len(state.findings) + 1
    mitre = narrative.get("mitre") or []
    tags = ["narrative", "incident_summary", *mitre]
    claim = str(report.get("primary_hypothesis") or report.get("summary") or state.hypothesis).strip()
    if any(f.get("claim", "").strip() == claim for f in state.findings):
        return narrative

    restraint = "no confirmed indicators" in claim.lower()
    has_platform = any(
        tag in {"R32", "R33"} for f in state.findings for tag in (f.get("tags") or [])
    )
    if restraint and has_platform:
        platform_claims = [
            str(f.get("claim", ""))
            for f in state.findings
            if f.get("status") == "confirmed" and any(t in {"R32", "R33"} for t in (f.get("tags") or []))
        ]
        if platform_claims:
            claim = platform_claims[0]
            restraint = False
    status = "inference" if restraint else ("confirmed" if state.confidence >= 0.5 else "inference")

    state.findings.append(
        {
            "id": f"n-{idx}",
            "claim": claim,
            "audit_ids": audit_ids[:20],
            "confidence": min(0.9, max(report.get("confidence", state.confidence), state.confidence)),
            "status": status,
            "tags": tags,
            "title": "Incident Assessment",
        }
    )
    return narrative
