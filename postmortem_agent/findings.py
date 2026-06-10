"""Generic findings from verifier output and agent hypothesis."""

from __future__ import annotations

from typing import Any

from postmortem_agent.state import InvestigationState
from postmortem_agent.synthesis import RULE_PROFILE
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


def _host_profile_finding(state: InvestigationState, idx: int) -> dict[str, Any] | None:
    """Build a context finding from the most recent successful reg_system_profile run."""
    runs = state.tool_results.get("reg_system_profile") or []
    for run in reversed(runs):
        if not run.get("ok"):
            continue
        data = run.get("data") or {}
        facts = data.get("facts") or []
        if not facts:
            continue
        claim = "Host profile — " + "; ".join(f"{f['label']}: {f['value']}" for f in facts)
        audit_id = run.get("audit_id")
        return {
            "id": f"f-{idx}",
            "claim": claim,
            "audit_ids": [audit_id] if audit_id else state.all_audit_ids()[:1],
            "confidence": 0.9,
            "status": "context",
            "tags": ["host_profile", "R23"],
            "title": "Host attribution / system profile",
            "severity": "info",
        }
    return None


def _content_context_findings(state: InvestigationState, idx: int) -> tuple[list[dict[str, Any]], int]:
    """Surface non-compromise context from legacy content parsers (recycle, IE, capture)."""
    extra: list[dict[str, Any]] = []
    tool_specs = (
        ("disk_recycle_bin", "Recycle Bin deleted executables", "R24", lambda d: (
            f"{d.get('executable_count', 0)} executable(s) in recycle metadata"
            + (f" ({', '.join((d.get('executables') or [])[:3])})" if d.get("executables") else "")
        )),
        ("disk_parse_ie_index_dat", "Legacy IE / webmail identity", "R25", lambda d: (
            "Emails: " + ", ".join((d.get("emails") or [])[:5]) if d.get("emails") else "index.dat parsed"
        )),
        ("disk_parse_ie_cache", "Legacy IE cache identity", "R25", lambda d: (
            "Emails: " + ", ".join((d.get("emails") or [])[:5]) if d.get("emails") else "cache parsed"
        )),
        ("disk_inspect_capture", "Traffic capture artifact on disk", "R26", lambda d: (
            f"Capture artifact: {d.get('filename', '?')} ({d.get('size_bytes', '?')} bytes)"
        )),
    )
    for tool, title, tag, claim_fn in tool_specs:
        runs = state.tool_results.get(tool) or []
        for run in reversed(runs):
            if not run.get("ok"):
                continue
            data = run.get("data") or {}
            claim = claim_fn(data)
            if not claim or claim.endswith("0 executable(s)"):
                continue
            audit_id = run.get("audit_id")
            extra.append(
                {
                    "id": f"f-{idx}",
                    "claim": claim,
                    "audit_ids": [audit_id] if audit_id else state.all_audit_ids()[:1],
                    "confidence": 0.85,
                    "status": "context",
                    "tags": [tag],
                    "title": title,
                    "severity": "info",
                }
            )
            idx += 1
            break
    return extra, idx


def build_findings(state: InvestigationState, *, partial: bool) -> list[dict[str, Any]]:
    audit_ids = state.all_audit_ids()
    findings: list[dict[str, Any]] = []
    idx = 1

    for result in state.verifier_results:
        if result.status != "contradiction":
            continue
        rule_audit = audit_ids_from_sources(result.sources)
        claim_audit = rule_audit or audit_ids
        profile = RULE_PROFILE.get(result.rule_id)
        finding: dict[str, Any] = {
            "id": f"f-{idx}",
            "claim": result.detail,
            "audit_ids": claim_audit,
            "confidence": 0.85,
            "status": "confirmed",
            "tags": [result.rule_id, result.rule_name],
        }
        if profile is not None:
            finding["title"] = profile.title
            finding["severity"] = profile.severity
            finding["mitre"] = list(profile.techniques)
            finding["tactic"] = profile.tactic
        findings.append(finding)
        idx += 1

    # Host attribution / system profile — surfaced as context (not a compromise
    # signal, so it never inflates the verdict or precision pool). Traces to the
    # reg_system_profile audit_id.
    profile_finding = _host_profile_finding(state, idx)
    if profile_finding is not None:
        findings.append(profile_finding)
        idx += 1

    content_findings, idx = _content_context_findings(state, idx)
    findings.extend(content_findings)

    # The grounded conclusion is carried by the narrative finding (appended later). Only emit a
    # standalone hypothesis finding when no rule-backed confirmed finding exists, so the report
    # always has a conclusion without duplicating it.
    has_confirmed = any(f["status"] == "confirmed" for f in findings)
    if state.hypothesis and state.hypothesis != "Investigation not started" and not has_confirmed:
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": state.hypothesis,
                "audit_ids": audit_ids,
                "confidence": state.confidence,
                "status": "confirmed" if state.confidence >= 0.5 else "inference",
                "tags": ["hypothesis"],
                "title": "Incident Assessment",
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
