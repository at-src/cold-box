"""MITRE-tagged incident narrative from audited findings."""

from __future__ import annotations

import json
from typing import Any

from postmortem_agent.llm import LLMError, anthropic_api_key
from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_verify.models import RuleResult

RULE_MITRE: dict[str, tuple[str, ...]] = {
    "R1": ("T1055",),
    "R2": ("T1070",),
    "R3": ("T1078",),
    "R4": ("T1070.006",),
    "R5": ("T1070",),
    "R6": ("T1071",),
    "R7": ("T1055", "T1027"),
    "R8": ("T1071.004",),
    "R9": ("T1071.001",),
    "R10": ("T1053", "T1098"),
    "R11": ("T1543.003",),
    "R12": ("T1200",),
    "R13": ("T1053.005",),
    "R14": ("T1505.003",),
    "R15": ("T1078",),
    "R16": ("T1059",),
    "R18": ("T1059.003",),
    "R19": ("T1190", "T1505.003"),
    "R20": ("T1078",),
}


def mitre_for_rules(rule_ids: list[str]) -> list[str]:
    seen: list[str] = []
    for rule_id in rule_ids:
        for technique in RULE_MITRE.get(rule_id, ()):
            if technique not in seen:
                seen.append(technique)
    return seen


def _confirmed_findings(state: InvestigationState) -> list[dict[str, Any]]:
    return [f for f in state.findings if f.get("status") in {"confirmed", "inference"}]


def build_template_narrative(state: InvestigationState) -> dict[str, Any]:
    """Deterministic senior-analyst summary when LLM is unavailable."""
    confirmed = _confirmed_findings(state)
    rule_ids = [
        r.rule_id for r in state.verifier_results if r.status == "contradiction"
    ]
    for finding in confirmed:
        for tag in finding.get("tags") or []:
            if str(tag).upper().startswith("R") and str(tag).upper() not in rule_ids:
                rule_ids.append(str(tag).upper())
    mitre = mitre_for_rules(rule_ids)
    audit_ids = state.all_audit_ids()

    bullets: list[str] = []
    for finding in confirmed[:8]:
        claim = str(finding.get("claim", "")).strip()
        aids = finding.get("audit_ids") or []
        ref = aids[0] if aids else "audit"
        bullets.append(f"- {claim} (audit: {ref})")

    if state.self_corrected:
        bullets.append(
            "- Agent self-corrected after verifier contradictions before finalizing the incident story."
        )

    techniques = ", ".join(mitre) if mitre else "techniques pending"
    body = (
        f"Host compromise assessment based on {len(audit_ids)} audited tool execution(s).\n\n"
        f"Key findings:\n"
        + "\n".join(bullets)
        + f"\n\nMITRE ATT&CK mapping: {techniques}.\n"
        f"Final hypothesis: {state.hypothesis}"
    )

    return {
        "text": body,
        "mitre": mitre,
        "audit_ids": audit_ids[:20],
        "source": "template",
    }


def build_llm_narrative(state: InvestigationState, config: AgentConfig) -> dict[str, Any]:
    """LLM-authored incident narrative citing audit IDs."""
    import urllib.error
    import urllib.request

    confirmed = _confirmed_findings(state)
    context = {
        "hypothesis": state.hypothesis,
        "self_corrected": state.self_corrected,
        "lessons": state.lessons,
        "findings": confirmed,
        "verifier_contradictions": [
            {"rule": r.rule_id, "detail": r.detail}
            for r in state.verifier_results
            if r.status == "contradiction"
        ],
        "audit_ids": state.all_audit_ids(),
        "kinds_present": state.survey.get("kinds_present"),
    }
    system = (
        "You are a senior DFIR analyst writing the final incident narrative. "
        "Use only the provided findings and audit_ids — do not invent evidence. "
        "Return JSON: {\"summary\": \"...\", \"mitre\": [\"Txxxx\", ...], "
        "\"timeline\": \"...\", \"recommended_actions\": [\"...\"]}"
    )
    body = {
        "model": config.llm_model or "claude-sonnet-4-20250514",
        "max_tokens": 1200,
        "system": system,
        "messages": [{"role": "user", "content": json.dumps(context)}],
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "x-api-key": anthropic_api_key(),
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise LLMError(f"Anthropic API error {exc.code}: {detail}") from exc

    text_blocks = [
        block.get("text", "")
        for block in payload.get("content", [])
        if block.get("type") == "text"
    ]
    raw = "".join(text_blocks).strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1]
        if raw.endswith("```"):
            raw = raw.rsplit("```", 1)[0]
    parsed = json.loads(raw)
    summary = str(parsed.get("summary", "")).strip()
    mitre = [str(m) for m in parsed.get("mitre") or []]
    timeline = str(parsed.get("timeline", "")).strip()
    actions = parsed.get("recommended_actions") or []
    text = summary
    if timeline:
        text += f"\n\nTimeline: {timeline}"
    if actions:
        text += "\n\nRecommended actions:\n" + "\n".join(f"- {a}" for a in actions[:5])

    return {
        "text": text,
        "mitre": mitre or mitre_for_rules(
            [r.rule_id for r in state.verifier_results if r.status == "contradiction"]
        ),
        "audit_ids": state.all_audit_ids()[:20],
        "source": "llm",
    }


def build_narrative(state: InvestigationState, config: AgentConfig) -> dict[str, Any]:
    if config.mode == "llm":
        try:
            return build_llm_narrative(state, config)
        except LLMError:
            pass
    return build_template_narrative(state)


def append_narrative_finding(
    state: InvestigationState,
    config: AgentConfig,
) -> dict[str, Any] | None:
    """Add a narrative finding and return the narrative payload."""
    if not state.findings:
        return None

    narrative = build_narrative(state, config)
    audit_ids = narrative.get("audit_ids") or state.all_audit_ids()
    if not audit_ids:
        return None

    idx = len(state.findings) + 1
    mitre = narrative.get("mitre") or []
    tags = ["narrative", "incident_summary", *mitre]

    state.findings.append(
        {
            "id": f"n-{idx}",
            "claim": narrative["text"],
            "audit_ids": audit_ids[:20],
            "confidence": min(0.9, state.confidence + 0.1),
            "status": "confirmed" if state.confidence >= 0.5 else "inference",
            "tags": tags,
        }
    )
    return narrative
