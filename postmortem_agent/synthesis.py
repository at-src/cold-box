"""Grounded incident synthesis — turn verifier signals into a senior-analyst report.

The verifier is the anti-hallucination layer: a rule only fires on real, audited
tool output. This module is the *analysis* layer on top of it. It does NOT invent
evidence — it organizes the confirmed signals into an ATT&CK-ordered attack chain,
a primary + alternative hypothesis, and remediation, and (when an LLM is available)
asks the model to write the narrative *constrained to the provided findings and
audit_ids*. Every sentence therefore traces back to a SHA-256-audited tool call.
"""

from __future__ import annotations

import json
from typing import Any

from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_verify.models import RuleResult

# Per-rule analyst profile: human title, severity, ATT&CK tactic (kill-chain order),
# and technique ids. Severity drives ordering and the executive summary emphasis.
# tactic_order follows the ATT&CK kill chain so the attack story reads in sequence.
TACTIC_ORDER: dict[str, int] = {
    "Initial Access": 1,
    "Execution": 2,
    "Persistence": 3,
    "Privilege Escalation": 4,
    "Defense Evasion": 5,
    "Credential Access": 6,
    "Discovery": 7,
    "Lateral Movement": 8,
    "Collection": 9,
    "Command and Control": 10,
    "Exfiltration": 11,
    "Impact": 12,
    "Correlation": 13,
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class RuleProfile:
    __slots__ = ("title", "severity", "tactic", "techniques")

    def __init__(self, title: str, severity: str, tactic: str, techniques: tuple[str, ...]):
        self.title = title
        self.severity = severity
        self.tactic = tactic
        self.techniques = techniques


RULE_PROFILE: dict[str, RuleProfile] = {
    "R1": RuleProfile("Hidden process (psscan vs pslist)", "high", "Defense Evasion", ("T1055",)),
    "R2": RuleProfile("Execution with no prefetch/amcache trail", "medium", "Defense Evasion", ("T1070",)),
    "R3": RuleProfile("Phantom logon without memory session", "high", "Lateral Movement", ("T1078",)),
    "R4": RuleProfile("MFT timestomping ($SI vs $FN)", "high", "Defense Evasion", ("T1070.006",)),
    "R5": RuleProfile("Ghost binary (prefetch, file deleted)", "high", "Defense Evasion", ("T1070.004",)),
    "R6": RuleProfile("Orphan network connection", "high", "Command and Control", ("T1071",)),
    "R7": RuleProfile("Injected / RWX memory region (malfind)", "critical", "Defense Evasion", ("T1055", "T1027")),
    "R8": RuleProfile("DNS tunneling / exfiltration", "high", "Exfiltration", ("T1048", "T1071.004")),
    "R9": RuleProfile("HTTP beaconing to C2", "high", "Command and Control", ("T1071.001",)),
    "R10": RuleProfile("Linux persistence (cron/bashrc/systemd)", "high", "Persistence", ("T1053", "T1098")),
    "R11": RuleProfile("Ghost service (ImagePath missing)", "high", "Persistence", ("T1543.003",)),
    "R12": RuleProfile("USB / IP-KVM initial access", "high", "Initial Access", ("T1200",)),
    "R13": RuleProfile("Scheduled task persistence", "high", "Persistence", ("T1053.005",)),
    "R14": RuleProfile("Suspicious IOC string hits", "medium", "Discovery", ("T1083",)),
    "R15": RuleProfile("Cross-source timeline correlation", "info", "Correlation", ("T1078",)),
    "R16": RuleProfile("Unusual / non-standard binary execution", "high", "Execution", ("T1059",)),
    "R18": RuleProfile("Suspicious command-line leftovers", "medium", "Execution", ("T1059.003",)),
    "R19": RuleProfile("Web application attack / webshell", "critical", "Initial Access", ("T1190", "T1505.003")),
    "R20": RuleProfile("Structured-log security alert", "medium", "Initial Access", ("T1078",)),
    "R21": RuleProfile("Removable USB mass-storage attribution", "medium", "Exfiltration", ("T1052.001", "T1200")),
    "R22": RuleProfile("Cleartext identity / sender attribution", "medium", "Collection", ("T1040", "T1071.001")),
    "R27": RuleProfile("Email / webmail exfiltration indicators", "medium", "Exfiltration", ("T1048", "T1567")),
    "R28": RuleProfile("Cloud storage exfiltration indicators", "medium", "Exfiltration", ("T1567.002",)),
    "R29": RuleProfile("Optical media / CD-R burn indicators", "medium", "Exfiltration", ("T1052",)),
    "R30": RuleProfile("YARA / suspicious malware patterns", "high", "Execution", ("T1204", "T1059")),
    "R31": RuleProfile("Linux memory Volatility ISF requirement", "info", "Discovery", ("T1082",)),
    "R23": RuleProfile("Host attribution / system profile", "info", "Discovery", ("T1082",)),
    "R24": RuleProfile("Recycle Bin deleted executables", "medium", "Defense Evasion", ("T1070.004",)),
    "R25": RuleProfile("Legacy IE / webmail identity", "medium", "Collection", ("T1071.001",)),
    "R26": RuleProfile("Traffic capture artifact on disk", "medium", "Collection", ("T1040",)),
}

# Remediation advice keyed by ATT&CK tactic present in the case.
TACTIC_REMEDIATION: dict[str, str] = {
    "Initial Access": "Close the entry vector (patch the exploited service / disable the exposed endpoint) and block the source IP at the perimeter.",
    "Execution": "Quarantine the implicated binaries and capture them for malware analysis; enable process-creation auditing (Sysmon / EID 4688).",
    "Persistence": "Remove the persistence mechanism (run key / service / scheduled task / cron) and re-image if integrity cannot be assured.",
    "Defense Evasion": "Treat on-disk timestamps as untrusted; corroborate with memory and external telemetry; preserve volatile artifacts before reboot.",
    "Credential Access": "Rotate all credentials that were resident on or reachable from the host, including cloud IAM roles.",
    "Discovery": "Review what the actor enumerated and assume that information is compromised.",
    "Lateral Movement": "Audit downstream hosts reachable with the observed sessions/credentials.",
    "Command and Control": "Block the C2 infrastructure and hunt for the same beacon pattern across the fleet.",
    "Exfiltration": "Assume data loss for the staged/exfiltrated paths and engage legal/compliance as required.",
    "Collection": "Preserve the capture/artifacts as evidence; treat exposed cleartext identities and credentials as compromised and attribute activity to the implicated host/account.",
}


def mitre_for_rules(rule_ids: list[str]) -> list[str]:
    """Ordered, de-duplicated ATT&CK techniques for a set of rule ids."""
    seen: list[str] = []
    for rule_id in rule_ids:
        profile = RULE_PROFILE.get(rule_id)
        if not profile:
            continue
        for technique in profile.techniques:
            if technique not in seen:
                seen.append(technique)
    return seen


def _audit_ids_from_sources(sources: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for source in sources or []:
        aid = source.get("audit_id")
        if aid and aid not in seen:
            seen.add(aid)
            ids.append(aid)
    return ids


COMPROMISE_SEVERITIES = frozenset({"critical", "high"})


def _signal_from_result(result: RuleResult, state: InvestigationState) -> dict[str, Any]:
    profile = RULE_PROFILE.get(result.rule_id)
    if profile is None:
        profile = RuleProfile(result.rule_name.replace("_", " ").title(), "medium", "Correlation", ())
    return {
        "rule": result.rule_id,
        "name": result.rule_name,
        "title": profile.title,
        "severity": profile.severity,
        "tactic": profile.tactic,
        "mitre": list(profile.techniques),
        "detail": result.detail,
        "audit_ids": _audit_ids_from_sources(result.sources) or state.all_audit_ids()[:1],
    }


def compromise_signals(state: InvestigationState) -> list[dict[str, Any]]:
    """High/critical contradiction signals only — the bar for a compromise verdict."""
    signals = [
        _signal_from_result(r, state)
        for r in state.verifier_results
        if r.status == "contradiction"
        and RULE_PROFILE.get(r.rule_id, RuleProfile("", "medium", "", ())).severity in COMPROMISE_SEVERITIES
    ]
    signals.sort(
        key=lambda s: (
            TACTIC_ORDER.get(s["tactic"], 99),
            -SEVERITY_RANK.get(s["severity"], 0),
        )
    )
    return signals


def confirmed_signals(state: InvestigationState) -> list[dict[str, Any]]:
    """Confirmed verifier signals enriched with analyst metadata, kill-chain ordered."""
    signals: list[dict[str, Any]] = []
    for result in state.verifier_results:
        if result.status != "contradiction":
            continue
        profile = RULE_PROFILE.get(result.rule_id)
        if profile is None:
            profile = RuleProfile(result.rule_name.replace("_", " ").title(), "medium", "Correlation", ())
        signals.append(
            {
                "rule": result.rule_id,
                "name": result.rule_name,
                "title": profile.title,
                "severity": profile.severity,
                "tactic": profile.tactic,
                "mitre": list(profile.techniques),
                "detail": result.detail,
                "audit_ids": _audit_ids_from_sources(result.sources) or state.all_audit_ids()[:1],
            }
        )

    if not signals:
        # Fallback: derive signals from finding tags when verifier results are unavailable
        # (e.g. narrative built directly from a findings list).
        for finding in state.findings:
            for tag in finding.get("tags") or []:
                profile = RULE_PROFILE.get(str(tag))
                if profile is None:
                    continue
                signals.append(
                    {
                        "rule": str(tag),
                        "name": str(tag),
                        "title": profile.title,
                        "severity": profile.severity,
                        "tactic": profile.tactic,
                        "mitre": list(profile.techniques),
                        "detail": str(finding.get("claim", profile.title)),
                        "audit_ids": list(finding.get("audit_ids") or []),
                    }
                )

    signals.sort(
        key=lambda s: (
            TACTIC_ORDER.get(s["tactic"], 99),
            -SEVERITY_RANK.get(s["severity"], 0),
        )
    )
    return signals


def synthesize_hypothesis(signals: list[dict[str, Any]], *, audit_count: int) -> str:
    """A grounded, concise final hypothesis built from confirmed signals.

    Used whenever the agent did not author its own conclusion (e.g. iteration cap),
    so the report never falls back to a placeholder lesson string.
    """
    if not signals:
        return "No confirmed indicators of compromise were produced by the verifier on the available evidence."

    high_critical = [s for s in signals if s["severity"] in COMPROMISE_SEVERITIES]
    if not high_critical:
        return (
            "No confirmed indicators of compromise were produced by the verifier on the available evidence."
        )

    # Highest-severity signals lead the sentence.
    ranked = sorted(high_critical, key=lambda s: -SEVERITY_RANK.get(s["severity"], 0))
    lead = ranked[0]
    phrases = []
    seen_titles: set[str] = set()
    for sig in ranked[:4]:
        title = sig["title"]
        if title in seen_titles:
            continue
        seen_titles.add(title)
        phrases.append(f"{title.lower()} ({sig['rule']})")

    tactics = sorted({s["tactic"] for s in signals if s["tactic"] != "Correlation"}, key=lambda t: TACTIC_ORDER.get(t, 99))
    chain = " \u2192 ".join(tactics) if tactics else "compromise indicators"

    verdict = "compromised" if lead["severity"] in {"critical", "high"} else "likely compromised"
    return (
        f"Host assessed as {verdict}: {', '.join(phrases)}. "
        f"Observed ATT&CK progression: {chain}. "
        f"Conclusion grounded in {audit_count} audited tool execution(s); every finding carries an audit_id."
    )


def _build_attack_chain(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group confirmed signals into ordered kill-chain steps."""
    by_tactic: dict[str, list[dict[str, Any]]] = {}
    for sig in signals:
        by_tactic.setdefault(sig["tactic"], []).append(sig)

    chain: list[dict[str, Any]] = []
    for tactic in sorted(by_tactic, key=lambda t: TACTIC_ORDER.get(t, 99)):
        items = by_tactic[tactic]
        techniques: list[str] = []
        audit_ids: list[str] = []
        for item in items:
            for t in item["mitre"]:
                if t not in techniques:
                    techniques.append(t)
            for aid in item["audit_ids"]:
                if aid not in audit_ids:
                    audit_ids.append(aid)
        chain.append(
            {
                "tactic": tactic,
                "techniques": techniques,
                "description": "; ".join(item["detail"] for item in items),
                "rules": [item["rule"] for item in items],
                "audit_ids": audit_ids,
            }
        )
    return chain


def _recommended_actions(signals: list[dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    seen: set[str] = set()
    tactics = sorted({s["tactic"] for s in signals}, key=lambda t: TACTIC_ORDER.get(t, 99))
    for tactic in tactics:
        advice = TACTIC_REMEDIATION.get(tactic)
        if advice and advice not in seen:
            seen.add(advice)
            actions.append(advice)
    if any(s["rule"] in {"R19"} for s in signals):
        actions.insert(0, "Take the affected web service offline; webshells may still be live and reachable.")
    if not actions:
        actions.append("Preserve the evidence read-only and continue collection; signals are weak.")
    return actions


def _alternative_hypothesis(signals: list[dict[str, Any]]) -> str:
    soft = [s for s in signals if s["severity"] in {"info", "medium"}]
    if soft:
        names = ", ".join(sorted({s["title"].lower() for s in soft}))
        return (
            f"Some lower-severity signals ({names}) could reflect benign administrative activity, "
            "pre-existing artifacts, or noisy IOC string matches rather than attacker action; "
            "confirm each against the underlying audited tool output before final attribution."
        )
    return (
        "Alternative: a subset of the high-severity signals could stem from an authorized red-team / "
        "admin action rather than an external actor; corroborate with change-management records."
    )


def build_template_report(state: InvestigationState) -> dict[str, Any]:
    """Deterministic structured incident report (no LLM)."""
    compromise = compromise_signals(state)
    signals = compromise if compromise else []
    audit_ids = state.all_audit_ids()
    chain = _build_attack_chain(signals)
    mitre = mitre_for_rules([s["rule"] for s in signals])

    hypothesis = state.hypothesis
    if _is_placeholder(hypothesis) or not compromise:
        hypothesis = synthesize_hypothesis(signals, audit_count=len(audit_ids))

    summary_bits = [step["description"] for step in chain]
    summary = hypothesis
    if summary_bits:
        summary += " Evidence chain: " + " | ".join(summary_bits[:6]) + "."

    return {
        "summary": summary,
        "attack_chain": chain,
        "primary_hypothesis": hypothesis,
        "alternative_hypothesis": _alternative_hypothesis(signals),
        "recommended_actions": _recommended_actions(signals),
        "mitre": mitre,
        "gaps": list(state.gaps),
        "confidence": state.confidence,
        "audit_ids": audit_ids[:20],
        "source": "template",
        "signals": signals,
    }


def build_llm_report(state: InvestigationState, config: AgentConfig) -> dict[str, Any]:
    """LLM-authored incident report, hard-constrained to confirmed signals + audit_ids."""
    from postmortem_agent.llm import complete_messages, parse_json_response, static_system_block

    signals = confirmed_signals(state)
    allowed_audit = set(state.all_audit_ids())
    if not signals:
        return build_template_report(state)

    context = {
        "agent_hypothesis": None if _is_placeholder(state.hypothesis) else state.hypothesis,
        "confirmed_signals": signals,
        "evidence_kinds": state.survey.get("kinds_present"),
        "investigation_gaps": list(state.gaps),
        "allowed_audit_ids": sorted(allowed_audit),
    }
    system = static_system_block(
        "You are a senior DFIR analyst writing the final incident report on a dead host. "
        "You are given the ONLY confirmed signals the deterministic verifier produced; each carries audit_ids. "
        "Write a rigorous report that reads like a senior analyst's, but invent NOTHING: every claim must trace to "
        "a provided signal, and you may ONLY cite audit_ids from allowed_audit_ids. Order the attack_chain by the "
        "ATT&CK kill chain. Provide a primary hypothesis AND a competing alternative hypothesis (analysis of "
        "competing hypotheses). If evidence is thin, say so and lower confidence. "
        'Return ONLY JSON: {"summary": "...", '
        '"attack_chain": [{"tactic": "...", "techniques": ["Txxxx"], "description": "...", "audit_ids": ["..."]}], '
        '"primary_hypothesis": "...", "alternative_hypothesis": "...", '
        '"recommended_actions": ["..."], "confidence": 0.0-1.0}'
    )
    payload = complete_messages(
        system=system,
        messages=[{"role": "user", "content": json.dumps(context, sort_keys=True)}],
        model=config.llm_model,
        max_tokens=1600,
    )
    text = "".join(
        block.get("text", "")
        for block in payload.get("content", [])
        if block.get("type") == "text"
    ).strip()
    parsed = parse_json_response(text)

    chain = []
    for step in parsed.get("attack_chain") or []:
        if not isinstance(step, dict):
            continue
        step_audit = [a for a in (step.get("audit_ids") or []) if a in allowed_audit]
        chain.append(
            {
                "tactic": str(step.get("tactic", "")).strip() or "Unknown",
                "techniques": [str(t) for t in step.get("techniques") or []],
                "description": str(step.get("description", "")).strip(),
                "audit_ids": step_audit,
            }
        )
    if not chain:
        chain = _build_attack_chain(signals)

    summary = str(parsed.get("summary", "")).strip()
    primary = str(parsed.get("primary_hypothesis", "")).strip()
    if not primary:
        primary = synthesize_hypothesis(signals, audit_count=len(allowed_audit))
    if not summary:
        summary = primary
    alternative = str(parsed.get("alternative_hypothesis", "")).strip() or _alternative_hypothesis(signals)
    actions = [str(a).strip() for a in parsed.get("recommended_actions") or [] if str(a).strip()]
    if not actions:
        actions = _recommended_actions(signals)
    try:
        confidence = float(parsed.get("confidence", state.confidence))
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        confidence = state.confidence

    return {
        "summary": summary,
        "attack_chain": chain,
        "primary_hypothesis": primary,
        "alternative_hypothesis": alternative,
        "recommended_actions": actions,
        "mitre": mitre_for_rules([s["rule"] for s in signals]),
        "gaps": list(state.gaps),
        "confidence": confidence,
        "audit_ids": state.all_audit_ids()[:20],
        "source": "llm",
        "signals": signals,
    }


def build_incident_report(state: InvestigationState, config: AgentConfig) -> dict[str, Any]:
    if config.mode in {"llm", "hybrid"}:
        try:
            return build_llm_report(state, config)
        except Exception:
            return build_template_report(state)
    return build_template_report(state)


def render_report_markdown(report: dict[str, Any]) -> str:
    """Render the structured incident report as analyst-readable markdown."""
    lines: list[str] = ["## Incident Summary", "", report.get("summary", "").strip(), ""]

    chain = report.get("attack_chain") or []
    if chain:
        lines += ["## Attack Chain (ATT&CK kill-chain order)", ""]
        for step in chain:
            techniques = ", ".join(step.get("techniques") or []) or "—"
            audits = ", ".join(f"`{a}`" for a in step.get("audit_ids") or []) or "—"
            lines.append(f"### {step.get('tactic', 'Unknown')}  ({techniques})")
            lines.append("")
            lines.append(step.get("description", "").strip() or "_no detail_")
            lines.append(f"\n_audit_: {audits}")
            lines.append("")

    lines += ["## Hypotheses", "", f"**Primary:** {report.get('primary_hypothesis', '').strip()}", ""]
    alt = report.get("alternative_hypothesis", "").strip()
    if alt:
        lines += [f"**Alternative:** {alt}", ""]

    actions = report.get("recommended_actions") or []
    if actions:
        lines += ["## Recommended Actions", ""]
        lines += [f"{i}. {a}" for i, a in enumerate(actions, start=1)]
        lines.append("")

    gaps = report.get("gaps") or []
    if gaps:
        lines += ["## Investigation Gaps", ""]
        lines += [f"- {g}" for g in gaps]
        lines.append("")

    mitre = report.get("mitre") or []
    if mitre:
        lines += ["## MITRE ATT&CK Techniques", "", ", ".join(mitre), ""]

    conf = report.get("confidence")
    if conf is not None:
        lines += [f"_Overall confidence: {float(conf):.2f}_  ", f"_Synthesis source: {report.get('source', 'template')}_"]
    return "\n".join(lines).strip()


def _is_placeholder(text: str | None) -> bool:
    if not text:
        return True
    lowered = text.strip().lower()
    return (
        lowered in {"investigation not started", ""}
        or lowered.startswith("contradiction ")
        or lowered.startswith("analyzing ")
        or lowered.startswith("triaging ")
    )
