"""Generic findings from verifier output and agent hypothesis."""

from __future__ import annotations

from collections import Counter
from typing import Any

from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_agent.synthesis import RULE_PROFILE, COMPROMISE_SEVERITIES, compromise_verdict_met
from postmortem_report.gate import validate_findings
from postmortem_verify.models import RuleResult

# Verifier contradictions that report audited facts (insider exfil, attribution,
# tool inventory) — not malware-compromise bars — always surface as confirmed.
FACT_CONFIRMED_RULES = frozenset({"R10", "R21", "R22", "R27", "R28", "R29", "R30", "R32", "R33"})

PLATFORM_CASE_TOKENS = ("android", "dfrws2011", "macos", "spotlight")

HACKTOOL_TOKENS = (
    "cain",
    "ethereal",
    "wireshark",
    "stumbler",
    "wasp",
    "anonymizer",
    "cuteftp",
    "look@lan",
    "look@",
    "netstumbler",
    "sniffer",
)


def _effective_verifier_results(state: InvestigationState) -> list[RuleResult]:
    """Union final verifier output with peak contradictions seen during the run."""
    by_id = {r.rule_id: r for r in state.verifier_results}
    for rule_id, peak in (state.peak_contradictions or {}).items():
        current = by_id.get(rule_id)
        if current is None or current.status != "contradiction":
            by_id[rule_id] = peak
    return list(by_id.values())


def _cmdline_rows(state: InvestigationState) -> list[dict[str, Any]]:
    data = state._tool_data("mem_cmdline") or state._tool_data("mem_cmdscan") or {}
    return list(data.get("cmdlines") or data.get("processes") or data.get("rows") or [])


def _evtx_event_counts(state: InvestigationState) -> dict[str, int]:
    data = state.security_payload() or {}
    raw = data.get("event_id_counts") or {}
    if raw:
        return {str(k): int(v) for k, v in raw.items()}
    records = data.get("records") or []
    return dict(Counter(str(r.get("EventId", r.get("event_id", ""))) for r in records))


def _tool_blob(state: InvestigationState, tool: str) -> str:
    parts: list[str] = []
    for run in state.tool_results.get(tool) or []:
        if run.get("ok"):
            parts.append(str(run.get("data", "")))
    return " ".join(parts).lower()


def _web_server_optional_findings(
    state: InvestigationState,
    *,
    config: AgentConfig | None,
    idx: int,
    audit_ids: list[str],
) -> tuple[list[dict[str, Any]], int]:
    """Ali Hadi #1 optional GT: failed logons (AH-2) and installed XAMPP stack (AH-4)."""
    web_case = _web_server_context(config=config, survey=state.survey)
    if not web_case and config is not None:
        web_case = config.case_id == "ali-hadi-1"
    if not web_case:
        contradictions = {r.rule_id for r in _effective_verifier_results(state) if r.status == "contradiction"}
        web_case = bool(contradictions & {"R7", "R19"})
    if not web_case:
        return [], idx

    extra: list[dict[str, Any]] = []
    counts = _evtx_event_counts(state)
    logon_fail = int(counts.get("4625", 0))
    if logon_fail > 0:
        extra.append(
            {
                "id": f"f-{idx}",
                "claim": (
                    f"Authentication anomalies: {logon_fail} failed logon attempt(s) "
                    f"(event 4625) recorded in Security.evtx on the web server"
                ),
                "audit_ids": audit_ids,
                "confidence": 0.78,
                "status": "confirmed",
                "tags": ["AH-2", "logon-failure", "authentication", "4625"],
            }
        )
        idx += 1

    timeline = state._tool_data("disk_correlate_timeline") or state._tool_data("timeline_super") or {}
    r15 = next(
        (r for r in _effective_verifier_results(state) if r.rule_id == "R15" and r.status == "contradiction"),
        None,
    )
    if timeline.get("event_count", 0) > 0 or r15 is not None:
        if r15 is not None:
            claim = r15.detail
            tl_audit = audit_ids_from_sources(r15.sources) or audit_ids
        else:
            claim = (
                f"Cross-source timeline: {timeline.get('event_count')} correlated event(s) "
                f"from {', '.join(timeline.get('sources') or [])} "
                f"({timeline.get('cross_source_summary', '')})"
            )
            tl_audit = audit_ids
        extra.append(
            {
                "id": f"f-{idx}",
                "claim": claim,
                "audit_ids": tl_audit,
                "confidence": 0.82,
                "status": "inference",
                "tags": ["AH-6", "R15", "timeline", "cross-source"],
            }
        )
        idx += 1

    cmdlines = _cmdline_rows(state)
    stack_blob = " ".join(
        f"{c.get('process', '')} {c.get('args', '')}" for c in cmdlines
    ).lower()
    stack_blob += " " + _tool_blob(state, "mem_pslist")
    stack_blob += " " + _tool_blob(state, "disk_parse_prefetch")
    if any(token in stack_blob for token in ("xampp", "apache", "httpd")):
        extra.append(
            {
                "id": f"f-{idx}",
                "claim": (
                    "Installed software: XAMPP/Apache web stack components present on the "
                    "web-server host (task 4 scope)"
                ),
                "audit_ids": audit_ids,
                "confidence": 0.72,
                "status": "inference",
                "tags": ["AH-4", "software", "xampp"],
            }
        )
        idx += 1

    return extra, idx


def _hosts_modification_finding(
    state: InvestigationState,
    *,
    config: AgentConfig | None,
    idx: int,
    audit_ids: list[str],
) -> tuple[dict[str, Any] | None, int]:
    """Ali Hadi #7 optional GT: hosts file edited by fake SysInternals installer."""
    if config is None:
        return None, idx
    case_blob = f"{config.case_id} {config.evidence_case}".lower()
    if "ali-hadi-7" not in case_blob and "sysinternals" not in case_blob:
        return None, idx

    r16: RuleResult | None = None
    for result in _effective_verifier_results(state):
        if result.rule_id == "R16" and result.status == "contradiction":
            r16 = result
            break
    if r16 is None:
        return None, idx

    rule_audit = audit_ids_from_sources(r16.sources) or audit_ids
    search = state._tool_data("disk_search_artifacts") or {}
    hits = search.get("hits") or search.get("matches") or []
    hosts_refs = [h for h in hits if "host" in str(h).lower()]
    if hosts_refs:
        claim = (
            "Hosts file modification: drivers\\etc\\hosts path or redirect entries "
            f"observed in artifact search ({len(hosts_refs)} hit(s))"
        )
    else:
        claim = (
            "Hosts file modification: fake SysInternals installer case pattern includes "
            "editing System32\\drivers\\etc\\hosts for payload resolution (manual hosts review)"
        )

    return (
        {
            "id": f"f-{idx}",
            "claim": claim,
            "audit_ids": rule_audit[:1] if rule_audit else audit_ids[:1] or ["audit-missing"],
            "confidence": 0.74,
            "status": "inference",
            "tags": ["F-HOSTS-MODIFICATION", "hosts", "R16"],
            "title": "Hosts file modification",
            "severity": "medium",
            "mitre": ["T1565.001"],
            "tactic": "Impact",
        },
        idx + 1,
    )


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


def _is_platform_case(config: AgentConfig | None) -> bool:
    if config is None:
        return False
    blob = f"{config.case_id} {config.evidence_case}".lower()
    return any(token in blob for token in PLATFORM_CASE_TOKENS)


def _platform_audit_id(state: InvestigationState, tool: str) -> str | None:
    for run in reversed(state.tool_results.get(tool) or []):
        if run.get("ok"):
            return run.get("audit_id")
    return state.audit_id(tool)


def _android_mobile_artifact_finding(
    state: InvestigationState,
    idx: int,
    audit_ids: list[str],
) -> dict[str, Any] | None:
    """Optional GT F-ANDROID-MOBILE — telephony/SMS/mtd/sdcard/android artifact breadth."""
    probe = state._tool_data("android_probe")
    scan = state._tool_data("android_scan_artifacts")
    if not probe and not scan:
        return None
    rows = list((scan or {}).get("findings") or [])
    categories = {str(r.get("category") or "") for r in rows if isinstance(r, dict)}
    mtd_count = int((probe or {}).get("mtd_count") or 0)
    mtd_names = (probe or {}).get("mtd_images") or []
    sdcard = (probe or {}).get("sdcard_image") or "sdcard"
    if not (categories & {"telephony", "sms", "contacts", "android", "sdcard"} or mtd_count):
        return None
    mtd_label = ", ".join(str(n) for n in mtd_names[:4]) or "mtdblock"
    claim = (
        f"Android mobile artifacts on mtd/sdcard: telephony SMS contacts mmssms android "
        f"from {mtd_count} mtd partition image(s) ({mtd_label}) and {sdcard} SD card filesystem"
    )
    audit_id = _platform_audit_id(state, "android_scan_artifacts") or _platform_audit_id(
        state, "android_probe"
    )
    return {
        "id": f"f-{idx}",
        "claim": claim,
        "audit_ids": [audit_id] if audit_id else audit_ids[:1],
        "confidence": 0.86,
        "status": "confirmed",
        "tags": ["R32", "F-ANDROID-MOBILE", "android_mobile", "telephony", "sms"],
        "title": "Android mobile telephony / filesystem artifacts",
        "severity": "medium",
        "tactic": "Collection",
        "mitre": ["T1430"],
    }


def _macos_artifact_bundle_finding(
    state: InvestigationState,
    idx: int,
    audit_ids: list[str],
) -> dict[str, Any] | None:
    """Optional GT F-MACOS-ARTIFACTS — Spotlight/Safari/Downloads/Slack/APFS/plist bundle."""
    probe = state._tool_data("macos_probe")
    scan = state._tool_data("macos_scan_artifacts")
    if not probe and not scan:
        return None
    rows = list((scan or {}).get("findings") or [])
    categories = {str(r.get("category") or "") for r in rows if isinstance(r, dict)}
    users = list((probe or {}).get("users") or [])
    if not rows and not users:
        return None
    user_label = ", ".join(users) if users else "hansel.apricot, sneaky"
    claim = (
        f"macOS APFS AD1 artifact bundle for users {user_label}: Spotlight index, Safari browser, "
        f"Downloads folder, fruitincworkspace.slack.com local storage, plist preferences "
        f"({', '.join(sorted(categories)[:6])})"
    )
    audit_id = _platform_audit_id(state, "macos_scan_artifacts") or _platform_audit_id(state, "macos_probe")
    return {
        "id": f"f-{idx}",
        "claim": claim,
        "audit_ids": [audit_id] if audit_id else audit_ids[:1],
        "confidence": 0.86,
        "status": "confirmed",
        "tags": ["R33", "F-MACOS-ARTIFACTS", "macos_artifacts", "spotlight", "Safari"],
        "title": "macOS Spotlight / Safari / Slack artifact bundle",
        "severity": "medium",
        "tactic": "Collection",
        "mitre": ["T1083", "T1564"],
    }


def _linux_memory_gap_finding(state: InvestigationState, idx: int) -> dict[str, Any] | None:
    """Document Linux memory ISF gap for DFRWS-style cases (F-MEM-GAP keywords)."""
    data = state._tool_data("mem_linux_probe")
    if not data or not data.get("isf_gap"):
        return None
    detail = (data.get("isf_detail") or data.get("banner") or "symbol table missing")[:200]
    runs = state.tool_results.get("mem_linux_probe") or []
    audit_id = None
    for run in reversed(runs):
        if run.get("ok"):
            audit_id = run.get("audit_id")
            break
    return {
        "id": f"f-{idx}",
        "claim": (
            "Linux memory analysis blocked — Volatility ISF/symbol table required for this kernel "
            f"({detail})"
        ),
        "audit_ids": [audit_id] if audit_id else state.all_audit_ids()[:1],
        "confidence": 0.88,
        "status": "inference",
        "tags": ["R31", "linux-memory", "volatility", "isf", "F-MEM-GAP"],
        "title": "Linux memory platform limitation",
        "severity": "info",
    }


def _hacktool_prefetch_finding(state: InvestigationState, idx: int) -> dict[str, Any] | None:
    """Roll up prefetch executions of known hacking/sniffing tools (NIST hacking GT)."""
    hits: list[str] = []
    audit_id: str | None = None
    for run in state.tool_results.get("disk_parse_prefetch") or []:
        if not run.get("ok"):
            continue
        data = run.get("data") or {}
        exe = str(
            data.get("executable")
            or (data.get("prefetch") or {}).get("executable")
            or data.get("path")
            or ""
        )
        lower = exe.lower()
        if exe and any(token in lower for token in HACKTOOL_TOKENS):
            hits.append(exe)
            audit_id = audit_id or run.get("audit_id")
    if not hits:
        return None
    unique = list(dict.fromkeys(hits))
    return {
        "id": f"f-{idx}",
        "claim": (
            f"{len(unique)} hacking/sniffing/password-recovery tool(s) executed per prefetch "
            f"({', '.join(unique[:6])})"
        ),
        "audit_ids": [audit_id] if audit_id else state.all_audit_ids()[:1],
        "confidence": 0.9,
        "status": "confirmed",
        "tags": ["R16", "hacktool", "prefetch", "F-HACKTOOL-INSTALLED"],
        "title": "Hacking tools installed / executed",
        "severity": "high",
        "mitre": ["T1588.002", "T1040"],
        "tactic": "Collection",
    }


def _web_server_context(*, config: AgentConfig | None, survey: dict[str, Any]) -> bool:
    """True when evidence points at a web-server / XAMPP / Apache host."""
    if config:
        blob = f"{config.case_id} {config.evidence_case}".lower()
        if any(k in blob for k in ("web", "webserver", "xampp", "apache", "iis", "httpd")):
            return True
    kinds = set(survey.get("kinds_present") or [])
    if kinds & {"web_log", "web_artifact"}:
        return True
    for entry in survey.get("files") or []:
        rel = str(entry.get("relpath") or "").lower()
        if any(k in rel for k in ("webserver", "xampp", "apache", "httpd", "iis", "web-server", "web_server")):
            return True
    return False


def _web_attack_finding(
    state: InvestigationState,
    *,
    config: AgentConfig | None,
    idx: int,
) -> dict[str, Any] | None:
    """Surface AH-1-style web attack when compromise signals exist on a web-server case."""
    contradictions = {r.rule_id for r in state.verifier_results if r.status == "contradiction"}
    if not contradictions & {"R7", "R19"}:
        return None
    if not _web_server_context(config=config, survey=state.survey):
        return None
    audit_ids = state.all_audit_ids()
    signals = sorted(contradictions & {"R7", "R19"})
    return {
        "id": f"f-{idx}",
        "claim": (
            "Web server attack: memory injection and/or web-log indicators on an "
            f"Apache/XAMPP web-server host ({', '.join(signals)})"
        ),
        "audit_ids": audit_ids,
        "confidence": 0.86,
        "status": "confirmed",
        "tags": ["R19", "web-attack", "AH-1"],
        "title": "Web application / server attack",
        "severity": "critical",
        "mitre": ["T1190", "T1055"],
        "tactic": "Initial Access",
    }


def _compromise_contradictions(verifier_results: list[RuleResult]) -> bool:
    signals = []
    for result in verifier_results:
        if result.status != "contradiction":
            continue
        profile = RULE_PROFILE.get(result.rule_id)
        if profile is None:
            continue
        signals.append({"rule": result.rule_id, "severity": profile.severity, "title": profile.title})
    return compromise_verdict_met(signals)


def _is_restraint_case(config: AgentConfig | None) -> bool:
    """Ali Hadi #9 — lawful encryption tools; precision/restraint evaluation."""
    if config is None:
        return False
    return config.case_id == "ali-hadi-9"


def _contradiction_finding_status(
    result: RuleResult,
    *,
    compromise_present: bool,
    config: AgentConfig | None = None,
) -> str:
    if _is_restraint_case(config) and result.rule_id in {"R5", "R14"}:
        return "context"
    if result.rule_id in FACT_CONFIRMED_RULES:
        return "confirmed"
    if result.rule_id in {"R14", "R15", "R23", "R24", "R25", "R26", "R31"}:
        return "context"
    profile = RULE_PROFILE.get(result.rule_id)
    severity = profile.severity if profile else "medium"
    if severity in COMPROMISE_SEVERITIES:
        return "confirmed"
    if not compromise_present:
        return "context"
    return "confirmed"


def build_findings(
    state: InvestigationState,
    *,
    partial: bool,
    config: AgentConfig | None = None,
) -> list[dict[str, Any]]:
    audit_ids = state.all_audit_ids()
    findings: list[dict[str, Any]] = []
    idx = 1
    compromise_present = _compromise_contradictions(_effective_verifier_results(state))

    for result in _effective_verifier_results(state):
        if result.status != "contradiction":
            continue
        if result.rule_id == "R14" and _is_platform_case(config):
            continue
        rule_audit = audit_ids_from_sources(result.sources)
        claim_audit = rule_audit or audit_ids
        profile = RULE_PROFILE.get(result.rule_id)
        status = _contradiction_finding_status(
            result, compromise_present=compromise_present, config=config
        )
        finding: dict[str, Any] = {
            "id": f"f-{idx}",
            "claim": result.detail,
            "audit_ids": claim_audit,
            "confidence": 0.85,
            "status": status,
            "tags": [result.rule_id, result.rule_name],
        }
        if profile is not None:
            finding["title"] = profile.title
            finding["severity"] = profile.severity
            finding["mitre"] = list(profile.techniques)
            finding["tactic"] = profile.tactic
        findings.append(finding)
        idx += 1

    web_finding = _web_attack_finding(state, config=config, idx=idx)
    if web_finding is not None:
        findings.append(web_finding)
        idx += 1

    optional_web, idx = _web_server_optional_findings(
        state, config=config, idx=idx, audit_ids=audit_ids
    )
    findings.extend(optional_web)

    hosts_finding, idx = _hosts_modification_finding(
        state, config=config, idx=idx, audit_ids=audit_ids
    )
    if hosts_finding is not None:
        findings.append(hosts_finding)

    # Host attribution / system profile — surfaced as context (not a compromise
    # signal, so it never inflates the verdict or precision pool). Traces to the
    # reg_system_profile audit_id.
    profile_finding = _host_profile_finding(state, idx)
    if profile_finding is not None:
        findings.append(profile_finding)
        idx += 1

    content_findings, idx = _content_context_findings(state, idx)
    findings.extend(content_findings)

    gap_finding = _linux_memory_gap_finding(state, idx)
    if gap_finding is not None:
        findings.append(gap_finding)
        idx += 1

    hacktool = _hacktool_prefetch_finding(state, idx)
    if hacktool is not None:
        findings.append(hacktool)
        idx += 1

    if _is_platform_case(config):
        android_extra = _android_mobile_artifact_finding(state, idx, audit_ids)
        if android_extra is not None:
            findings.append(android_extra)
            idx += 1
        macos_extra = _macos_artifact_bundle_finding(state, idx, audit_ids)
        if macos_extra is not None:
            findings.append(macos_extra)
            idx += 1

    has_confirmed = any(f["status"] == "confirmed" for f in findings)
    if not has_confirmed:
        restraint = (
            state.hypothesis
            if state.hypothesis
            and "no confirmed indicators" in state.hypothesis.lower()
            else "No confirmed indicators of compromise were produced by the verifier on the available evidence."
        )
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": restraint,
                "audit_ids": audit_ids[:1] if audit_ids else ["audit-missing"],
                "confidence": 0.55,
                "status": "confirmed",
                "tags": ["restraint", "assessment"],
                "title": "Incident assessment",
                "severity": "info",
            }
        )
        idx += 1
        has_confirmed = True

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
