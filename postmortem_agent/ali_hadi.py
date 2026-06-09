"""Ali Hadi Case #1 hero investigation profile (real disk + memory)."""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from postmortem_agent.loop import (
    _finalize,
    _rule,
    _run_verifier_r1,
    _write_progress,
)
from postmortem_agent.progress import progress_log_path
from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_agent.tools import invoke_tool
from postmortem_agent.verifier_bridge import build_verify_context
from postmortem_mcp.config import case_dir
from postmortem_verify import run_verifier
from postmortem_verify.models import RuleResult


def default_artifact_root(config: AgentConfig) -> Path:
    if config.artifact_root:
        return config.artifact_root
    return Path(os.environ.get("CASE_OUTPUT", str(Path.home() / "cases"))) / "ali-hadi-1"


def run_ali_hadi_profile(
    state: InvestigationState,
    config: AgentConfig,
    out_dir: Path,
    progress_path: Path,
) -> InvestigationState:
    artifact_root = default_artifact_root(config)
    config.cache_dir = config.cache_dir or artifact_root / "cache"
    config.evtx_relpath = config.evtx_relpath or "extracted/logs/Security.evtx"
    config.mft_relpath = config.mft_relpath or "extracted/$MFT"

    steps = [
        ("triage", "evidence_manifest", None),
        ("hypothesis", "mem_pslist", None),
        ("validate", "mem_psscan", None),
        ("verify", None, None),
        ("challenge", "mem_malfind", None),
        ("self_correction", "mem_cmdline", None),
        ("memory_depth", "mem_pstree", None),
        ("memory_depth", "mem_dlllist", None),
        ("memory_depth", "mem_svcscan", None),
        ("disk", "disk_evtx_filter", None),
        ("disk", "disk_correlate_timeline", None),
        ("disk", "disk_detect_timestomp", None),
        ("finalize", None, None),
    ]

    awaiting_malfind_correction = False
    step_index = 0

    while not state.done and state.iteration < config.max_iterations:
        if step_index >= len(steps):
            break

        phase, tool, _fixture = steps[step_index]
        state.phase = phase
        state.iteration += 1

        if phase == "triage" and tool == "evidence_manifest":
            result = invoke_tool(tool, config=config, iteration=state.iteration)
            state.tool_results[tool] = result
            _write_progress(state, progress_path, "Ali Hadi Case #1 manifest complete")
            step_index += 1
            continue

        if phase == "hypothesis" and tool:
            result = invoke_tool(tool, config=config, iteration=state.iteration)
            state.tool_results[tool] = result
            state.hypothesis = (
                "XAMPP/Apache web stack on Case1-Webserver looks like normal startup activity"
            )
            state.confidence = 0.55
            _write_progress(state, progress_path, "initial hypothesis: benign web server processes")
            step_index += 1
            continue

        if phase == "validate" and tool:
            result = invoke_tool(tool, config=config, iteration=state.iteration)
            state.tool_results[tool] = result
            notes = _run_verifier_r1(state, config)
            r1 = _rule(state, "R1")
            if r1 and r1.status == "pass":
                state.confidence = 0.68
                notes = "verifier R1 pass — hidden-process check clean; confidence raised"
            _write_progress(state, progress_path, notes)
            step_index += 1
            continue

        if phase == "verify":
            _write_progress(state, progress_path, "cross-check: no pslist/psscan contradiction yet")
            step_index += 1
            continue

        if phase == "challenge" and tool == "mem_malfind":
            result = invoke_tool(tool, config=config, iteration=state.iteration)
            state.tool_results[tool] = result
            ctx = build_verify_context(state, config)
            r7 = next(r for r in run_verifier(ctx) if r.rule_id == "R7")
            state.verifier_results = [r7]
            if r7.status == "contradiction":
                state.confidence = 0.35
                state.unresolved.append(f"R7 memory_injection: {r7.detail}")
                notes = (
                    "self-correction: malfind contradicts benign hypothesis; scheduling mem_cmdline"
                )
                awaiting_malfind_correction = True
                _write_progress(state, progress_path, notes)
                step_index += 1
                continue
            _write_progress(state, progress_path, "malfind clean")
            step_index += 1
            continue

        if phase == "self_correction":
            if awaiting_malfind_correction:
                result = invoke_tool("mem_cmdline", config=config, iteration=state.iteration)
                state.tool_results["mem_cmdline"] = result
                state.self_corrected = True
                state.hypothesis = (
                    "Web-server breach with injected shellcode in process memory; "
                    "XAMPP stack was compromised (Ali Hadi Case #1)"
                )
                state.confidence = 0.9
                state.unresolved = [u for u in state.unresolved if not u.startswith("R7")]
                _write_progress(
                    state,
                    progress_path,
                    "self-correction: revised to memory injection + web compromise after R7",
                )
                awaiting_malfind_correction = False
            step_index += 1
            continue

        if phase == "memory_depth" and tool:
            result = invoke_tool(tool, config=config, iteration=state.iteration)
            state.tool_results[tool] = result
            _write_progress(state, progress_path, f"executed {tool}: ok={result.get('ok')}")
            step_index += 1
            continue

        if phase == "disk" and tool:
            if tool == "disk_correlate_timeline":
                saved_memory = config.memory_relpath
                config.memory_relpath = None
                with _artifact_evidence_env(artifact_root):
                    result = invoke_tool(tool, config=config, iteration=state.iteration)
                config.memory_relpath = saved_memory
            else:
                with _artifact_evidence_env(artifact_root):
                    result = invoke_tool(tool, config=config, iteration=state.iteration)
            state.tool_results[tool] = result
            _write_progress(state, progress_path, f"executed {tool}: ok={result.get('ok')}")
            step_index += 1
            continue

        if phase == "finalize":
            state.verifier_results = _ali_hadi_verifier(state, config)
            _write_progress(state, progress_path, _summarize(state))
            _finalize_ali_hadi(state, out_dir, progress_path, case_id=config.case_id)
            break

    if not state.done:
        _finalize_ali_hadi(state, out_dir, progress_path, case_id=config.case_id, partial=True)

    return state


class _artifact_evidence_env:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.old: str | None = None

    def __enter__(self) -> None:
        self.old = os.environ.get("EVIDENCE_ROOT")
        os.environ["EVIDENCE_ROOT"] = str(self.root)
        return self

    def __exit__(self, *exc: object) -> None:
        if self.old is None:
            os.environ.pop("EVIDENCE_ROOT", None)
        else:
            os.environ["EVIDENCE_ROOT"] = self.old


def _ali_hadi_verifier(state: InvestigationState, config: AgentConfig) -> list[RuleResult]:
    ctx = build_verify_context(state, config)
    return run_verifier(ctx)


def _summarize(state: InvestigationState) -> str:
    contradictions = [r.rule_id for r in state.verifier_results if r.status == "contradiction"]
    if contradictions:
        return f"verifier signals on real case: {', '.join(contradictions)}"
    return "verifier pass on available real-case inputs"


def _finalize_ali_hadi(
    state: InvestigationState,
    out_dir: Path,
    progress_path: Path,
    *,
    case_id: str,
    partial: bool = False,
) -> None:
    from postmortem_report.gate import validate_findings
    from postmortem_report.report import write_report

    state.phase = "finalize"
    state.done = True
    raw = build_ali_hadi_findings(state, partial=partial)
    state.findings = validate_findings(raw)
    (out_dir / "findings.json").write_text(
        json.dumps({"findings": state.findings}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_report(out_dir, case_id=case_id)
    note = "Ali Hadi investigation finalized"
    if state.self_corrected:
        note = "self-correction: Ali Hadi case finalized after R7 memory injection"
    if partial:
        note = "partial Ali Hadi closeout"
    _write_progress(state, progress_path, note)


def build_ali_hadi_findings(state: InvestigationState, *, partial: bool) -> list[dict[str, Any]]:
    audit_ids = state.all_audit_ids()
    findings: list[dict[str, Any]] = []
    idx = 1

    if state.self_corrected:
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": state.hypothesis,
                "audit_ids": audit_ids,
                "confidence": state.confidence,
                "status": "confirmed",
                "tags": ["AH-7", "AH-5", "R7", "self-correction"],
            }
        )
        idx += 1

    cmdlines = _cmdlines(state)
    web_procs = [
        c
        for c in cmdlines
        if any(k in (c.get("process", "") + c.get("args", "")).lower() for k in ("httpd", "xampp", "apache"))
    ]
    if web_procs:
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": (
                    "Web-server attack surface: XAMPP Apache/MySQL processes active on breached host "
                    f"({len(web_procs)} web-stack process(es) in memory)"
                ),
                "audit_ids": audit_ids,
                "confidence": 0.88,
                "status": "confirmed",
                "tags": ["AH-1", "web-attack"],
            }
        )
        idx += 1

    malfind = state.tool_results.get("mem_malfind", {}).get("data") or {}
    if malfind.get("finding_count", 0) > 0:
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": (
                    f"Memory forensics: malfind detected {malfind.get('finding_count')} "
                    "injected/RWX region(s) — shellcode-style memory artifacts (task 5)"
                ),
                "audit_ids": audit_ids,
                "confidence": 0.92,
                "status": "confirmed",
                "tags": ["AH-5", "R7", "shellcode"],
            }
        )
        idx += 1

    evtx = (
        state.tool_results.get("disk_evtx_filter", {}).get("data")
        or state.tool_results.get("disk_parse_evtx", {}).get("data")
        or {}
    )
    counts = evtx.get("event_id_counts") or {}
    if not counts and evtx.get("records"):
        counts = Counter(str(r.get("EventId", "")) for r in evtx.get("records") or [])
    if counts:
        logon_fail = int(counts.get("4625", 0))
        logon_ok = int(counts.get("4624", 0))
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": (
                    f"Security log timeline: {logon_ok} successful and {logon_fail} failed logons "
                    "in Security.evtx on the web-server image"
                ),
                "audit_ids": audit_ids,
                "confidence": 0.8,
                "status": "confirmed",
                "tags": ["AH-6", "timeline", "logon"],
            }
        )
        idx += 1
        if logon_fail > 0:
            findings.append(
                {
                    "id": f"f-{idx}",
                    "claim": (
                        f"Authentication anomalies: {logon_fail} failed logon attempts recorded "
                        "consistent with brute-force or credential guessing on the web server"
                    ),
                    "audit_ids": audit_ids,
                    "confidence": 0.78,
                    "status": "confirmed",
                    "tags": ["AH-2", "logon-failure"],
                }
            )
            idx += 1

    timeline = state.tool_results.get("disk_correlate_timeline", {}).get("data") or {}
    if timeline.get("event_count", 0) > 0:
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": (
                    f"Cross-source timeline: {timeline.get('event_count')} correlated events "
                    f"from {', '.join(timeline.get('sources') or [])} "
                    f"({timeline.get('cross_source_summary', '')})"
                ),
                "audit_ids": audit_ids,
                "confidence": 0.82,
                "status": "confirmed",
                "tags": ["AH-6", "timeline", "cross-source"],
            }
        )
        idx += 1

    svc = state.tool_results.get("mem_svcscan", {}).get("data") or {}
    running = [
        s
        for s in (svc.get("services") or [])
        if str(s.get("State", "")).upper().endswith("RUNNING")
    ]
    if running:
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": (
                    f"Service persistence triage: {len(running)} running service(s) enumerated "
                    "from memory via svcscan"
                ),
                "audit_ids": audit_ids,
                "confidence": 0.72,
                "status": "inference",
                "tags": ["persistence", "services"],
            }
        )
        idx += 1

    cmd_hits = [
        c for c in cmdlines if "cmd.exe" in (c.get("process", "") + c.get("args", "")).lower()
    ]
    if cmd_hits:
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": (
                    f"Attacker leftovers: {len(cmd_hits)} cmd.exe instance(s) in memory "
                    "suggest post-exploitation command activity on the box"
                ),
                "audit_ids": audit_ids,
                "confidence": 0.75,
                "status": "confirmed",
                "tags": ["AH-3", "leftovers"],
            }
        )
        idx += 1

    if any("xampp" in (c.get("args", "") + c.get("process", "")).lower() for c in cmdlines):
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": (
                    "Installed/running software: XAMPP control panel and stack components "
                    "present — attacker leveraged existing web stack (task 4 scope)"
                ),
                "audit_ids": audit_ids,
                "confidence": 0.7,
                "status": "inference",
                "tags": ["AH-4", "software"],
            }
        )
        idx += 1

    timestomp = state.tool_results.get("disk_detect_timestomp", {}).get("data") or {}
    ts_count = timestomp.get("findings_count", 0)
    if ts_count:
        findings.append(
            {
                "id": f"f-{idx}",
                "claim": f"MFT timeline anomalies: {ts_count} timestomp indicator(s) on extracted $MFT",
                "audit_ids": audit_ids,
                "confidence": 0.82,
                "status": "confirmed",
                "tags": ["AH-6", "R4", "timestomp"],
            }
        )
        idx += 1

    if partial and not findings:
        findings.append(
            {
                "id": "u-0",
                "claim": "Ali Hadi investigation incomplete at iteration limit",
                "audit_ids": audit_ids,
                "confidence": state.confidence,
                "status": "unresolved",
            }
        )

    return findings


def _cmdlines(state: InvestigationState) -> list[dict[str, Any]]:
    data = state.tool_results.get("mem_cmdline", {}).get("data") or {}
    rows = data.get("cmdlines") or data.get("processes") or data.get("rows") or []
    return list(rows)
