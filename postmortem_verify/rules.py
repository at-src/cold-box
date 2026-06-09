"""Verifier rule implementations."""

from __future__ import annotations

import os
from typing import Any

from postmortem_mcp.timestomp import detect_timestomp_rows
from postmortem_verify.models import VerifyContext, _connection_pid
from postmortem_verify.models import RuleResult


def _process_ref(proc: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "process",
        "pid": proc.get("pid"),
        "name": proc.get("name") or proc.get("process") or proc.get("Image"),
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


def _normalize_exe(name: str) -> str:
    base = os.path.basename(name.strip()).lower()
    if base.endswith(".exe"):
        return base
    return base


def _process_exe_name(proc: dict[str, Any]) -> str | None:
    raw = proc.get("name") or proc.get("process") or proc.get("Image") or proc.get("image")
    if not raw:
        return None
    return _normalize_exe(str(raw))


def _amcache_executables(records: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for row in records:
        for key in ("FullPath", "Path", "path", "FileName", "file_name", "Name", "name"):
            value = row.get(key)
            if value:
                names.add(_normalize_exe(str(value)))
    return names


def _prefetch_executables(entries: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for entry in entries:
        exe = entry.get("executable") or entry.get("Executable")
        if exe:
            names.add(_normalize_exe(str(exe)))
    return names


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

    pslist_by_pid = {proc["pid"]: proc for proc in ctx.pslist_processes if "pid" in proc}

    pslist_pids = set(pslist_by_pid)

    hidden: list[dict[str, Any]] = []
    for proc in ctx.psscan_processes:
        pid = proc.get("pid")
        if pid is None:
            continue
        if pid not in pslist_pids:
            hidden.append({"reason": "absent_from_pslist", "process": proc})
            continue

        listed = pslist_by_pid[pid]
        listed_name = listed.get("name") or listed.get("process")
        proc_name = proc.get("name") or proc.get("process")
        if listed_name != proc_name:
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


def rule_r2_no_execution_trail(ctx: VerifyContext) -> RuleResult:
    """R2: process in memory with no prefetch and no amcache trail for its binary."""
    if not ctx.pslist_processes:
        return RuleResult("R2", "no_execution_trail", "skipped", "pslist missing", [])
    if ctx.amcache_records is None and ctx.prefetch_entries is None:
        return RuleResult(
            "R2",
            "no_execution_trail",
            "skipped",
            "amcache and prefetch inputs missing",
            [],
        )

    amcache_names = _amcache_executables(ctx.amcache_records or [])
    prefetch_names = _prefetch_executables(ctx.prefetch_entries or [])

    untrailed: list[dict[str, Any]] = []
    for proc in ctx.pslist_processes:
        exe = _process_exe_name(proc)
        if not exe or not exe.endswith(".exe"):
            continue
        if exe in {"system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe"}:
            continue
        if exe in amcache_names or exe in prefetch_names:
            continue
        untrailed.append(proc)

    sources: list[dict[str, Any]] = []
    for tool, audit_id, source in (
        ("mem_pslist", ctx.pslist_audit_id, ctx.pslist_source),
        ("disk_parse_amcache", ctx.amcache_audit_id, ctx.amcache_source),
        ("disk_parse_prefetch", ctx.prefetch_audit_id, ctx.prefetch_source),
    ):
        ref = _audit_ref(audit_id, tool, source)
        if ref:
            sources.append(ref)
    for proc in untrailed:
        sources.append(_process_ref(proc))

    if untrailed:
        names = ", ".join(sorted({_process_exe_name(p) or "?" for p in untrailed})[:5])
        return RuleResult(
            "R2",
            "no_execution_trail",
            "contradiction",
            f"{len(untrailed)} process(es) in memory without prefetch/amcache trail ({names})",
            sources,
        )

    return RuleResult(
        "R2",
        "no_execution_trail",
        "pass",
        f"All checked processes have prefetch or amcache execution trail",
        sources,
    )


def rule_r7_memory_injection(ctx: VerifyContext) -> RuleResult:
    """R7: malfind reports injected/RWX memory regions."""
    count = ctx.malfind_finding_count
    if ctx.malfind_findings and not count:
        count = len(ctx.malfind_findings)
    if not count:
        return RuleResult(
            "R7",
            "memory_injection",
            "skipped",
            "malfind output missing",
            [],
        )

    sources: list[dict[str, Any]] = []
    audit = _audit_ref(ctx.malfind_audit_id, "mem_malfind", None)
    if audit:
        sources.append(audit)
    sources.append({"type": "malfind", "finding_count": count})

    return RuleResult(
        "R7",
        "memory_injection",
        "contradiction",
        f"{count} injected/RWX memory region(s) detected by malfind",
        sources,
    )


def rule_r3_phantom_logon(ctx: VerifyContext) -> RuleResult:
    """R3: successful logon in security events with no matching memory session."""
    if not ctx.security_events:
        return RuleResult("R3", "phantom_logon", "skipped", "security event input missing", [])
    if not ctx.pslist_processes:
        return RuleResult("R3", "phantom_logon", "skipped", "pslist missing", [])

    memory_sessions: set[str] = set()
    for proc in ctx.pslist_processes:
        sid = proc.get("session_id")
        if sid is not None and str(sid).strip() not in {"", "0"}:
            memory_sessions.add(str(sid))

    phantoms: list[dict[str, Any]] = []
    for event in ctx.security_events:
        if int(event.get("event_id", 0)) != 4624:
            continue
        logon_type = int(event.get("logon_type", 0))
        if logon_type not in {2, 3, 10}:
            continue
        session_id = event.get("session_id")
        if session_id is None:
            continue
        sid = str(session_id)
        if sid not in memory_sessions:
            phantoms.append(event)

    sources: list[dict[str, Any]] = []
    sec_ref = _audit_ref(ctx.security_audit_id, "disk_parse_evtx", ctx.security_source)
    ps_ref = _audit_ref(ctx.pslist_audit_id, "mem_pslist", ctx.pslist_source)
    if sec_ref:
        sources.append(sec_ref)
    if ps_ref:
        sources.append(ps_ref)
    for event in phantoms:
        sources.append({"type": "logon_event", **event})

    if phantoms:
        users = ", ".join(str(e.get("user", "?")) for e in phantoms[:5])
        return RuleResult(
            "R3",
            "phantom_logon",
            "contradiction",
            f"{len(phantoms)} successful logon(s) with no memory session ({users})",
            sources,
        )

    return RuleResult(
        "R3",
        "phantom_logon",
        "pass",
        "All checked logons have matching memory session activity",
        sources,
    )


def rule_r4_timestomp(ctx: VerifyContext) -> RuleResult:
    """R4: MFT $SI timestamp predates or contradicts $FN for the same entry."""
    findings: list[dict[str, Any]] = []
    if ctx.timestomp_findings is not None:
        findings = list(ctx.timestomp_findings)
    elif ctx.mft_records:
        findings = detect_timestomp_rows(
            ctx.mft_records,
            tolerance_seconds=ctx.timestomp_tolerance_seconds,
        )
    else:
        return RuleResult("R4", "timestomp", "skipped", "MFT/timestomp inputs missing", [])
    sources: list[dict[str, Any]] = []
    audit = _audit_ref(ctx.mft_audit_id, "disk_detect_timestomp", ctx.mft_source)
    if audit:
        sources.append(audit)
    for item in findings[:10]:
        sources.append({"type": "mft_anomaly", **item})

    if findings:
        return RuleResult(
            "R4",
            "timestomp",
            "contradiction",
            f"{len(findings)} MFT timestomp anomaly/anomalies detected",
            sources,
        )

    return RuleResult(
        "R4",
        "timestomp",
        "pass",
        f"No timestomp anomalies in scanned MFT evidence",
        sources,
    )


def rule_r5_ghost_binary(ctx: VerifyContext) -> RuleResult:
    """R5: prefetch references an executable absent from the evidence tree."""
    if not ctx.prefetch_entries:
        return RuleResult("R5", "ghost_binary", "skipped", "prefetch input missing", [])
    if not ctx.evidence_basenames:
        return RuleResult("R5", "ghost_binary", "skipped", "evidence file index missing", [])

    ghosts: list[dict[str, Any]] = []
    for entry in ctx.prefetch_entries:
        exe = entry.get("executable") or entry.get("Executable")
        if not exe:
            continue
        normalized = _normalize_exe(str(exe))
        if normalized not in ctx.evidence_basenames:
            ghosts.append({"executable": exe, "normalized": normalized, "prefetch": entry})

    sources: list[dict[str, Any]] = []
    audit = _audit_ref(ctx.prefetch_audit_id, "disk_parse_prefetch", ctx.prefetch_source)
    if audit:
        sources.append(audit)
    for ghost in ghosts:
        sources.append({"type": "ghost_binary", **ghost})

    if ghosts:
        names = ", ".join(item["executable"] for item in ghosts[:5])
        return RuleResult(
            "R5",
            "ghost_binary",
            "contradiction",
            f"{len(ghosts)} prefetch executable(s) missing on disk ({names})",
            sources,
        )

    return RuleResult(
        "R5",
        "ghost_binary",
        "pass",
        f"All {len(ctx.prefetch_entries)} prefetch executable(s) exist in evidence",
        sources,
    )


def rule_r6_orphan_connection(ctx: VerifyContext) -> RuleResult:
    """R6: netscan socket owner PID absent from pslist."""
    if not ctx.netscan_connections:
        return RuleResult("R6", "orphan_connection", "skipped", "netscan connections missing", [])
    if not ctx.pslist_processes:
        return RuleResult("R6", "orphan_connection", "skipped", "pslist missing", [])

    pslist_pids = {proc.get("pid") for proc in ctx.pslist_processes if proc.get("pid") is not None}
    orphans: list[dict[str, Any]] = []
    for conn in ctx.netscan_connections:
        pid = _connection_pid(conn)
        if pid is None or pid <= 0:
            continue
        if pid not in pslist_pids:
            orphans.append(conn)

    sources: list[dict[str, Any]] = []
    for tool, audit_id, source in (
        ("mem_netscan", ctx.netscan_audit_id, ctx.netscan_source),
        ("mem_pslist", ctx.pslist_audit_id, ctx.pslist_source),
    ):
        ref = _audit_ref(audit_id, tool, source)
        if ref:
            sources.append(ref)
    for conn in orphans[:10]:
        sources.append({"type": "connection", **conn})

    if orphans:
        pids = ", ".join(str(_connection_pid(c)) for c in orphans[:5])
        return RuleResult(
            "R6",
            "orphan_connection",
            "contradiction",
            f"{len(orphans)} connection(s) owned by PID(s) absent from pslist ({pids})",
            sources,
        )

    return RuleResult(
        "R6",
        "orphan_connection",
        "pass",
        f"All {len(ctx.netscan_connections)} netscan connection(s) reconcile with pslist",
        sources,
    )


def rule_r8_dns_exfil(ctx: VerifyContext) -> RuleResult:
    """R8: high-volume or high-entropy DNS queries suggest tunneling/exfil."""
    queries = ctx.dns_queries or []
    if not queries:
        return RuleResult("R8", "dns_exfil", "skipped", "DNS query input missing", [])

    domain_counts: dict[str, int] = {}
    long_labels = 0
    for row in queries:
        q = str(row.get("query") or row.get("domain") or "")
        if not q:
            continue
        base = q.lower().rstrip(".")
        domain_counts[base] = domain_counts.get(base, 0) + 1
        if len(base) > 48 or base.count(".") >= 5:
            long_labels += 1

    sources: list[dict[str, Any]] = []
    if ctx.dns_audit_id:
        sources.append(_audit_ref(ctx.dns_audit_id, "net_dns_extract", ctx.dns_source))

    hot = max(domain_counts.values()) if domain_counts else 0
    hot_domain = next((d for d, c in domain_counts.items() if c == hot), "?")

    if hot >= 10 or long_labels >= 3:
        detail = (
            f"DNS anomaly: {hot} queries to {hot_domain!r}, {long_labels} long/high-entropy labels"
        )
        sources.append({"type": "dns", "top_domain": hot_domain, "count": hot})
        return RuleResult("R8", "dns_exfil", "contradiction", detail, sources)

    return RuleResult(
        "R8",
        "dns_exfil",
        "pass",
        f"No DNS exfil pattern in {len(queries)} queries",
        sources,
    )


def rule_r9_http_beacon(ctx: VerifyContext) -> RuleResult:
    """R9: periodic same-size HTTP requests suggest beaconing."""
    periodic = ctx.http_periodic or []
    if not periodic and not ctx.http_requests:
        return RuleResult("R9", "http_beacon", "skipped", "HTTP request input missing", [])

    sources: list[dict[str, Any]] = []
    if ctx.http_audit_id:
        sources.append(_audit_ref(ctx.http_audit_id, "net_http_extract", ctx.http_source))

    if periodic:
        item = periodic[0]
        host = item.get("host", "?")
        size = item.get("size", "?")
        count = item.get("count", len(periodic))
        sources.append({"type": "http_beacon", **item})
        return RuleResult(
            "R9",
            "http_beacon",
            "contradiction",
            f"{count} same-size HTTP request(s) to {host} (size={size})",
            sources,
        )

    return RuleResult("R9", "http_beacon", "pass", "No periodic same-size HTTP beacon pattern", sources)


def rule_r10_linux_persistence(ctx: VerifyContext) -> RuleResult:
    """R10: Linux persistence indicators in cron/bash/history scans."""
    findings = ctx.linux_persistence_findings or []
    if not findings:
        return RuleResult("R10", "linux_persistence", "skipped", "Linux persistence input missing", [])

    sources: list[dict[str, Any]] = []
    if ctx.linux_audit_id:
        sources.append(_audit_ref(ctx.linux_audit_id, "linux_persistence", ctx.linux_source))

    suspicious = [f for f in findings if isinstance(f, dict)]
    for item in suspicious[:10]:
        sources.append({"type": "linux_persistence", **item})

    if suspicious:
        sample = suspicious[0].get("line") or suspicious[0].get("command") or "?"
        return RuleResult(
            "R10",
            "linux_persistence",
            "contradiction",
            f"{len(suspicious)} Linux persistence indicator(s) ({str(sample)[:60]})",
            sources,
        )

    return RuleResult("R10", "linux_persistence", "pass", "No Linux persistence indicators", sources)
