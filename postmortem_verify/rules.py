"""Verifier rule implementations."""

from __future__ import annotations

import os
from typing import Any

from postmortem_mcp.timestomp import detect_timestomp_rows
from postmortem_verify.known_good import (
    is_known_good_binary,
    is_known_good_path,
    is_suspicious_location,
    is_user_writable_path,
)
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
        logon_type_raw = event.get("logon_type", 0)
        try:
            logon_type = int(logon_type_raw or 0)
        except (TypeError, ValueError):
            logon_type = 0
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
        if normalized in ctx.evidence_basenames:
            continue
        # The verifier's on-disk index is only the extracted forensic artifacts,
        # not the full filesystem, so "absent" is a weak signal. Suppress
        # standard OS / first-party Microsoft binaries to avoid declaring
        # benign hosts compromised; surface only genuinely non-standard ones.
        if is_known_good_binary(normalized):
            continue
        lower = normalized.lower()
        if any(h in lower for h in ("gnupg", "veracrypt", "truecrypt", "bitlocker", "7z", "7-zip")):
            continue
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


def rule_r11_ghost_service(ctx: VerifyContext) -> RuleResult:
    """R11: service ImagePath references a binary absent from the evidence tree."""
    services = ctx.service_entries or []
    if not services:
        return RuleResult("R11", "ghost_service", "skipped", "service list input missing", [])
    if not ctx.evidence_basenames:
        return RuleResult("R11", "ghost_service", "skipped", "evidence file index missing", [])

    def _ghost_priority(svc: dict[str, Any]) -> int:
        name = str(svc.get("name", "")).lower()
        binary = str(svc.get("binary", "")).lower().replace("/", "\\")
        score = 0
        if "vmware" in name or "vmware" in binary:
            score += 12
        if "vmtools" in binary and "program files" not in binary:
            score += 10
        if "\\windows\\" in binary and "system32" not in binary:
            score += 6
        if is_suspicious_location(binary):
            score += 4
        if is_user_writable_path(binary) and not is_known_good_path(binary):
            score += 10
        return score

    ghosts: list[dict[str, Any]] = []
    for svc in services:
        basename = svc.get("binary_basename") or ""
        if not basename or not basename.endswith(".exe"):
            continue
        if basename in ctx.evidence_basenames:
            continue
        if basename in {"svchost.exe", "services.exe", "lsass.exe", "csrss.exe"}:
            continue
        if is_known_good_binary(basename):
            continue
        raw_path = str(svc.get("binary") or svc.get("imagepath") or "")
        if raw_path and is_known_good_path(raw_path):
            continue
        ghosts.append(svc)

    ghosts.sort(key=_ghost_priority, reverse=True)

    sources: list[dict[str, Any]] = []
    audit = _audit_ref(ctx.services_audit_id, "reg_services", None) or _audit_ref(
        ctx.services_audit_id, "mem_svcscan", None
    )
    if audit:
        sources.append(audit)
    for ghost in ghosts[:10]:
        sources.append({"type": "ghost_service", **ghost})

    serious = [g for g in ghosts if _ghost_priority(g) >= 10]
    if ghosts and not serious:
        return RuleResult(
            "R11",
            "ghost_service",
            "pass",
            f"{len(ghosts)} service(s) absent from artifact index (partial extract — no high-confidence ghosts)",
            sources,
        )

    if serious:
        names = ", ".join(str(g.get("name", "?")) for g in serious[:5])
        return RuleResult(
            "R11",
            "ghost_service",
            "contradiction",
            f"{len(serious)} service(s) reference missing binary on disk ({names})",
            sources,
        )

    return RuleResult(
        "R11",
        "ghost_service",
        "pass",
        f"All {len(services)} checked service(s) reconcile with evidence",
        sources,
    )


def rule_r12_usb_initial_access(ctx: VerifyContext) -> RuleResult:
    """R12: diagnostic USB / IP-KVM device inserted (setupapi.dev.log)."""
    devices = ctx.setupapi_devices or []
    if not devices:
        return RuleResult("R12", "usb_initial_access", "skipped", "setupapi USB input missing", [])

    suspicious = [d for d in devices if d.get("suspicious_kvm")]
    if not suspicious:
        suspicious = devices

    sources: list[dict[str, Any]] = []
    audit = _audit_ref(ctx.setupapi_audit_id, "disk_parse_setupapi", None)
    if audit:
        sources.append(audit)
    for device in suspicious[:10]:
        sources.append({"type": "usb_device", **device})

    kvm = [d for d in suspicious if d.get("suspicious_kvm")]
    if kvm:
        sample = kvm[0]
        detail = (
            f"IP-KVM/diagnostic USB inserted ({sample.get('device_id')}) "
            f"at {sample.get('timestamp', '?')}"
        )
        return RuleResult("R12", "usb_initial_access", "contradiction", detail, sources)

    return RuleResult(
        "R12",
        "usb_initial_access",
        "pass",
        f"No suspicious KVM USB pattern in {len(devices)} device(s)",
        sources,
    )


def rule_r13_scheduled_task(ctx: VerifyContext) -> RuleResult:
    """R13: suspicious Windows scheduled task persistence."""
    tasks = ctx.scheduled_tasks or []
    if not tasks:
        return RuleResult("R13", "scheduled_task", "skipped", "scheduled task input missing", [])

    suspicious = [t for t in tasks if t.get("suspicious")]
    sources: list[dict[str, Any]] = []
    audit = _audit_ref(ctx.scheduled_task_audit_id, "disk_parse_scheduled_tasks", None)
    if audit:
        sources.append(audit)
    for task in suspicious[:10]:
        sources.append({"type": "scheduled_task", **task})

    if suspicious:
        sample = suspicious[0]
        detail = (
            f"{len(suspicious)} suspicious scheduled task(s) "
            f"({sample.get('task_name')}: {str(sample.get('command', ''))[:60]})"
        )
        return RuleResult("R13", "scheduled_task", "contradiction", detail, sources)

    return RuleResult(
        "R13",
        "scheduled_task",
        "pass",
        f"No suspicious scheduled tasks in {len(tasks)} task(s)",
        sources,
    )


def rule_r14_suspicious_ioc(ctx: VerifyContext) -> RuleResult:
    """R14: IOC string search hits suspicious web/shell/cmd patterns on disk."""
    hits = ctx.search_hits or []
    if not hits:
        return RuleResult("R14", "suspicious_ioc", "skipped", "artifact search input missing", [])

    suspicious: list[dict[str, Any]] = []
    for hit in hits:
        blob = f"{hit.get('pattern', '')} {hit.get('snippet', '')} {hit.get('path', '')}".lower()
        if any(
            token in blob
            for token in (
                "cmd.exe",
                "powershell",
                "php",
                "shell",
                "xampp",
                "apache",
                "eval(",
                "webshell",
                ".php",
            )
        ):
            suspicious.append(hit)

    sources: list[dict[str, Any]] = []
    audit = _audit_ref(ctx.search_audit_id, "disk_search_artifacts", None)
    if audit:
        sources.append(audit)
    for hit in suspicious[:10]:
        sources.append({"type": "search_hit", **hit})

    if suspicious:
        sample = suspicious[0]
        return RuleResult(
            "R14",
            "suspicious_ioc",
            "contradiction",
            f"{len(suspicious)} suspicious IOC hit(s) in evidence ({sample.get('pattern', '?')})",
            sources,
        )

    return RuleResult(
        "R14",
        "suspicious_ioc",
        "pass",
        f"No suspicious IOC patterns in {len(hits)} search hit(s)",
        sources,
    )


def rule_r16_unusual_execution(ctx: VerifyContext) -> RuleResult:
    """R16: non-standard binary execution from amcache, prefetch, or EVTX synthesis."""
    records: list[dict[str, Any]] = []
    if ctx.amcache_records:
        records.extend(ctx.amcache_records)
    if ctx.prefetch_entries:
        for entry in ctx.prefetch_entries:
            exe = entry.get("executable") or entry.get("Executable")
            if not exe:
                continue
            records.append(
                {
                    "FullPath": exe,
                    "LastRun": entry.get("last_run") or entry.get("LastRun"),
                    "source": "prefetch",
                }
            )

    if not records:
        return RuleResult(
            "R16",
            "unusual_execution",
            "skipped",
            "execution history inputs missing",
            [],
        )

    suspicious_hints = ("remote", "admin", "stage", "loader", "cold", "backdoor", "helper")

    unusual: list[dict[str, Any]] = []
    for row in records:
        raw_path = str(row.get("FullPath") or row.get("Path") or "")
        exe = _normalize_exe(
            str(
                row.get("FullPath")
                or row.get("Path")
                or row.get("FileName")
                or row.get("executable")
                or row.get("name")
                or ""
            )
        )
        if not exe or not exe.endswith(".exe"):
            continue
        # Suppress standard OS / first-party Microsoft binaries and binaries
        # running from trusted install locations (system32, Program Files,
        # OneDrive/Edge/Teams app dirs) — these are the dominant false positives.
        if is_known_good_binary(exe) or is_known_good_path(raw_path):
            continue
        lower = exe.lower()
        if any(hint in lower for hint in suspicious_hints):
            unusual.append({**row, "executable": exe})
            continue
        # Otherwise only surface unknown binaries executing from user-writable /
        # staging locations (not the broad "anything under users\\" heuristic).
        if is_user_writable_path(raw_path) or is_suspicious_location(raw_path):
            unusual.append({**row, "executable": exe})

    sources: list[dict[str, Any]] = []
    for tool, audit_id, source in (
        ("disk_parse_amcache", ctx.amcache_audit_id, ctx.amcache_source),
        ("reg_amcache", ctx.amcache_audit_id, ctx.amcache_source),
        ("disk_parse_prefetch", ctx.prefetch_audit_id, ctx.prefetch_source),
    ):
        ref = _audit_ref(audit_id, tool, source)
        if ref:
            sources.append(ref)
            break
    for item in unusual[:10]:
        sources.append({"type": "execution_record", **item})

    if unusual:
        sample = unusual[0].get("executable", "?")
        when = unusual[0].get("LastRun") or unusual[0].get("time_created") or "?"
        return RuleResult(
            "R16",
            "unusual_execution",
            "contradiction",
            f"Unusual binary execution: {sample} (last seen {when})",
            sources,
        )

    return RuleResult(
        "R16",
        "unusual_execution",
        "pass",
        f"No unusual execution in {len(records)} record(s)",
        sources,
    )


def rule_r20_structured_log_alert(ctx: VerifyContext) -> RuleResult:
    """R20: security-relevant events in JSONL/NDJSON application logs."""
    events = ctx.structured_log_events or []
    if not events:
        return RuleResult(
            "R20",
            "structured_log_alert",
            "skipped",
            "structured log input missing",
            [],
        )

    sources: list[dict[str, Any]] = []
    audit = _audit_ref(ctx.structured_log_audit_id, "logs_parse_structured", None)
    if audit:
        sources.append(audit)
    for event in events[:10]:
        sources.append({"type": "structured_event", **event})

    sample = events[0]
    detail_key = str(sample.get("message") or sample.get("event") or sample.get("raw_line") or "?")[:80]
    return RuleResult(
        "R20",
        "structured_log_alert",
        "contradiction",
        f"{len(events)} security-relevant structured log event(s) ({detail_key})",
        sources,
    )


def rule_r19_web_attack(ctx: VerifyContext) -> RuleResult:
    """R19: web access-log attacks and/or webshell upload artifacts."""
    access_hits = ctx.web_suspicious_requests or []
    artifact_hits = ctx.web_artifact_indicators or []

    if not access_hits and not artifact_hits:
        return RuleResult(
            "R19",
            "web_attack",
            "skipped",
            "web log/artifact input missing",
            [],
        )

    sources: list[dict[str, Any]] = []
    for tool, audit_id in (
        ("web_parse_access_log", ctx.web_access_audit_id),
        ("web_inspect_artifact", ctx.web_inspect_audit_id),
    ):
        ref = _audit_ref(audit_id, tool, None)
        if ref:
            sources.append(ref)

    combined = access_hits + artifact_hits
    for item in combined[:10]:
        sources.append({"type": "web_attack", **item})

    if access_hits:
        sample = access_hits[0]
        attack = sample.get("attack_type") or sample.get("pattern") or "attack"
        req = str(sample.get("request") or sample.get("line") or "")[:70]
        detail = f"{len(access_hits)} web attack request(s) ({attack}: {req})"
    else:
        sample = artifact_hits[0]
        detail = f"{len(artifact_hits)} webshell indicator(s) in {sample.get('path', 'upload')}"

    if access_hits and artifact_hits:
        detail = (
            f"Web compromise: {len(access_hits)} attack request(s) and "
            f"{len(artifact_hits)} webshell indicator(s)"
        )

    return RuleResult("R19", "web_attack", "contradiction", detail, sources)


def rule_r18_cmd_leftover(ctx: VerifyContext) -> RuleResult:
    """R18: suspicious cmd.exe / web-stack command lines in memory."""
    entries = ctx.cmdline_entries or []
    if not entries:
        return RuleResult("R18", "cmd_leftover", "skipped", "memory cmdline input missing", [])

    cmd_hits: list[dict[str, Any]] = []
    stack_hits: list[dict[str, Any]] = []
    for row in entries:
        proc = str(row.get("process") or row.get("name") or row.get("Image") or "").lower()
        args = str(row.get("args") or row.get("cmdline") or row.get("CommandLine") or "")
        lower_args = args.lower()
        if proc in {"cmd.exe", "cmd"}:
            cmd_hits.append(row)
        if any(token in lower_args for token in ("xampp", "apache", "httpd.exe", "php", "mysql")):
            stack_hits.append(row)

    suspicious = cmd_hits if len(cmd_hits) >= 2 else []
    if not suspicious and cmd_hits and stack_hits:
        suspicious = cmd_hits + stack_hits
    if not suspicious and stack_hits:
        suspicious = stack_hits

    sources: list[dict[str, Any]] = []
    audit = _audit_ref(ctx.cmdline_audit_id, "mem_cmdline", None) or _audit_ref(
        ctx.cmdline_audit_id, "mem_cmdscan", None
    )
    if audit:
        sources.append(audit)
    for item in suspicious[:10]:
        sources.append({"type": "cmdline", **item})

    if suspicious:
        sample = suspicious[0]
        proc = sample.get("process") or sample.get("name") or "cmd.exe"
        args = str(sample.get("args") or sample.get("cmdline") or "")[:80]
        return RuleResult(
            "R18",
            "cmd_leftover",
            "contradiction",
            f"{len(suspicious)} suspicious command-line artifact(s) ({proc}: {args})",
            sources,
        )

    return RuleResult(
        "R18",
        "cmd_leftover",
        "pass",
        f"No suspicious cmdline artifacts in {len(entries)} entry(ies)",
        sources,
    )


def rule_r15_timeline_correlation(ctx: VerifyContext) -> RuleResult:
    """R15: cross-source timeline merged multiple forensic sources."""
    events = ctx.timeline_events or []
    if not events:
        return RuleResult("R15", "timeline_correlation", "skipped", "timeline input missing", [])

    sources: list[dict[str, Any]] = []
    audit = _audit_ref(ctx.timeline_audit_id, "timeline_super", None) or _audit_ref(
        ctx.timeline_audit_id, "disk_correlate_timeline", None
    )
    if audit:
        sources.append(audit)

    by_source: dict[str, int] = {}
    for event in events:
        src = str(event.get("source") or "unknown")
        by_source[src] = by_source.get(src, 0) + 1
        if len(sources) < 12:
            sources.append({"type": "timeline_event", **event})

    if len(by_source) >= 2 or len(events) >= 5:
        auth_count = sum(1 for event in events if event.get("category") == "authentication")
        detail = (
            f"Cross-source timeline: {len(events)} event(s) from "
            + ", ".join(f"{k}={v}" for k, v in sorted(by_source.items()))
        )
        if auth_count:
            detail += f"; {auth_count} security logon event(s)"
        return RuleResult("R15", "timeline_correlation", "contradiction", detail, sources)

    return RuleResult(
        "R15",
        "timeline_correlation",
        "pass",
        f"Timeline has {len(events)} event(s) from {len(by_source)} source(s)",
        sources,
    )


def rule_r21_removable_storage(ctx: VerifyContext) -> RuleResult:
    """R21: removable USB mass-storage attributed to the host (data-exfil vector).

    Surfaces every device with vendor/product/serial so it can be tied back to a
    specific USBSTOR key. This is a confirmed *fact* (the device touched the host),
    not an assertion of malice — intent is decided downstream against the case
    narrative, so a lawful USB does not become a false MALICE call.
    """
    devices = ctx.usb_devices or []
    if not devices:
        return RuleResult("R21", "removable_storage", "skipped", "USB device input missing", [])

    sources: list[dict[str, Any]] = []
    audit = _audit_ref(ctx.usb_audit_id, "disk_parse_usb", ctx.usb_source)
    if audit:
        sources.append(audit)
    fields = ("vendor", "product", "serial", "friendly_name", "last_connected", "key_path")
    for device in devices[:10]:
        sources.append(
            {"type": "usb_device", **{k: device.get(k) for k in fields if device.get(k)}}
        )

    def _label(dev: dict[str, Any]) -> str:
        vendor = dev.get("vendor") or "?"
        product = dev.get("product") or ""
        serial = dev.get("serial") or "?"
        return f"{vendor} {product}".strip() + f" (SN {serial})"

    names = "; ".join(_label(d) for d in devices[:3])
    return RuleResult(
        "R21",
        "removable_storage",
        "contradiction",
        f"{len(devices)} removable USB mass-storage device(s) attributed to host ({names})",
        sources,
    )


def rule_r22_cleartext_identity(ctx: VerifyContext) -> RuleResult:
    """R22: cleartext webmail identity / anonymous-relay use enabling sender attribution.

    Network captures often expose a sender's real identity in cleartext: an
    authenticated webmail session, a plaintext e-mail address, or use of an
    anonymous remailer from an internal host. Correlating those to a source IP
    attributes anonymous activity to a real account. This is a *fact* about what
    the capture reveals, not an accusation — intent is decided downstream.
    """
    identities = ctx.web_identities or []
    if not identities:
        return RuleResult("R22", "cleartext_identity", "skipped", "HTTP identity input missing", [])

    # Attributable = used an anonymous relay, OR authenticated webmail + a real address.
    attributable = [
        ident
        for ident in identities
        if ident.get("anon_mailer_hosts")
        or (ident.get("auth_cookie") and ident.get("emails"))
    ]
    if not attributable:
        return RuleResult(
            "R22", "cleartext_identity", "pass", "No attributable cleartext identity exposed", []
        )

    sources: list[dict[str, Any]] = []
    audit = _audit_ref(ctx.http_audit_id, "net_http_extract", ctx.http_source)
    if audit:
        sources.append(audit)
    for ident in attributable[:5]:
        sources.append(
            {
                "type": "network_identity",
                "src_ip": ident.get("src_ip"),
                "emails": (ident.get("emails") or [])[:6],
                "webmail_hosts": ident.get("webmail_hosts") or [],
                "anon_mailer_hosts": ident.get("anon_mailer_hosts") or [],
                "auth_cookie": bool(ident.get("auth_cookie")),
            }
        )

    top = attributable[0]
    ip = top.get("src_ip", "?")
    relays = ", ".join(top.get("anon_mailer_hosts") or []) or "—"
    email = next(iter(top.get("emails") or []), "?")
    detail = (
        f"{len(attributable)} host(s) with attributable cleartext identity; "
        f"strongest: {ip} (relay(s): {relays}; identity: {email})"
    )
    return RuleResult("R22", "cleartext_identity", "contradiction", detail, sources)
