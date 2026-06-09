"""Linux log and persistence MCP tools."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.paths import resolve_linux_log_path, resolve_readonly_file

SUSPICIOUS_PATTERNS = (
    re.compile(r"curl\s+.*\|\s*bash", re.I),
    re.compile(r"wget\s+.*\|\s*sh", re.I),
    re.compile(r"authorized_keys", re.I),
    re.compile(r"history\s+-c", re.I),
    re.compile(r"chmod\s+\+x", re.I),
    re.compile(r"/tmp/", re.I),
)

CRON_SUSPICIOUS = re.compile(r"(curl|wget|bash|/tmp/|\.sh\b)", re.I)


def _read_lines(path: Path, max_lines: int) -> list[str]:
    lines: list[str] = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            lines.append(line.rstrip("\n"))
            if len(lines) >= max_lines:
                break
    return lines


def _cap(data: dict[str, Any], key: str, max_records: int) -> dict[str, Any]:
    rows = data.get(key) or []
    total = len(rows)
    if total > max_records:
        data["truncated"] = True
        data["record_count"] = total
        data[key] = rows[:max_records]
    else:
        data["truncated"] = False
        data["record_count"] = total
    return data


def linux_auth_log(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse Linux auth/secure log for failed logins and remote access."""
    args = {"case_id": case_id, "artifact_relpath": artifact_relpath, "max_records": max_records}

    def execute() -> dict[str, Any]:
        path = resolve_linux_log_path(artifact_relpath)
        args["artifact_path"] = str(path)
        events: list[dict[str, Any]] = []
        for line in _read_lines(path, max_records):
            lower = line.lower()
            if "failed password" in lower or "accepted password" in lower or "invalid user" in lower:
                events.append({"line": line, "kind": "auth"})
            elif "sudo:" in lower or "session opened" in lower:
                events.append({"line": line, "kind": "session"})
        payload = {
            "source": str(path),
            "parser": "linux-auth-log",
            "events": events,
            "event_count": len(events),
        }
        return _cap(payload, "events", max_records)

    return run_audited_tool(case_id=case_id, tool="linux_auth_log", args=args, iteration=iteration, execute=execute)


def linux_syslog(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse syslog/messages for service and kernel anomalies."""
    args = {"case_id": case_id, "artifact_relpath": artifact_relpath, "max_records": max_records}

    def execute() -> dict[str, Any]:
        path = resolve_linux_log_path(artifact_relpath)
        args["artifact_path"] = str(path)
        events: list[dict[str, Any]] = []
        for line in _read_lines(path, max_records):
            if any(token in line.lower() for token in ("error", "warning", "segfault", "killed process")):
                events.append({"line": line})
        payload = {
            "source": str(path),
            "parser": "linux-syslog",
            "events": events,
            "event_count": len(events),
        }
        return _cap(payload, "events", max_records)

    return run_audited_tool(case_id=case_id, tool="linux_syslog", args=args, iteration=iteration, execute=execute)


def linux_bash_history(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 500,
) -> dict:
    """Parse bash history for suspicious command patterns."""
    args = {"case_id": case_id, "artifact_relpath": artifact_relpath, "max_records": max_records}

    def execute() -> dict[str, Any]:
        path = resolve_readonly_file(artifact_relpath)
        args["artifact_path"] = str(path)
        hits: list[dict[str, Any]] = []
        for line in _read_lines(path, max_records):
            stripped = line.lstrip("#").strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern.search(stripped):
                    hits.append({"command": stripped, "pattern": pattern.pattern})
                    break
        payload = {
            "source": str(path),
            "parser": "linux-bash-history",
            "hits": hits,
            "hit_count": len(hits),
        }
        return _cap(payload, "hits", max_records)

    return run_audited_tool(
        case_id=case_id, tool="linux_bash_history", args=args, iteration=iteration, execute=execute
    )


def linux_cron(
    case_id: str,
    artifact_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 200,
) -> dict:
    """Parse cron/spool/crontab files for suspicious scheduled commands."""
    args = {"case_id": case_id, "artifact_relpath": artifact_relpath, "max_records": max_records}

    def execute() -> dict[str, Any]:
        path = resolve_readonly_file(artifact_relpath)
        args["artifact_path"] = str(path)
        entries: list[dict[str, Any]] = []
        for line in _read_lines(path, max_records):
            if line.strip().startswith("#") or not line.strip():
                continue
            if CRON_SUSPICIOUS.search(line):
                entries.append({"entry": line.strip()})
        payload = {
            "source": str(path),
            "parser": "linux-cron",
            "entries": entries,
            "entry_count": len(entries),
        }
        return _cap(payload, "entries", max_records)

    return run_audited_tool(case_id=case_id, tool="linux_cron", args=args, iteration=iteration, execute=execute)


def linux_persistence(
    case_id: str,
    search_root_relpath: str,
    *,
    iteration: int = 0,
    max_records: int = 100,
) -> dict:
    """Scan a Linux evidence subtree for persistence indicators (cron, bashrc, profile.d)."""
    args = {"case_id": case_id, "search_root_relpath": search_root_relpath, "max_records": max_records}

    def execute() -> dict[str, Any]:
        from postmortem_mcp.paths import resolve_case_directory

        root = resolve_case_directory(search_root_relpath)
        args["search_root"] = str(root)
        findings: list[dict[str, Any]] = []
        patterns = ("crontab", "cron.d", "bashrc", "profile", "bash_history", "systemd")
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            name = path.name.lower()
            if not any(p in name or p in str(path).lower() for p in patterns):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines()[:200]:
                if CRON_SUSPICIOUS.search(line) or any(p.search(line) for p in SUSPICIOUS_PATTERNS):
                    findings.append(
                        {
                            "path": str(path.relative_to(root)),
                            "line": line.strip()[:500],
                        }
                    )
                    if len(findings) >= max_records:
                        break
            if len(findings) >= max_records:
                break
        return {
            "source": str(root),
            "parser": "linux-persistence-scan",
            "findings": findings,
            "finding_count": len(findings),
        }

    return run_audited_tool(
        case_id=case_id, tool="linux_persistence", args=args, iteration=iteration, execute=execute
    )
