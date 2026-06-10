"""Cross-artifact timeline correlation and evidence search."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

TEXT_SUFFIXES = {
    ".txt",
    ".log",
    ".json",
    ".csv",
    ".md",
    ".xml",
    ".html",
    ".php",
    ".ini",
    ".conf",
    ".evtx",
    ".pf",
}
BINARY_SKIP_SUFFIXES = {".mem", ".raw", ".dmp", ".e01", ".img", ".vmdk", ".iso"}


def _parse_ts(raw: str | None) -> str | None:
    if not raw or raw in {"N/A", "-", ""}:
        return None
    return raw.strip()


def _evtx_events(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in records:
        eid = str(row.get("EventId") or row.get("Event ID") or row.get("Id") or "")
        ts = _parse_ts(
            str(row.get("TimeCreated") or row.get("Timestamp") or row.get("Created") or "")
        )
        user = str(row.get("TargetUserName") or row.get("SubjectUserName") or "")
        events.append(
            {
                "timestamp": ts,
                "source": "evtx",
                "category": "authentication" if eid in {"4624", "4625", "4648"} else "eventlog",
                "event_id": eid,
                "summary": f"Security event {eid}" + (f" user={user}" if user else ""),
                "detail": {k: v for k, v in row.items() if v and k in {
                    "EventId", "TimeCreated", "TargetUserName", "IpAddress", "LogonType",
                    "SubjectUserName", "WorkstationName",
                }},
            }
        )
    return events


def _mft_events(records: list[dict[str, Any]], *, max_rows: int = 200) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in records[:max_rows]:
        name = str(row.get("FileName") or row.get("ParentPath") or row.get("Name") or "")
        if not name:
            continue
        ts = _parse_ts(
            str(
                row.get("Created0x10")
                or row.get("LastModified0x10")
                or row.get("Created")
                or row.get("LastModified")
                or ""
            )
        )
        if not ts:
            continue
        events.append(
            {
                "timestamp": ts,
                "source": "mft",
                "category": "filesystem",
                "event_id": None,
                "summary": f"MFT activity: {name[:120]}",
                "detail": {"path": name[:200]},
            }
        )
    return events


def _memory_events(processes: list[dict[str, Any]], *, max_rows: int = 100) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for proc in processes[:max_rows]:
        name = str(proc.get("name") or proc.get("ImageFileName") or proc.get("process") or "")
        if not name:
            continue
        ts = _parse_ts(str(proc.get("create_time") or proc.get("CreateTime") or ""))
        if not ts or ts in {"N/A", "t", "-"}:
            events.append(
                {
                    "timestamp": None,
                    "source": "memory",
                    "category": "process",
                    "event_id": None,
                    "summary": f"Process in memory: {name} pid={proc.get('pid', proc.get('PID', '?'))}",
                    "detail": {
                        "pid": proc.get("pid", proc.get("PID")),
                        "ppid": proc.get("ppid", proc.get("PPID")),
                        "name": name,
                    },
                }
            )
            continue
        events.append(
            {
                "timestamp": ts,
                "source": "memory",
                "category": "process",
                "event_id": None,
                "summary": f"Process start: {name} pid={proc.get('pid', proc.get('PID', '?'))}",
                "detail": {
                    "pid": proc.get("pid", proc.get("PID")),
                    "ppid": proc.get("ppid", proc.get("PPID")),
                    "name": name,
                },
            }
        )
    return events


def _web_access_events(records: list[dict[str, Any]], *, max_rows: int = 100) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in records[:max_rows]:
        ts = _parse_ts(str(row.get("time") or row.get("timestamp") or ""))
        request = str(row.get("request") or row.get("line") or "")[:120]
        attack = row.get("attack_type") or row.get("pattern")
        summary = f"Web request: {request}"
        if attack:
            summary = f"Web attack ({attack}): {request[:80]}"
        events.append(
            {
                "timestamp": ts,
                "source": "web_log",
                "category": "web_attack" if attack else "web",
                "event_id": None,
                "summary": summary,
                "detail": row,
            }
        )
    return events


def _cmdline_timeline_events(records: list[dict[str, Any]], *, max_rows: int = 50) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in records[:max_rows]:
        proc = str(row.get("process") or row.get("name") or "?")
        args = str(row.get("args") or row.get("cmdline") or "")[:100]
        events.append(
            {
                "timestamp": None,
                "source": "cmdline",
                "category": "execution",
                "event_id": None,
                "summary": f"Memory cmdline: {proc} {args}",
                "detail": row,
            }
        )
    return events


def _setupapi_events(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in records:
        if not row.get("timestamp"):
            continue
        label = row.get("device_id") or f"VID_{row.get('vid')}&PID_{row.get('pid')}"
        events.append(
            {
                "timestamp": row.get("timestamp"),
                "source": "setupapi",
                "category": "usb",
                "event_id": None,
                "summary": f"USB device inserted: {label}",
                "detail": row,
            }
        )
    return events


def _task_events(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in records:
        events.append(
            {
                "timestamp": row.get("registered"),
                "source": "scheduled_task",
                "category": "persistence",
                "event_id": None,
                "summary": f"Scheduled task {row.get('task_name')}: {str(row.get('command', ''))[:80]}",
                "detail": row,
            }
        )
    return events


def build_correlated_timeline(
    *,
    evtx_records: list[dict[str, Any]] | None = None,
    mft_records: list[dict[str, Any]] | None = None,
    memory_processes: list[dict[str, Any]] | None = None,
    max_events: int = 300,
) -> dict[str, Any]:
    """Merge disk + memory artifacts into one sorted timeline with source counts."""
    events: list[dict[str, Any]] = []
    sources: list[str] = []

    if evtx_records:
        events.extend(_evtx_events(evtx_records))
        sources.append("evtx")
    if mft_records:
        events.extend(_mft_events(mft_records))
        sources.append("mft")
    if memory_processes:
        events.extend(_memory_events(memory_processes))
        sources.append("memory")

    dated = [e for e in events if e.get("timestamp")]
    undated = [e for e in events if not e.get("timestamp")]
    dated.sort(key=lambda e: e["timestamp"])

    merged = dated + undated
    truncated = len(merged) > max_events
    if truncated:
        merged = merged[:max_events]

    by_source = {src: sum(1 for e in merged if e["source"] == src) for src in sources}
    auth_events = [e for e in merged if e.get("category") == "authentication"]

    return {
        "sources": sources,
        "event_count": len(merged),
        "returned_count": len(merged),
        "truncated": truncated,
        "by_source": by_source,
        "authentication_events": len(auth_events),
        "events": merged,
        "cross_source_summary": (
            f"Correlated {len(sources)} source(s): "
            + ", ".join(f"{k}={v}" for k, v in by_source.items())
        ),
    }


def build_super_timeline(
    *,
    evtx_records: list[dict[str, Any]] | None = None,
    mft_records: list[dict[str, Any]] | None = None,
    memory_processes: list[dict[str, Any]] | None = None,
    setupapi_records: list[dict[str, Any]] | None = None,
    scheduled_tasks: list[dict[str, Any]] | None = None,
    shimcache_records: list[dict[str, Any]] | None = None,
    web_access_records: list[dict[str, Any]] | None = None,
    cmdline_records: list[dict[str, Any]] | None = None,
    max_events: int = 500,
) -> dict[str, Any]:
    """Cross-source super timeline merging disk, memory, USB, and persistence artifacts."""
    events: list[dict[str, Any]] = []
    sources: list[str] = []

    if evtx_records:
        events.extend(_evtx_events(evtx_records))
        sources.append("evtx")
    if mft_records:
        events.extend(_mft_events(mft_records))
        sources.append("mft")
    if memory_processes:
        mem_events = _memory_events(memory_processes)
        if mem_events:
            events.extend(mem_events)
            sources.append("memory")
    if setupapi_records:
        events.extend(_setupapi_events(setupapi_records))
        sources.append("setupapi")
    if scheduled_tasks:
        events.extend(_task_events(scheduled_tasks))
        sources.append("scheduled_task")
    if shimcache_records:
        for row in shimcache_records[:100]:
            ts = _parse_ts(str(row.get("LastModifiedTimeUTC") or row.get("Timestamp") or ""))
            path = str(row.get("Path") or row.get("path") or "")
            if not path:
                continue
            events.append(
                {
                    "timestamp": ts,
                    "source": "shimcache",
                    "category": "execution",
                    "event_id": None,
                    "summary": f"ShimCache execution: {path[:100]}",
                    "detail": {"path": path, "executed": row.get("Executed")},
                }
            )
        sources.append("shimcache")
    if web_access_records:
        web_events = _web_access_events(web_access_records)
        if web_events:
            events.extend(web_events)
            sources.append("web_log")
    if cmdline_records:
        cmd_events = _cmdline_timeline_events(cmdline_records)
        if cmd_events:
            events.extend(cmd_events)
            sources.append("cmdline")

    dated = [e for e in events if e.get("timestamp")]
    undated = [e for e in events if not e.get("timestamp")]
    dated.sort(key=lambda e: e["timestamp"])
    merged = dated + undated
    truncated = len(merged) > max_events
    if truncated:
        merged = merged[:max_events]

    by_source = {src: sum(1 for e in merged if e["source"] == src) for src in sources}
    return {
        "sources": sources,
        "event_count": len(merged),
        "returned_count": len(merged),
        "truncated": truncated,
        "by_source": by_source,
        "authentication_events": sum(1 for e in merged if e.get("category") == "authentication"),
        "persistence_events": sum(1 for e in merged if e.get("category") == "persistence"),
        "events": merged,
        "cross_source_summary": (
            f"Super-timeline from {len(sources)} source(s): "
            + ", ".join(f"{k}={v}" for k, v in by_source.items())
        ),
    }


def search_evidence_tree(
    root: Path,
    patterns: list[str],
    *,
    max_hits: int = 50,
    max_file_bytes: int = 2_000_000,
    case_sensitive: bool = False,
) -> dict[str, Any]:
    """Search read-only evidence tree for IOC strings (web shells, suspicious paths)."""
    if not patterns:
        raise ValueError("patterns must not be empty")

    flags = 0 if case_sensitive else re.IGNORECASE
    compiled = [re.compile(re.escape(p), flags) for p in patterns if p.strip()]
    hits: list[dict[str, Any]] = []
    files_scanned = 0

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix in BINARY_SKIP_SUFFIXES:
            continue
        if suffix and suffix not in TEXT_SUFFIXES and suffix not in {".hve", ".dat"}:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_file_bytes:
            continue

        files_scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for pattern, raw in zip(compiled, patterns, strict=False):
            for match in pattern.finditer(text):
                start = max(0, match.start() - 40)
                end = min(len(text), match.end() + 40)
                hits.append(
                    {
                        "path": str(path.relative_to(root)),
                        "pattern": raw,
                        "offset": match.start(),
                        "snippet": text[start:end].replace("\n", " ")[:160],
                    }
                )
                if len(hits) >= max_hits:
                    return {
                        "root": str(root),
                        "patterns": patterns,
                        "files_scanned": files_scanned,
                        "hit_count": len(hits),
                        "truncated": True,
                        "hits": hits,
                    }

    return {
        "root": str(root),
        "patterns": patterns,
        "files_scanned": files_scanned,
        "hit_count": len(hits),
        "truncated": False,
        "hits": hits,
    }
