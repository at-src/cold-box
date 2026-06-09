"""MFT timestomp detection (T1070.006)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

_EXEC_EXTS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".com",
    ".cpl",
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".lnk",
    ".hta",
    ".msi",
}


def _parse_ts(value: str | None) -> datetime | None:
    if not value or not str(value).strip():
        return None
    text = str(value).split(".")[0].split("+")[0].strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _record_path(row: dict[str, Any]) -> str:
    full = row.get("FullPath") or row.get("full_path")
    if full:
        return str(full)
    parent = row.get("ParentPath") or row.get("parent_path") or ""
    name = row.get("FileName") or row.get("file_name") or row.get("Filename") or ""
    if parent and name:
        return f"{parent}\\{name}"
    return str(name)


def detect_timestomp_rows(
    rows: list[dict[str, Any]],
    *,
    tolerance_seconds: int = 1,
    executables_only: bool = False,
) -> list[dict[str, Any]]:
    """Find $SI vs $FN timestamp contradictions in MFTECmd-style rows."""
    findings: list[dict[str, Any]] = []
    for row in rows:
        path = _record_path(row)
        is_exec = any(path.lower().endswith(ext) for ext in _EXEC_EXTS)
        if executables_only and not is_exec:
            continue

        si_ct = _parse_ts(row.get("Created0x10") or row.get("created0x10"))
        fn_ct = _parse_ts(row.get("Created0x30") or row.get("created0x30"))
        si_mt = _parse_ts(row.get("LastModified0x10") or row.get("lastmodified0x10"))

        if si_ct and fn_ct:
            delta = (fn_ct - si_ct).total_seconds()
            if delta > tolerance_seconds:
                severity = (
                    "critical"
                    if is_exec and delta > 3600
                    else "high"
                    if delta > 3600 or is_exec
                    else "medium"
                )
                findings.append(
                    {
                        "pattern": "SI_CREATED_PREDATES_FN_CREATED",
                        "path": path,
                        "si_created": si_ct.isoformat(),
                        "fn_created": fn_ct.isoformat(),
                        "delta_seconds": int(delta),
                        "is_executable": is_exec,
                        "severity": severity,
                        "mitre": "T1070.006",
                    }
                )

        if si_mt and fn_ct:
            delta = (fn_ct - si_mt).total_seconds()
            if delta > tolerance_seconds:
                findings.append(
                    {
                        "pattern": "SI_MODIFIED_BEFORE_FN_CREATED_IMPOSSIBLE",
                        "path": path,
                        "si_modified": si_mt.isoformat(),
                        "fn_created": fn_ct.isoformat(),
                        "delta_seconds": int(delta),
                        "is_executable": is_exec,
                        "severity": "critical",
                        "mitre": "T1070.006",
                        "note": "A file cannot be modified before it was created",
                    }
                )

    return findings
