"""Pure-Python parsers for Windows disk/registry artifacts."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

USB_VID_PID = re.compile(r"USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.I)
SETUPAPI_SECTION_START = re.compile(
    r">>>\s+Section start\s+(\d{4}/\d{2}/\d{2}\s+[\d:.]+)", re.I
)
TASK_COMMAND = re.compile(r"<Command>([^<]+)</Command>", re.I)
TASK_DATE = re.compile(r"<Date>([^<]+)</Date>", re.I)
TASK_DESCRIPTION = re.compile(r"<Description>([^<]+)</Description>", re.I)
KVM_HINTS = ("kvm", "aten", "composite kvm", "ip-kvm", "remote-hands")


def cap_records(records: list[dict[str, Any]], max_records: int) -> dict[str, Any]:
    total = len(records)
    if max_records <= 0:
        raise ValueError("max_records must be positive")
    if total <= max_records:
        return {
            "record_count": total,
            "returned_count": total,
            "truncated": False,
            "records": records,
        }
    return {
        "record_count": total,
        "returned_count": max_records,
        "truncated": True,
        "records": records[:max_records],
    }


def load_csv_records(path: Path, *, max_records: int = 500) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        for row in csv.DictReader(handle):
            records.append(dict(row))
            if len(records) >= max_records:
                break
    capped = cap_records(records, max_records)
    return {"source": str(path), "parser": "csv", **capped}


def load_json_sidecar(path: Path, *, max_records: int = 500) -> dict[str, Any] | None:
    sidecar = path.with_suffix(".json")
    if not sidecar.is_file():
        sidecar = path.parent / f"{path.name}.json"
    if not sidecar.is_file():
        return None
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        records = [item for item in payload if isinstance(item, dict)]
    elif isinstance(payload, dict):
        nested = payload.get("records") or payload.get("entries") or payload.get("Rows")
        if isinstance(nested, list):
            records = [item for item in nested if isinstance(item, dict)]
        else:
            records = [payload]
    else:
        return None
    capped = cap_records(records, max_records)
    return {"source": str(path), "parser": "sidecar-json", **capped}


def parse_setupapi_dev_log(path: Path, *, max_records: int = 200) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    entries: list[dict[str, Any]] = []

    i = 0
    while i < len(lines):
        line = lines[i]
        match = USB_VID_PID.search(line)
        if not match:
            i += 1
            continue

        vid = match.group(1).upper()
        pid = match.group(2).upper()
        timestamp: str | None = None
        description_parts: list[str] = []

        for j in range(i + 1, min(i + 6, len(lines))):
            start_match = SETUPAPI_SECTION_START.search(lines[j])
            if start_match:
                timestamp = start_match.group(1)
                continue
            stripped = lines[j].strip()
            if stripped.startswith("<<<"):
                break
            if stripped and not stripped.startswith(">>>"):
                description_parts.append(stripped)

        description = " ".join(description_parts)
        entries.append(
            {
                "vid": vid,
                "pid": pid,
                "device_id": f"USB\\VID_{vid}&PID_{pid}",
                "timestamp": timestamp,
                "description": description,
                "suspicious_kvm": _is_kvm_entry(vid, pid, description),
            }
        )
        i += 1

    capped = cap_records(entries, max_records)
    suspicious = [row for row in capped["records"] if row.get("suspicious_kvm")]
    return {
        "source": str(path),
        "parser": "setupapi-text",
        "suspicious_count": len(suspicious),
        "suspicious_devices": suspicious,
        **capped,
    }


def _is_kvm_entry(vid: str, pid: str, description: str) -> bool:
    if vid == "0557" and pid == "2419":
        return True
    blob = description.lower()
    return any(hint in blob for hint in KVM_HINTS)


def parse_scheduled_task_file(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")

    command_match = TASK_COMMAND.search(text)
    date_match = TASK_DATE.search(text)
    desc_match = TASK_DESCRIPTION.search(text)
    command = command_match.group(1).strip() if command_match else ""
    description = desc_match.group(1).strip() if desc_match else ""

    suspicious = _is_suspicious_task(command, description, path.name)
    return {
        "source": str(path),
        "parser": "scheduled-task-xml",
        "task_name": path.name,
        "command": command,
        "registered": date_match.group(1).strip() if date_match else None,
        "description": description,
        "suspicious": suspicious,
        "records": [
            {
                "task_name": path.name,
                "command": command,
                "registered": date_match.group(1).strip() if date_match else None,
                "description": description,
                "suspicious": suspicious,
            }
        ],
        "record_count": 1,
        "returned_count": 1,
        "truncated": False,
    }


def _is_suspicious_task(command: str, description: str, task_name: str) -> bool:
    blob = f"{command} {description} {task_name}".lower()
    markers = (
        "remote-admin",
        "remotehands",
        "powershell -w hidden",
        "downloadstring",
        "iex ",
        "cmd /c",
        "sync helper",
    )
    return any(marker in blob for marker in markers)


def parse_lnk_metadata(path: Path) -> dict[str, Any]:
    sidecar = load_json_sidecar(path)
    if sidecar:
        return sidecar
    size = path.stat().st_size
    return {
        "source": str(path),
        "parser": "lnk-header",
        "records": [
            {
                "path": path.name,
                "size_bytes": size,
                "note": "LNK binary present; use sidecar JSON for full parse",
            }
        ],
        "record_count": 1,
        "returned_count": 1,
        "truncated": False,
    }


def parse_recycle_bin(path: Path, *, max_records: int = 200) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file():
                records.append(
                    {
                        "path": str(child.relative_to(path)),
                        "size_bytes": child.stat().st_size,
                    }
                )
                if len(records) >= max_records:
                    break
    elif path.is_file():
        sidecar = load_json_sidecar(path)
        if sidecar:
            return sidecar
        records.append({"path": path.name, "size_bytes": path.stat().st_size})

    capped = cap_records(records, max_records)
    return {"source": str(path), "parser": "recycle-bin", **capped}


def normalize_service_binary(binary: str) -> str:
    raw = binary.strip().strip('"')
    if not raw:
        return ""
    lower = raw.lower()
    if ".exe" in lower:
        end = lower.index(".exe") + 4
        raw = raw[:end]
    normalized = raw.replace("\\", "/")
    return normalized.rsplit("/", 1)[-1].lower()


PLACEHOLDER_MARKERS = ("placeholder", "PLACEHOLDER")


def is_placeholder_file(path: Path, *, max_bytes: int = 512) -> bool:
    """True when a stub/placeholder stands in for a real forensic artifact."""
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return False
        head = path.read_text(encoding="utf-8", errors="ignore")[:240]
        return any(marker in head for marker in PLACEHOLDER_MARKERS)
    except OSError:
        return False


def csv_sidecar_path(path: Path) -> Path | None:
    for candidate in (path.with_suffix(".csv"), path.parent / f"{path.name}.csv"):
        if candidate.is_file():
            return candidate
    return None


def _normalize_exe_name(raw: str) -> str:
    base = raw.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
    if not base.endswith(".exe") and ".exe" in base:
        end = base.index(".exe") + 4
        base = base[:end]
    return base


def normalize_evtx_csv_row(row: dict[str, Any]) -> dict[str, Any]:
    """Map EvtxECmd CSV columns into verifier-friendly security event rows."""
    eid_raw = row.get("EventId") or row.get("Event ID") or row.get("Id") or 0
    try:
        event_id = int(eid_raw)
    except (TypeError, ValueError):
        event_id = 0

    payload = " ".join(
        str(row.get(key, ""))
        for key in (
            "PayloadData1",
            "PayloadData2",
            "PayloadData3",
            "Payload",
            "Message",
        )
    )
    user = str(row.get("UserName") or row.get("TargetUserName") or row.get("SubjectUserName") or "")
    logon_type = row.get("LogonType")
    if logon_type is None and "LogonType=" in payload:
        for part in payload.split(","):
            if "LogonType=" in part:
                try:
                    logon_type = int(part.split("=", 1)[1].strip())
                except ValueError:
                    pass
                break

    return {
        "event_id": event_id,
        "time_created": row.get("TimeCreated") or row.get("Timestamp") or row.get("Created"),
        "user": user,
        "logon_type": logon_type,
        "channel": row.get("Channel") or row.get("Provider"),
        "payload": payload,
        "raw": row,
    }


def parse_evtx_csv_sidecar(
    evtx_path: Path,
    *,
    event_ids: list[int] | None = None,
    max_records: int = 500,
) -> dict[str, Any] | None:
    csv_path = csv_sidecar_path(evtx_path)
    if csv_path is None:
        return None

    payload = load_csv_records(csv_path, max_records=max_records * 3)
    rows = payload.get("records") or []
    events: list[dict[str, Any]] = []
    for row in rows:
        normalized = normalize_evtx_csv_row(row)
        eid = int(normalized.get("event_id") or 0)
        if event_ids and eid not in event_ids:
            continue
        events.append(normalized)
        if len(events) >= max_records:
            break

    capped = cap_records(events, max_records)
    counts: dict[str, int] = {}
    for event in events:
        key = str(event.get("event_id", ""))
        if key:
            counts[key] = counts.get(key, 0) + 1

    return {
        "source": str(evtx_path),
        "sidecar_csv": str(csv_path),
        "parser": "evtx-csv-sidecar",
        "event_ids": event_ids or [],
        "event_id_counts": counts,
        "events": events,
        **capped,
    }


def synthesize_execution_from_prefetch_sidecars(
    case_root: Path,
    *,
    max_records: int = 200,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not case_root.is_dir():
        return records

    for path in sorted(case_root.rglob("*.json")):
        parts = {p.lower() for p in path.parts}
        if "prefetch" not in parts and not path.name.lower().endswith(".pf.json"):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        exe = payload.get("executable") or payload.get("Executable")
        if not exe:
            continue
        last_run = payload.get("last_run") or payload.get("LastRun")
        if not last_run:
            runs = payload.get("run_times") or payload.get("RunTimes") or []
            if runs:
                last_run = runs[0]
        records.append(
            {
                "FullPath": str(exe),
                "Path": str(exe),
                "FileName": _normalize_exe_name(str(exe)),
                "LastRun": last_run,
                "source_sidecar": str(path.relative_to(case_root)),
                "synthesis": "prefetch-sidecar",
            }
        )
        if len(records) >= max_records:
            break
    return records


def synthesize_execution_from_evtx_sidecars(
    case_root: Path,
    *,
    max_records: int = 200,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not case_root.is_dir():
        return records

    for csv_path in sorted(case_root.rglob("*.csv")):
        if ".evtx" not in csv_path.name.lower() and "security" not in csv_path.name.lower():
            continue
        try:
            payload = load_csv_records(csv_path, max_records=max_records * 2)
        except OSError:
            continue
        for row in payload.get("records") or []:
            normalized = normalize_evtx_csv_row(row)
            if int(normalized.get("event_id") or 0) != 4688:
                continue
            payload_text = str(normalized.get("payload") or "")
            proc = ""
            for token in ("NewProcessName=", "ProcessName="):
                if token in payload_text:
                    proc = payload_text.split(token, 1)[1].split(",", 1)[0].strip()
                    break
            if not proc:
                continue
            records.append(
                {
                    "FullPath": proc,
                    "Path": proc,
                    "FileName": _normalize_exe_name(proc),
                    "LastRun": normalized.get("time_created"),
                    "source_sidecar": str(csv_path.relative_to(case_root)),
                    "synthesis": "evtx-4688",
                }
            )
            if len(records) >= max_records:
                return records
    return records


def load_amcache_with_fallbacks(
    amcache_path: Path,
    *,
    case_root: Path | None,
    max_records: int,
) -> dict[str, Any]:
    """Load amcache records from hive, sidecars, or cross-artifact synthesis."""
    sidecar = load_json_sidecar(amcache_path, max_records=max_records)
    if sidecar:
        sidecar["parser"] = "amcache-sidecar-json"
        return sidecar

    csv_path = csv_sidecar_path(amcache_path)
    if csv_path is not None:
        payload = load_csv_records(csv_path, max_records=max_records)
        payload["parser"] = "amcache-csv-sidecar"
        payload["source"] = str(amcache_path)
        return payload

    synthesized: list[dict[str, Any]] = []
    if case_root is not None:
        synthesized.extend(
            synthesize_execution_from_prefetch_sidecars(case_root, max_records=max_records)
        )
        if len(synthesized) < max_records:
            synthesized.extend(
                synthesize_execution_from_evtx_sidecars(
                    case_root,
                    max_records=max_records - len(synthesized),
                )
            )

    if synthesized:
        capped = cap_records(synthesized[:max_records], max_records)
        return {
            "source": str(amcache_path),
            "parser": "execution-synthesis",
            **capped,
        }

    if is_placeholder_file(amcache_path):
        return {
            "source": str(amcache_path),
            "parser": "placeholder-hive",
            "records": [],
            "record_count": 0,
            "returned_count": 0,
            "truncated": False,
        }

    return {
        "source": str(amcache_path),
        "parser": "empty",
        "records": [],
        "record_count": 0,
        "returned_count": 0,
        "truncated": False,
    }


def parse_services_csv(path: Path, *, max_records: int = 500) -> dict[str, Any]:
    payload = load_csv_records(path, max_records=max_records)
    records = payload.get("records") or []
    normalized: list[dict[str, Any]] = []
    for row in records:
        name = row.get("Name") or row.get("ServiceName") or row.get("name") or "?"
        binary = row.get("Binary") or row.get("ImagePath") or row.get("Path") or ""
        normalized.append(
            {
                "name": name,
                "binary": binary,
                "binary_basename": normalize_service_binary(str(binary)),
                "state": row.get("State") or row.get("StartType"),
                "raw": row,
            }
        )
    payload["records"] = normalized
    payload["parser"] = "services-csv"
    return payload
