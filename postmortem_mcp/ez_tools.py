"""Eric Zimmerman tool wrappers and structured output loading."""

from __future__ import annotations

import csv
import json
import secrets
import subprocess
from pathlib import Path
from typing import Any


def cap_records(records: list[dict[str, Any]], max_records: int) -> dict[str, Any]:
    if max_records <= 0:
        raise ValueError("max_records must be positive")
    total = len(records)
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


def _load_json_records(output_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for json_path in sorted(output_dir.glob("*.json")):
        text = json_path.read_text(encoding="utf-8")
        loaded_any = False
        for line in text.splitlines():
            line = line.strip()
            if not line or line[0] not in "{[":
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            loaded_any = True
            if isinstance(payload, list):
                records.extend(item for item in payload if isinstance(item, dict))
            elif isinstance(payload, dict):
                nested = payload.get("Records") or payload.get("records")
                if isinstance(nested, list):
                    records.extend(item for item in nested if isinstance(item, dict))
                else:
                    records.append(payload)
        if loaded_any:
            continue
        payload = json.loads(text)
        if isinstance(payload, list):
            records.extend(item for item in payload if isinstance(item, dict))
        elif isinstance(payload, dict):
            nested = payload.get("Records") or payload.get("records")
            if isinstance(nested, list):
                records.extend(item for item in nested if isinstance(item, dict))
            else:
                records.append(payload)
    return records


def _load_csv_records(output_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for csv_path in sorted(output_dir.glob("*.csv")):
        with csv_path.open(newline="", encoding="utf-8-sig") as handle:
            records.extend(dict(row) for row in csv.DictReader(handle))
    return records


def run_json_tool(
    *,
    binary: str,
    input_path: Path,
    output_dir: Path,
    args: list[str],
    timeout_sec: int = 600,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [binary, *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_sec,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"{binary} failed"
        raise RuntimeError(detail)


def parse_evtx(
    evtx_path: Path,
    *,
    binary: str,
    scratch_dir: Path,
    max_records: int,
    timeout_sec: int = 600,
) -> dict[str, Any]:
    out_dir = scratch_dir / f"evtx-{secrets.token_hex(4)}"
    csv_name = f"{evtx_path.stem}.csv"
    run_json_tool(
        binary=binary,
        input_path=evtx_path,
        output_dir=out_dir,
        args=["-f", str(evtx_path), "--csv", str(out_dir), "--csvf", csv_name],
        timeout_sec=timeout_sec,
    )
    records = _load_csv_records(out_dir)
    capped = cap_records(records, max_records)
    return {
        "source": str(evtx_path),
        "parser": "EvtxECmd-csv",
        **capped,
    }


def parse_mft_csv(mft_csv_path: Path, *, max_records: int) -> dict[str, Any]:
    with mft_csv_path.open(newline="", encoding="utf-8-sig") as handle:
        records = list(csv.DictReader(handle))
    capped = cap_records(records, max_records)
    return {
        "source": str(mft_csv_path),
        "parser": "mft-csv",
        **capped,
    }


def parse_mft(
    mft_path: Path,
    *,
    binary: str,
    scratch_dir: Path,
    max_records: int,
    timeout_sec: int = 600,
) -> dict[str, Any]:
    out_dir = scratch_dir / f"mft-{secrets.token_hex(4)}"
    run_json_tool(
        binary=binary,
        input_path=mft_path,
        output_dir=out_dir,
        args=["-f", str(mft_path), "--json", str(out_dir)],
        timeout_sec=timeout_sec,
    )
    records = _load_json_records(out_dir)
    capped = cap_records(records, max_records)
    return {
        "source": str(mft_path),
        "parser": "MFTECmd",
        **capped,
    }


def parse_amcache(
    amcache_path: Path,
    *,
    binary: str,
    scratch_dir: Path,
    max_records: int,
    timeout_sec: int = 600,
) -> dict[str, Any]:
    out_dir = scratch_dir / f"amcache-{secrets.token_hex(4)}"
    run_json_tool(
        binary=binary,
        input_path=amcache_path,
        output_dir=out_dir,
        args=["-f", str(amcache_path), "-i", "--csv", str(out_dir)],
        timeout_sec=timeout_sec,
    )
    records = _load_csv_records(out_dir)
    capped = cap_records(records, max_records)
    return {
        "source": str(amcache_path),
        "parser": "AmcacheParser",
        **capped,
    }


def parse_evtx_filtered(
    evtx_path: Path,
    *,
    binary: str,
    scratch_dir: Path,
    event_ids: list[int],
    max_records: int,
    timeout_sec: int = 600,
) -> dict[str, Any]:
    """Parse EVTX with Event ID filter and structured auth summary."""
    if not event_ids:
        raise ValueError("event_ids must not be empty")
    out_dir = scratch_dir / f"evtx-filter-{secrets.token_hex(4)}"
    csv_name = f"{evtx_path.stem}-filtered.csv"
    inc = ",".join(str(eid) for eid in event_ids)
    run_json_tool(
        binary=binary,
        input_path=evtx_path,
        output_dir=out_dir,
        args=[
            "-f",
            str(evtx_path),
            "--csv",
            str(out_dir),
            "--csvf",
            csv_name,
            "--inc",
            inc,
        ],
        timeout_sec=timeout_sec,
    )
    records = _load_csv_records(out_dir)
    capped = cap_records(records, max_records)
    counts: dict[str, int] = {}
    for row in records:
        eid = str(row.get("EventId") or row.get("Event ID") or "")
        if eid:
            counts[eid] = counts.get(eid, 0) + 1
    return {
        "source": str(evtx_path),
        "parser": "EvtxECmd-filtered",
        "event_ids": event_ids,
        "event_id_counts": counts,
        "total_matching": len(records),
        **capped,
    }


def parse_registry_hive(
    hive_path: Path,
    *,
    binary: str,
    scratch_dir: Path,
    key_path: str | None = None,
    search_string: str | None = None,
    max_records: int = 500,
    timeout_sec: int = 600,
) -> dict[str, Any]:
    """Parse registry hive via RECmd — persistence run keys or string search."""
    out_dir = scratch_dir / f"reg-{secrets.token_hex(4)}"
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_name = f"{hive_path.stem}-registry.csv"
    args = ["-f", str(hive_path), "--csv", str(out_dir), "--csvf", csv_name]
    if key_path:
        args.extend(["--kn", key_path])
    elif search_string:
        args.extend(["--sa", search_string])
    else:
        args.extend(["--kn", "Microsoft\\Windows\\CurrentVersion\\Run"])

    run_json_tool(
        binary=binary,
        input_path=hive_path,
        output_dir=out_dir,
        args=args,
        timeout_sec=timeout_sec,
    )
    records = _load_csv_records(out_dir)
    capped = cap_records(records, max_records)
    persistence_hits = [
        r
        for r in records
        if any(
            k in str(r.get("KeyPath") or r.get("Key Name") or "").lower()
            for k in ("run", "runonce", "services")
        )
    ]
    return {
        "source": str(hive_path),
        "parser": "RECmd",
        "query_key": key_path or "Microsoft\\Windows\\CurrentVersion\\Run",
        "search_string": search_string,
        "persistence_candidates": len(persistence_hits),
        **capped,
    }
