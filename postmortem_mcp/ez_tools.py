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
        payload = json.loads(json_path.read_text(encoding="utf-8"))
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
        with csv_path.open(newline="", encoding="utf-8") as handle:
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
    run_json_tool(
        binary=binary,
        input_path=evtx_path,
        output_dir=out_dir,
        args=["-f", str(evtx_path), "--json", str(out_dir)],
        timeout_sec=timeout_sec,
    )
    records = _load_json_records(out_dir)
    capped = cap_records(records, max_records)
    return {
        "source": str(evtx_path),
        "parser": "EvtxECmd",
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
