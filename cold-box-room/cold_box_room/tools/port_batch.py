"""Port tools from cold-box-final manifest into cold_box_room.tools_manifest_v1."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SOURCE_DEFAULT = Path("/opt/cold-box-final/cold_box/tools/tools_manifest.json")

# Curated descriptions where source help text or verify output leaked in.
DESCRIPTION_OVERRIDES: dict[str, str] = {
    "SIFT-021": "Query and inspect SQLite database files from the command line.",
    "SIFT-030": "7-Zip archiver — extract and list 7z and related archive formats.",
    "SIFT-031": "7-Zip standalone binary — extract and list archives.",
    "SIFT-035": "List symbols from object files and binaries.",
    "SIFT-036": "Create and modify ZIP archives.",
    "SIFT-038": "ClamAV antivirus scanner for files and directories.",
    "SIFT-039": "Detect compressed or encrypted regions in files (density analysis).",
    "SIFT-040": "Carve files from disk images and byte streams by header/footer signatures.",
    "SIFT-042": "Carve files from disk images using configurable header/footer rules.",
    "SIFT-046": "Extract and list files from 7z, zip, gzip, bzip2, xz, tar, and related archives.",
    "SIFT-047": "Autopsy digital forensics platform (GUI; often needs manual invocation).",
    "SIFT-033": "Enhanced dd variant for forensic imaging with hashing and progress.",
    "SIFT-034": "Copy and convert raw data blocks (use with care on evidence images).",
    "SIFT-041": "Recover lost files and partitions interactively from disk images.",
    "SIFT-048": "Enhanced dd variant for forensic disk imaging.",
    "SIFT-049": "Extract font metadata from Microsoft Word documents (RegRipper plugin).",
    "SIFT-050": "Parse Windows EVT event logs (legacy Perl parser).",
}


def _strip_tags(text: str) -> str:
    text = re.sub(r"\[VERIFIED OK\]\s*", "", text)
    text = re.sub(r"\[BAD — DO NOT USE\]\s*", "", text)
    text = re.sub(r"\s*RISK:.*$", "", text, flags=re.IGNORECASE)
    return text.strip()


def _clean_description(tool_id: str, raw: str) -> str:
    if tool_id in DESCRIPTION_OVERRIDES:
        return DESCRIPTION_OVERRIDES[tool_id]
    cleaned = _strip_tags(raw)
    if not cleaned or "invalid option" in cleaned.lower() or "invalid flag" in cleaned.lower():
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned or tool_id)
    # Drop obvious --help noise (version banners kept only if no override)
    if cleaned.startswith("7-Zip (") or cleaned.startswith("Copyright (c)"):
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned)
    if cleaned.startswith("Clam AntiVirus:") or cleaned.startswith("DensityScout"):
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned)
    if cleaned.startswith("Scalpel version"):
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned)
    if cleaned.startswith("FILENAME is the name of an SQLite"):
        return DESCRIPTION_OVERRIDES["SIFT-021"]
    if cleaned.startswith("List symbols in [file(s)]"):
        return DESCRIPTION_OVERRIDES["SIFT-035"]
    return cleaned


def _map_verification(old: dict[str, Any]) -> dict[str, Any]:
    status = str(old.get("verification_status") or "untested")
    detail = str(old.get("verification_detail") or "").strip()
    runnable = bool(old.get("runnable", False))

    if status == "ok":
        new_status = "ok"
        if not detail:
            detail = "Lab auto-verified on host."
    elif status == "bad":
        new_status = "bad"
    elif status == "unavailable":
        new_status = "unavailable"
        if not detail:
            detail = "Binary not installed on this host."
    else:
        # skip, untested, or unknown — fine to run, just not lab-tested
        new_status = "not_tested"
        if not detail:
            detail = "Not lab auto-tested; runnable if installed on host."
        elif status == "skip" and "manual verify" in detail:
            detail = "Not lab auto-tested; may need case-specific arguments."

    return {"status": new_status, "detail": detail, "runnable": runnable}


def _map_output_style(old_style: str, name: str) -> str:
    if old_style == "inode_stream" or name == "icat":
        return "inode_stream"
    if old_style in {"stdout", "stderr", "scratch_file", "inode_stream"}:
        return old_style
    return "stdout"


def convert_tool(old: dict[str, Any]) -> dict[str, Any]:
    tool_id = str(old["tool_id"])
    name = str(old["name"])
    out_format = str(old.get("output_format") or "text")
    if out_format not in {"text", "json", "csv", "binary"}:
        out_format = "text"

    flags = old.get("common_flags") or []
    normalized_flags = [
        {
            "flag": str(f.get("flag", "")),
            "description": str(f.get("description", "")),
            **({"required": bool(f["required"])} if "required" in f else {}),
        }
        for f in flags
        if f.get("flag")
    ]

    inp_style = str(old.get("input_style") or "positional")
    if inp_style not in {"positional", "flag", "stdin", "none"}:
        inp_style = "positional"

    record: dict[str, Any] = {
        "tool_id": tool_id,
        "name": name,
        "binary": str(old["binary"]),
        "category": str(old.get("category") or "misc"),
        "description": _clean_description(tool_id, str(old.get("description") or "")),
        "host_platforms": list(old.get("host_platforms") or ["linux"]),
        "artifact_platforms": list(old.get("artifact_platforms") or ["any"]),
        "input": {
            "style": inp_style,
            "flag": str(old.get("input_flag") or ""),
            "common_flags": normalized_flags,
        },
        "output": {
            "format": out_format,
            "style": _map_output_style(str(old.get("output_style") or "stdout"), name),
        },
        "timeout_seconds": int(old.get("timeout_seconds") or 600),
        "interactive": bool(old.get("interactive", False)),
        "verification": _map_verification(old),
    }
    harness = old.get("harness_usage")
    if harness:
        record["input"]["harness_usage"] = str(harness)
    return record


def port_batch(
    *,
    source: Path = SOURCE_DEFAULT,
    start: int = 0,
    limit: int = 50,
) -> list[dict[str, Any]]:
    data = json.loads(source.read_text(encoding="utf-8"))
    tools = data.get("tools") or []
    slice_ = tools[start : start + limit]
    return [convert_tool(t) for t in slice_]


def validate_tool_record(rec: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = (
        "tool_id",
        "name",
        "binary",
        "category",
        "description",
        "host_platforms",
        "artifact_platforms",
        "input",
        "output",
        "timeout_seconds",
        "verification",
    )
    for key in required:
        if key not in rec:
            errors.append(f"missing {key}")
    if not re.match(r"^SIFT-[0-9]{3}$", rec.get("tool_id", "")):
        errors.append("bad tool_id")
    if not rec.get("description"):
        errors.append("empty description")
    if "[VERIFIED OK]" in rec.get("description", ""):
        errors.append("description still has verification tag")
    ver = rec.get("verification") or {}
    if ver.get("status") not in {"ok", "bad", "not_tested", "unavailable"}:
        errors.append(f"bad verification.status {ver.get('status')}")
    return errors
