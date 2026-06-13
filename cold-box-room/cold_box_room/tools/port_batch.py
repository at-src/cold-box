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
    # Batch 2 (SIFT-051 … SIFT-100)
    "SIFT-051": "Generate reports from Windows EVT event logs (RegRipper evtrpt.pl).",
    "SIFT-052": "Create forensic disk images in E01/EWF format.",
    "SIFT-053": "Mount E01/EWF evidence images as a raw read-only device.",
    "SIFT-054": "Map EXIF geolocation metadata from images (RegRipper exif2map.pl).",
    "SIFT-055": "Extract file metadata (EXIF, timestamps, author) from many file types.",
    "SIFT-056": "Parse Windows Facebook-related artifacts (RegRipper fb.pl).",
    "SIFT-057": "Parse Firefox browser artifacts (RegRipper ff.pl).",
    "SIFT-058": "Parse Firefox sign-on and session data (RegRipper ff_signons.pl).",
    "SIFT-059": "Convert XML/HTML/text to braille embosser format (accessibility utility).",
    "SIFT-060": "Report file extent layout and fragmentation on a filesystem.",
    "SIFT-061": "Extract files from a mounted filesystem over the network (filesnarf).",
    "SIFT-062": "Update ClamAV virus definition databases.",
    "SIFT-063": "Parse FTK-generated reports (RegRipper ftkparse.pl).",
    "SIFT-064": "Identify processes using specified files or sockets.",
    "SIFT-065": "Parse Google Analytics cookie data (RegRipper gis4cookie.pl).",
    "SIFT-066": "Recursive file hashing with audit and match modes.",
    "SIFT-067": "Parse Internet Explorer index.dat records (RegRipper idx.pl).",
    "SIFT-068": "Parse and decode index.dat structures (RegRipper idxparse.pl).",
    "SIFT-069": "Parse Windows Jump List DestList streams (RegRipper jl.pl).",
    "SIFT-070": "Parse Windows job files (RegRipper jobparse.pl).",
    "SIFT-071": "Pretty-print JSON forensic output (RegRipper json-printer.pl).",
    "SIFT-072": "Parse LastFolderListExplorer MRU artifacts (RegRipper lfle.pl).",
    "SIFT-073": "Set up and manage loopback block devices for mounted images.",
    "SIFT-074": "List open files and the processes that opened them.",
    "SIFT-075": "Mount filesystems from disk images or devices (use with care on evidence).",
    "SIFT-076": "Generic RegRipper parse plugin (parse.pl).",
    "SIFT-077": "Parse NTFS $I30 index slack artifacts (RegRipper parsei30.pl).",
    "SIFT-078": "Parse Internet Explorer artifacts (RegRipper parseie.pl).",
    "SIFT-079": "Parse IE Prefetch-related data (RegRipper pie.pl).",
    "SIFT-080": "Parse IE Preferences records (RegRipper pref.pl).",
    "SIFT-081": "Radare2 reverse-engineering framework (r2 CLI).",
    "SIFT-082": "Radare2 binary analysis utility (rabin2).",
    "SIFT-083": "Radare2 multi-purpose reverse-engineering shell.",
    "SIFT-084": "Parse raw Internet Explorer index structures (RegRipper rawie.pl).",
    "SIFT-085": "Radare2 base converter and expression evaluator (rax2).",
    "SIFT-086": "Parse Windows Recycle Bin metadata (RegRipper recbin.pl).",
    "SIFT-087": "Windows Registry Editor (Wine; Windows-only, often unavailable on Linux).",
    "SIFT-088": "Windows Registry Editor stable build (Wine; Windows-only).",
    "SIFT-089": "Export Windows Registry hive files to JSON (libregf regfexport).",
    "SIFT-090": "Display Windows Registry hive file information (libregf regfinfo).",
    "SIFT-091": "Mount Windows Registry hive as FUSE filesystem (libregf regfmount).",
    "SIFT-092": "Compare two Windows Registry hives with regipy.",
    "SIFT-093": "Dump Windows Registry hive contents with regipy.",
    "SIFT-094": "Parse Registry hive header metadata with regipy.",
    "SIFT-095": "List available regipy Registry analysis plugins.",
    "SIFT-096": "Run regipy plugins against a Registry hive.",
    "SIFT-097": "Process Registry transaction logs with regipy.",
    "SIFT-098": "Registry hive parser with plugin framework (RegRipper rip.pl).",
    "SIFT-099": "Parse Registry slack space (RegRipper regslack.pl).",
    "SIFT-100": "Windows regsvr32 DLL registration utility (Wine; Windows-only).",
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
    if "traceback" in cleaned.lower():
        return DESCRIPTION_OVERRIDES.get(tool_id, "Registry analysis tool (regipy).")
    if "wine32 is missing" in cleaned.lower():
        return DESCRIPTION_OVERRIDES.get(tool_id, "Windows-only tool (Wine required).")
    if cleaned.startswith("Forensic CLI:"):
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned.replace("Forensic CLI:", "RegRipper plugin:").strip())
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
