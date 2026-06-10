"""Evidence survey — classify case files for agent triage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from postmortem_evidence.guard import resolve_read_path
from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.catalog import tools_for_kind
from postmortem_mcp.paths import resolve_case_directory

MAX_SURVEY_FILES = 500

LINUX_LOG_NAMES = frozenset(
    {
        "auth.log",
        "syslog",
        "messages",
        "secure",
        "kern.log",
        "bash_history",
        "lastlog",
        "wtmp",
    }
)

REGISTRY_BASENAMES = frozenset(
    {"system", "software", "sam", "security", "ntuser.dat", "amcache.hve", "usrclass.dat"}
)


def classify_file(relpath: str, path: Path) -> str:
    """Return forensic kind for a file path."""
    name = path.name.lower()
    suffix = path.suffix.lower()
    parts_lower = [p.lower() for p in path.parts]

    if suffix in {".mem", ".raw", ".dmp", ".vmem", ".img", ".crash"}:
        return "memory_image"
    if suffix == ".evtx":
        return "evtx"
    if suffix == ".pf":
        return "prefetch"
    if suffix == ".lnk":
        return "lnk"
    if name in {"setupapi.dev.log", "setupapi.log"} or "setupapi" in name:
        return "setupapi_log"
    if "tasks" in parts_lower and suffix in {"", ".xml"} and path.is_file():
        return "scheduled_task"
    if "shimcache" in name and suffix == ".csv":
        return "shimcache"
    if "runkeys" in name and suffix == ".csv":
        return "registry_export"
    if "shellbags" in name and suffix == ".csv":
        return "shellbags"
    if "services" in name and suffix == ".csv":
        return "services_csv"
    if "usnjrnl" in name or name.startswith("$j"):
        return "usnjrnl"
    if name == "srudb.dat":
        return "srum"
    if "recycle" in name or "$recycle.bin" in parts_lower:
        return "recycle_bin"
    if suffix in {".pcap", ".pcapng"}:
        return "pcap"
    if name in {"$mft", "mft"} or suffix in {".mft"}:
        return "mft"
    if name == "amcache.hve" or (name.endswith(".hve") and "amcache" in name):
        return "amcache"
    if name in REGISTRY_BASENAMES or suffix in {".dat", ".hve", ".log"}:
        if name in REGISTRY_BASENAMES or "registry" in parts_lower or "config" in parts_lower:
            return "registry_hive"
    if name in LINUX_LOG_NAMES or "bash_history" in name or name.endswith(".cron"):
        return "linux_log"
    if "var/log" in "/".join(parts_lower):
        return "linux_log"
    if suffix == ".csv" and "$mft" in name:
        return "mft"

    if path.is_file() and path.stat().st_size >= 4:
        try:
            magic = path.read_bytes()[:4]
            if magic[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"}:
                return "pcap"
            if magic == b"\x0a\x0d\x0d\x0a":
                return "pcap"
        except OSError:
            pass

    if suffix in {".json", ".txt", ".md", ".csv"}:
        return "text"
    if suffix in {".jsonl", ".ndjson"} or name.endswith(".ndjson"):
        return "structured_log"
    if suffix == ".php" or (suffix in {".html", ".htm"} and "web" in parts_lower):
        return "web_artifact"
    if name in {"access.log", "error.log"} or (name.endswith(".log") and "web" in parts_lower):
        return "web_log"
    return "unknown"


def merge_extracted_survey(
    payload: dict[str, Any],
    extracted_root: Path,
    *,
    prefix: str = "extracted",
) -> dict[str, Any]:
    """Append classified files from an extracted disk tree into an existing survey."""
    if not extracted_root.is_dir():
        return payload

    files = list(payload.get("files") or [])
    kinds_present = set(payload.get("kinds_present") or [])
    seen = {entry.get("relpath") for entry in files}
    added = 0

    for path in sorted(extracted_root.rglob("*")):
        if not path.is_file():
            continue
        try:
            inner = path.relative_to(extracted_root.resolve()).as_posix()
        except ValueError:
            inner = path.name
        relpath = f"{prefix}/{inner}"
        if relpath in seen:
            continue
        kind = classify_file(relpath, path)
        kinds_present.add(kind)
        files.append(
            {
                "relpath": relpath,
                "kind": kind,
                "size": path.stat().st_size,
                "applicable_tools": tools_for_kind(kind),
                "extracted": True,
            }
        )
        seen.add(relpath)
        added += 1

    payload["files"] = files
    payload["kinds_present"] = sorted(kinds_present)
    payload["extracted_file_count"] = added
    payload["extracted_root"] = str(extracted_root)
    return payload


def build_survey_payload(case_root: Path, case_relpath: str) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    kinds_present: set[str] = set()
    truncated = False
    count = 0

    for path in sorted(case_root.rglob("*")):
        if not path.is_file():
            continue
        count += 1
        if len(files) >= MAX_SURVEY_FILES:
            truncated = True
            continue
        try:
            relpath = path.relative_to(case_root.resolve()).as_posix()
        except ValueError:
            relpath = path.name
        kind = classify_file(relpath, path)
        kinds_present.add(kind)
        applicable = tools_for_kind(kind)
        if kind == "case_directory":
            applicable = tools_for_kind("case_directory")
        files.append(
            {
                "relpath": relpath,
                "kind": kind,
                "size": path.stat().st_size,
                "applicable_tools": applicable,
            }
        )

    kinds_present.add("case_directory")
    return {
        "case_root": str(case_root),
        "case_relpath": case_relpath,
        "file_count": count,
        "surveyed_count": len(files),
        "truncated": truncated,
        "kinds_present": sorted(kinds_present),
        "files": files,
    }


def evidence_survey(case_id: str, case_relpath: str, *, iteration: int = 0) -> dict:
    """Walk a case directory (read-only) and classify every file by forensic kind."""
    args = {"case_id": case_id, "case_relpath": case_relpath}

    def execute() -> dict[str, Any]:
        case_root = resolve_case_directory(case_relpath)
        args["case_path"] = str(case_root)
        return build_survey_payload(case_root, case_relpath)

    return run_audited_tool(
        case_id=case_id,
        tool="evidence_survey",
        args=args,
        iteration=iteration,
        execute=execute,
    )


def synthetic_survey(case_relpath: str, fixture_tools: dict[str, str]) -> dict[str, Any]:
    """Minimal survey for synthetic/fixture runs when evidence tree is sparse."""
    kinds: set[str] = {"case_directory"}
    files: list[dict[str, Any]] = [
        {
            "relpath": ".",
            "kind": "case_directory",
            "size": 0,
            "applicable_tools": tools_for_kind("case_directory"),
        }
    ]
    kind_for_tool = {
        "mem_pslist": "memory_image",
        "mem_psscan": "memory_image",
        "mem_cmdline": "memory_image",
        "mem_netscan": "memory_image",
        "mem_malfind": "memory_image",
        "mem_pstree": "memory_image",
        "mem_dlllist": "memory_image",
        "mem_svcscan": "memory_image",
    }
    for tool in fixture_tools:
        kind = kind_for_tool.get(tool, "text")
        kinds.add(kind)
        relpath = f"fixture/{tool}.json"
        if not any(f["relpath"] == relpath for f in files):
            files.append(
                {
                    "relpath": relpath,
                    "kind": kind,
                    "size": 0,
                    "applicable_tools": tools_for_kind(kind),
                    "fixture": True,
                }
            )
    return {
        "case_root": case_relpath,
        "case_relpath": case_relpath,
        "file_count": len(files),
        "surveyed_count": len(files),
        "truncated": False,
        "kinds_present": sorted(kinds),
        "files": files,
        "synthetic": True,
    }
