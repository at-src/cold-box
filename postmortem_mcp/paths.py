"""Evidence path helpers for MCP tools."""

from __future__ import annotations

from pathlib import Path

from postmortem_evidence.guard import EvidencePathError, resolve_read_path

MEMORY_SUFFIXES = {".mem", ".raw", ".dmp", ".img", ".crash", ".vmem"}
PREFETCH_SUFFIXES = {".pf"}
AMCACHE_SUFFIXES = {".hve"}
EVTX_SUFFIXES = {".evtx"}
MFT_NAMES = {"$mft", "mft"}
REGISTRY_SUFFIXES = {".dat", ".hve", ".log", ".reg"}
REGISTRY_BASENAMES = {"software", "system", "sam", "security", "ntuser.dat"}
SETUPAPI_NAMES = {"setupapi.dev.log", "setupapi.log"}
SCHEDULED_TASK_DIR = "tasks"


def resolve_memory_path(relpath: str) -> Path:
    from postmortem_mcp.survey import classify_file

    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"Memory image must be a file: {path}")
    kind = classify_file(relpath.replace("\\", "/"), path)
    if kind in {"android_mtd", "android_sdcard", "macos_ad1", "disk_image"}:
        raise EvidencePathError(
            f"Path is classified as {kind!r}, not a memory capture: {path.name!r}"
        )
    if path.suffix.lower() not in MEMORY_SUFFIXES:
        raise EvidencePathError(
            f"Expected memory image suffix {sorted(MEMORY_SUFFIXES)}; got {path.name!r}"
        )
    return path


def resolve_artifact_path(relpath: str, *, allowed_suffixes: set[str] | None = None) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"Artifact must be a file: {path}")
    if allowed_suffixes is not None and path.suffix.lower() not in allowed_suffixes:
        raise EvidencePathError(
            f"Expected suffix {sorted(allowed_suffixes)}; got {path.name!r}"
        )
    return path


def resolve_prefetch_path(relpath: str) -> Path:
    return resolve_artifact_path(relpath, allowed_suffixes=PREFETCH_SUFFIXES)


def resolve_amcache_path(relpath: str) -> Path:
    return resolve_artifact_path(relpath, allowed_suffixes=AMCACHE_SUFFIXES)


def resolve_evtx_path(relpath: str) -> Path:
    return resolve_artifact_path(relpath, allowed_suffixes=EVTX_SUFFIXES)


def resolve_mft_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"MFT artifact must be a file: {path}")
    name = path.name.lower()
    if path.suffix.lower() not in {".mft", ".csv", ""} and name not in MFT_NAMES:
        raise EvidencePathError(f"Expected MFT file; got {path.name!r}")
    return path


def resolve_registry_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"Registry hive must be a file: {path}")
    name = path.name.lower()
    if path.suffix.lower() not in REGISTRY_SUFFIXES and name not in REGISTRY_BASENAMES:
        raise EvidencePathError(f"Expected registry hive; got {path.name!r}")
    return path


def resolve_case_directory(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_dir():
        raise EvidencePathError(f"Case path must be a directory: {path}")
    return path


def resolve_readonly_file(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"Artifact must be a file: {path}")
    return path


def resolve_pcap_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"PCAP must be a file: {path}")
    if path.suffix.lower() not in {".pcap", ".pcapng"}:
        raise EvidencePathError(f"Expected .pcap/.pcapng; got {path.name!r}")
    return path


def resolve_setupapi_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"SetupAPI log must be a file: {path}")
    name = path.name.lower()
    if name not in SETUPAPI_NAMES and "setupapi" not in name:
        raise EvidencePathError(f"Expected setupapi log; got {path.name!r}")
    return path


def resolve_scheduled_task_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"Scheduled task must be a file: {path}")
    if "tasks" not in path.as_posix().lower() and path.suffix.lower() not in {".xml", ""}:
        raise EvidencePathError(f"Expected scheduled task file; got {path.name!r}")
    return path


def resolve_csv_artifact_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"CSV artifact must be a file: {path}")
    if path.suffix.lower() != ".csv":
        raise EvidencePathError(f"Expected .csv artifact; got {path.name!r}")
    return path


def resolve_lnk_path(relpath: str) -> Path:
    return resolve_artifact_path(relpath, allowed_suffixes={".lnk"})


def resolve_text_or_dir_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file() and not path.is_dir():
        raise EvidencePathError(f"Path must be a file or directory: {path}")
    return path


def resolve_linux_log_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"Linux log must be a file: {path}")
    name = path.name.lower()
    allowed = {"auth.log", "secure", "syslog", "messages", "kern.log", "auditd_sample.txt"}
    if name not in allowed and "log" not in name:
        raise EvidencePathError(f"Expected Linux log file; got {path.name!r}")
    return path


def resolve_web_log_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"Web log must be a file: {path}")
    name = path.name.lower()
    parts = [p.lower() for p in path.parts]
    if name not in {"access.log", "error.log"} and not (name.endswith(".log") and "web" in parts):
        raise EvidencePathError(f"Expected web access/error log; got {path.name!r}")
    return path


def resolve_web_artifact_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"Web artifact must be a file: {path}")
    if path.suffix.lower() not in {".php", ".html", ".htm", ".asp", ".aspx", ".jsp"}:
        raise EvidencePathError(f"Expected web artifact suffix; got {path.name!r}")
    return path


def resolve_structured_log_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"Structured log must be a file: {path}")
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix not in {".jsonl", ".ndjson", ".json"} and "journal" not in name:
        raise EvidencePathError(f"Expected JSONL/NDJSON log; got {path.name!r}")
    return path
