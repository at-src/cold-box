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


def resolve_memory_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"Memory image must be a file: {path}")
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


def resolve_linux_log_path(relpath: str) -> Path:
    path = resolve_read_path(relpath)
    if not path.is_file():
        raise EvidencePathError(f"Linux log must be a file: {path}")
    name = path.name.lower()
    allowed = {"auth.log", "secure", "syslog", "messages", "kern.log", "auditd_sample.txt"}
    if name not in allowed and "log" not in name:
        raise EvidencePathError(f"Expected Linux log file; got {path.name!r}")
    return path
