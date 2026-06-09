"""Environment and path configuration for MCP runs."""

from __future__ import annotations

import os
import re
from pathlib import Path

from postmortem_evidence.guard import assert_not_evidence_write

CASE_OUTPUT_ENV = "CASE_OUTPUT"
VOL3_ENV = "VOL3"
PREFETCH_PARSER_ENV = "PREFETCH_PARSER"
EVTX_ECMD_ENV = "EVTX_ECMD"
AMCACHE_PARSER_ENV = "AMCACHE_PARSER"
MFTECMD_ENV = "MFTECMD"
RECMD_ENV = "RECMD"
DEFAULT_VOL3 = "/opt/postmortem/bin/vol"
DEFAULT_PREFETCH_PARSER = "/opt/postmortem/tools/parse_prefetch.py"
DEFAULT_EVTX_ECMD = "EvtxECmd"
DEFAULT_AMCACHE_PARSER = "AmcacheParser"
DEFAULT_MFTECMD = "MFTECmd"
DEFAULT_RECMD = "RECmd"
CASE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")


class ConfigError(ValueError):
    """Invalid cold-box run configuration."""


def get_case_output_root() -> Path:
    raw = os.environ.get(CASE_OUTPUT_ENV, "/cases").strip()
    if not raw:
        raise ConfigError(f"{CASE_OUTPUT_ENV} is empty")
    root = Path(raw).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def validate_case_id(case_id: str) -> str:
    case_id = case_id.strip()
    if not CASE_ID_RE.fullmatch(case_id):
        raise ConfigError(f"Invalid case_id: {case_id!r}")
    return case_id


def case_dir(case_id: str) -> Path:
    safe_id = validate_case_id(case_id)
    path = get_case_output_root() / safe_id
    assert_not_evidence_write(path, "w")
    path.mkdir(parents=True, exist_ok=True)
    return path


def audit_log_path(case_id: str) -> Path:
    path = case_dir(case_id) / "audit.jsonl"
    assert_not_evidence_write(path, "a")
    return path


def vol3_binary() -> str:
    return os.environ.get(VOL3_ENV, DEFAULT_VOL3).strip() or DEFAULT_VOL3


def prefetch_parser() -> str:
    return os.environ.get(PREFETCH_PARSER_ENV, DEFAULT_PREFETCH_PARSER).strip() or DEFAULT_PREFETCH_PARSER


def evtx_ecmd_binary() -> str:
    return os.environ.get(EVTX_ECMD_ENV, DEFAULT_EVTX_ECMD).strip() or DEFAULT_EVTX_ECMD


def amcache_parser_binary() -> str:
    return os.environ.get(AMCACHE_PARSER_ENV, DEFAULT_AMCACHE_PARSER).strip() or DEFAULT_AMCACHE_PARSER


def mftecmd_binary() -> str:
    return os.environ.get(MFTECMD_ENV, DEFAULT_MFTECMD).strip() or DEFAULT_MFTECMD


def recmd_binary() -> str:
    return os.environ.get(RECMD_ENV, DEFAULT_RECMD).strip() or DEFAULT_RECMD


def scratch_dir(case_id: str) -> Path:
    path = case_dir(case_id) / ".scratch"
    assert_not_evidence_write(path, "w")
    path.mkdir(parents=True, exist_ok=True)
    return path
