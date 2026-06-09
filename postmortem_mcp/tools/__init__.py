"""MCP tool exports."""

from postmortem_mcp.tools.disk import (
    disk_detect_timestomp,
    disk_parse_amcache,
    disk_parse_evtx,
    disk_parse_mft,
    disk_parse_prefetch,
)
from postmortem_mcp.tools.evidence import evidence_manifest
from postmortem_mcp.tools.memory import (
    mem_cmdline,
    mem_malfind,
    mem_netscan,
    mem_pslist,
    mem_psscan,
)

WAVE1_TOOLS = [
    mem_pslist,
    mem_psscan,
    mem_cmdline,
    disk_parse_prefetch,
    disk_parse_amcache,
    disk_parse_evtx,
    disk_parse_mft,
    evidence_manifest,
]

WAVE2_TOOLS = [
    mem_malfind,
    mem_netscan,
    disk_detect_timestomp,
]

ALL_TOOLS = WAVE1_TOOLS + WAVE2_TOOLS

__all__ = [fn.__name__ for fn in ALL_TOOLS] + ["WAVE1_TOOLS", "WAVE2_TOOLS", "ALL_TOOLS"]
