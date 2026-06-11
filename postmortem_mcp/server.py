"""FastMCP server for cold-box DFIR tools."""

from __future__ import annotations

from collections.abc import Callable

from fastmcp import FastMCP

from postmortem_mcp.tools import ALL_TOOLS

INSTRUCTIONS = """
cold-box MCP exposes deterministic DFIR tools for dead-host disk + memory analysis.

Rules:
- Evidence under EVIDENCE_ROOT is read-only.
- All tool output is structured JSON with an audit_id for traceability.
- Writes go to CASE_OUTPUT/<case_id>/ only (audit.jsonl, scratch, reports).

Wave 1 tools:
- mem_pslist, mem_psscan, mem_cmdline — memory image paths (.mem, .raw, .dmp, ...)
- disk_parse_prefetch (.pf), disk_parse_amcache (.hve), disk_parse_evtx (.evtx), disk_parse_mft
- evidence_manifest — SHA-256 manifest for a case directory under EVIDENCE_ROOT

Wave 2 tools:
- mem_malfind, mem_netscan — injection and network triage from memory
- disk_detect_timestomp — MFT $SI vs $FN anti-forensics (T1070.006)

Wave 3+ tools (breadth + depth): timeline, registry, IOC search, Linux, network, Tier-3 exfil/YARA,
Android (DFRWS mtd/sdcard), macOS (AD1 carve). See postmortem_mcp.catalog for the full surface (~66 tools).

Configure backends via env: VOL3, PREFETCH_PARSER, EVTX_ECMD, AMCACHE_PARSER, MFTECMD, RECMD.
On SIFT, `yara` is optional — yara_scan_evidence falls back to bundled pattern rules when absent.
""".strip()


def create_server() -> FastMCP:
    mcp = FastMCP(name="cold-box", instructions=INSTRUCTIONS)

    for tool_fn in ALL_TOOLS:
        _register_tool(mcp, tool_fn)

    return mcp


def _register_tool(mcp: FastMCP, tool_fn: Callable) -> None:
    mcp.tool(name=tool_fn.__name__, description=tool_fn.__doc__ or "")(tool_fn)


def main() -> int:
    create_server().run()
    return 0
