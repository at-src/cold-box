"""FastMCP server for cold-box DFIR tools."""

from __future__ import annotations

from fastmcp import FastMCP

from postmortem_mcp.tools.memory import mem_pslist as mem_pslist_impl

INSTRUCTIONS = """
cold-box MCP exposes deterministic DFIR tools for dead-host disk + memory analysis.

Rules:
- Evidence under EVIDENCE_ROOT is read-only.
- All tool output is structured JSON with an audit_id for traceability.
- Writes go to CASE_OUTPUT/<case_id>/ only (audit.jsonl, reports, etc.).

Start a run by choosing a case_id, then call tools with paths relative to EVIDENCE_ROOT
or absolute paths under the evidence root.
""".strip()


def create_server() -> FastMCP:
    mcp = FastMCP(name="cold-box", instructions=INSTRUCTIONS)

    @mcp.tool
    def mem_pslist(case_id: str, memory_relpath: str, iteration: int = 0) -> dict:
        """List Windows processes from a memory image using Volatility pslist."""
        return mem_pslist_impl(case_id, memory_relpath, iteration=iteration)

    return mcp


def main() -> int:
    create_server().run()
    return 0
