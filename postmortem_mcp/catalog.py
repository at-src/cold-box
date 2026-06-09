"""Tool catalog — agent-facing metadata for every MCP tool."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from postmortem_mcp.audit_tool import run_audited_tool


@dataclass(frozen=True)
class ToolParam:
    name: str
    type: str
    required: bool
    description: str


@dataclass(frozen=True)
class ToolSpec:
    name: str
    summary: str
    consumes: tuple[str, ...]
    produces: tuple[str, ...]
    when_to_use: str
    params: tuple[ToolParam, ...]
    prerequisites: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    feeds_rules: tuple[str, ...] = ()


def _p(name: str, type_: str, required: bool, description: str) -> ToolParam:
    return ToolParam(name=name, type=type_, required=required, description=description)


def _mem_params(relpath_desc: str = "Memory image path relative to EVIDENCE_ROOT") -> tuple[ToolParam, ...]:
    return (
        _p("memory_relpath", "string", True, relpath_desc),
        _p("max_records", "integer", False, "Cap rows returned (default varies by tool)"),
    )


def _artifact_params(desc: str = "Artifact path relative to EVIDENCE_ROOT") -> tuple[ToolParam, ...]:
    return (
        _p("artifact_relpath", "string", True, desc),
        _p("max_records", "integer", False, "Cap rows returned"),
    )


CATALOG: dict[str, ToolSpec] = {
    "evidence_survey": ToolSpec(
        name="evidence_survey",
        summary="Classify all files in a case directory by forensic kind",
        consumes=("case_directory",),
        produces=("evidence_inventory",),
        when_to_use="First step on any new case — see what evidence exists before picking tools",
        params=(_p("case_relpath", "string", True, "Case directory relative to EVIDENCE_ROOT"),),
        feeds_rules=(),
    ),
    "tool_catalog": ToolSpec(
        name="tool_catalog",
        summary="Return metadata for all registered MCP tools",
        consumes=(),
        produces=("tool_metadata",),
        when_to_use="When you need full tool descriptions, parameters, and rule mappings",
        params=(),
    ),
    "evidence_manifest": ToolSpec(
        name="evidence_manifest",
        summary="SHA-256 manifest of all files under a case directory",
        consumes=("case_directory",),
        produces=("integrity_manifest",),
        when_to_use="Establish integrity baseline before deep analysis",
        params=(_p("case_relpath", "string", True, "Case directory relative to EVIDENCE_ROOT"),),
        feeds_rules=(),
    ),
    "mem_pslist": ToolSpec(
        name="mem_pslist",
        summary="Active process list from memory (Volatility pslist)",
        consumes=("memory_image",),
        produces=("process_list",),
        when_to_use="Baseline running processes; compare with psscan for hidden PIDs (R1)",
        params=_mem_params(),
        prerequisites=("evidence_manifest",),
        feeds_rules=("R1", "R2", "R3", "R6"),
    ),
    "mem_psscan": ToolSpec(
        name="mem_psscan",
        summary="Pool-scan processes including unlinked/hidden (Volatility psscan)",
        consumes=("memory_image",),
        produces=("process_list",),
        when_to_use="Cross-check pslist — catches processes unlinked from active list",
        params=_mem_params(),
        prerequisites=("mem_pslist",),
        feeds_rules=("R1",),
    ),
    "mem_cmdline": ToolSpec(
        name="mem_cmdline",
        summary="Process command lines from memory",
        consumes=("memory_image",),
        produces=("cmdlines",),
        when_to_use="Follow-up when R1 hidden-process contradiction fires",
        params=_mem_params(),
        feeds_rules=("R1",),
    ),
    "mem_netscan": ToolSpec(
        name="mem_netscan",
        summary="Network connections and sockets from memory",
        consumes=("memory_image",),
        produces=("network_connections",),
        when_to_use="Map live connections; cross-check owning PIDs against pslist (R6)",
        params=_mem_params(),
        feeds_rules=("R6",),
    ),
    "mem_malfind": ToolSpec(
        name="mem_malfind",
        summary="Injected/RWX memory regions (Volatility malfind)",
        consumes=("memory_image",),
        produces=("injection_findings",),
        when_to_use="When injection suspected or benign hypothesis contradicted by memory",
        params=_mem_params(),
        mitre=("T1055",),
        feeds_rules=("R7",),
    ),
    "mem_pstree": ToolSpec(
        name="mem_pstree",
        summary="Parent/child process tree from memory",
        consumes=("memory_image",),
        produces=("process_tree",),
        when_to_use="Understand process ancestry after suspicious PID identified",
        params=_mem_params(),
    ),
    "mem_dlllist": ToolSpec(
        name="mem_dlllist",
        summary="Loaded DLLs per process — injection/hollowing follow-up",
        consumes=("memory_image",),
        produces=("dll_loads",),
        when_to_use="After malfind or suspicious process — inspect loaded modules",
        params=_mem_params(),
        mitre=("T1055",),
    ),
    "mem_svcscan": ToolSpec(
        name="mem_svcscan",
        summary="Windows services enumerated from memory",
        consumes=("memory_image",),
        produces=("service_list",),
        when_to_use="Persistence triage — services running at capture time",
        params=_mem_params(),
        mitre=("T1543",),
    ),
    "disk_parse_prefetch": ToolSpec(
        name="disk_parse_prefetch",
        summary="Parse Windows prefetch (.pf) execution history",
        consumes=("prefetch",),
        produces=("execution_history",),
        when_to_use="Prove program execution; cross-check with memory (R2, R5)",
        params=_artifact_params("Prefetch .pf file relative to EVIDENCE_ROOT"),
        feeds_rules=("R2", "R5"),
    ),
    "disk_parse_amcache": ToolSpec(
        name="disk_parse_amcache",
        summary="Parse Amcache.hve program execution records",
        consumes=("amcache",),
        produces=("execution_history",),
        when_to_use="Execution trail for processes seen in memory (R2)",
        params=_artifact_params("Amcache.hve path relative to EVIDENCE_ROOT"),
        feeds_rules=("R2",),
    ),
    "disk_parse_evtx": ToolSpec(
        name="disk_parse_evtx",
        summary="Parse Windows EVTX event log",
        consumes=("evtx",),
        produces=("event_log",),
        when_to_use="Authentication and system events; pair with pslist for phantom logon (R3)",
        params=_artifact_params("EVTX file relative to EVIDENCE_ROOT"),
        feeds_rules=("R3",),
    ),
    "disk_parse_mft": ToolSpec(
        name="disk_parse_mft",
        summary="Parse extracted $MFT file records",
        consumes=("mft",),
        produces=("file_metadata",),
        when_to_use="File system timeline and path analysis",
        params=_artifact_params("MFT export relative to EVIDENCE_ROOT"),
    ),
    "disk_detect_timestomp": ToolSpec(
        name="disk_detect_timestomp",
        summary="Detect MFT $SI vs $FN timestomp anomalies",
        consumes=("mft",),
        produces=("timestomp_findings",),
        when_to_use="Anti-forensics check on MFT timestamps (R4)",
        params=_artifact_params("MFT export relative to EVIDENCE_ROOT"),
        mitre=("T1070.006",),
        feeds_rules=("R4",),
    ),
    "disk_evtx_filter": ToolSpec(
        name="disk_evtx_filter",
        summary="EVTX with auth Event ID filter and summary",
        consumes=("evtx",),
        produces=("auth_events",),
        when_to_use="Focused logon analysis (4624/4625/4648/4672) for R3",
        params=(
            _p("artifact_relpath", "string", True, "EVTX file relative to EVIDENCE_ROOT"),
            _p("event_ids", "array", False, "Event IDs to include (default auth set)"),
            _p("max_records", "integer", False, "Cap events returned"),
        ),
        feeds_rules=("R3",),
    ),
    "disk_parse_registry": ToolSpec(
        name="disk_parse_registry",
        summary="Registry hive persistence sweep (RECmd)",
        consumes=("registry_hive",),
        produces=("registry_entries",),
        when_to_use="Run keys and persistence strings in registry hives",
        params=(
            _p("artifact_relpath", "string", True, "Registry hive relative to EVIDENCE_ROOT"),
            _p("key_path", "string", False, "Hive key path filter"),
            _p("search_string", "string", False, "Value search string"),
            _p("max_records", "integer", False, "Cap entries returned"),
        ),
        mitre=("T1547",),
    ),
    "disk_correlate_timeline": ToolSpec(
        name="disk_correlate_timeline",
        summary="Cross-source timeline from EVTX, MFT, and memory",
        consumes=("case_directory", "evtx", "mft", "memory_image"),
        produces=("timeline",),
        when_to_use="After individual sources parsed — merge temporal view",
        params=(
            _p("evtx_relpath", "string", False, "EVTX relative path"),
            _p("mft_relpath", "string", False, "MFT relative path"),
            _p("memory_relpath", "string", False, "Memory image relative path"),
            _p("max_events", "integer", False, "Cap timeline events"),
        ),
    ),
    "disk_search_artifacts": ToolSpec(
        name="disk_search_artifacts",
        summary="IOC string search across evidence tree",
        consumes=("case_directory",),
        produces=("search_hits",),
        when_to_use="Hunt keywords, web shells, suspicious paths across the case",
        params=(
            _p("search_root_relpath", "string", True, "Directory to search relative to EVIDENCE_ROOT"),
            _p("patterns", "array", True, "Search strings (e.g. cmd.exe, powershell, php)"),
            _p("max_hits", "integer", False, "Cap hits returned"),
        ),
    ),
}


def tools_for_kind(kind: str) -> list[str]:
    """Return tool names whose catalog entry consumes the given evidence kind."""
    return sorted(spec.name for spec in CATALOG.values() if kind in spec.consumes)


def catalog_entry(name: str) -> ToolSpec | None:
    return CATALOG.get(name)


def catalog_as_dict() -> dict[str, Any]:
    return {name: asdict(spec) for name, spec in sorted(CATALOG.items())}


def tool_catalog(case_id: str, *, iteration: int = 0) -> dict:
    """Return the full tool catalog as structured JSON."""

    def execute() -> dict[str, Any]:
        return {"tools": catalog_as_dict(), "tool_count": len(CATALOG)}

    return run_audited_tool(
        case_id=case_id,
        tool="tool_catalog",
        args={"case_id": case_id},
        iteration=iteration,
        execute=execute,
    )
