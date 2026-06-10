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
        feeds_rules=("R1", "R18"),
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
        feeds_rules=("R11",),
    ),
    "disk_parse_prefetch": ToolSpec(
        name="disk_parse_prefetch",
        summary="Parse Windows prefetch (.pf) execution history",
        consumes=("prefetch",),
        produces=("execution_history",),
        when_to_use="Prove program execution; cross-check with memory (R2, R5)",
        params=_artifact_params("Prefetch .pf file relative to EVIDENCE_ROOT"),
        feeds_rules=("R2", "R5", "R16"),
    ),
    "disk_parse_amcache": ToolSpec(
        name="disk_parse_amcache",
        summary="Parse Amcache.hve program execution records",
        consumes=("amcache",),
        produces=("execution_history",),
        when_to_use="Execution trail for processes seen in memory (R2)",
        params=_artifact_params("Amcache.hve path relative to EVIDENCE_ROOT"),
        feeds_rules=("R2", "R16"),
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
        feeds_rules=("R11", "R13"),
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
        consumes=("case_directory", "web_log", "web_artifact"),
        produces=("search_hits",),
        when_to_use="Hunt keywords, web shells, suspicious paths across the case",
        params=(
            _p("search_root_relpath", "string", True, "Directory to search relative to EVIDENCE_ROOT"),
            _p("patterns", "array", True, "Search strings (e.g. cmd.exe, powershell, php)"),
            _p("max_hits", "integer", False, "Cap hits returned"),
        ),
        feeds_rules=("R14",),
    ),
    "web_parse_access_log": ToolSpec(
        name="web_parse_access_log",
        summary="Parse web access logs for SQLi, scanners, and webshell hits",
        consumes=("web_log",),
        produces=("web_requests", "web_attacks"),
        when_to_use="Web server compromise triage — apache/nginx access.log under web/",
        params=_artifact_params("Web access log relative to EVIDENCE_ROOT"),
        mitre=("T1190", "T1505.003"),
        feeds_rules=("R19",),
    ),
    "web_inspect_artifact": ToolSpec(
        name="web_inspect_artifact",
        summary="Inspect PHP/HTML uploads for webshell code patterns",
        consumes=("web_artifact",),
        produces=("webshell_indicators",),
        when_to_use="Follow suspicious upload paths or R19 access-log hits to uploaded shells",
        params=_artifact_params("Web artifact (.php/.html) relative to EVIDENCE_ROOT"),
        mitre=("T1505.003",),
        feeds_rules=("R14", "R19"),
    ),
    "logs_parse_structured": ToolSpec(
        name="logs_parse_structured",
        summary="Parse JSONL/NDJSON logs for security-relevant events",
        consumes=("structured_log",),
        produces=("structured_events",),
        when_to_use="Application, journal, or unified event logs in JSONL/NDJSON format",
        params=_artifact_params("Structured log file (.jsonl/.ndjson) relative to EVIDENCE_ROOT"),
        feeds_rules=("R20",),
    ),
    "net_pcap_summary": ToolSpec(
        name="net_pcap_summary",
        summary="Summarize packet counts and protocols in a PCAP",
        consumes=("pcap",),
        produces=("packet_summary",),
        when_to_use="First look at network capture — size and protocol mix",
        params=_artifact_params("PCAP file relative to EVIDENCE_ROOT"),
    ),
    "net_dns_extract": ToolSpec(
        name="net_dns_extract",
        summary="Extract DNS queries from PCAP for tunneling/exfil triage",
        consumes=("pcap",),
        produces=("dns_queries",),
        when_to_use="Suspected DNS exfil or high-volume lookups to one domain (R8)",
        params=_artifact_params("PCAP file relative to EVIDENCE_ROOT"),
        mitre=("T1071.004",),
        feeds_rules=("R8",),
    ),
    "net_http_extract": ToolSpec(
        name="net_http_extract",
        summary="Extract HTTP hosts and periodic same-size POST patterns",
        consumes=("pcap",),
        produces=("http_requests",),
        when_to_use="Suspected C2 beaconing over HTTP (R9)",
        params=_artifact_params("PCAP file relative to EVIDENCE_ROOT"),
        mitre=("T1071.001",),
        feeds_rules=("R9",),
    ),
    "net_conversations": ToolSpec(
        name="net_conversations",
        summary="Rank IP:port conversation pairs by packet volume",
        consumes=("pcap",),
        produces=("conversations",),
        when_to_use="Identify top talkers and lateral movement flows",
        params=_artifact_params("PCAP file relative to EVIDENCE_ROOT"),
    ),
    "linux_auth_log": ToolSpec(
        name="linux_auth_log",
        summary="Parse auth.log/secure for login anomalies",
        consumes=("linux_log",),
        produces=("auth_events",),
        when_to_use="Linux authentication triage on auth.log or secure",
        params=_artifact_params("Linux auth log relative to EVIDENCE_ROOT"),
    ),
    "linux_syslog": ToolSpec(
        name="linux_syslog",
        summary="Parse syslog/messages for errors and anomalies",
        consumes=("linux_log",),
        produces=("syslog_events",),
        when_to_use="Linux service/kernel anomaly triage",
        params=_artifact_params("Syslog file relative to EVIDENCE_ROOT"),
    ),
    "linux_bash_history": ToolSpec(
        name="linux_bash_history",
        summary="Parse bash history for suspicious commands",
        consumes=("linux_log", "text"),
        produces=("history_hits",),
        when_to_use="User command history triage on Linux hosts",
        params=_artifact_params("bash_history or similar relative to EVIDENCE_ROOT"),
        feeds_rules=("R10",),
    ),
    "linux_cron": ToolSpec(
        name="linux_cron",
        summary="Parse crontab files for suspicious scheduled commands",
        consumes=("linux_log", "text"),
        produces=("cron_entries",),
        when_to_use="Scheduled task persistence on Linux",
        params=_artifact_params("Crontab file relative to EVIDENCE_ROOT"),
        mitre=("T1053.003",),
        feeds_rules=("R10",),
    ),
    "linux_persistence": ToolSpec(
        name="linux_persistence",
        summary="Scan Linux evidence tree for persistence indicators",
        consumes=("case_directory", "linux_log"),
        produces=("persistence_findings",),
        when_to_use="Breadth sweep for cron/bashrc/profile persistence (R10)",
        params=(
            _p("search_root_relpath", "string", True, "Linux evidence root relative to EVIDENCE_ROOT"),
            _p("max_records", "integer", False, "Cap findings returned"),
        ),
        mitre=("T1053", "T1546"),
        feeds_rules=("R10",),
    ),
    "disk_parse_setupapi": ToolSpec(
        name="disk_parse_setupapi",
        summary="Parse setupapi.dev.log for USB device insertion history",
        consumes=("setupapi_log",),
        produces=("usb_history",),
        when_to_use="IP-KVM / diagnostic USB remote-hands triage before logon (R12)",
        params=_artifact_params("setupapi.dev.log relative to EVIDENCE_ROOT"),
        mitre=("T1200",),
        feeds_rules=("R12",),
    ),
    "disk_parse_scheduled_tasks": ToolSpec(
        name="disk_parse_scheduled_tasks",
        summary="Parse Windows scheduled task XML for persistence",
        consumes=("scheduled_task",),
        produces=("scheduled_tasks",),
        when_to_use="Windows task-folder persistence (RemoteHandsSync-style) triage (R13)",
        params=_artifact_params("Task XML file under System32/Tasks"),
        mitre=("T1053.005",),
        feeds_rules=("R13",),
    ),
    "disk_parse_shimcache": ToolSpec(
        name="disk_parse_shimcache",
        summary="Parse AppCompat ShimCache CSV export",
        consumes=("shimcache",),
        produces=("execution_history",),
        when_to_use="Recent program execution on disk when prefetch/amcache incomplete",
        params=_artifact_params("ShimCache CSV relative to EVIDENCE_ROOT"),
        feeds_rules=("R2", "R16"),
    ),
    "disk_parse_userassist": ToolSpec(
        name="disk_parse_userassist",
        summary="Parse UserAssist CSV export for GUI execution history",
        consumes=("shellbags", "registry_export", "text"),
        produces=("execution_history",),
        when_to_use="User GUI program execution history from registry export",
        params=_artifact_params("UserAssist or runkeys CSV relative to EVIDENCE_ROOT"),
    ),
    "disk_parse_lnk": ToolSpec(
        name="disk_parse_lnk",
        summary="Parse Windows .lnk shortcut metadata",
        consumes=("lnk",),
        produces=("shortcut_metadata",),
        when_to_use="User opened files/programs via shortcut artifacts",
        params=_artifact_params(".lnk file relative to EVIDENCE_ROOT"),
    ),
    "disk_parse_jumplist": ToolSpec(
        name="disk_parse_jumplist",
        summary="Parse Jump List CSV/sidecar export",
        consumes=("text",),
        produces=("execution_history",),
        when_to_use="Recent user file/application access via Jump Lists",
        params=_artifact_params("Jump list CSV or sidecar JSON relative to EVIDENCE_ROOT"),
    ),
    "disk_parse_srum": ToolSpec(
        name="disk_parse_srum",
        summary="Parse SRUM database sidecar export",
        consumes=("srum",),
        produces=("network_usage",),
        when_to_use="Application network usage and execution timeline from SRUM",
        params=_artifact_params("SRUDB.dat sidecar CSV/JSON relative to EVIDENCE_ROOT"),
    ),
    "disk_parse_usnjrnl": ToolSpec(
        name="disk_parse_usnjrnl",
        summary="Parse USN journal CSV for rename/delete activity",
        consumes=("usnjrnl", "text"),
        produces=("filesystem_journal",),
        when_to_use="File rename/delete anti-forensics on NTFS volume",
        params=_artifact_params("USN journal CSV relative to EVIDENCE_ROOT"),
        mitre=("T1070.004",),
    ),
    "disk_recycle_bin": ToolSpec(
        name="disk_recycle_bin",
        summary="List deleted files in Recycle Bin export",
        consumes=("recycle_bin",),
        produces=("deleted_files",),
        when_to_use="Recover evidence of deleted attacker tools or staging files",
        params=_artifact_params("Recycle Bin directory or sidecar relative to EVIDENCE_ROOT"),
    ),
    "reg_run_keys": ToolSpec(
        name="reg_run_keys",
        summary="Parse Run/RunOnce registry CSV export",
        consumes=("registry_export",),
        produces=("registry_entries",),
        when_to_use="Startup persistence via Run keys (R13 follow-up)",
        params=_artifact_params("Run keys CSV export relative to EVIDENCE_ROOT"),
        mitre=("T1547.001",),
        feeds_rules=("R13",),
    ),
    "reg_services": ToolSpec(
        name="reg_services",
        summary="Parse services CSV export for ImagePath ghost-service triage",
        consumes=("services_csv", "registry_hive"),
        produces=("service_list",),
        when_to_use="Service persistence whose binary is missing on disk (R11)",
        params=_artifact_params("Services CSV export relative to EVIDENCE_ROOT"),
        mitre=("T1543.003",),
        feeds_rules=("R11",),
    ),
    "reg_userassist": ToolSpec(
        name="reg_userassist",
        summary="Parse UserAssist registry CSV export",
        consumes=("registry_export", "shellbags"),
        produces=("execution_history",),
        when_to_use="GUI program execution counts from UserAssist keys",
        params=_artifact_params("UserAssist CSV relative to EVIDENCE_ROOT"),
    ),
    "reg_shellbags": ToolSpec(
        name="reg_shellbags",
        summary="Parse ShellBags registry CSV export",
        consumes=("shellbags",),
        produces=("folder_access",),
        when_to_use="Folder access history even when directory deleted",
        params=_artifact_params("ShellBags CSV relative to EVIDENCE_ROOT"),
    ),
    "reg_amcache": ToolSpec(
        name="reg_amcache",
        summary="Parse Amcache.hve for program execution (registry path)",
        consumes=("amcache",),
        produces=("execution_history",),
        when_to_use="First-execution timeline for binaries (R2)",
        params=_artifact_params("Amcache.hve relative to EVIDENCE_ROOT"),
        feeds_rules=("R2", "R16"),
    ),
    "mem_hivelist": ToolSpec(
        name="mem_hivelist",
        summary="Registry hives loaded in memory (Volatility hivelist)",
        consumes=("memory_image",),
        produces=("registry_hives",),
        when_to_use="Map in-memory registry before hive-on-disk analysis",
        params=_mem_params(),
    ),
    "mem_filescan": ToolSpec(
        name="mem_filescan",
        summary="File objects in memory (Volatility filescan)",
        consumes=("memory_image",),
        produces=("file_objects",),
        when_to_use="Find hidden/opened files not visible on disk",
        params=_mem_params(),
    ),
    "mem_cmdscan": ToolSpec(
        name="mem_cmdscan",
        summary="Command history buffers in memory (Volatility cmdscan)",
        consumes=("memory_image",),
        produces=("cmdlines",),
        when_to_use="Recover cmd.exe/PowerShell commands not in process cmdline",
        params=_mem_params(),
        feeds_rules=("R1", "R18"),
    ),
    "mem_handles": ToolSpec(
        name="mem_handles",
        summary="Open handles per process (Volatility handles)",
        consumes=("memory_image",),
        produces=("handle_list",),
        when_to_use="Inspect suspicious process handles after hidden PID found",
        params=_mem_params(),
    ),
    "mem_modules": ToolSpec(
        name="mem_modules",
        summary="Kernel modules in memory (Volatility modules)",
        consumes=("memory_image",),
        produces=("module_list",),
        when_to_use="Rootkit/driver triage — unexpected kernel modules",
        params=_mem_params(),
        mitre=("T1014",),
    ),
    "timeline_super": ToolSpec(
        name="timeline_super",
        summary="Super timeline merging EVTX, MFT, memory, USB, tasks, shimcache",
        consumes=("case_directory", "evtx", "mft", "memory_image", "setupapi_log", "scheduled_task", "shimcache"),
        produces=("timeline",),
        when_to_use="After individual parsers — unified cross-source temporal view",
        params=(
            _p("evtx_relpath", "string", False, "EVTX relative path"),
            _p("mft_relpath", "string", False, "MFT relative path"),
            _p("memory_relpath", "string", False, "Memory image relative path"),
            _p("setupapi_relpath", "string", False, "setupapi.dev.log relative path"),
            _p("scheduled_task_relpath", "string", False, "Scheduled task XML relative path"),
            _p("shimcache_relpath", "string", False, "ShimCache CSV relative path"),
            _p("max_events", "integer", False, "Cap timeline events"),
        ),
        feeds_rules=("R15",),
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
