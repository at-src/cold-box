"""MCP tool exports."""

from postmortem_mcp.tools.analysis import (
    disk_correlate_timeline,
    disk_evtx_filter,
    disk_parse_registry,
    disk_search_artifacts,
    timeline_super,
)
from postmortem_mcp.tools.disk import (
    disk_detect_timestomp,
    disk_parse_amcache,
    disk_parse_evtx,
    disk_parse_jumplist,
    disk_parse_lnk,
    disk_parse_mft,
    disk_parse_prefetch,
    disk_parse_scheduled_tasks,
    disk_parse_setupapi,
    disk_parse_shimcache,
    disk_parse_srum,
    disk_parse_userassist,
    disk_parse_usnjrnl,
    disk_recycle_bin,
    disk_parse_ie_index_dat,
    disk_parse_ie_cache,
    disk_inspect_capture,
    disk_parse_pst,
    disk_mft_user_docs,
)
from postmortem_mcp.catalog import tool_catalog
from postmortem_mcp.survey import evidence_survey
from postmortem_mcp.tools.evidence import evidence_manifest
from postmortem_mcp.tools.ingest import disk_extract_image
from postmortem_mcp.tools.linux import (
    linux_auth_log,
    linux_bash_history,
    linux_cron,
    linux_persistence,
    linux_syslog,
)
from postmortem_mcp.tools.network import (
    net_conversations,
    net_dns_extract,
    net_http_extract,
    net_pcap_summary,
)
from postmortem_mcp.tools.memory import (
    mem_cmdline,
    mem_cmdscan,
    mem_dlllist,
    mem_filescan,
    mem_handles,
    mem_hivelist,
    mem_linux_probe,
    mem_malfind,
    mem_modules,
    mem_netscan,
    mem_pslist,
    mem_psscan,
    mem_pstree,
    mem_svcscan,
)
from postmortem_mcp.tools.agent_runner import investigation_run
from postmortem_mcp.tools.android import android_probe, android_scan_artifacts
from postmortem_mcp.tools.macos import macos_probe, macos_scan_artifacts
from postmortem_mcp.tools.tier3 import disk_scan_exfil, yara_scan_evidence
from postmortem_mcp.tools.logs import logs_parse_structured
from postmortem_mcp.tools.web import web_inspect_artifact, web_parse_access_log
from postmortem_mcp.tools.registry import (
    disk_parse_usb,
    reg_amcache,
    reg_query,
    reg_run_keys,
    reg_services,
    reg_shellbags,
    reg_system_profile,
    reg_userassist,
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

WAVE3_TOOLS = [
    mem_pstree,
    mem_dlllist,
    mem_svcscan,
    disk_evtx_filter,
    disk_parse_registry,
    disk_correlate_timeline,
    disk_search_artifacts,
]

META_TOOLS = [
    evidence_survey,
    tool_catalog,
    investigation_run,
]

WAVE4_TOOLS = [
    net_pcap_summary,
    net_dns_extract,
    net_http_extract,
    net_conversations,
    linux_auth_log,
    linux_syslog,
    linux_bash_history,
    linux_cron,
    linux_persistence,
]

WAVE5_TOOLS = [
    disk_parse_setupapi,
    disk_parse_scheduled_tasks,
    disk_parse_shimcache,
    disk_parse_userassist,
    disk_parse_lnk,
    disk_parse_jumplist,
    disk_parse_srum,
    disk_parse_usnjrnl,
    disk_recycle_bin,
    disk_parse_ie_index_dat,
    disk_parse_ie_cache,
    disk_inspect_capture,
    disk_parse_pst,
    disk_mft_user_docs,
    reg_run_keys,
    reg_services,
    reg_userassist,
    reg_shellbags,
    reg_amcache,
    reg_system_profile,
    reg_query,
    mem_hivelist,
    mem_filescan,
    mem_cmdscan,
    mem_handles,
    mem_modules,
    timeline_super,
]

WAVE6_TOOLS = [
    web_parse_access_log,
    web_inspect_artifact,
    logs_parse_structured,
]

WAVE7_TOOLS = [
    disk_scan_exfil,
    yara_scan_evidence,
    mem_linux_probe,
]

WAVE8_TOOLS = [
    android_probe,
    android_scan_artifacts,
    macos_probe,
    macos_scan_artifacts,
]

# Raw-image ingest — the front door that turns a disk image into the extracted
# artifact tree every other tool consumes.
INGEST_TOOLS = [
    disk_extract_image,
    disk_parse_usb,
]

ALL_TOOLS = (
    WAVE1_TOOLS + WAVE2_TOOLS + WAVE3_TOOLS + META_TOOLS
    + WAVE4_TOOLS + WAVE5_TOOLS + WAVE6_TOOLS + WAVE7_TOOLS + WAVE8_TOOLS + INGEST_TOOLS
)

__all__ = [
    fn.__name__
    for fn in ALL_TOOLS
] + ["WAVE1_TOOLS", "WAVE2_TOOLS", "WAVE3_TOOLS", "ALL_TOOLS"]
