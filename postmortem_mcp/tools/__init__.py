"""MCP tool exports."""

from postmortem_mcp.tools.analysis import (
    disk_correlate_timeline,
    disk_evtx_filter,
    disk_parse_registry,
    disk_search_artifacts,
)
from postmortem_mcp.tools.disk import (
    disk_detect_timestomp,
    disk_parse_amcache,
    disk_parse_evtx,
    disk_parse_mft,
    disk_parse_prefetch,
)
from postmortem_mcp.catalog import tool_catalog
from postmortem_mcp.survey import evidence_survey
from postmortem_mcp.tools.evidence import evidence_manifest
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
    mem_dlllist,
    mem_malfind,
    mem_netscan,
    mem_pslist,
    mem_psscan,
    mem_pstree,
    mem_svcscan,
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

ALL_TOOLS = WAVE1_TOOLS + WAVE2_TOOLS + WAVE3_TOOLS + META_TOOLS + WAVE4_TOOLS

__all__ = [
    fn.__name__
    for fn in ALL_TOOLS
] + ["WAVE1_TOOLS", "WAVE2_TOOLS", "WAVE3_TOOLS", "ALL_TOOLS"]
