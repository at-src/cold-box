"""Tool dispatch for agent runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from postmortem_agent.cache import load_cached_tool
from postmortem_agent.state import AgentConfig
from postmortem_mcp.dispatch import TOOL_REGISTRY

FIXTURES_R1 = {
    "mem_pslist": "r1-pslist.json",
    "mem_psscan": "r1-psscan.json",
    "mem_cmdline": "r1-cmdline.json",
}

FIXTURES_LAB = {
    **FIXTURES_R1,
    "mem_netscan": "r6-netscan.json",
    "security_events": "r3-security.json",
}

FIXTURE_ALIASES = {
    "mem_pslist_r3": "r3-pslist.json",
    "mem_pslist_r6": "r6-pslist.json",
    "mem_pslist_r2": "r2-pslist.json",
}

MEMORY_TOOLS = frozenset({"mem_pslist", "mem_psscan", "mem_cmdline", "mem_netscan", "mem_malfind"})


def _fixture_map(config: AgentConfig) -> dict[str, str]:
    if config.profile == "lab":
        return FIXTURES_LAB
    return FIXTURES_R1


def _load_fixture(config: AgentConfig, name: str) -> dict[str, Any]:
    assert config.fixture_dir is not None
    path = config.fixture_dir / name
    return json.loads(path.read_text(encoding="utf-8"))


def _run_fixture_tool(
    config: AgentConfig,
    tool: str,
    fixture_name: str,
    iteration: int,
) -> dict[str, Any]:
    from postmortem_mcp.audit_tool import run_audited_tool

    payload = _load_fixture(config, fixture_name)

    def execute() -> dict[str, Any]:
        return payload

    return run_audited_tool(
        case_id=config.case_id,
        tool=tool,
        args={"mode": "fixture", "fixture": fixture_name},
        iteration=iteration,
        execute=execute,
    )


def _resolve_fixture(
    config: AgentConfig,
    tool: str,
    fixture_override: str | None,
) -> str | None:
    if fixture_override:
        return fixture_override
    if config.fixture_dir is None:
        return None
    if tool in _fixture_map(config):
        if config.mode == "synthetic" or config.profile == "lab":
            return _fixture_map(config)[tool]
    return FIXTURE_ALIASES.get(tool)


def invoke_tool(
    tool: str,
    *,
    config: AgentConfig,
    iteration: int,
    fixture_override: str | None = None,
) -> dict[str, Any]:
    if config.cache_dir and tool in MEMORY_TOOLS:
        cached = load_cached_tool(config.cache_dir, tool)
        if cached is not None:
            from postmortem_mcp.audit_tool import run_audited_tool

            def execute() -> dict[str, Any]:
                return cached

            return run_audited_tool(
                case_id=config.case_id,
                tool=tool,
                args={"from_cache": str(config.cache_dir / f"{tool}.json")},
                iteration=iteration,
                execute=execute,
            )

    fixture_name = _resolve_fixture(config, tool, fixture_override)
    if fixture_name and config.fixture_dir:
        return _run_fixture_tool(config, tool, fixture_name, iteration)

    fn = TOOL_REGISTRY.get(tool)
    if fn is None:
        raise RuntimeError(f"Unknown tool {tool}")

    if tool == "evidence_manifest":
        if config.mode == "synthetic" or config.profile == "lab":

            def execute() -> dict[str, Any]:
                return {
                    "case_root": config.evidence_case,
                    "manifest_digest": "bundled-demo",
                    "file_count": 12,
                    "generated_at": "demo",
                    "files": [],
                }

            from postmortem_mcp.audit_tool import run_audited_tool

            return run_audited_tool(
                case_id=config.case_id,
                tool=tool,
                args={"mode": "demo", "case": config.evidence_case},
                iteration=iteration,
                execute=execute,
            )
        return fn(config.case_id, config.evidence_case, iteration=iteration)

    if tool in MEMORY_TOOLS:
        if not config.memory_relpath:
            raise RuntimeError(f"{tool} requires --memory")
        return fn(config.case_id, config.memory_relpath, iteration=iteration)

    if tool == "disk_parse_prefetch" and config.prefetch_relpath:
        return fn(config.case_id, config.prefetch_relpath, iteration=iteration)
    if tool == "disk_parse_amcache" and config.amcache_relpath:
        return fn(config.case_id, config.amcache_relpath, iteration=iteration)
    if tool == "disk_parse_mft" and config.mft_relpath:
        return fn(config.case_id, config.mft_relpath, iteration=iteration)
    if tool == "disk_detect_timestomp" and config.mft_relpath:
        return fn(config.case_id, config.mft_relpath, iteration=iteration)
    if tool == "disk_parse_evtx" and config.evtx_relpath:
        return fn(config.case_id, config.evtx_relpath, iteration=iteration)

    raise RuntimeError(f"Agent cannot invoke {tool} without explicit artifact paths")
