"""Tool dispatch for agent runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from postmortem_agent.state import AgentConfig
from postmortem_mcp.dispatch import TOOL_REGISTRY

SYNTHETIC_FIXTURES = {
    "mem_pslist": "r1-pslist.json",
    "mem_psscan": "r1-psscan.json",
    "mem_cmdline": "r1-cmdline.json",
}


def _load_fixture(config: AgentConfig, tool: str) -> dict[str, Any]:
    assert config.fixture_dir is not None
    name = SYNTHETIC_FIXTURES.get(tool)
    if not name:
        raise RuntimeError(f"No synthetic fixture for tool {tool}")
    path = config.fixture_dir / name
    return json.loads(path.read_text(encoding="utf-8"))


def invoke_tool(
    tool: str,
    *,
    config: AgentConfig,
    iteration: int,
) -> dict[str, Any]:
    if config.mode == "synthetic" and tool in SYNTHETIC_FIXTURES:
        from postmortem_mcp.audit_tool import run_audited_tool

        fixture = _load_fixture(config, tool)

        def execute() -> dict[str, Any]:
            return fixture

        return run_audited_tool(
            case_id=config.case_id,
            tool=tool,
            args={"mode": "synthetic", "fixture": SYNTHETIC_FIXTURES[tool]},
            iteration=iteration,
            execute=execute,
        )

    fn = TOOL_REGISTRY[tool]
    if tool == "evidence_manifest":
        if config.mode == "synthetic":

            def execute() -> dict[str, Any]:
                return {
                    "case_root": "synthetic-r1",
                    "manifest_digest": "synthetic-demo",
                    "file_count": 2,
                    "generated_at": "synthetic",
                    "files": [],
                }

            from postmortem_mcp.audit_tool import run_audited_tool

            return run_audited_tool(
                case_id=config.case_id,
                tool=tool,
                args={"mode": "synthetic", "case": config.evidence_case},
                iteration=iteration,
                execute=execute,
            )
        return fn(config.case_id, config.evidence_case, iteration=iteration)
    if tool in {"mem_pslist", "mem_psscan", "mem_cmdline", "mem_netscan", "mem_malfind"}:
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
    raise RuntimeError(f"Agent cannot invoke {tool} without explicit artifact paths")
