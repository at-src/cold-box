"""Generic tool invocation with catalog validation and fixture/cache support."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from postmortem_agent.cache import load_cached_tool
from postmortem_agent.state import AgentConfig
from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.catalog import CATALOG, ToolSpec
from postmortem_mcp.dispatch import TOOL_REGISTRY, ToolNotFound

FIXTURE_MAP: dict[str, str] = {
    "mem_pslist": "r1-pslist.json",
    "mem_psscan": "r1-psscan.json",
    "mem_cmdline": "r1-cmdline.json",
    "mem_netscan": "r6-netscan.json",
}

FIXTURE_ALIASES: dict[str, str] = {
    "mem_pslist_r3": "r3-pslist.json",
    "mem_pslist_r6": "r6-pslist.json",
}


class ArgValidationError(ValueError):
    pass


def validate_args(spec: ToolSpec, arguments: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise ArgValidationError("arguments must be a JSON object")
    validated: dict[str, Any] = {}
    allowed = {p.name for p in spec.params}
    for key, value in arguments.items():
        if key not in allowed:
            raise ArgValidationError(f"unknown argument {key!r} for tool {spec.name}")
        validated[key] = value
    for param in spec.params:
        if param.required and param.name not in validated:
            raise ArgValidationError(f"missing required argument {param.name!r} for tool {spec.name}")
    return validated


def _load_fixture(config: AgentConfig, name: str) -> dict[str, Any]:
    assert config.fixture_dir is not None
    path = config.fixture_dir / name
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_fixture_name(config: AgentConfig, tool: str) -> str | None:
    if config.fixture_dir is None:
        return None
    if tool in FIXTURE_MAP and (config.use_fixtures or config.mode == "synthetic"):
        return FIXTURE_MAP[tool]
    return FIXTURE_ALIASES.get(tool)


def _run_fixture_tool(
    config: AgentConfig,
    tool: str,
    fixture_name: str,
    iteration: int,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    payload = _load_fixture(config, fixture_name)

    def execute() -> dict[str, Any]:
        return payload

    return run_audited_tool(
        case_id=config.case_id,
        tool=tool,
        args={"mode": "fixture", "fixture": fixture_name, **arguments},
        iteration=iteration,
        execute=execute,
    )


def call_agent_tool(
    name: str,
    arguments: dict[str, Any] | None,
    *,
    config: AgentConfig,
    iteration: int,
) -> dict[str, Any]:
    """Validate and invoke a tool; returns structured result (never raises to caller)."""
    args = dict(arguments or {})
    if name not in CATALOG:
        return {
            "ok": False,
            "tool": name,
            "audit_id": None,
            "error": f"unknown tool {name!r}",
        }

    spec = CATALOG[name]
    try:
        validated = validate_args(spec, args)
    except ArgValidationError as exc:
        return {"ok": False, "tool": name, "audit_id": None, "error": str(exc)}

    if config.cache_dir and name.startswith("mem_"):
        cached = load_cached_tool(config.cache_dir, name)
        if cached is not None:

            def execute_cache() -> dict[str, Any]:
                return cached

            return run_audited_tool(
                case_id=config.case_id,
                tool=name,
                args={"from_cache": str(config.cache_dir / f"{name}.json"), **validated},
                iteration=iteration,
                execute=execute_cache,
            )

    fixture_name = _resolve_fixture_name(config, name)
    if fixture_name:
        return _run_fixture_tool(config, name, fixture_name, iteration, validated)

    if name == "evidence_manifest" and config.use_fixtures:
        def execute_manifest() -> dict[str, Any]:
            return {
                "case_root": config.evidence_case,
                "manifest_digest": "synthetic-fixture",
                "file_count": 0,
                "generated_at": "synthetic",
                "files": [],
            }

        return run_audited_tool(
            case_id=config.case_id,
            tool=name,
            args={"mode": "synthetic", **validated},
            iteration=iteration,
            execute=execute_manifest,
        )

    fn = TOOL_REGISTRY.get(name)
    if fn is None:
        return {"ok": False, "tool": name, "audit_id": None, "error": f"tool {name!r} not registered"}

    try:
        return fn(config.case_id, iteration=iteration, **validated)
    except ToolNotFound as exc:
        return {"ok": False, "tool": name, "audit_id": None, "error": str(exc)}
    except TypeError as exc:
        return {"ok": False, "tool": name, "audit_id": None, "error": f"invalid arguments: {exc}"}
    except Exception as exc:
        return {"ok": False, "tool": name, "audit_id": None, "error": str(exc)}


def list_registered_tools() -> list[str]:
    return sorted(TOOL_REGISTRY.keys())
