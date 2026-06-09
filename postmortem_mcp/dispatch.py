"""Central MCP tool dispatch with explicit ToolNotFound guardrails."""

from __future__ import annotations

from typing import Any, Callable

from postmortem_mcp.tools import ALL_TOOLS

FORBIDDEN_TOOLS = frozenset(
    {
        "execute_shell",
        "write_file",
        "mount",
        "umount",
        "network_egress",
        "eval",
        "exec_python",
        "delete_file",
        "system",
    }
)

TOOL_REGISTRY: dict[str, Callable[..., dict]] = {fn.__name__: fn for fn in ALL_TOOLS}


class ToolNotFound(KeyError):
    """Raised when a tool is not registered on the MCP surface."""


def list_tools() -> list[str]:
    return sorted(TOOL_REGISTRY)


def call_tool(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    if name in FORBIDDEN_TOOLS:
        raise ToolNotFound(f"ToolNotFound: {name!r} is not registered")
    fn = TOOL_REGISTRY.get(name)
    if fn is None:
        raise ToolNotFound(f"ToolNotFound: {name!r} is not registered")
    return fn(**(arguments or {}))
