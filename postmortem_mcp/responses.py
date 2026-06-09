"""Structured MCP tool responses."""

from __future__ import annotations

from typing import Any


def tool_response(
    *,
    ok: bool,
    tool: str,
    audit_id: str,
    data: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": ok,
        "tool": tool,
        "audit_id": audit_id,
    }
    if data is not None:
        payload["data"] = data
    if error is not None:
        payload["error"] = error
    return payload
