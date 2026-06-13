"""Tool catalog record — one SIFT operator definition."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolInput:
    style: str
    flag: str = ""
    common_flags: tuple[dict[str, Any], ...] = ()
    harness_usage: str = ""


@dataclass(frozen=True)
class ToolOutput:
    format: str
    style: str


STATUS_AGENT_LABELS: dict[str, str] = {
    "ok": "lab tested",
    "not_tested": "not tested",
    "bad": "do not use",
    "unavailable": "not installed on host",
}


@dataclass(frozen=True)
class ToolVerification:
    status: str
    runnable: bool
    detail: str = ""

    @property
    def agent_label(self) -> str:
        return STATUS_AGENT_LABELS.get(self.status, self.status)

    @property
    def agent_runnable(self) -> bool:
        if self.status in {"bad", "unavailable"}:
            return False
        return self.runnable


@dataclass(frozen=True)
class ToolRecord:
    tool_id: str
    name: str
    binary: str
    category: str
    description: str
    host_platforms: tuple[str, ...]
    artifact_platforms: tuple[str, ...]
    input: ToolInput
    output: ToolOutput
    timeout_seconds: int
    verification: ToolVerification
    interactive: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ToolRecord:
        inp = raw.get("input") or {}
        out = raw.get("output") or {}
        ver = raw.get("verification") or {}
        flags = tuple(inp.get("common_flags") or ())
        return cls(
            tool_id=str(raw["tool_id"]),
            name=str(raw["name"]),
            binary=str(raw["binary"]),
            category=str(raw["category"]),
            description=str(raw["description"]),
            host_platforms=tuple(raw.get("host_platforms") or ["linux"]),
            artifact_platforms=tuple(raw.get("artifact_platforms") or ["any"]),
            input=ToolInput(
                style=str(inp.get("style") or "positional"),
                flag=str(inp.get("flag") or ""),
                common_flags=flags,
                harness_usage=str(inp.get("harness_usage") or ""),
            ),
            output=ToolOutput(
                format=str(out.get("format") or "text"),
                style=str(out.get("style") or "stdout"),
            ),
            timeout_seconds=int(raw.get("timeout_seconds") or 600),
            interactive=bool(raw.get("interactive", False)),
            verification=ToolVerification(
                status=str(ver.get("status") or "not_tested"),
                runnable=bool(ver.get("runnable", False)),
                detail=str(ver.get("detail") or ""),
            ),
        )

    def to_describe_dict(self) -> dict[str, Any]:
        """Shape returned by describe_sift_tool (MCP / agent)."""
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "binary": self.binary,
            "category": self.category,
            "description": self.description,
            "host_platforms": list(self.host_platforms),
            "artifact_platforms": list(self.artifact_platforms),
            "input": {
                "style": self.input.style,
                "flag": self.input.flag,
                "common_flags": list(self.input.common_flags),
                "harness_usage": self.input.harness_usage,
            },
            "output": {
                "format": self.output.format,
                "style": self.output.style,
            },
            "timeout_seconds": self.timeout_seconds,
            "interactive": self.interactive,
            "verification": {
                "status": self.verification.status,
                "label": self.verification.agent_label,
                "detail": self.verification.detail,
                "runnable": self.verification.runnable,
                "agent_runnable": self.verification.agent_runnable,
            },
        }

    def to_list_dict(self) -> dict[str, Any]:
        """Compact row for list_sift_tools."""
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "host_platforms": list(self.host_platforms),
            "artifact_platforms": list(self.artifact_platforms),
            "verification": {
                "status": self.verification.status,
                "label": self.verification.agent_label,
                "runnable": self.verification.runnable,
            },
        }
