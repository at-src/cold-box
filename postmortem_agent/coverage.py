"""Coverage frontier — track (tool × evidence) pairs before investigation can close."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from postmortem_agent.state import AgentConfig
from postmortem_mcp.catalog import CATALOG, ToolSpec

MEMORY_DEPTH_TOOLS = (
    "mem_pslist",
    "mem_psscan",
    "mem_netscan",
    "mem_malfind",
    "mem_cmdline",
    "mem_cmdscan",
)

LINUX_TOOLS = frozenset(
    {
        "linux_auth_log",
        "linux_syslog",
        "linux_bash_history",
        "linux_cron",
        "linux_persistence",
    }
)

SKIP_TOOLS = frozenset({"tool_catalog", "evidence_survey"})

WEB_TOOLS = frozenset({"web_parse_access_log", "web_inspect_artifact"})


def action_key(tool: str, arguments: dict[str, Any]) -> str:
    return f"{tool}:{json.dumps(arguments, sort_keys=True)}"


@dataclass(frozen=True)
class FrontierItem:
    tool: str
    arguments: dict[str, Any]
    reason: str
    priority: int = 0


@dataclass
class CoverageReport:
    total: int
    executed: int
    failed: int
    pending: list[FrontierItem]
    ratio: float

    def is_complete(self, *, min_ratio: float = 0.85) -> bool:
        return self.ratio >= min_ratio and not self.pending


def _linux_path_ok(relpath: str) -> bool:
    lower = relpath.lower().replace("\\", "/")
    name = lower.rsplit("/", 1)[-1]
    if "bash_history" in name or name == ".bash_history":
        return True
    if "cron" in name or "/cron" in lower:
        return True
    if "/var/log/" in lower or lower.startswith("var/log/"):
        return True
    if lower.startswith("linux/") or "/linux/" in lower:
        return True
    return name in {"auth.log", "syslog", "messages", "secure", "journal.ndjson"}


def _arguments_for(
    spec: ToolSpec,
    file_entry: dict[str, Any],
    config: AgentConfig,
    survey: dict[str, Any],
) -> dict[str, Any] | None:
    kind = file_entry.get("kind")
    relpath = file_entry.get("relpath", "")
    args: dict[str, Any] = {}

    if spec.name in LINUX_TOOLS and kind == "text" and not _linux_path_ok(relpath):
        return None

    basename = relpath.rsplit("/", 1)[-1].lower()
    if spec.name in {"disk_parse_usb", "reg_services"} and kind == "registry_hive" and basename != "system":
        return None

    for param in spec.params:
        if param.name == "memory_relpath" and kind == "memory_image":
            args["memory_relpath"] = relpath
        elif param.name == "artifact_relpath" and kind in spec.consumes:
            args["artifact_relpath"] = relpath
        elif param.name == "case_relpath":
            args["case_relpath"] = config.evidence_case
        elif param.name == "search_root_relpath":
            args["search_root_relpath"] = config.evidence_case or relpath or "."
        elif param.name == "patterns" and param.required:
            args["patterns"] = config.search_patterns or _default_search_patterns()
        elif param.name == "evtx_relpath" and kind == "evtx":
            args["evtx_relpath"] = relpath
        elif param.name == "mft_relpath" and kind == "mft":
            args["mft_relpath"] = relpath
        elif param.name == "memory_relpath" and kind == "memory_image" and "memory_relpath" not in args:
            args["memory_relpath"] = relpath

    required = {p.name for p in spec.params if p.required}
    if not required.issubset(args.keys()):
        if spec.name in {"disk_correlate_timeline", "timeline_super"}:
            return _correlate_args(config, survey)
        return None
    return args


def _correlate_args(config: AgentConfig, survey: dict[str, Any]) -> dict[str, Any] | None:
    args: dict[str, Any] = {}
    mem = _memory_relpath(config, survey)
    if mem:
        args["memory_relpath"] = mem
    for entry in survey.get("files") or []:
        kind = entry.get("kind")
        rel = entry.get("relpath")
        if kind == "evtx" and "evtx_relpath" not in args:
            args["evtx_relpath"] = rel
        if kind == "mft" and "mft_relpath" not in args:
            args["mft_relpath"] = rel
        if kind == "setupapi_log" and "setupapi_relpath" not in args:
            args["setupapi_relpath"] = rel
        if kind == "scheduled_task" and "scheduled_task_relpath" not in args:
            args["scheduled_task_relpath"] = rel
        if kind == "shimcache" and "shimcache_relpath" not in args:
            args["shimcache_relpath"] = rel
    return args or None


def _memory_relpath(config: AgentConfig, survey: dict[str, Any]) -> str | None:
    if config.memory_relpath:
        return config.memory_relpath
    for entry in survey.get("files") or []:
        if entry.get("kind") == "memory_image":
            return entry.get("relpath")
    return None


def _default_search_patterns() -> list[str]:
    return [
        "cmd.exe",
        "powershell",
        "php",
        "shell",
        "eval(",
        "webshell",
        "xampp",
        "apache",
        "sqlmap",
        "union select",
    ]


def _survey_has_web_surface(survey: dict[str, Any]) -> bool:
    for entry in survey.get("files") or []:
        kind = entry.get("kind", "")
        rel = str(entry.get("relpath", "")).lower()
        if kind in {"web_log", "web_artifact"}:
            return True
        if rel.startswith("web/") or "/uploads/" in rel:
            return True
    return False


def build_frontier(
    survey: dict[str, Any],
    config: AgentConfig,
    executed: set[str],
    failed: set[str],
) -> list[FrontierItem]:
    """All applicable (tool × evidence) actions not yet attempted."""
    items: list[FrontierItem] = []
    files = list(survey.get("files") or [])
    if not any(f.get("kind") == "case_directory" for f in files):
        files.insert(
            0,
            {
                "relpath": config.evidence_case,
                "kind": "case_directory",
                "applicable_tools": ["evidence_manifest"],
            },
        )

    for entry in files:
        for tool_name in entry.get("applicable_tools") or []:
            if tool_name in SKIP_TOOLS:
                continue
            spec = CATALOG.get(tool_name)
            if spec is None:
                continue
            if tool_name in {"disk_correlate_timeline", "timeline_super"}:
                arguments = _correlate_args(config, survey)
            else:
                arguments = _arguments_for(spec, entry, config, survey)
            if arguments is None:
                continue
            key = action_key(tool_name, arguments)
            if key in executed or key in failed:
                continue
            items.append(
                FrontierItem(
                    tool=tool_name,
                    arguments=arguments,
                    reason=f"coverage {entry.get('kind')} → {tool_name}",
                    priority=0,
                )
            )

    mem = _memory_relpath(config, survey)
    if mem:
        for tool_name in MEMORY_DEPTH_TOOLS:
            spec = CATALOG.get(tool_name)
            if spec is None:
                continue
            arguments = {"memory_relpath": mem}
            if spec.params and any(p.name == "max_records" for p in spec.params):
                arguments["max_records"] = 500 if tool_name != "mem_malfind" else 200
            key = action_key(tool_name, arguments)
            if key in executed or key in failed:
                continue
            items.append(
                FrontierItem(
                    tool=tool_name,
                    arguments=arguments,
                    reason=f"memory depth → {tool_name}",
                    priority=10,
                )
            )

    search_args = {
        "search_root_relpath": config.evidence_case or ".",
        "patterns": config.search_patterns or _default_search_patterns(),
    }
    search_key = action_key("disk_search_artifacts", search_args)
    if search_key not in executed and search_key not in failed:
        priority = 15 if _survey_has_web_surface(survey) else 5
        items.append(
            FrontierItem(
                tool="disk_search_artifacts",
                arguments=search_args,
                reason="breadth IOC search across case tree",
                priority=priority,
            )
        )

    if config.extracted_root and config.extracted_root.is_dir():
        ext_args = {
            "search_root_relpath": "extracted",
            "patterns": config.search_patterns or _default_search_patterns(),
        }
        ext_key = action_key("disk_search_artifacts", ext_args)
        if ext_key not in executed and ext_key not in failed:
            items.append(
                FrontierItem(
                    tool="disk_search_artifacts",
                    arguments=ext_args,
                    reason="breadth IOC search on extracted disk",
                    priority=12,
                )
            )

    if _survey_has_web_surface(survey):
        for entry in survey.get("files") or []:
            kind = entry.get("kind")
            rel = entry.get("relpath")
            if kind == "web_log":
                args = {"artifact_relpath": rel}
                key = action_key("web_parse_access_log", args)
                if key not in executed and key not in failed:
                    items.append(
                        FrontierItem(
                            tool="web_parse_access_log",
                            arguments=args,
                            reason="web access log attack triage",
                            priority=18,
                        )
                    )
            if kind == "web_artifact":
                args = {"artifact_relpath": rel}
                key = action_key("web_inspect_artifact", args)
                if key not in executed and key not in failed:
                    items.append(
                        FrontierItem(
                            tool="web_inspect_artifact",
                            arguments=args,
                            reason="inspect upload artifact for webshell code",
                            priority=16,
                        )
                    )

    return items


def coverage_report(
    survey: dict[str, Any],
    config: AgentConfig,
    executed: set[str],
    failed: set[str],
) -> CoverageReport:
    pending = build_frontier(survey, config, executed, failed)
    attempted = len(executed) + len(failed)
    total = attempted + len(pending)
    ratio = (attempted / total) if total else 1.0
    return CoverageReport(
        total=total,
        executed=len(executed),
        failed=len(failed),
        pending=pending,
        ratio=ratio,
    )


def next_frontier_action(report: CoverageReport) -> dict[str, Any] | None:
    if not report.pending:
        return None
    best = max(report.pending, key=lambda item: item.priority)
    return {
        "action": "tool",
        "tool": best.tool,
        "arguments": best.arguments,
        "reason": best.reason,
    }


def should_block_done(report: CoverageReport, *, min_ratio: float = 0.82) -> bool:
    """Block early termination while meaningful surface remains."""
    if report.pending and report.ratio < min_ratio:
        return True
    high_priority = [p for p in report.pending if p.priority >= 10]
    return bool(high_priority)
