"""Evidence-driven policy reasoner — no fixed step lists."""

from __future__ import annotations

import json
from typing import Any

from postmortem_agent.coverage import (
    action_key as _action_key,
    build_frontier,
    coverage_report,
    next_frontier_action,
    should_block_done,
)
from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_mcp.catalog import CATALOG, ToolSpec

FOLLOWUP: dict[str, tuple[str, ...]] = {
    "R1": ("mem_cmdline", "mem_malfind", "mem_psscan"),
    "R7": ("mem_cmdline", "mem_dlllist", "mem_malfind"),
    "R3": ("disk_evtx_filter", "disk_parse_evtx", "mem_pslist"),
    "R6": ("mem_netscan", "mem_pslist"),
    "R4": ("disk_detect_timestomp", "disk_parse_mft"),
    "R5": ("disk_search_artifacts", "disk_parse_prefetch"),
    "R2": ("reg_amcache", "disk_parse_amcache", "disk_parse_prefetch"),
    "R8": ("net_dns_extract", "net_conversations"),
    "R9": ("net_http_extract", "net_conversations"),
    "R10": ("linux_persistence", "linux_bash_history", "linux_cron"),
    "R11": ("reg_services", "mem_svcscan", "disk_search_artifacts"),
    "R12": ("disk_parse_setupapi", "timeline_super"),
    "R13": ("disk_parse_scheduled_tasks", "reg_run_keys", "timeline_super"),
    "R14": ("disk_search_artifacts",),
    "R15": ("timeline_super", "disk_correlate_timeline"),
    "R16": ("reg_amcache", "disk_parse_amcache", "disk_parse_prefetch", "disk_parse_shimcache"),
    "R18": ("mem_cmdline", "mem_cmdscan"),
    "R19": ("web_parse_access_log", "web_inspect_artifact"),
    "R20": ("logs_parse_structured",),
}

COVERAGE_RULES: dict[str, tuple[str, ...]] = {
    "R2": ("reg_amcache", "disk_parse_amcache"),
    "R6": ("mem_netscan",),
    "R14": ("disk_search_artifacts",),
    "R16": ("reg_amcache", "disk_parse_amcache", "disk_parse_prefetch"),
    "R19": ("web_parse_access_log", "web_inspect_artifact"),
    "R20": ("logs_parse_structured",),
    "R21": ("disk_parse_usb",),
}

PRIORITY_TOOLS = ("evidence_manifest", "mem_pslist", "mem_psscan", "disk_search_artifacts")


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


def _arguments_for(spec: ToolSpec, file_entry: dict[str, Any], config: AgentConfig) -> dict[str, Any] | None:
    kind = file_entry.get("kind")
    relpath = file_entry.get("relpath", "")

    if spec.name in {"linux_bash_history", "linux_cron"} and kind == "text":
        if not _linux_path_ok(relpath):
            return None

    # USBSTOR lives only in the SYSTEM hive; and the RECmd services sweep only
    # makes sense against SYSTEM. Targeting the right hive avoids burning
    # iterations failing against NTUSER.DAT / UsrClass.dat / SOFTWARE.
    basename = relpath.rsplit("/", 1)[-1].lower()
    if spec.name in {"disk_parse_usb", "reg_services"} and kind == "registry_hive" and basename != "system":
        return None

    args: dict[str, Any] = {}

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
            args["patterns"] = config.search_patterns or [
                "cmd.exe",
                "powershell",
                "php",
                "shell",
                "eval",
            ]
        elif param.name == "evtx_relpath" and kind == "evtx":
            args["evtx_relpath"] = relpath
        elif param.name == "mft_relpath" and kind == "mft":
            args["mft_relpath"] = relpath
        elif param.name == "memory_relpath" and kind == "memory_image" and "memory_relpath" not in args:
            args["memory_relpath"] = relpath

    required = {p.name for p in spec.params if p.required}
    if not required.issubset(args.keys()):
        if spec.name in {"disk_correlate_timeline", "timeline_super"}:
            return _correlate_args(config, file_entry)
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


def _tool_succeeded(results: dict[str, list[dict[str, Any]]], tool: str) -> bool:
    return any(run.get("ok") for run in results.get(tool) or [])


def _coverage_action(
    verifier: list[Any],
    results: dict[str, list[dict[str, Any]]],
    survey: dict[str, Any],
    config: AgentConfig,
    executed: set[str],
    failed: set[str],
) -> dict[str, Any] | None:
    skipped = {r.rule_id for r in verifier if getattr(r, "status", None) == "skipped"}
    for rule_id, tools in COVERAGE_RULES.items():
        if rule_id not in skipped:
            continue
        if any(_tool_succeeded(results, tool) for tool in tools):
            continue
        for tool in tools:
            args = _coverage_tool_args(tool, survey, config)
            if args is None:
                continue
            key = _action_key(tool, args)
            if key in executed or key in failed:
                continue
            return {
                "action": "tool",
                "tool": tool,
                "arguments": args,
                "reason": f"coverage for skipped {rule_id}",
            }
    return None


def _coverage_tool_args(
    tool: str,
    survey: dict[str, Any],
    config: AgentConfig,
) -> dict[str, Any] | None:
    if tool == "mem_netscan":
        mem = _memory_relpath(config, survey)
        return {"memory_relpath": mem} if mem else None
    if tool in {"reg_amcache", "disk_parse_amcache"}:
        rel = _first_relpath(survey, "amcache")
        return {"artifact_relpath": rel} if rel else None
    if tool == "disk_search_artifacts":
        root = "extracted" if config.extracted_root else config.evidence_case
        return {
            "search_root_relpath": root,
            "patterns": config.search_patterns or _default_search_patterns(),
        }
    if tool == "web_parse_access_log":
        rel = _first_relpath(survey, "web_log")
        return {"artifact_relpath": rel} if rel else None
    if tool == "web_inspect_artifact":
        rel = _first_relpath(survey, "web_artifact")
        return {"artifact_relpath": rel} if rel else None
    if tool == "logs_parse_structured":
        rel = _first_relpath(survey, "structured_log")
        return {"artifact_relpath": rel} if rel else None
    if tool == "disk_parse_usb":
        rel = _system_hive_relpath(survey)
        return {"artifact_relpath": rel} if rel else None
    return None


def _build_candidates(
    survey: dict[str, Any],
    catalog: dict[str, Any],
    config: AgentConfig,
    executed: set[str],
    failed: set[str] | None = None,
) -> list[tuple[int, str, dict[str, Any], str]]:
    failed = failed or set()
    candidates: list[tuple[int, str, dict[str, Any], str]] = []
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
            if tool_name in {"tool_catalog", "evidence_survey"}:
                continue
            spec = CATALOG.get(tool_name)
            if spec is None:
                continue
            if tool_name == "disk_correlate_timeline" or tool_name == "timeline_super":
                arguments = _correlate_args(config, survey)
            else:
                arguments = _arguments_for(spec, entry, config)
            if arguments is None:
                continue
            key = _action_key(tool_name, arguments)
            if key in executed or key in failed:
                continue
            reason = f"survey {entry.get('kind')} → {tool_name}"
            candidates.append((0, tool_name, arguments, reason))

    for tool_name in PRIORITY_TOOLS:
        spec = CATALOG.get(tool_name)
        if spec is None:
            continue
        if tool_name == "evidence_manifest":
            arguments = {"case_relpath": config.evidence_case}
        elif tool_name.startswith("mem_"):
            mem = _memory_relpath(config, survey)
            if not mem and config.use_fixtures:
                mem = "fixture/mem_pslist.json"
            if not mem:
                continue
            arguments = {"memory_relpath": mem}
        else:
            continue
        key = _action_key(tool_name, arguments)
        if key not in executed and key not in failed:
            candidates.append((5, tool_name, arguments, f"baseline {tool_name}"))

    if config.extracted_root and config.extracted_root.is_dir():
        key = _action_key(
            "disk_search_artifacts",
            {"search_root_relpath": "extracted", "patterns": config.search_patterns or _default_search_patterns()},
        )
        if key not in executed and key not in failed:
            candidates.append(
                (
                    8,
                    "disk_search_artifacts",
                    {
                        "search_root_relpath": "extracted",
                        "patterns": config.search_patterns or _default_search_patterns(),
                    },
                    "breadth IOC search on extracted disk",
                )
            )

    return candidates


def _default_search_patterns() -> list[str]:
    return ["cmd.exe", "powershell", "php", "shell", "eval", "xampp", "apache"]


def _memory_relpath(config: AgentConfig, survey: dict[str, Any]) -> str | None:
    if config.memory_relpath:
        return config.memory_relpath
    return _first_relpath(survey, "memory_image")


def _first_relpath(survey: dict[str, Any], kind: str) -> str | None:
    for entry in survey.get("files") or []:
        if entry.get("kind") == kind:
            return entry.get("relpath")
    return None


def _system_hive_relpath(survey: dict[str, Any]) -> str | None:
    """The SYSTEM hive specifically — USBSTOR / services live only there."""
    for entry in survey.get("files") or []:
        if entry.get("kind") != "registry_hive":
            continue
        rel = entry.get("relpath") or ""
        if rel.rsplit("/", 1)[-1].lower() == "system":
            return rel
    return None


def _score_candidate(
    tool: str,
    results: dict[str, list[dict[str, Any]]],
    verifier: list[Any],
    survey: dict[str, Any],
) -> int:
    spec = CATALOG.get(tool)
    if spec is None:
        return 0
    score = 0
    skipped = {r.rule_id for r in verifier if getattr(r, "status", None) == "skipped"}
    contradictions = {r.rule_id for r in verifier if getattr(r, "status", None) == "contradiction"}
    survey_kinds = set(survey.get("kinds_present") or [])

    for rule_id in spec.feeds_rules:
        if rule_id in skipped:
            if rule_id == "R10" and "linux_log" not in survey_kinds:
                continue
            if rule_id in {"R8", "R9"} and "pcap" not in survey_kinds:
                continue
            if rule_id in {"R11", "R12", "R13", "R16"} and not set(spec.consumes) & survey_kinds:
                continue
            score += 100
            if rule_id in {"R11", "R12", "R13", "R16"}:
                score += 60
        if rule_id in contradictions:
            score += 80
        followups = FOLLOWUP.get(rule_id, ())
        if tool in followups and rule_id in contradictions:
            score += 120

    if "R1" in skipped and tool == "mem_psscan" and _tool_succeeded(results, "mem_pslist"):
        score += 80
    if "R6" in skipped and tool == "mem_netscan":
        score += 90
    if "R14" in skipped and tool == "disk_search_artifacts":
        score += 140
    if "R16" in skipped and tool in {"reg_amcache", "disk_parse_amcache", "disk_parse_prefetch"}:
        score += 125
    if "R19" in skipped and tool in {"web_parse_access_log", "web_inspect_artifact"}:
        score += 140
    if "R20" in skipped and tool == "logs_parse_structured":
        score += 90
    if "R21" in skipped and tool == "disk_parse_usb" and "registry_hive" in survey_kinds:
        score += 135
    if "amcache" in survey_kinds and tool in {"reg_amcache", "disk_parse_amcache"}:
        if not _tool_succeeded(results, tool):
            score += 130

    if _tool_succeeded(results, tool):
        score -= 180

    if tool not in results:
        score += 10
    return score


class PolicyReasoner:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.executed: set[str] = set()
        self.failed: set[str] = set()
        self._catalog_requested = False

    def decide(
        self,
        *,
        goal: str,
        survey: dict[str, Any],
        catalog: dict[str, Any],
        skills: list[dict[str, Any]],
        results: dict[str, list[dict[str, Any]]],
        verifier: list[Any],
        hypothesis: str,
        lessons: list[str],
        pattern_hints: list[str],
        **_ignored: Any,
    ) -> dict[str, Any]:
        del goal, skills, lessons, pattern_hints  # advisory only; policy uses evidence scores

        for tool, runs in results.items():
            for run in runs:
                args_used = run.get("args") or {}
                key = _action_key(tool, args_used)
                if run.get("ok"):
                    self.executed.add(key)
                else:
                    self.failed.add(key)

        if not self._catalog_requested and "tool_catalog" not in results:
            self._catalog_requested = True
            return {
                "action": "tool",
                "tool": "tool_catalog",
                "arguments": {},
                "reason": "load tool metadata",
            }

        candidates = _build_candidates(survey, catalog, self.config, self.executed, self.failed)
        report = coverage_report(survey, self.config, self.executed, self.failed)

        if not candidates:
            forced = _coverage_action(verifier, results, survey, self.config, self.executed, self.failed)
            if forced:
                return forced
            frontier = next_frontier_action(report)
            if frontier:
                return frontier
            if should_block_done(report):
                pending = build_frontier(survey, self.config, self.executed, self.failed)
                if pending:
                    item = max(pending, key=lambda p: p.priority)
                    return {
                        "action": "tool",
                        "tool": item.tool,
                        "arguments": item.arguments,
                        "reason": f"coverage frontier ({report.ratio:.0%} complete): {item.reason}",
                    }
            return {
                "action": "done",
                "hypothesis": hypothesis,
                "confidence": state_confidence(results, verifier),
            }

        best: tuple[int, str, dict[str, Any], str] | None = None
        for _, tool, arguments, reason in candidates:
            score = _score_candidate(tool, results, verifier, survey)
            if best is None or score > best[0]:
                best = (score, tool, arguments, reason)

        assert best is not None
        _, tool, arguments, reason = best

        report = coverage_report(survey, self.config, self.executed, self.failed)
        if tool != "disk_search_artifacts" and "R14" in {
            r.rule_id for r in verifier if getattr(r, "status", None) == "skipped"
        }:
            for item in report.pending:
                if item.tool == "disk_search_artifacts" and item.priority >= 12:
                    return {
                        "action": "tool",
                        "tool": item.tool,
                        "arguments": item.arguments,
                        "reason": item.reason,
                    }

        return {"action": "tool", "tool": tool, "arguments": arguments, "reason": reason}


def state_confidence(results: dict[str, list[dict[str, Any]]], verifier: list[Any]) -> float:
    contradictions = sum(1 for r in verifier if getattr(r, "status", None) == "contradiction")
    tools_ok = sum(1 for runs in results.values() for r in runs if r.get("ok"))
    if contradictions and tools_ok >= 3:
        return 0.75
    if contradictions:
        return 0.55
    if tools_ok >= 2:
        return 0.7
    return 0.5
