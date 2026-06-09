"""Evidence-driven policy reasoner — no fixed step lists."""

from __future__ import annotations

import json
from typing import Any

from postmortem_agent.state import AgentConfig, InvestigationState
from postmortem_mcp.catalog import CATALOG, ToolSpec

FOLLOWUP: dict[str, tuple[str, ...]] = {
    "R1": ("mem_cmdline", "mem_malfind", "mem_psscan"),
    "R7": ("mem_cmdline", "mem_dlllist", "mem_malfind"),
    "R3": ("disk_evtx_filter", "disk_parse_evtx", "mem_pslist"),
    "R6": ("mem_netscan", "mem_pslist"),
    "R4": ("disk_detect_timestomp", "disk_parse_mft"),
    "R5": ("disk_search_artifacts", "disk_parse_prefetch"),
    "R2": ("disk_parse_amcache", "disk_parse_prefetch"),
    "R8": ("net_dns_extract", "net_conversations"),
    "R9": ("net_http_extract", "net_conversations"),
    "R10": ("linux_persistence", "linux_bash_history", "linux_cron"),
}

PRIORITY_TOOLS = ("evidence_manifest", "mem_pslist", "mem_psscan")


def _action_key(tool: str, arguments: dict[str, Any]) -> str:
    return f"{tool}:{json.dumps(arguments, sort_keys=True)}"


def _arguments_for(spec: ToolSpec, file_entry: dict[str, Any], config: AgentConfig) -> dict[str, Any] | None:
    kind = file_entry.get("kind")
    relpath = file_entry.get("relpath", "")
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
        if spec.name in {"disk_correlate_timeline"}:
            return _correlate_args(config, file_entry)
        return None
    return args


def _correlate_args(config: AgentConfig, survey: dict[str, Any]) -> dict[str, Any] | None:
    args: dict[str, Any] = {}
    for entry in survey.get("files") or []:
        kind = entry.get("kind")
        rel = entry.get("relpath")
        if kind == "evtx" and "evtx_relpath" not in args:
            args["evtx_relpath"] = rel
        if kind == "mft" and "mft_relpath" not in args:
            args["mft_relpath"] = rel
        if kind == "memory_image" and "memory_relpath" not in args:
            args["memory_relpath"] = rel
    return args or None


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
            if tool_name == "disk_correlate_timeline":
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
            mem = _first_relpath(survey, "memory_image")
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

    return candidates


def _first_relpath(survey: dict[str, Any], kind: str) -> str | None:
    for entry in survey.get("files") or []:
        if entry.get("kind") == kind:
            return entry.get("relpath")
    return None


def _score_candidate(
    tool: str,
    state: InvestigationState,
    verifier: list[Any],
) -> int:
    spec = CATALOG.get(tool)
    if spec is None:
        return 0
    score = 0
    skipped = {r.rule_id for r in verifier if getattr(r, "status", None) == "skipped"}
    contradictions = {r.rule_id for r in verifier if getattr(r, "status", None) == "contradiction"}

    for rule_id in spec.feeds_rules:
        if rule_id in skipped:
            score += 100
        if rule_id in contradictions:
            score += 80
        followups = FOLLOWUP.get(rule_id, ())
        if tool in followups and rule_id in contradictions:
            score += 120

    if tool not in state.tool_results:
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
        if not candidates:
            return {
                "action": "done",
                "hypothesis": hypothesis,
                "confidence": state_confidence(results, verifier),
            }

        best: tuple[int, str, dict[str, Any], str] | None = None
        for _, tool, arguments, reason in candidates:
            score = _score_candidate(tool, _ResultsView(results), verifier)
            if best is None or score > best[0]:
                best = (score, tool, arguments, reason)

        assert best is not None
        _, tool, arguments, reason = best
        return {"action": "tool", "tool": tool, "arguments": arguments, "reason": reason}


class _ResultsView:
    def __init__(self, results: dict[str, list[dict[str, Any]]]) -> None:
        self.tool_results = {k: v[-1] if v else {} for k, v in results.items()}


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
