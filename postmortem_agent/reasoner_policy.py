"""Evidence-driven policy reasoner — no fixed step lists."""

from __future__ import annotations

import json
from pathlib import Path
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
from postmortem_mcp.config import case_dir
from postmortem_evidence.guard import get_extracted_root

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
    "R27": ("disk_scan_exfil",),
    "R30": ("yara_scan_evidence",),
    "R31": ("mem_linux_probe",),
}

COVERAGE_RULES: dict[str, tuple[str, ...]] = {
    "R2": ("reg_amcache", "disk_parse_amcache"),
    "R3": ("disk_evtx_filter",),
    "R6": ("mem_netscan",),
    "R7": ("mem_malfind",),
    "R11": ("reg_services", "mem_svcscan"),
    "R12": ("disk_parse_setupapi",),
    "R13": ("disk_parse_scheduled_tasks", "reg_run_keys"),
    "R14": ("disk_search_artifacts",),
    "R15": ("timeline_super",),
    "R16": ("reg_amcache", "disk_parse_amcache", "disk_parse_prefetch"),
    "R18": ("mem_cmdline",),
    "R19": ("web_parse_access_log", "web_inspect_artifact"),
    "R20": ("logs_parse_structured",),
    "R21": ("disk_parse_usb",),
    "R22": ("net_http_extract",),
    "R27": ("disk_scan_exfil",),
    "R28": ("disk_scan_exfil",),
    "R29": ("disk_scan_exfil",),
    "R30": ("yara_scan_evidence",),
    "R31": ("mem_linux_probe",),
    "R10": ("linux_bash_history", "linux_persistence", "linux_cron", "linux_auth_log"),
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


def _effective_extracted_root(config: AgentConfig) -> Path | None:
    if config.extracted_root and config.extracted_root.is_dir():
        return config.extracted_root.expanduser().resolve()
    env_root = get_extracted_root()
    if env_root and env_root.is_dir():
        return env_root.expanduser().resolve()
    candidate = case_dir(config.case_id) / "extracted"
    if candidate.is_dir() and any(candidate.iterdir()):
        return candidate.resolve()
    return None


def _scan_relpath_is_extracted(relpath: str) -> bool:
    normalized = relpath.replace("\\", "/").strip("/")
    return normalized == "extracted" or normalized.startswith("extracted/")


def _exfil_scan_on_extracted(results: dict[str, list[dict[str, Any]]]) -> bool:
    for run in results.get("disk_scan_exfil") or []:
        if not run.get("ok"):
            continue
        rel = str((run.get("args") or {}).get("search_root_relpath") or "")
        if _scan_relpath_is_extracted(rel):
            return True
    return False


def _coverage_tool_done(
    rule_id: str,
    tools: tuple[str, ...],
    results: dict[str, list[dict[str, Any]]],
    config: AgentConfig,
) -> bool:
    if not any(_tool_succeeded(results, tool) for tool in tools):
        return False
    if rule_id in {"R27", "R28", "R29"} and _effective_extracted_root(config) is not None:
        return _exfil_scan_on_extracted(results)
    if rule_id == "R30" and _effective_extracted_root(config) is not None:
        for run in results.get("yara_scan_evidence") or []:
            if run.get("ok") and _scan_relpath_is_extracted(
                str((run.get("args") or {}).get("search_root_relpath") or "")
            ):
                return True
        return False
    return True


CRITICAL_COVERAGE_TOOLS: frozenset[str] = frozenset(
    tool for tools in COVERAGE_RULES.values() for tool in tools
)


def sync_tool_attempts(
    results: dict[str, list[dict[str, Any]]],
) -> tuple[set[str], set[str]]:
    """Return executed/failed action keys from prior tool runs."""
    executed: set[str] = set()
    failed: set[str] = set()
    for tool, runs in results.items():
        for run in runs:
            args_used = run.get("args") or {}
            key = _action_key(tool, args_used)
            if run.get("ok"):
                executed.add(key)
            else:
                failed.add(key)
    return executed, failed


def _tag_hybrid_reason(action: dict[str, Any], detail: str) -> dict[str, Any]:
    tagged = dict(action)
    tagged["reason"] = f"hybrid policy floor: {detail}"
    return tagged


def policy_coverage_floor(
    *,
    verifier: list[Any],
    results: dict[str, list[dict[str, Any]]],
    survey: dict[str, Any],
    config: AgentConfig,
    executed: set[str],
    failed: set[str],
) -> dict[str, Any] | None:
    """Mandatory tool action before the LLM chooses — one attempt per coverage rule."""
    forced = _coverage_action(verifier, results, survey, config, executed, failed)
    if forced:
        return _tag_hybrid_reason(forced, str(forced.get("reason", "coverage")))
    return None


def policy_block_llm_done(
    *,
    verifier: list[Any],
    results: dict[str, list[dict[str, Any]]],
    survey: dict[str, Any],
    config: AgentConfig,
    executed: set[str],
    failed: set[str],
) -> dict[str, Any] | None:
    """Override an LLM 'done' when a coverage-rule tool has not been attempted yet."""
    forced = _coverage_action(verifier, results, survey, config, executed, failed)
    if forced:
        return _tag_hybrid_reason(forced, f"LLM done blocked — {forced.get('reason', 'coverage')}")
    return None


def _coverage_action(
    verifier: list[Any],
    results: dict[str, list[dict[str, Any]]],
    survey: dict[str, Any],
    config: AgentConfig,
    executed: set[str],
    failed: set[str],
) -> dict[str, Any] | None:
    skipped = {r.rule_id for r in verifier if getattr(r, "status", None) == "skipped"}
    tier3_rules = {"R27", "R28", "R29", "R30", "R31"}
    for rule_id, tools in COVERAGE_RULES.items():
        if config.mode == "synthetic" and rule_id in tier3_rules:
            continue
        if rule_id not in skipped:
            continue
        if _coverage_tool_done(rule_id, tools, results, config):
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


def _first_prefetch_relpath(survey: dict[str, Any]) -> str | None:
    """Pick one prefetch file — prefer names that look like setup/hack tools (NIST hacking case)."""
    files = [f for f in survey.get("files") or [] if f.get("kind") == "prefetch"]
    if not files:
        return None
    prefer = ("wasp", "setup", "install", "hack", "cain", "stumbler", "sniff", "123")
    for pattern in prefer:
        for entry in files:
            rel = (entry.get("relpath") or "").lower()
            if pattern in rel:
                return entry.get("relpath")
    return files[0].get("relpath")


def _coverage_tool_args(
    tool: str,
    survey: dict[str, Any],
    config: AgentConfig,
) -> dict[str, Any] | None:
    if tool in {"mem_netscan", "mem_malfind", "mem_cmdline", "mem_svcscan", "mem_pslist"}:
        mem = _memory_relpath(config, survey)
        return {"memory_relpath": mem} if mem else None
    if tool == "disk_parse_setupapi":
        rel = _first_relpath(survey, "setupapi_log")
        return {"artifact_relpath": rel} if rel else None
    if tool == "timeline_super":
        return _correlate_args(config, survey)
    if tool == "disk_evtx_filter":
        rel = _first_relpath(survey, "evtx")
        return {"evtx_relpath": rel} if rel else None
    if tool in {"reg_amcache", "disk_parse_amcache"}:
        rel = _first_relpath(survey, "amcache")
        return {"artifact_relpath": rel} if rel else None
    if tool == "disk_search_artifacts":
        root = _search_root_relpath(config, survey) or config.evidence_case
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
    if tool == "reg_services":
        rel = _system_hive_relpath(survey)
        return {"artifact_relpath": rel} if rel else None
    if tool == "disk_parse_prefetch":
        rel = _first_prefetch_relpath(survey)
        return {"artifact_relpath": rel} if rel else None
    if tool == "disk_parse_scheduled_tasks":
        rel = _first_relpath(survey, "scheduled_task")
        return {"artifact_relpath": rel} if rel else None
    if tool == "reg_run_keys":
        rel = _hive_relpath(survey, "software")
        if not rel:
            rel = _first_relpath(survey, "registry_export")
        return {"artifact_relpath": rel} if rel else None
    if tool in {"disk_scan_exfil", "yara_scan_evidence"}:
        if config.mode == "synthetic":
            return None
        root = _search_root_relpath(config, survey)
        if not root:
            return None
        args: dict[str, Any] = {"search_root_relpath": root}
        if tool == "disk_scan_exfil":
            args["max_hits"] = 40
        else:
            args["max_matches"] = 30
        return args
    if tool == "mem_linux_probe":
        if config.mode == "synthetic":
            return None
        mem = _memory_relpath(config, survey)
        return {"memory_relpath": mem} if mem else None
    return None


def _search_root_relpath(config: AgentConfig, survey: dict[str, Any]) -> str | None:
    """Best directory for breadth scans (extracted disk tree or raw case folder)."""
    if config.mode != "synthetic" and _effective_extracted_root(config) is not None:
        return "extracted"
    if config.evidence_case:
        return config.evidence_case
    return _first_relpath(survey, "case_directory")


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
            if config.mode == "synthetic" and tool_name in {
                "disk_scan_exfil",
                "yara_scan_evidence",
                "mem_linux_probe",
            }:
                continue
            spec = CATALOG.get(tool_name)
            if spec is None:
                continue
            if tool_name == "disk_correlate_timeline" or tool_name == "timeline_super":
                arguments = _correlate_args(config, survey)
            elif tool_name == "reg_system_profile":
                arguments = _system_profile_args(survey)
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

    if config.mode != "synthetic" and _effective_extracted_root(config) is not None:
        profile_args = _system_profile_args(survey)
        if profile_args:
            key = _action_key("reg_system_profile", profile_args)
            if key not in executed and key not in failed:
                candidates.append(
                    (
                        14,
                        "reg_system_profile",
                        profile_args,
                        "host attribution / system profile (registered owner, NICs, accounts)",
                    )
                )

    system_hive = _system_hive_relpath(survey)
    if system_hive and "registry_hive" in set(survey.get("kinds_present") or []):
        svc_args = {"artifact_relpath": system_hive}
        key = _action_key("reg_services", svc_args)
        if key not in executed and key not in failed:
            candidates.append(
                (
                    16,
                    "reg_services",
                    svc_args,
                    "enumerate services from SYSTEM hive (ghost-service / R11)",
                )
            )

    if config.mode != "synthetic" and _effective_extracted_root(config) is not None:
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
        for tool, priority, reason in (
            ("disk_scan_exfil", 9, "exfil channel scan on extracted disk (R27–R29)"),
            ("yara_scan_evidence", 9, "YARA/pattern scan on extracted disk (R30)"),
        ):
            args = _coverage_tool_args(tool, survey, config)
            if args is None:
                continue
            key = _action_key(tool, args)
            if key not in executed and key not in failed:
                candidates.append((priority, tool, args, reason))

    search_root = _search_root_relpath(config, survey)
    if config.mode != "synthetic" and search_root and not config.extracted_root:
        for tool, priority, reason in (
            ("disk_scan_exfil", 9, "exfil channel scan (R27–R29)"),
            ("yara_scan_evidence", 8, "YARA/pattern scan (R30)"),
        ):
            args = _coverage_tool_args(tool, survey, config)
            if args is None:
                continue
            key = _action_key(tool, args)
            if key not in executed and key not in failed:
                candidates.append((priority, tool, args, reason))

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


def _hive_relpath(survey: dict[str, Any], basename: str) -> str | None:
    for entry in survey.get("files") or []:
        if entry.get("kind") != "registry_hive":
            continue
        rel = entry.get("relpath") or ""
        if rel.rsplit("/", 1)[-1].lower() == basename:
            return rel
    return None


def _system_profile_args(survey: dict[str, Any]) -> dict[str, Any] | None:
    """reg_system_profile is keyed on the SOFTWARE hive, enriched with SYSTEM + SAM."""
    software = _hive_relpath(survey, "software")
    if not software:
        return None
    args: dict[str, Any] = {"artifact_relpath": software}
    system = _hive_relpath(survey, "system")
    if system:
        args["system_relpath"] = system
    sam = _hive_relpath(survey, "sam")
    if sam:
        args["sam_relpath"] = sam
    return args


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
            if rule_id in {"R8", "R9", "R22"} and "pcap" not in survey_kinds:
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
    if "R12" in skipped and tool == "disk_parse_setupapi" and "setupapi_log" in survey_kinds:
        score += 150
    if "R21" in skipped and tool == "disk_parse_usb" and "registry_hive" in survey_kinds:
        score += 135
    if skipped & {"R27", "R28", "R29"} and tool == "disk_scan_exfil":
        score += 130
    if "R30" in skipped and tool == "yara_scan_evidence":
        score += 125
    if "R31" in skipped and tool == "mem_linux_probe" and "memory_image" in survey_kinds:
        score += 110
    if "R11" in skipped and tool == "reg_services" and "registry_hive" in survey_kinds:
        score += 150
    if "R13" in skipped and tool in {"disk_parse_scheduled_tasks", "reg_run_keys"}:
        if "scheduled_task" in survey_kinds or "registry_hive" in survey_kinds:
            score += 140
    if "R22" in skipped and tool == "net_http_extract" and "pcap" in survey_kinds:
        score += 135
    if (
        "R10" in skipped
        and tool in {"linux_bash_history", "linux_persistence", "linux_cron",
                     "linux_auth_log", "linux_syslog"}
        and "linux_log" in survey_kinds
    ):
        score += 135
    if "amcache" in survey_kinds and tool in {"reg_amcache", "disk_parse_amcache"}:
        if not _tool_succeeded(results, tool):
            score += 130

    # Host attribution / system profile: a sensible early step on any disk case
    # with hives, but below the high-value contradiction follow-ups so it never
    # crowds out compromise analysis.
    if tool == "reg_system_profile" and "registry_hive" in survey_kinds:
        if not _tool_succeeded(results, tool):
            score += 170

    if tool == "disk_recycle_bin" and "recycle_bin" in survey_kinds:
        if not _tool_succeeded(results, tool):
            score += 145

    if tool in {"disk_parse_ie_index_dat", "disk_parse_ie_cache"} and (
        "ie_index_dat" in survey_kinds or "ie_cache" in survey_kinds
    ):
        if not _tool_succeeded(results, tool):
            score += 140

    if tool == "disk_inspect_capture" and "capture_file" in survey_kinds:
        if not _tool_succeeded(results, tool):
            score += 130

    if _tool_succeeded(results, tool):
        score -= 180

    prefetch_failures = sum(
        1 for run in results.get("disk_parse_prefetch") or [] if not run.get("ok")
    )
    if tool == "disk_parse_prefetch" and prefetch_failures >= 2:
        score -= 200

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

        if self.config.mode != "synthetic":
            forced = _coverage_action(verifier, results, survey, self.config, self.executed, self.failed)
            if forced:
                return forced

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
