"""Cross-run diagnostic memory — learned patterns from completed cases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from postmortem_evidence.guard import assert_not_evidence_write
from postmortem_mcp.config import get_case_output_root


def memory_dir() -> Path:
    path = get_case_output_root() / ".diagnostic_memory"
    assert_not_evidence_write(path, "w")
    path.mkdir(parents=True, exist_ok=True)
    return path


def patterns_path() -> Path:
    return memory_dir() / "patterns.jsonl"


def record_case_pattern(
    *,
    kinds_present: list[str],
    tools_run: list[str],
    rules_fired: list[str],
    lessons: list[str],
    iterations: int,
    self_corrected: bool,
) -> None:
    entry = {
        "kinds_signature": sorted(set(kinds_present)),
        "tools_run": tools_run,
        "rules_fired": rules_fired,
        "lessons": lessons,
        "iterations": iterations,
        "self_corrected": self_corrected,
    }
    path = patterns_path()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def load_similar_patterns(kinds_present: list[str], *, limit: int = 5) -> list[dict[str, Any]]:
    path = patterns_path()
    if not path.is_file():
        return []
    target = set(kinds_present)
    scored: list[tuple[int, dict[str, Any]]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        sig = set(entry.get("kinds_signature") or [])
        overlap = len(target & sig)
        if overlap == 0:
            continue
        scored.append((overlap, entry))
    scored.sort(key=lambda item: (-item[0], -len(item[1].get("tools_run") or [])))
    return [entry for _, entry in scored[:limit]]


def hints_from_patterns(patterns: list[dict[str, Any]]) -> list[str]:
    hints: list[str] = []
    tool_counts: dict[str, int] = {}
    for pattern in patterns:
        for tool in pattern.get("tools_run") or []:
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        for lesson in pattern.get("lessons") or []:
            if lesson not in hints:
                hints.append(f"Past case: {lesson}")
    if tool_counts:
        ranked = sorted(tool_counts.items(), key=lambda item: -item[1])[:5]
        tools = ", ".join(name for name, _ in ranked)
        hints.append(f"Similar past cases often started with: {tools}")
    return hints[:10]
