"""Reasoner factory and skill index loader."""

from __future__ import annotations

import re
from pathlib import Path

from postmortem_agent.reasoner_llm import LLMReasoner
from postmortem_agent.reasoner_policy import PolicyReasoner
from postmortem_agent.state import AgentConfig


def make_reasoner(config: AgentConfig):
    if config.mode == "llm":
        return LLMReasoner(config)
    return PolicyReasoner(config)


def load_skill_index(skills_root: Path | None = None) -> list[dict[str, str]]:
    root = skills_root or Path("skills")
    if not root.is_dir():
        return []
    skills: list[dict[str, str]] = []
    for path in sorted(root.glob("*/SKILL.md")):
        text = path.read_text(encoding="utf-8")
        name = path.parent.name.replace("-", " ")
        when = _extract_when_to_use(text)
        skills.append({"name": name, "when_to_use": when, "path": str(path)})
    return skills


def _extract_when_to_use(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("run this when"):
            return stripped
    match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    return match.group(1).strip() if match else "General investigation guidance"
