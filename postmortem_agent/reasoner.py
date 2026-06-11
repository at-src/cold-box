"""Reasoner factory and skill index loader."""

from __future__ import annotations

import re
from pathlib import Path

from postmortem_agent.reasoner_hybrid import HybridReasoner
from postmortem_agent.reasoner_llm import LLMReasoner
from postmortem_agent.reasoner_policy import PolicyReasoner
from postmortem_agent.state import AgentConfig


def make_reasoner(config: AgentConfig):
    if config.mode == "hybrid":
        return HybridReasoner(config)
    if config.mode == "llm":
        return LLMReasoner(config)
    return PolicyReasoner(config)


def load_skill_index(skills_root: Path | None = None) -> list[dict[str, str]]:
    root = skills_root or Path(__file__).resolve().parents[1] / "skills"
    if not root.is_dir():
        return []
    skills: list[dict[str, str]] = []
    for path in sorted(root.glob("*/SKILL.md")):
        text = path.read_text(encoding="utf-8")
        meta = _parse_frontmatter(text)
        name = meta.get("name") or path.parent.name.replace("-", " ")
        when = meta.get("when_to_use") or _extract_when_to_use(text)
        skills.append({"name": name, "when_to_use": when, "path": str(path)})
    return skills


def _parse_frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---"):
        return {}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    meta: dict[str, str] = {}
    for line in parts[1].splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        meta[key.strip()] = value.strip().strip('"').strip("'")
    return meta


def _extract_when_to_use(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("run this when"):
            return stripped
    match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    return match.group(1).strip() if match else "General investigation guidance"
