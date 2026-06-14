"""Skill catalog record — library playbook + optional harness script."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SkillRecord:
    skill_id: str
    journal_id: str
    library_slug: str
    name: str
    description: str
    tier: str
    execution_mode: str
    category: str
    subdomain: str
    tags: tuple[str, ...]
    case_profiles: tuple[str, ...]
    has_script: bool
    reference_only: bool
    suggested_tool_ids: tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SkillRecord:
        return cls(
            skill_id=str(raw["skill_id"]),
            journal_id=str(raw.get("journal_id") or ""),
            library_slug=str(raw["library_slug"]),
            name=str(raw.get("name") or raw["library_slug"].removeprefix("cb-")),
            description=str(raw.get("description") or ""),
            tier=str(raw.get("tier") or "core"),
            execution_mode=str(raw.get("execution_mode") or "sift_runnable"),
            category=str(raw.get("category") or "methodology"),
            subdomain=str(raw.get("subdomain") or ""),
            tags=tuple(raw.get("tags") or []),
            case_profiles=tuple(raw.get("case_profiles") or []),
            has_script=bool(raw.get("has_script", False)),
            reference_only=bool(raw.get("reference_only", False)),
            suggested_tool_ids=tuple(raw.get("suggested_tool_ids") or []),
        )

    def skill_md_path(self, *, skills_root: Path) -> Path:
        return (skills_root / "library" / self.library_slug / "SKILL.md").resolve()

    def script_path(self, *, skills_root: Path) -> Path:
        return (
            skills_root / "library" / self.library_slug / "scripts" / "agent.py"
        ).resolve()

    def to_list_dict(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "journal_id": self.journal_id,
            "library_slug": self.library_slug,
            "name": self.name,
            "category": self.category,
            "tier": self.tier,
            "execution_mode": self.execution_mode,
            "description": self.description,
            "tags": list(self.tags),
            "has_script": self.has_script,
            "reference_only": self.reference_only,
        }

    def to_describe_dict(self, *, playbook: str = "") -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "journal_id": self.journal_id,
            "library_slug": self.library_slug,
            "name": self.name,
            "category": self.category,
            "subdomain": self.subdomain,
            "tier": self.tier,
            "execution_mode": self.execution_mode,
            "description": self.description,
            "tags": list(self.tags),
            "case_profiles": list(self.case_profiles),
            "has_script": self.has_script,
            "reference_only": self.reference_only,
            "suggested_tool_ids": list(self.suggested_tool_ids),
            "suggested_tool_ids_note": (
                "Hints from SKILL.md — run via run_sift_tool in Room 2 or inside "
                "run_skill script when has_script=true."
            ),
            "playbook": playbook,
        }
