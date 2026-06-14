"""Validate skill manifest records (batch authoring helper)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from cold_box_room.skills.registry import skills_root


def validate_skill_record(rec: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = (
        "skill_id",
        "journal_id",
        "library_slug",
        "name",
        "description",
        "tier",
        "execution_mode",
        "category",
        "has_script",
        "reference_only",
    )
    for key in required:
        if key not in rec:
            errors.append(f"missing {key}")
    skill_id = rec.get("skill_id", "")
    if not re.match(r"^SKILL-[0-9]{3}$", skill_id):
        errors.append("bad skill_id")
    slug = str(rec.get("library_slug") or "")
    if not slug.startswith("cb-"):
        errors.append("bad library_slug")
    if not str(rec.get("description") or "").strip():
        errors.append("empty description")
    root = skills_root()
    skill_md = root / "library" / slug / "SKILL.md"
    if slug and not skill_md.is_file():
        errors.append(f"SKILL.md missing: {skill_md.relative_to(root)}")
    if rec.get("has_script"):
        script = root / "library" / slug / "scripts" / "agent.py"
        if not script.is_file():
            errors.append(f"agent.py missing: {script.relative_to(root)}")
    return errors
