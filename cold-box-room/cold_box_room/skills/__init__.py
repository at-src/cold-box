"""Skill catalog loader, registry, and Room 3 harness execution."""

from cold_box_room.skills.executor import SkillExecutionError, run_skill
from cold_box_room.skills.models import SkillRecord
from cold_box_room.skills.registry import (
    SkillCatalogError,
    LIBRARY_DIR,
    clear_registry_cache,
    describe_skill,
    get_skill,
    list_categories,
    list_skills,
    list_skills_dict,
    list_tags,
    load_manifest,
    manifest_path,
    resolve_skill_ref,
    skills_root,
)
from cold_box_room.skills.skill_runner import has_skill_script, run_skill_script

__all__ = [
    "LIBRARY_DIR",
    "SkillCatalogError",
    "SkillExecutionError",
    "SkillRecord",
    "clear_registry_cache",
    "describe_skill",
    "get_skill",
    "has_skill_script",
    "list_categories",
    "list_skills",
    "list_skills_dict",
    "list_tags",
    "load_manifest",
    "manifest_path",
    "resolve_skill_ref",
    "run_skill",
    "run_skill_script",
    "skills_root",
]
