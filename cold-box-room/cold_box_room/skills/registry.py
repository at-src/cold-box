"""Load and query the skill catalog."""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from cold_box_room.skills.models import SkillRecord

MANIFEST_ENV = "COLD_BOX_SKILLS_MANIFEST"
LIBRARY_DIR = Path(__file__).resolve().parents[2] / "skills" / "library"

TOOL_HINTS = re.compile(
    r"\b(mmls|fls|icat|fsstat|img_stat|ewfinfo|ewfverify|MFTECmd|EvtxECmd|"
    r"AmcacheParser|PECmd|RECmd|LECmd|JLECmd|vol\.py|volatility|log2timeline|"
    r"psort|hayabusa|tshark|yara|strings|file|regripper|rip\.pl|autopsy|"
    r"bulk_extractor|mactime|tsk_recover)\b",
    re.I,
)


class SkillCatalogError(ValueError):
    pass


def manifest_path() -> Path:
    raw = os.environ.get(MANIFEST_ENV, "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / "skills" / "manifest.json"


def skills_root() -> Path:
    return manifest_path().parent


def load_manifest(*, path: Path | None = None) -> dict:
    mp = path or manifest_path()
    if not mp.is_file():
        raise SkillCatalogError(f"Skill manifest not found: {mp}")
    data = json.loads(mp.read_text(encoding="utf-8"))
    schema = data.get("schema", "")
    if schema not in {"cold_box_room.skills_manifest_v2", "cold_box_room.skills_manifest_v1"}:
        raise SkillCatalogError(f"Unsupported manifest schema in {mp}: {schema}")
    skills = data.get("skills") or []
    if int(data.get("count", -1)) != len(skills):
        raise SkillCatalogError(
            f"Manifest count mismatch in {mp}: count={data.get('count')} skills={len(skills)}"
        )
    return data


def clear_registry_cache() -> None:
    _records_by_id.cache_clear()
    _records_by_journal.cache_clear()
    _records_by_slug.cache_clear()


@lru_cache(maxsize=1)
def _records_by_id() -> dict[str, SkillRecord]:
    root = skills_root()
    records: dict[str, SkillRecord] = {}
    for raw in load_manifest().get("skills", []):
        rec = SkillRecord.from_dict(raw)
        if rec.skill_id in records:
            raise SkillCatalogError(f"Duplicate skill_id {rec.skill_id!r}")
        skill_md = rec.skill_md_path(skills_root=root)
        if not skill_md.is_file():
            raise SkillCatalogError(f"SKILL.md missing for {rec.skill_id}: {skill_md}")
        if rec.has_script:
            script = rec.script_path(skills_root=root)
            if not script.is_file():
                raise SkillCatalogError(f"Script missing for {rec.skill_id}: {script}")
        records[rec.skill_id] = rec
    return records


@lru_cache(maxsize=1)
def _records_by_journal() -> dict[str, SkillRecord]:
    return {rec.journal_id: rec for rec in _records_by_id().values() if rec.journal_id}


@lru_cache(maxsize=1)
def _records_by_slug() -> dict[str, SkillRecord]:
    return {rec.library_slug: rec for rec in _records_by_id().values()}


def resolve_skill_ref(ref: str) -> SkillRecord:
    key = ref.strip()
    if key in _records_by_id():
        return _records_by_id()[key]
    if key in _records_by_journal():
        return _records_by_journal()[key]
    if key in _records_by_slug():
        return _records_by_slug()[key]
    raise SkillCatalogError(
        f"Unknown skill ref {ref!r} (use SKILL-###, CB-SKL-###, or library slug)"
    )


def get_skill(skill_id: str) -> SkillRecord:
    return resolve_skill_ref(skill_id)


def list_skills(
    *,
    category: str | None = None,
    tag: str | None = None,
    runnable_only: bool = False,
) -> list[SkillRecord]:
    rows = list(_records_by_id().values())
    if category:
        rows = [r for r in rows if r.category == category]
    if tag:
        needle = tag.strip().lower()
        rows = [r for r in rows if needle in {t.lower() for t in r.tags}]
    if runnable_only:
        rows = [r for r in rows if r.has_script and not r.reference_only]
    return sorted(rows, key=lambda r: r.skill_id)


def list_categories() -> list[str]:
    return sorted({r.category for r in _records_by_id().values()})


def list_tags() -> list[str]:
    tags: set[str] = set()
    for rec in _records_by_id().values():
        tags.update(rec.tags)
    return sorted(tags)


def list_skills_dict(
    *,
    category: str | None = None,
    tag: str | None = None,
    runnable_only: bool = False,
) -> list[dict[str, Any]]:
    return [
        s.to_list_dict()
        for s in list_skills(category=category, tag=tag, runnable_only=runnable_only)
    ]


def _read_skill_md(rec: SkillRecord) -> tuple[dict[str, Any], str]:
    text = rec.skill_md_path(skills_root=skills_root()).read_text(encoding="utf-8")
    meta: dict[str, Any] = {}
    body = text
    if text.startswith("---"):
        end = text.find("---", 3)
        if end > 0:
            meta = yaml.safe_load(text[3:end]) or {}
            body = text[end + 3 :].lstrip()
    return meta, body


def extract_tool_hints(text: str) -> list[str]:
    found = {m.lower() for m in TOOL_HINTS.findall(text)}
    for match in re.finditer(r"\|\s*`([^`]+)`\s*\|\s*`(SIFT-\d+)`", text):
        found.add(match.group(1).lower())
    norm: list[str] = []
    for name in sorted(found):
        if name == "vol.py":
            norm.append("vol")
        elif name in {"log2timeline.py", "psort.py"}:
            norm.append(name.replace(".py", ""))
        elif name.startswith("sift-"):
            continue
        else:
            norm.append(name)
    return norm


def describe_skill(skill_id: str) -> dict[str, Any]:
    rec = get_skill(skill_id)
    meta, body = _read_skill_md(rec)
    payload = rec.to_describe_dict(playbook=body)
    payload["frontmatter"] = meta
    payload["tool_hints"] = extract_tool_hints(body)
    return payload
