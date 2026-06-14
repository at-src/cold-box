"""Skill catalog — manifest schema and registry."""

import pytest

from cold_box_room.skills.registry import (
    SkillCatalogError,
    clear_registry_cache,
    describe_skill,
    get_skill,
    list_skills,
    load_manifest,
    manifest_path,
    skills_root,
)
from cold_box_room.skills.validate_record import validate_skill_record


@pytest.fixture(autouse=True)
def _fresh_registry():
    clear_registry_cache()
    yield
    clear_registry_cache()


def test_manifest_path_exists():
    assert manifest_path().is_file()


def test_load_manifest_runnable_catalog():
    data = load_manifest()
    assert data["schema"] == "cold_box_room.skills_manifest_v2"
    assert data["count"] == 213
    assert len(data["skills"]) == 213
    assert data["skills"][0]["skill_id"] == "SKILL-001"
    assert all(s["has_script"] for s in data["skills"])
    assert not any(s.get("reference_only") for s in data["skills"])


def test_batch1_uniform_schema():
    data = load_manifest()
    ids = set()
    root = skills_root()
    for rec in data["skills"]:
        assert not validate_skill_record(rec), rec["skill_id"]
        assert rec["skill_id"] not in ids
        ids.add(rec["skill_id"])
        skill_md = root / "library" / rec["library_slug"] / "SKILL.md"
        assert skill_md.is_file(), rec["skill_id"]
        if rec["has_script"]:
            script = root / "library" / rec["library_slug"] / "scripts" / "agent.py"
            assert script.is_file(), rec["skill_id"]


def test_get_skill_001_runnable():
    skill = get_skill("SKILL-001")
    assert skill.library_slug == "cb-active-directory-compromise-investigation"
    assert skill.has_script is True
    assert skill.reference_only is False


def test_get_skill_019_has_script_without_external_api():
    skill = get_skill("SKILL-019")
    assert skill.name == "containing-active-breach"
    assert skill.has_script is True
    assert skill.reference_only is False


def test_describe_includes_full_playbook():
    d = describe_skill("SKILL-034")
    assert d["skill_id"] == "SKILL-034"
    assert d["playbook"]
    assert "##" in d["playbook"]
    assert d["suggested_tool_ids_note"]


def test_list_skills_by_category():
    rows = list_skills(category="windows-artifacts")
    assert rows
    assert all(r.category == "windows-artifacts" for r in rows)


def test_list_runnable_only():
    rows = list_skills(runnable_only=True)
    assert rows
    assert all(r.has_script and not r.reference_only for r in rows)


def test_unknown_skill():
    with pytest.raises(SkillCatalogError, match="Unknown skill ref"):
        get_skill("SKILL-999")


def test_get_skill_052_batch2():
    skill = get_skill("SKILL-052")
    assert skill.journal_id == "CB-SKL-052"
    assert skill.library_slug == "cb-hunting-for-lateral-movement-via-wmi"
    assert skill.skill_md_path(skills_root=skills_root()).is_file()


def test_get_skill_151_batch4():
    skill = get_skill("SKILL-151")
    assert skill.journal_id == "CB-SKL-151"
    assert skill.library_slug == "cb-building-threat-intelligence-platform"


def test_get_skill_202_batch5():
    skill = get_skill("SKILL-202")
    assert skill.journal_id == "CB-SKL-202"
    assert skill.library_slug == "cb-detecting-port-scanning-with-fail2ban"
    assert skill.skill_md_path(skills_root=skills_root()).is_file()


def test_get_skill_252_batch6():
    skill = get_skill("SKILL-252")
    assert skill.journal_id == "CB-SKL-252"
    assert skill.library_slug == "cb-implementing-api-key-security-controls"
    assert skill.skill_md_path(skills_root=skills_root()).is_file()


def test_get_skill_302_batch7():
    skill = get_skill("SKILL-302")
    assert skill.journal_id == "CB-SKL-302"
    assert skill.library_slug == "cb-network-covert-channels-in-malware"
    assert skill.skill_md_path(skills_root=skills_root()).is_file()


def test_catalog_preserves_original_skill_ids():
    data = load_manifest()
    ids = {s["skill_id"] for s in data["skills"]}
    assert "SKILL-001" in ids
    assert "SKILL-339" in ids
    assert "SKILL-002" not in ids
    assert len(ids) == 213
