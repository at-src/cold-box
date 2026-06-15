"""Tests for heavy-tool agent guidance."""

from cold_box_room.tools.agent_guidance import enrich_describe_dict, enrich_tool_dict
from cold_box_room.tools.registry import describe_tool


def test_blkls_describe_includes_heavy_guidance():
    spec = describe_tool("SIFT-138")
    assert spec["execution_profile"] == "heavy"
    assert "agent_guidance" in spec
    assert "fls" in spec["agent_guidance"].lower()
    assert "[HEAVY]" in spec["description"]


def test_list_enrichment_marks_profile():
    row = enrich_tool_dict({"name": "grep", "description": "search"})
    assert "execution_profile" not in row

    row = enrich_tool_dict({"name": "blkls", "description": "blocks"})
    assert row["execution_profile"] == "heavy"
    assert "agent_guidance" in row


def test_enrich_describe_appends_once():
    base = {"name": "blkls", "description": "List blocks"}
    once = enrich_describe_dict(base)
    twice = enrich_describe_dict(once)
    assert twice["description"].count("[HEAVY]") == 1
