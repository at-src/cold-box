"""Phase 3 — skill index with frontmatter."""

from __future__ import annotations

from postmortem_agent.reasoner import load_skill_index


def test_load_skill_index_frontmatter() -> None:
    skills = load_skill_index()
    names = {s["name"] for s in skills}
    assert "Network exfil hunt" in names
    assert "Registry and Windows persistence" in names
    assert all(s.get("when_to_use") for s in skills)
