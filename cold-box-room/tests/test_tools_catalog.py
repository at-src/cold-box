"""Tool catalog — manifest schema and registry."""

import pytest

from cold_box_room.tools.models import STATUS_AGENT_LABELS
from cold_box_room.tools.port_batch import port_batch, validate_tool_record
from cold_box_room.tools.registry import (
    ToolCatalogError,
    clear_registry_cache,
    describe_tool,
    get_tool,
    list_tools,
    load_manifest,
    manifest_path,
)


@pytest.fixture(autouse=True)
def _fresh_registry():
    clear_registry_cache()
    yield
    clear_registry_cache()


def test_manifest_path_exists():
    assert manifest_path().is_file()


def test_load_manifest_batch1():
    data = load_manifest()
    assert data["schema"] == "cold_box_room.tools_manifest_v1"
    assert data["count"] == 100
    assert len(data["tools"]) == 100
    assert data["tools"][0]["tool_id"] == "SIFT-001"
    assert data["tools"][49]["tool_id"] == "SIFT-050"
    assert data["tools"][50]["tool_id"] == "SIFT-051"
    assert data["tools"][-1]["tool_id"] == "SIFT-100"


def test_batch1_uniform_schema():
    data = load_manifest()
    ids = set()
    for rec in data["tools"]:
        assert not validate_tool_record(rec), rec["tool_id"]
        assert rec["tool_id"] not in ids
        ids.add(rec["tool_id"])
        assert rec["input"]["style"] in {"positional", "flag", "stdin", "none"}
        assert rec["output"]["format"] in {"text", "json", "csv", "binary"}
        assert rec["output"]["style"] in {"stdout", "stderr", "scratch_file", "inode_stream"}
        assert rec["verification"]["status"] in STATUS_AGENT_LABELS
        assert "label" not in rec["verification"]  # label computed at describe time


def test_get_file_tool():
    tool = get_tool("SIFT-008")
    assert tool.name == "file"
    assert tool.verification.status == "ok"
    assert tool.verification.agent_label == "lab tested"


def test_not_tested_tool():
    tool = get_tool("SIFT-033")
    assert tool.name == "dcfldd"
    assert tool.verification.status == "not_tested"
    assert tool.verification.agent_label == "not tested"
    assert tool.verification.agent_runnable is True


def test_unavailable_tool():
    tool = get_tool("SIFT-037")
    assert tool.name == "binwalk"
    assert tool.verification.status == "unavailable"
    assert tool.verification.agent_runnable is False


def test_describe_includes_label():
    d = describe_tool("SIFT-033")
    assert d["verification"]["label"] == "not tested"
    assert d["verification"]["agent_runnable"] is True
    assert "[VERIFIED OK]" not in d["description"]


def test_list_tools_runnable_excludes_unavailable():
    runnable = list_tools(runnable_only=True)
    ids = {t.tool_id for t in runnable}
    assert "SIFT-037" not in ids
    assert "SIFT-008" in ids


def test_unknown_tool():
    with pytest.raises(ToolCatalogError, match="Unknown tool_id"):
        get_tool("SIFT-999")


def test_batch2_exiftool():
    tool = get_tool("SIFT-055")
    assert tool.name == "exiftool"
    assert tool.verification.status == "ok"
    assert "[VERIFIED OK]" not in tool.description


def test_batch2_regripper_ok():
    tool = get_tool("SIFT-098")
    assert tool.name == "regripper"
    assert tool.verification.status == "ok"
    assert tool.verification.agent_label == "lab tested"


def test_batch2_evtrpt_not_tested():
    tool = get_tool("SIFT-051")
    assert tool.verification.status == "not_tested"
    assert tool.verification.agent_label == "not tested"


def test_port_batch_matches_manifest_count():
    b1 = port_batch(start=0, limit=50)
    b2 = port_batch(start=50, limit=50)
    assert len(b1) == len(b2) == 50
    for rec in b1 + b2:
        assert not validate_tool_record(rec)
