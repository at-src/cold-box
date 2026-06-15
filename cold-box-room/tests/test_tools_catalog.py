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
    assert data["count"] == 234
    assert len(data["tools"]) == 234
    assert data["tools"][0]["tool_id"] == "SIFT-001"
    assert data["tools"][99]["tool_id"] == "SIFT-100"
    assert data["tools"][100]["tool_id"] == "SIFT-101"
    assert data["tools"][150]["tool_id"] == "SIFT-151"
    assert data["tools"][200]["tool_id"] == "SIFT-201"
    assert data["tools"][-1]["tool_id"] == "SIFT-234"


def test_batch1_uniform_schema():
    data = load_manifest()
    ids = set()
    for rec in data["tools"]:
        assert not validate_tool_record(rec), rec["tool_id"]
        assert rec["tool_id"] not in ids
        ids.add(rec["tool_id"])
        assert rec["input"]["style"] in {"positional", "flag", "stdin", "none"}
        assert rec["output"]["format"] in {"text", "json", "csv", "binary"}
        assert rec["output"]["style"] in {
            "stdout",
            "stderr",
            "scratch_file",
            "inode_stream",
            "scratch_dir_trailing",
            "scratch_dir_flag_o",
        }
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
    tool = get_tool("SIFT-174")
    assert tool.name == "accesschk"
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
    assert "SIFT-174" not in ids
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


def test_batch3_fls():
    tool = get_tool("SIFT-148")
    assert tool.name == "fls"
    assert tool.category == "sleuthkit"
    assert tool.verification.status == "ok"
    assert tool.input.harness_usage
    assert "INODE" in tool.input.harness_usage


def test_batch3_tshark_ok():
    tool = get_tool("SIFT-117")
    assert tool.name == "tshark"
    assert tool.verification.status == "ok"
    assert tool.verification.agent_runnable is True


def test_batch4_icat():
    tool = get_tool("SIFT-151")
    assert tool.name == "icat"
    assert tool.category == "sleuthkit"
    assert tool.verification.status == "not_tested"
    assert tool.verification.runnable is True
    assert tool.output.style == "inode_stream"
    assert tool.input.harness_usage
    assert "INODE" in tool.input.harness_usage


def test_batch4_mmls_not_tested():
    tool = get_tool("SIFT-160")
    assert tool.name == "mmls"
    assert tool.verification.status == "not_tested"
    assert tool.input.harness_usage


def test_batch4_evtx_dump():
    tool = get_tool("SIFT-194")
    assert tool.name == "evtx_dump"
    assert tool.category == "zimmerman"
    assert tool.verification.status == "ok"


def test_batch4_tsk_recover_scratch_dir_trailing():
    tool = get_tool("SIFT-164")
    assert tool.name == "tsk_recover"
    assert tool.output.style == "scratch_dir_trailing"
    assert tool.input.harness_usage
    assert "output directory" in tool.input.harness_usage.lower()
    ported = next(r for r in port_batch(start=150, limit=50) if r["tool_id"] == "SIFT-164")
    assert ported["output"]["style"] == "scratch_dir_trailing"


def test_batch5_sqlecmd():
    tool = get_tool("SIFT-227")
    assert tool.name == "SQLECmd"
    assert tool.category == "zimmerman"
    assert tool.verification.status == "ok"
    assert "[VERIFIED OK]" not in tool.description


def test_batch5_pecmd_unavailable():
    tool = get_tool("SIFT-221")
    assert tool.name == "PECmd"
    assert tool.verification.status == "unavailable"
    assert tool.verification.agent_runnable is False


def test_catalog_complete():
    data = load_manifest()
    ids = [t["tool_id"] for t in data["tools"]]
    assert ids == [f"SIFT-{i:03d}" for i in range(1, 235)]


def test_port_batch_matches_manifest_count():
    b1 = port_batch(start=0, limit=50)
    b2 = port_batch(start=50, limit=50)
    b3 = port_batch(start=100, limit=50)
    b4 = port_batch(start=150, limit=50)
    b5 = port_batch(start=200, limit=50)
    assert len(b1) == len(b2) == len(b3) == len(b4) == 50
    assert len(b5) == 34
    for rec in b1 + b2 + b3 + b4 + b5:
        assert not validate_tool_record(rec)
