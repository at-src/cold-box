"""Audit log helpers — ewfverify cache regression."""

from cold_box_room.r2.audit import append_audit, find_prior_success


def test_find_prior_success_matches_exit_code_zero(tmp_path, monkeypatch):
    records = tmp_path / "records"
    monkeypatch.setenv("COLD_BOX_ROOM_RECORDS", str(records))
    case_id = "cache-case"
    append_audit(
        case_id=case_id,
        audit_id="CB-first",
        tool_id="SIFT-146",
        tool_name="ewfverify",
        purpose="test",
        why="test",
        command=["ewfverify", "disk.e01"],
        input_relpath="disk.e01",
        input_sha256="abc123",
        exit_code=0,
        elapsed_ms=10.0,
        stdout_preview="verified ok",
    )
    prior = find_prior_success(
        case_id,
        tool_name="ewfverify",
        input_sha256="abc123",
    )
    assert prior is not None
    assert prior["audit_id"] == "CB-first"
