"""Tests for legacy Windows parsers (recycle bin, IE index.dat)."""

from __future__ import annotations

from pathlib import Path

from postmortem_mcp.legacy_parse import (
    parse_ie_cache_text,
    parse_index_dat,
    parse_info2,
)


def test_parse_ie_cache_text_finds_email(tmp_path: Path) -> None:
    path = tmp_path / "mr. evil@yahoo[1].txt"
    path.write_text("From: mrevilrulez@yahoo.com\nSubject: test\n", encoding="ascii")
    result = parse_ie_cache_text(path)
    assert any("mrevilrulez@yahoo.com" in e for e in result["emails"])


def test_parse_index_dat_finds_embedded_email(tmp_path: Path) -> None:
    payload = "noise\x00mrevilrulez@yahoo.com\x00more".encode("latin-1")
    path = tmp_path / "index.dat"
    path.write_bytes(payload)
    result = parse_index_dat(path)
    assert any("mrevilrulez@yahoo.com" in e for e in result["emails"])


def test_parse_info2_counts_executables(tmp_path: Path) -> None:
    # UTF-16-LE path strings as in INFO2
    raw = "C:\\RECYCLER\\evil.exe\x00".encode("utf-16-le") + b"\x00" * 4
    raw += "C:\\RECYCLER\\tool2.exe\x00".encode("utf-16-le")
    path = tmp_path / "INFO2"
    path.write_bytes(raw)
    result = parse_info2(path)
    assert result["executable_count"] >= 2
