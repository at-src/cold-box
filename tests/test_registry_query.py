"""Tests for the read-only generic registry-value primitives."""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

from postmortem_mcp.registry_query import (
    _filetime_to_iso,
    query_value,
    sam_accounts,
    system_profile,
)


def _filetime_bytes(dt: datetime) -> bytes:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    intervals = int((dt - epoch).total_seconds() * 10_000_000)
    return struct.pack("<Q", intervals)


def test_filetime_decode_roundtrip() -> None:
    dt = datetime(2004, 8, 27, 15, 46, 33, tzinfo=timezone.utc)
    iso = _filetime_to_iso(_filetime_bytes(dt))
    assert iso is not None
    assert iso.startswith("2004-08-27T15:46:33")


def test_filetime_decode_zero_and_garbage() -> None:
    assert _filetime_to_iso(b"\x00" * 8) is None
    assert _filetime_to_iso(b"\x01\x02") is None
    assert _filetime_to_iso("not bytes") is None


def test_query_value_missing_hive_is_graceful() -> None:
    result = query_value(Path("/nonexistent/SOFTWARE"), "Some\\Key", "Value")
    assert result["found"] is False
    assert "error" in result


def test_system_profile_no_hives_returns_empty_facts() -> None:
    profile = system_profile(software=None, system=None, sam=None)
    assert profile["facts"] == []


def test_sam_accounts_missing_hive_is_graceful() -> None:
    result = sam_accounts(Path("/nonexistent/SAM"))
    assert result["found"] is False
    assert result["accounts"] == []
