"""Platform breadth — Android mtd/sdcard and macOS AD1 tools, verifier R32–R33."""

from __future__ import annotations

from pathlib import Path

import pytest

from postmortem_mcp.android_parse import probe_android_case, scan_android_artifacts
from postmortem_mcp.macos_parse import probe_macos_ad1, scan_macos_ad1
from postmortem_mcp.survey import classify_file
from postmortem_verify import VerifyContext
from postmortem_verify.rules import rule_r32_android_mobile, rule_r33_macos_artifacts


def test_classify_android_case2_mtd_dd(tmp_path: Path) -> None:
    root = tmp_path / "dfrws2011-android/case2-extract"
    root.mkdir(parents=True)
    mtd = root / "mtd6.dd"
    mtd.write_bytes(b"\x00" * 32)
    sdcard = root / "sdcard.dd"
    sdcard.write_bytes(b"\x00" * 32)
    assert classify_file("dfrws2011-android/case2-extract/mtd6.dd", mtd) == "android_mtd"
    assert classify_file("dfrws2011-android/case2-extract/sdcard.dd", sdcard) == "android_sdcard"
    mtd = tmp_path / "mtdblock4.img"
    mtd.write_bytes(b"\x00" * 32)
    ad1 = tmp_path / "FruitBook.ad1"
    ad1.write_bytes(b"ADSEGMENTEDFILE.\x00" + b"\x00" * 32)
    assert classify_file("dfrws2011-android/case1/mtdblock4.img", mtd) == "android_mtd"
    assert classify_file("macos-spotlight/c18/FruitBook.ad1", ad1) == "macos_ad1"


def test_android_probe_parses_acquisition_log(tmp_path: Path) -> None:
    (tmp_path / "acquisition.log").write_text(
        "SuperOneClick 1.7.0.0 with psneuter\n"
        "adb devices serial 040373BF0B01B01A\n"
        "motorola A855 in airplane mode; text messages were received\n",
        encoding="utf-8",
    )
    (tmp_path / "mtdblock0.img").write_bytes(b"\x00" * 64)
    payload = probe_android_case(tmp_path)
    assert payload["mtd_count"] == 1
    assert payload["note_count"] >= 3
    categories = {note["category"] for note in payload["acquisition_notes"]}
    assert "root_exploit" in categories
    assert "device_serial" in categories


def test_android_scan_finds_log_signals(tmp_path: Path) -> None:
    (tmp_path / "acquisition.log").write_text(
        "USB debugging enabled during live acquisition via adb\n",
        encoding="utf-8",
    )
    payload = scan_android_artifacts(tmp_path, max_records=20, sample_bytes=4096)
    assert payload["finding_count"] >= 1
    assert any(hit.get("category") == "adb_acquisition" for hit in payload["findings"])


def test_macos_probe_reads_manifest_users(tmp_path: Path) -> None:
    ad1 = tmp_path / "FruitBook.ad1"
    ad1.write_bytes(b"ADSEGMENTEDFILE.\x00" + b"\x00" * 64)
    manifest = tmp_path / "FruitBook.ad1.txt"
    manifest.write_text(
        "Users|hansel.apricot|Library|Safari\nUsers|sneaky|Library|Preferences\n",
        encoding="utf-8",
    )
    payload = probe_macos_ad1(ad1)
    assert payload["format"] == "ADSEGMENTEDFILE"
    assert "hansel.apricot" in payload["users"]
    assert "sneaky" in payload["users"]


def test_macos_scan_finds_spotlight_and_slack(tmp_path: Path) -> None:
    ad1 = tmp_path / "FruitBook.ad1"
    ad1.write_bytes(
        b"ADSEGMENTEDFILE.\x00"
        b"com.apple.spotlight\x00"
        b"https_fruitincworkspace.slack.com_0.localstorage\x00"
        b"Hansel Apricot\x00Super Sneaky\x00"
    )
    payload = scan_macos_ad1(ad1, max_records=20, sample_bytes=4096)
    categories = {hit["category"] for hit in payload["findings"]}
    assert "spotlight" in categories
    assert "slack" in categories
    assert "user_account" in categories


def test_r32_android_contradiction() -> None:
    ctx = VerifyContext(
        android_probe={"parser": "android-probe", "mtd_count": 6, "note_count": 2},
        android_findings=[
            {"category": "root_exploit", "detail": "SuperOneClick psneuter", "source": "acquisition.log"}
        ],
        android_audit_id="aud-android",
    )
    result = rule_r32_android_mobile(ctx)
    assert result.status == "contradiction"
    assert "SuperOneClick" in result.detail or "mtdblock" in result.detail


def test_r33_macos_contradiction() -> None:
    ctx = VerifyContext(
        macos_probe={"parser": "macos-probe", "users": ["hansel.apricot", "sneaky"], "user_count": 2},
        macos_findings=[
            {"category": "spotlight", "detail": "com.apple.spotlight", "source": "FruitBook.ad1"}
        ],
        macos_audit_id="aud-macos",
    )
    result = rule_r33_macos_artifacts(ctx)
    assert result.status == "contradiction"
    assert "hansel.apricot" in result.detail
    assert "Spotlight" in result.detail


@pytest.mark.integration
def test_live_android_case1_probe() -> None:
    root = Path("/evidence/dfrws2011-android/case1-extract")
    if not root.is_dir():
        pytest.skip("Android Case1 evidence not mounted")
    payload = probe_android_case(root)
    assert payload["mtd_count"] >= 6
    assert payload["sdcard_image"] == "SDCard.img"
    assert payload["note_count"] >= 5


@pytest.mark.integration
def test_live_macos_spotlight_scan() -> None:
    ad1 = Path("/evidence/macos-spotlight/c18-spotlight/FruitBook.ad1")
    if not ad1.is_file():
        pytest.skip("macOS Spotlight AD1 not mounted")
    probe = probe_macos_ad1(ad1)
    assert probe["user_count"] >= 2
    scan = scan_macos_ad1(ad1, max_records=30, sample_bytes=4_000_000)
    categories = {hit["category"] for hit in scan["findings"]}
    assert "spotlight" in categories
    assert "user_account" in categories
