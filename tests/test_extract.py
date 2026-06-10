"""Hermetic tests for the raw-image ingest engine (no TSK / no real image)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from postmortem_mcp import extract


MMLS_SAMPLE = """\
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
003:  000:001   0000206848   0041940991   0041734144   NTFS / exFAT (0x07)
004:  -------   0041940992   0041943039   0000002048   Unallocated
"""

FLS_WINDOWS = """\
r/r 58912-128-3:\tWindows/System32/config/SYSTEM
r/r 58910-128-3:\tWindows/System32/config/SOFTWARE
r/r 15001-128-1:\tWindows/Prefetch/CMD.EXE-12345678.pf
r/r 16002-128-1:\tWindows/System32/winevt/Logs/Security.evtx
r/r 17003-128-1:\tWindows/inf/setupapi.dev.log
r/r 18004-128-1:\tUsers/informant/NTUSER.DAT
r/r 99999-128-1:\tWindows/System32/notepad.exe
"""

FLS_LINUX = """\
r/r 100-128-1:\tetc/passwd
r/r 101-128-1:\tvar/log/auth.log
r/r 102-128-1:\tetc/crontab
r/r 103-128-1:\troot/.bash_history
"""


def _completed(stdout: str = "", returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["x"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_list_partitions_parses_mmls(monkeypatch):
    monkeypatch.setattr(extract, "_run", lambda cmd, *, timeout: _completed(MMLS_SAMPLE))
    parts = extract.list_partitions(Path("img.E01"))
    fs = [p for p in parts if p.is_filesystem]
    assert len(fs) == 2
    assert fs[1].start == 206848
    assert fs[1].length == 41734144
    # Unallocated / meta rows are not filesystems.
    assert any(not p.is_filesystem for p in parts)


def test_list_partitions_bare_image(monkeypatch):
    monkeypatch.setattr(extract, "_run", lambda cmd, *, timeout: _completed(returncode=1, stderr="no table"))
    parts = extract.list_partitions(Path("bare.dd"))
    assert len(parts) == 1
    assert parts[0].slot == "bare"
    assert parts[0].start == 0
    # A bare single-volume image (no partition table, length 0) must still be
    # treated as a filesystem, else extraction silently skips the whole image.
    assert parts[0].is_filesystem is True


@pytest.mark.parametrize(
    "paths,expected",
    [
        (["Windows/System32/config/SYSTEM", "Users/x/NTUSER.DAT"], "windows"),
        (["etc/passwd", "var/log/syslog"], "linux"),
        (["random/file.txt"], "unknown"),
    ],
)
def test_detect_os(paths, expected):
    assert extract._detect_os(paths) == expected


def test_match_targets_windows():
    t = extract._match_targets("Windows/System32/config/SYSTEM", extract.WINDOWS_TARGETS)
    assert t is not None and t.kind == "registry_hive"
    t2 = extract._match_targets("Windows/Prefetch/CMD.EXE-1.pf", extract.WINDOWS_TARGETS)
    assert t2 is not None and t2.kind == "prefetch"
    assert extract._match_targets("Windows/System32/notepad.exe", extract.WINDOWS_TARGETS) is None


def _fake_run_factory(fls_output: str, main_offset: str = "206848"):
    def _fake_run(cmd, *, timeout):
        if cmd[0] == "mmls":
            return _completed(MMLS_SAMPLE)
        if cmd[0] == "fls":
            # Only the main volume carries the OS; the small reserved volume is empty.
            if "-o" in cmd and cmd[cmd.index("-o") + 1] == main_offset:
                return _completed(fls_output)
            return _completed("")
        return _completed(returncode=1)
    return _fake_run


def test_extract_image_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(extract, "_run", _fake_run_factory(FLS_WINDOWS))

    def fake_icat(image, offset, inode, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(f"data-{inode}".encode())
        return True

    monkeypatch.setattr(extract, "_icat", fake_icat)

    image = tmp_path / "img.E01"
    image.write_bytes(b"EVF\x00")  # only needs to exist
    out = tmp_path / "extracted"
    manifest = extract.extract_image(image, out).as_dict()

    assert manifest["os_guess"] == "windows"
    kinds = manifest["kinds_extracted"]
    assert kinds.get("registry_hive", 0) >= 2  # SYSTEM + SOFTWARE + NTUSER
    assert kinds.get("prefetch") == 1
    assert kinds.get("evtx") == 1
    assert kinds.get("setupapi_log") == 1
    assert kinds.get("mft") == 1  # $MFT via inode 0
    # notepad.exe must NOT be extracted
    assert all("notepad" not in a["relpath"].lower() for a in manifest["artifacts"])
    # every artifact carries a real sha256 + source inode for audit
    for a in manifest["artifacts"]:
        assert len(a["sha256"]) == 64
        assert a["inode"]


def test_extract_image_linux(monkeypatch, tmp_path):
    monkeypatch.setattr(extract, "_run", _fake_run_factory(FLS_LINUX))
    monkeypatch.setattr(
        extract, "_icat",
        lambda image, offset, inode, dest: (dest.parent.mkdir(parents=True, exist_ok=True), dest.write_bytes(b"x"), True)[-1],
    )
    image = tmp_path / "img.dd"
    image.write_bytes(b"\x00" * 16)
    manifest = extract.extract_image(image, tmp_path / "out").as_dict()
    assert manifest["os_guess"] == "linux"
    assert manifest["kinds_extracted"].get("linux_log", 0) >= 3


def test_missing_image_raises(tmp_path):
    with pytest.raises(extract.ExtractionError):
        extract.extract_image(tmp_path / "nope.E01", tmp_path / "out")
