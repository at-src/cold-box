#!/usr/bin/env python3
"""Build binary fixtures used by tool verification and harness probes."""

from __future__ import annotations

import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "cold_box_room" / "tools" / "fixtures"


def _write_sample_text() -> None:
    FIX.mkdir(parents=True, exist_ok=True)
    (FIX / "sample.txt").write_text("cold-box-verify-token\nline-two\n", encoding="utf-8")
    (FIX / "sample.bin").write_bytes(b"cold-box-verify-token-binary\x00padding")


def _write_sample_zip() -> None:
    path = FIX / "sample.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("sample.txt", "cold-box-verify-token\n")


def _write_tiny_ext2() -> None:
    path = FIX / "tiny.ext2.dd"
    if path.is_file() and path.stat().st_size >= 8192:
        return
    tmp = path.with_suffix(".tmp")
    if tmp.exists():
        tmp.unlink()
    subprocess.run(
        ["dd", "if=/dev/zero", f"of={tmp}", "bs=1024", "count=8192", "status=none"],
        check=True,
    )
    subprocess.run(["mkfs.ext2", "-F", str(tmp)], check=True, capture_output=True)
    tmp.replace(path)


def _write_sample_pcap() -> None:
    path = FIX / "sample.pcap"
    # Minimal valid pcap: global header + one empty-ish frame header.
    global_hdr = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        1,
    )
    pkt_hdr = struct.pack("<IIII", 0, 0, 42, 42)
    pkt = b"\x00" * 42
    path.write_bytes(global_hdr + pkt_hdr + pkt)


def _write_sample_evtx() -> None:
    path = FIX / "sample.evtx"
    if path.is_file() and path.stat().st_size > 4096:
        return
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        # Fallback: copy a minimal header-only stub; evtx tools accept help/version only.
        path.write_bytes(b"ElfFile\x00" + b"\x00" * 4088)
        return
    # If Evtx is available but no generator, keep stub header for parser smoke tests.
    path.write_bytes(b"ElfFile\x00" + b"\x00" * 4088)


def main() -> int:
    _write_sample_text()
    _write_sample_zip()
    _write_tiny_ext2()
    _write_sample_pcap()
    _write_sample_evtx()
    elf_src = Path("/bin/ls")
    if elf_src.is_file():
        shutil.copy2(elf_src, FIX / "sample.elf")
    names = sorted(p.name for p in FIX.iterdir() if p.is_file())
    print("fixtures:", ", ".join(names))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
