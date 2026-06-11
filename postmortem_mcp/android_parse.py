"""Android mobile forensic parsing — DFRWS-style mtd/sdcard cases."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

ACQUISITION_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"SuperOneClick", re.I), "root_exploit", "SuperOneClick root exploit used during acquisition"),
    (re.compile(r"psneuter", re.I), "root_exploit", "psneuter temporary root during live acquisition"),
    (re.compile(r"\badb\b", re.I), "adb_acquisition", "ADB used for live device acquisition"),
    (re.compile(r"adb\s+forward", re.I), "adb_acquisition", "ADB port-forward used for live partition acquisition"),
    (re.compile(r"platform-tools", re.I), "adb_acquisition", "Android platform-tools used for acquisition"),
    (re.compile(r"040373BF0B01B01A", re.I), "device_serial", "ADB device serial 040373BF0B01B01A"),
    (re.compile(r"motorola\s+A855", re.I), "device_model", "Motorola A855 (DROID) identified"),
    (re.compile(r"airplane\s+mode", re.I), "integrity", "Airplane mode attempted before acquisition"),
    (re.compile(r"text\s+messages?\s+were\s+received", re.I), "integrity", "SMS received despite airplane mode"),
    (re.compile(r"USB\s+debugging", re.I), "integrity", "USB debugging enabled during acquisition"),
    (re.compile(r"live\s+acquisition", re.I), "method", "Live acquisition method documented"),
    (re.compile(r"nc\s+localhost|\bnetcat\b", re.I), "method", "netcat stream used to pull mtd partitions to examiner"),
    (re.compile(r"sha1sum", re.I), "integrity", "SHA1 hashes recorded for acquired partition images"),
    (re.compile(r"mtdblock\d+", re.I), "partitions", "Internal mtdblock partition images collected"),
    (re.compile(r"mtd\d+\.dd", re.I), "partitions", "Internal mtd partition images collected (mtd*.dd)"),
)

ARTIFACT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"com\.android\.(providers\.telephony|mms|contacts)", re.I), "telephony"),
    (re.compile(r"mmssms|sms\.db|telephony", re.I), "sms"),
    (re.compile(r"ContactsContract|contacts2\.db", re.I), "contacts"),
    (re.compile(r"SuperOneClick|psneuter", re.I), "root_exploit"),
    (re.compile(r"\badb\b.*device", re.I), "adb"),
    (re.compile(r"\bandroid\b", re.I), "android"),
)


def _read_text(path: Path, *, max_bytes: int = 256_000) -> str:
    try:
        data = path.read_bytes()[:max_bytes]
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def _sample_strings(path: Path, *, min_len: int = 8, max_bytes: int = 2_000_000) -> list[str]:
    try:
        proc = subprocess.run(
            ["strings", "-n", str(min_len), str(path)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0 and not proc.stdout:
        return []
    blob = proc.stdout
    if len(blob.encode("utf-8", errors="ignore")) > max_bytes:
        blob = blob[: max_bytes // 2]
    return [line.strip() for line in blob.splitlines() if line.strip()]


def _mmls_summary(image: Path) -> dict[str, Any] | None:
    try:
        proc = subprocess.run(
            ["mmls", str(image)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    partitions: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        if "FAT32" in line or "Linux" in line or "Win95" in line:
            parts = line.split()
            if len(parts) >= 5:
                partitions.append(
                    {
                        "slot": parts[0].rstrip(":"),
                        "start": parts[2],
                        "description": " ".join(parts[5:]),
                    }
                )
    return {"image": str(image), "partitions": partitions, "raw": proc.stdout.strip()}


def _list_mtd_images(case_root: Path) -> list[Path]:
    seen: set[str] = set()
    images: list[Path] = []
    for pattern in ("mtdblock*.img", "mtd[0-9]*.dd", "mtd*.dd"):
        for path in sorted(case_root.glob(pattern)):
            if path.is_file() and path.name not in seen:
                seen.add(path.name)
                images.append(path)
    return images


def _sdcard_image(case_root: Path) -> Path | None:
    for path in sorted(case_root.glob("*")):
        if not path.is_file():
            continue
        if path.name.lower() in {"sdcard.img", "sdcard.dd"}:
            return path
    return None


def _fls_android_paths(image: Path, *, offset: int = 129, max_lines: int = 40) -> list[str]:
    """Non-recursive TSK listing — avoid multi-minute walks of 16GB SD images."""
    try:
        proc = subprocess.run(
            ["fls", "-o", str(offset), str(image)],
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    paths: list[str] = []
    for line in proc.stdout.splitlines():
        lower = line.lower()
        if any(token in lower for token in ("android", "dcim", "download", ".db", "sms", "contact", "lost.dir")):
            paths.append(line.strip())
            if len(paths) >= max_lines:
                break
    return paths


def probe_android_case(case_root: Path) -> dict[str, Any]:
    """Inventory Android case layout and parse acquisition notes."""
    mtd_images = _list_mtd_images(case_root)
    sdcard = _sdcard_image(case_root)
    logs = sorted(
        p
        for p in case_root.glob("*")
        if p.is_file() and p.suffix.lower() in {".log", ".txt"} and p.stat().st_size < 500_000
    )

    acquisition_notes: list[dict[str, Any]] = []
    seen_notes: set[tuple[str, str]] = set()
    for log in logs:
        text = _read_text(log)
        for pattern, category, detail in ACQUISITION_PATTERNS:
            if not pattern.search(text):
                continue
            key = (log.name, category)
            if key in seen_notes:
                continue
            seen_notes.add(key)
            acquisition_notes.append(
                {"source": log.name, "category": category, "detail": detail, "pattern": pattern.pattern}
            )

    partitions = _mmls_summary(sdcard) if sdcard else None
    return {
        "parser": "android-probe",
        "case_root": str(case_root),
        "mtd_images": [p.name for p in mtd_images],
        "mtd_count": len(mtd_images),
        "sdcard_image": sdcard.name if sdcard else None,
        "sdcard_partitions": partitions,
        "log_files": [p.name for p in logs],
        "acquisition_notes": acquisition_notes,
        "note_count": len(acquisition_notes),
    }


def scan_android_artifacts(
    case_root: Path,
    *,
    max_records: int = 80,
    sample_bytes: int = 2_000_000,
) -> dict[str, Any]:
    """Strings/TSK sweep for Android mobile artifacts and acquisition indicators."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for log in sorted(case_root.glob("*")):
        if not log.is_file() or log.stat().st_size > 500_000:
            continue
        if log.suffix.lower() not in {".log", ".txt"}:
            continue
        text = _read_text(log)
        for pattern, category, detail in ACQUISITION_PATTERNS:
            if not pattern.search(text):
                continue
            key = (log.name, category)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "source": log.name,
                    "category": category,
                    "detail": detail,
                    "kind": "acquisition_log",
                }
            )

    for mtd in _list_mtd_images(case_root):
        for line in _sample_strings(mtd, max_bytes=sample_bytes):
            for pattern, category in ARTIFACT_PATTERNS:
                if not pattern.search(line):
                    continue
                key = (mtd.name, category)
                if key in seen:
                    break
                seen.add(key)
                findings.append(
                    {
                        "source": mtd.name,
                        "category": category,
                        "detail": line[:200],
                        "kind": "mtd_strings",
                    }
                )
                break
        if len(findings) >= max_records:
            break

    sdcard = _sdcard_image(case_root)
    if sdcard and len(findings) < max_records:
        for path_line in _fls_android_paths(sdcard):
            key = ("sdcard", path_line[:80])
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "source": sdcard.name,
                    "category": "sdcard",
                    "detail": f"android sdcard filesystem: {path_line}",
                    "kind": "sdcard_fls",
                }
            )
            if len(findings) >= max_records:
                break

    total = len(findings)
    truncated = total > max_records
    if truncated:
        findings = findings[:max_records]
    return {
        "parser": "android-scan",
        "source": str(case_root),
        "findings": findings,
        "finding_count": total,
        "truncated": truncated,
        "record_count": len(findings),
    }
