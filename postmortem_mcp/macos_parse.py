"""macOS forensic parsing — AD1 custom-content / Spotlight-style cases."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

USER_PATH_RE = re.compile(
    r"Users\|([^|]+)\|",
    re.I,
)
MANIFEST_USER_RE = re.compile(r"Users\|([^\|]+)\|", re.I)

ARTIFACT_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"(_spotlight|corespotlight|com\.apple\.spotlight)", re.I), "spotlight", "Spotlight index/metadata"),
    (re.compile(r"Safari", re.I), "safari", "Safari browser artifacts"),
    (re.compile(r"Downloads", re.I), "downloads", "User Downloads folder"),
    (re.compile(r"(fruitincworkspace\.slack\.com|slack\.com)", re.I), "slack", "Slack workspace / web client storage"),
    (re.compile(r"Super Sneaky", re.I), "user_account", "User account Super Sneaky"),
    (re.compile(r"Hansel Apricot|hansel\.apricot", re.I), "user_account", "User account Hansel Apricot"),
    (re.compile(r"macOS Catalina", re.I), "os_version", "macOS Catalina system volume"),
    (re.compile(r"APFS", re.I), "filesystem", "APFS container/volume"),
    (re.compile(r"\.localstorage", re.I), "browser_storage", "Browser local storage (Slack/web)"),
    (re.compile(r"\.plist", re.I), "plist", "macOS preference plist"),
)


def _read_text(path: Path, *, max_bytes: int = 512_000) -> str:
    try:
        return path.read_bytes()[:max_bytes].decode("utf-8", errors="replace")
    except OSError:
        return ""


def _sample_strings(path: Path, *, min_len: int = 8, max_bytes: int = 8_000_000) -> list[str]:
    import subprocess

    try:
        proc = subprocess.run(
            ["strings", "-n", str(min_len), str(path)],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0 and not proc.stdout:
        return []
    blob = proc.stdout
    encoded = blob.encode("utf-8", errors="ignore")
    if len(encoded) > max_bytes:
        blob = encoded[:max_bytes].decode("utf-8", errors="replace")
    return [line.strip() for line in blob.splitlines() if line.strip()]


def _manifest_path(ad1_path: Path) -> Path | None:
    companion = ad1_path.with_suffix(ad1_path.suffix + ".txt")
    if companion.is_file():
        return companion
    alt = ad1_path.parent / f"{ad1_path.stem}.ad1.txt"
    if alt.is_file():
        return alt
    return None


def probe_macos_ad1(ad1_path: Path) -> dict[str, Any]:
    """Parse AD1 header/manifest and summarize carved macOS content."""
    header = b""
    try:
        header = ad1_path.read_bytes()[:16]
    except OSError:
        pass

    manifest = _manifest_path(ad1_path)
    users: set[str] = set()
    volumes: set[str] = set()
    manifest_lines = 0
    if manifest:
        text = _read_text(manifest, max_bytes=2_000_000)
        manifest_lines = text.count("\n")
        for match in MANIFEST_USER_RE.finditer(text):
            user = match.group(1).strip()
            if user and user not in {"Shared", "root"} and not user.startswith("*"):
                users.add(user)
        for line in text.splitlines():
            if "volume_" in line or "macOS Catalina" in line:
                volumes.add(line.split("|")[0].strip()[-80:])

    return {
        "parser": "macos-probe",
        "source": str(ad1_path),
        "format": "ADSEGMENTEDFILE" if header.startswith(b"ADSEGMENTEDFILE") else "unknown",
        "size_bytes": ad1_path.stat().st_size if ad1_path.is_file() else 0,
        "manifest": str(manifest) if manifest else None,
        "manifest_lines": manifest_lines,
        "users": sorted(users),
        "user_count": len(users),
        "volumes_sample": sorted(volumes)[:8],
    }


def scan_macos_ad1(
    ad1_path: Path,
    *,
    max_records: int = 80,
    sample_bytes: int = 8_000_000,
) -> dict[str, Any]:
    """Strings sweep of AD1 custom content for users, Spotlight, Safari, Slack."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    by_category: dict[str, dict[str, Any]] = {}

    manifest = _manifest_path(ad1_path)
    if manifest:
        text = _read_text(manifest, max_bytes=2_000_000)
        for pattern, category, detail in ARTIFACT_PATTERNS:
            if not pattern.search(text):
                continue
            key = ("manifest", category)
            if key in seen:
                continue
            seen.add(key)
            entry = {
                "source": manifest.name,
                "category": category,
                "detail": detail,
                "kind": "manifest",
            }
            by_category.setdefault(category, entry)

    extras: list[dict[str, Any]] = []
    for line in _sample_strings(ad1_path, max_bytes=sample_bytes):
        for pattern, category, detail in ARTIFACT_PATTERNS:
            if not pattern.search(line):
                continue
            key = (category, line[:60])
            if key in seen:
                break
            seen.add(key)
            entry = {
                "source": ad1_path.name,
                "category": category,
                "detail": line[:200] if len(line) > 40 else detail,
                "kind": "ad1_strings",
            }
            if category not in by_category:
                by_category[category] = entry
            else:
                extras.append(entry)
            break

    findings = list(by_category.values()) + extras

    total = len(findings)
    truncated = total > max_records
    if truncated:
        findings = findings[:max_records]
    return {
        "parser": "macos-scan",
        "source": str(ad1_path),
        "findings": findings,
        "finding_count": total,
        "truncated": truncated,
        "record_count": len(findings),
    }
