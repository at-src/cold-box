"""YARA / Sigma-style pattern scanning for suspicious binaries and strings."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from postmortem_mcp.timeline import BINARY_SKIP_SUFFIXES

RULES_DIR = Path(__file__).resolve().parents[1] / "rules" / "yara"

# Fallback when the `yara` binary is not installed — mirrors bundled .yar intent.
PATTERN_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("EICAR-Test-File", "critical", re.compile(rb"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")),
    (
        "Suspicious-Keylogger-Strings",
        "high",
        re.compile(rb"(GetAsyncKeyState|SetWindowsHookEx)", re.I),
    ),
    (
        "Suspicious-Reverse-Shell",
        "high",
        re.compile(rb"(cmd\.exe /c|/bin/sh -i|powershell -enc)", re.I),
    ),
    (
        "Suspicious-Hacking-Tool-Names",
        "medium",
        re.compile(rb"(cain\.exe|l0phtcrack|netstumbler|wasp_setup|look@lan)", re.I),
    ),
)


def _yara_binary() -> str | None:
    return shutil.which("yara")


def scan_with_yara(
    root: Path,
    *,
    rules_path: Path | None = None,
    max_matches: int = 30,
    max_file_bytes: int = 5_000_000,
) -> dict[str, Any]:
    """Scan evidence files with YARA when available, else regex fallback."""
    rules = rules_path or (RULES_DIR / "malware_suspicious.yar")
    yara = _yara_binary()
    if yara and rules.is_file():
        return _scan_yara_cli(root, yara=yara, rules=rules, max_matches=max_matches)

    return _scan_patterns(root, max_matches=max_matches, max_file_bytes=max_file_bytes)


def _scan_yara_cli(
    root: Path,
    *,
    yara: str,
    rules: Path,
    max_matches: int,
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    proc = subprocess.run(
        [yara, "-s", str(rules), str(root)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    for line in (proc.stdout or "").splitlines():
        if not line.strip() or line.startswith("warning"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        rule_name, relpath = parts[0], parts[1]
        matches.append({"rule": rule_name, "path": relpath, "engine": "yara"})
        if len(matches) >= max_matches:
            break
    return {
        "parser": "yara",
        "source": str(root),
        "rules": str(rules),
        "match_count": len(matches),
        "matches": matches,
        "engine": "yara-cli",
        "stderr": (proc.stderr or "")[:500] or None,
    }


def _scan_patterns(
    root: Path,
    *,
    max_matches: int,
    max_file_bytes: int,
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    files_scanned = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in BINARY_SKIP_SUFFIXES:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_file_bytes:
            continue
        files_scanned += 1
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        for rule_name, severity, pattern in PATTERN_RULES:
            if pattern.search(blob):
                matches.append(
                    {
                        "rule": rule_name,
                        "path": str(path),
                        "severity": severity,
                        "engine": "pattern-fallback",
                    }
                )
                if len(matches) >= max_matches:
                    break
        if len(matches) >= max_matches:
            break
    return {
        "parser": "yara-pattern-fallback",
        "source": str(root),
        "files_scanned": files_scanned,
        "match_count": len(matches),
        "matches": matches,
        "engine": "pattern-fallback",
    }
