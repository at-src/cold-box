"""Pure-Python parsers for web server logs and upload artifacts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

ACCESS_LINE = re.compile(
    r'^(?P<remote>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

ATTACK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("sql_injection", re.compile(r"union\s+select|sqlmap|'\s*or\s*'|sleep\s*\(", re.I)),
    ("path_traversal", re.compile(r"\.\./|/etc/passwd|file=", re.I)),
    ("webshell_access", re.compile(r"shell\.php|cmd\.php|/uploads/.*\.php\?", re.I)),
    ("rce_probe", re.compile(r";\s*cat\s+|exec\?cmd=|jndi:ldap", re.I)),
    ("scanner", re.compile(r"sqlmap|nikto|dirbuster|gobuster", re.I)),
)

WEBSHELL_CODE = re.compile(
    r"(?:eval\s*\(|base64_decode\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|\$_REQUEST)",
    re.I,
)


def parse_access_log(path: Path, *, max_records: int = 500) -> dict[str, Any]:
    """Parse Apache-style access logs and flag attack-like requests."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    requests: list[dict[str, Any]] = []
    suspicious: list[dict[str, Any]] = []

    for line in lines:
        if not line.strip():
            continue
        match = ACCESS_LINE.match(line)
        if match:
            row = {
                "remote": match.group("remote"),
                "time": match.group("time"),
                "request": match.group("request"),
                "status": match.group("status"),
                "size": match.group("size"),
                "line": line,
            }
        else:
            row = {"line": line, "request": line[:160]}

        requests.append(row)
        blob = f"{row.get('request', '')} {line}".lower()
        for label, pattern in ATTACK_PATTERNS:
            if pattern.search(blob):
                suspicious.append({**row, "attack_type": label, "pattern": label})
                break

        if len(requests) >= max_records:
            break

    return {
        "source": str(path),
        "parser": "web-access-log",
        "line_count": len(lines),
        "request_count": len(requests),
        "requests": requests,
        "suspicious_requests": suspicious,
        "suspicious_count": len(suspicious),
        "truncated": len(lines) > max_records,
    }


def inspect_web_artifact(path: Path, *, max_snippets: int = 20) -> dict[str, Any]:
    """Scan PHP/HTML upload artifacts for webshell indicators."""
    text = path.read_text(encoding="utf-8", errors="replace")
    indicators: list[dict[str, Any]] = []

    for match in WEBSHELL_CODE.finditer(text):
        start = max(0, match.start() - 30)
        end = min(len(text), match.end() + 30)
        indicators.append(
            {
                "pattern": match.group(0),
                "offset": match.start(),
                "snippet": text[start:end].replace("\n", " ")[:120],
            }
        )
        if len(indicators) >= max_snippets:
            break

    lower = text.lower()
    if "webshell" in lower or "c99" in lower or "r57" in lower:
        indicators.append({"pattern": "webshell_keyword", "snippet": path.name})

    return {
        "source": str(path),
        "parser": "web-artifact-inspect",
        "path": path.name,
        "size_bytes": path.stat().st_size,
        "indicators": indicators,
        "indicator_count": len(indicators),
        "suspicious": bool(indicators),
    }
