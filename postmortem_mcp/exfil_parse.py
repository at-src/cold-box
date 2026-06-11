"""Scan evidence for exfiltration-channel indicators (email, cloud, optical)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from postmortem_mcp.timeline import BINARY_SKIP_SUFFIXES, TEXT_SUFFIXES

EMAIL_HINTS = (
    "gmail",
    "mail.google",
    "webmail",
    "smtp.",
    "outlook.com",
    "attachment",
    "sent mail",
    "mailto:",
    "pop3",
    "imap",
)

CLOUD_HINTS = (
    "dropbox",
    "google drive",
    "drive.google",
    "naver",
    "box.com",
    "icloud",
    "onedrive.live",
    "upload",
    "sync client",
    "cloud storage",
)

OPTICAL_HINTS = (
    "cd-r",
    "cd r",
    "optical",
    "imgburn",
    "nero",
    "imapi",
    "burn disc",
    "disc burn",
    "iso9660",
    "dvd-r",
    "mastered burn",
)


_HINT_CHANNELS: tuple[tuple[str, str], ...] = (
    *((h, "email") for h in EMAIL_HINTS),
    *((h, "cloud") for h in CLOUD_HINTS),
    *((h, "optical") for h in OPTICAL_HINTS),
)


def scan_exfil_channels(
    root: Path,
    *,
    max_hits: int = 40,
    max_file_bytes: int = 2_000_000,
) -> dict[str, Any]:
    """Search read-only evidence for email / cloud / optical exfil indicators."""
    hits: list[dict[str, Any]] = []
    by_channel: dict[str, int] = {"email": 0, "cloud": 0, "optical": 0}
    files_scanned = 0

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix in BINARY_SKIP_SUFFIXES:
            continue
        if suffix and suffix not in TEXT_SUFFIXES and suffix not in {".hve", ".dat", ".pf", ".json"}:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_file_bytes:
            continue

        files_scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel = str(path)
        lower = text.lower()
        for hint, channel in _HINT_CHANNELS:
            if hint not in lower:
                continue
            if any(h["pattern"] == hint and h["relpath"] == rel for h in hits):
                continue
            by_channel[channel] = by_channel.get(channel, 0) + 1
            hits.append(
                {
                    "channel": channel,
                    "pattern": hint,
                    "relpath": rel,
                    "snippet": _snippet(text, hint),
                }
            )
            if len(hits) >= max_hits:
                break
        if len(hits) >= max_hits:
            break

    return {
        "parser": "exfil-channel-scan",
        "source": str(root),
        "files_scanned": files_scanned,
        "hit_count": len(hits),
        "by_channel": by_channel,
        "hits": hits[:max_hits],
        "record_count": len(hits),
        "returned_count": min(len(hits), max_hits),
    }


def _snippet(text: str, hint: str, *, radius: int = 48) -> str:
    idx = text.lower().find(hint.lower())
    if idx < 0:
        return hint[:80]
    start = max(0, idx - radius)
    end = min(len(text), idx + len(hint) + radius)
    blob = text[start:end].replace("\n", " ").strip()
    return re.sub(r"\s+", " ", blob)[:160]
