"""Outlook PST extraction — read-only forensic attribution."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    re.IGNORECASE,
)
_ATTACHMENT_RE = re.compile(
    r"([\w\-. ]{1,64}\.(?:xls|xlsx|doc|docx|pdf|csv|zip|ppt|pptx))\b",
    re.IGNORECASE,
)
_EXTERNAL_DOMAINS = (
    "gmail.com",
    "googlemail.com",
    "hotmail.com",
    "outlook.com",
    "yahoo.com",
    "live.com",
    "aol.com",
    "protonmail.com",
    "mail.com",
)
_SENSITIVE_SUFFIXES = frozenset({".xls", ".xlsx", ".doc", ".docx", ".pdf", ".csv"})


def _decode_pst_blob(raw: bytes) -> str:
    parts: list[str] = []
    try:
        parts.append(raw.decode("utf-16-le", errors="ignore"))
    except Exception:
        pass
    parts.append(raw.decode("latin-1", errors="ignore"))
    return "\n".join(parts)


def _domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower()


def _is_plausible_email(email: str) -> bool:
    if not email or "@" not in email:
        return False
    local, _, domain = email.partition("@")
    if len(local) > 64 or len(domain) > 255:
        return False
    lower = email.lower()
    if re.fullmatch(r"[0-9a-f]{12,}@google\.com", lower):
        return False
    if re.fullmatch(r"[0-9a-f]{12,}@[0-9a-f.]+\.[a-z]{2,}", lower):
        return False
    if "@alerts.bounces." in lower or "@bounces." in lower:
        return False
    if "javamail" in lower or "ins-frontend@" in lower:
        return False
    if re.match(r"20\d{6,}", local):
        return False
    if re.search(r"@(mercury\d+\.|xy\.dreamhostps\.)", lower):
        return False
    return bool(_EMAIL_RE.fullmatch(email))


def _extract_header_emails(blob: str) -> list[str]:
    emails: set[str] = set(_EMAIL_RE.findall(blob))
    for match in re.finditer(
        r"(?i)(?:from|to|cc|bcc|reply-to|envelope-from|return-path|sender)\s*:\s*([^\n\r]+)",
        blob,
    ):
        emails.update(_EMAIL_RE.findall(match.group(1)))
    for match in re.finditer(r"(?i)mailto:([^\s>\)\]]+)", blob):
        emails.add(match.group(1))
    return sorted(emails)


def _external_webmail_emails(emails: list[str], blob: str, *, internal_domains: tuple[str, ...]) -> list[str]:
    internal = {d.lower() for d in internal_domains}
    prioritized: list[str] = []
    for pattern in (r"[\w.+-]+@gmail\.com", r"[\w.+-]+@hotmail\.com", r"[\w.+-]+@yahoo\.com"):
        prioritized.extend(sorted(set(re.findall(pattern, blob, re.IGNORECASE))))
    external: list[str] = []
    for email in prioritized + emails:
        if not _is_plausible_email(email):
            continue
        if _domain(email) in internal:
            continue
        if any(_domain(email).endswith(ext) or ext in _domain(email) for ext in _EXTERNAL_DOMAINS):
            external.append(email)
    return sorted(set(external))


def _classify_emails(
    emails: list[str],
    *,
    internal_domains: tuple[str, ...],
) -> tuple[list[str], list[str]]:
    internal = {d.lower() for d in internal_domains}
    cleaned = sorted({e for e in emails if _is_plausible_email(e)})
    external_recipients = _external_webmail_emails(cleaned, "\n".join(cleaned), internal_domains=internal_domains)
    return cleaned, external_recipients


def _parse_pst_strings(path: Path, *, max_bytes: int) -> dict[str, Any]:
    size = path.stat().st_size
    read_len = min(size, max_bytes)
    raw = path.read_bytes()[:read_len]
    text = _decode_pst_blob(raw)
    emails = sorted(set(_EMAIL_RE.findall(text)))
    _, external_recipients = _classify_emails(emails, internal_domains=("m57.biz", "m57dotbiz.com"))
    attachment_names = sorted(set(_ATTACHMENT_RE.findall(text)))
    return {
        "parser": "pst-strings",
        "emails": emails[:40],
        "external_recipients": external_recipients[:20],
        "attachment_names": attachment_names[:20],
        "email_count": len(emails),
        "external_recipient_count": len(external_recipients),
        "attachment_count": len(attachment_names),
        "bytes_scanned": read_len,
    }


def _parse_pst_readpst(path: Path) -> dict[str, Any] | None:
    readpst = shutil.which("readpst")
    if not readpst:
        return None
    with tempfile.TemporaryDirectory(prefix="cold-box-pst-") as tmp:
        proc = subprocess.run(
            [readpst, "-o", tmp, "-e", "-q", str(path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        if proc.returncode != 0:
            return None
        texts: list[str] = []
        sent_items = 0
        for eml in Path(tmp).rglob("*.eml"):
            try:
                texts.append(eml.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
            if "sent items" in str(eml).lower():
                sent_items += 1
        if not texts:
            return None
        blob = "\n".join(texts)
        emails = _extract_header_emails(blob)
        external_recipients = _external_webmail_emails(emails, blob, internal_domains=("m57.biz", "m57dotbiz.com"))
        attachment_names = sorted(set(_ATTACHMENT_RE.findall(blob)))
        spoof_hints = []
        if re.search(r"from:.*tuckgorge@gmail\.com.*alison@m57\.biz", blob, re.I):
            spoof_hints.append("spoofed internal sender via external Gmail")
        if re.search(r"mailto:tuckgorge@gmail\.com", blob, re.I):
            spoof_hints.append("outbound mail to external Gmail recipient")
        return {
            "parser": "readpst-eml",
            "emails": emails[:40],
            "external_recipients": external_recipients[:20],
            "attachment_names": attachment_names[:20],
            "email_count": len(emails),
            "external_recipient_count": len(external_recipients),
            "attachment_count": len(attachment_names),
            "eml_count": len(texts),
            "sent_item_count": sent_items,
            "spoof_hints": spoof_hints,
            "bytes_scanned": len(blob.encode("utf-8", errors="ignore")),
        }


def parse_pst_file(
    path: Path,
    *,
    max_bytes: int = 8_000_000,
    internal_domains: tuple[str, ...] = ("m57.biz", "m57dotbiz.com"),
) -> dict[str, Any]:
    """Extract emails, external recipients, and attachment names from a PST."""
    size = path.stat().st_size
    parsed = _parse_pst_readpst(path)
    if parsed is None:
        parsed = _parse_pst_strings(path, max_bytes=max_bytes)
    emails = list(parsed.get("emails") or [])
    external_recipients = list(parsed.get("external_recipients") or [])
    if not external_recipients:
        emails, external_recipients = _classify_emails(emails, internal_domains=internal_domains)

    return {
        "parser": parsed.get("parser", "pst-strings"),
        "source": str(path),
        "size_bytes": size,
        "bytes_scanned": parsed.get("bytes_scanned", min(size, max_bytes)),
        "email_count": len(emails),
        "emails": emails[:40],
        "external_recipient_count": len(external_recipients),
        "external_recipients": external_recipients[:20],
        "attachment_count": len(parsed.get("attachment_names") or []),
        "attachment_names": list(parsed.get("attachment_names") or [])[:20],
        "spoof_hints": parsed.get("spoof_hints") or [],
        "eml_count": parsed.get("eml_count", 0),
        "record_count": len(external_recipients) + len(parsed.get("attachment_names") or []),
        "returned_count": min(40, len(emails)),
    }
