"""Legacy Windows artifact parsers (XP-era recycle bin, IE/Outlook Express index.dat)."""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from postmortem_mcp.artifact_parse import cap_records

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_URL_RE = re.compile(r"https?://[^\s\x00\"<>]{4,200}", re.IGNORECASE)


def _unicode_strings(raw: bytes, *, min_len: int = 4) -> list[str]:
    """Extract plausible UTF-16-LE and ASCII strings from a binary blob."""
    found: list[str] = []
    seen: set[str] = set()

    # UTF-16-LE (Windows registry / index.dat paths)
    i = 0
    while i < len(raw) - min_len * 2:
        end = i
        chars: list[str] = []
        while end < len(raw) - 1:
            code = raw[end] | (raw[end + 1] << 8)
            if code == 0:
                break
            if 32 <= code < 127 or code in (9, 10, 13):
                chars.append(chr(code))
            else:
                chars.clear()
                break
            end += 2
        if len(chars) >= min_len:
            text = "".join(chars).strip()
            if text and text not in seen:
                seen.add(text)
                found.append(text)
        i += max(2, end - i if end > i else 2)

    # ASCII runs
    for match in re.finditer(rb"[\x20-\x7e]{4,}", raw):
        text = match.group().decode("ascii", errors="ignore").strip()
        if text and text not in seen:
            seen.add(text)
            found.append(text)
    return found


def parse_info2(path: Path) -> dict[str, Any]:
    """Parse a Windows XP RECYCLER INFO2 metadata file."""
    raw = path.read_bytes()
    strings = _unicode_strings(raw, min_len=3)
    deleted: list[dict[str, Any]] = []
    for text in strings:
        if "\\" in text or "/" in text or text.lower().endswith(".exe"):
            deleted.append({"original_path": text, "is_executable": text.lower().endswith(".exe")})
    executables = [d for d in deleted if d.get("is_executable")]
    return {
        "source": str(path),
        "parser": "info2-strings",
        "deleted_entries": deleted[:200],
        "executable_count": len(executables),
        "executables": [d["original_path"] for d in executables[:50]],
        "record_count": len(deleted),
    }


def parse_recycle_metadata_file(path: Path) -> dict[str, Any]:
    """Parse a single recycle-bin metadata file (INFO2 or $I)."""
    name = path.name.lower()
    if name == "info2":
        return parse_info2(path)
    if name.startswith("$i") and path.is_file():
        raw = path.read_bytes()
        strings = _unicode_strings(raw, min_len=3)
        originals = [s for s in strings if "\\" in s or s.lower().endswith(".exe")]
        exes = [s for s in originals if s.lower().endswith(".exe")]
        return {
            "source": str(path),
            "parser": "recycle-$I-strings",
            "original_paths": originals[:50],
            "executable_count": len(exes),
            "executables": exes[:50],
            "record_count": len(originals),
        }
    return {"source": str(path), "parser": "recycle-unknown", "record_count": 0}


def parse_index_dat(path: Path, *, max_records: int = 200) -> dict[str, Any]:
    """Extract emails, URLs, and host hints from IE/Outlook Express index.dat."""
    raw = path.read_bytes()
    strings = _unicode_strings(raw, min_len=4)
    emails: list[str] = []
    urls: list[str] = []
    hosts: list[str] = []
    seen: set[str] = set()
    for text in strings:
        for email in _EMAIL_RE.findall(text):
            key = email.lower()
            if key not in seen:
                seen.add(key)
                emails.append(email)
        for url in _URL_RE.findall(text):
            if url not in seen:
                seen.add(url)
                urls.append(url)
            if "yahoo.com" in url.lower() and ".id=" in url.lower():
                yid = url.split(".id=", 1)[-1].split("&", 1)[0].strip()
                if yid:
                    hosts.append(f"yahoo_id:{yid}")
        lower = text.lower()
        if "yahoo" in lower or "mail" in lower or "@" in text or "mrevil" in lower:
            if text not in seen and len(text) < 240:
                seen.add(text)
                hosts.append(text)
    records = [{"email": e} for e in emails] + [{"url": u} for u in urls]
    capped = cap_records(records, max_records)
    return {
        "source": str(path),
        "parser": "ie-index-dat-strings",
        "emails": emails[:max_records],
        "urls": urls[:max_records],
        "hints": hosts[:50],
        "email_count": len(emails),
        **capped,
    }


def parse_ie_cache_text(path: Path, *, max_records: int = 50) -> dict[str, Any]:
    """Read a legacy IE cache/cookie text artifact for email/identity strings."""
    try:
        raw = path.read_bytes()[:65536]
    except OSError as exc:
        return {"source": str(path), "parser": "ie-cache", "error": str(exc), "emails": []}
    text = raw.decode("latin-1", errors="ignore")
    emails = list(dict.fromkeys(_EMAIL_RE.findall(text)))[:max_records]
    return {
        "source": str(path),
        "parser": "ie-cache-text",
        "emails": emails,
        "email_count": len(emails),
        "record_count": len(emails),
        "records": [{"email": e} for e in emails],
        "returned_count": len(emails),
        "truncated": False,
    }


def parse_capture_file(path: Path) -> dict[str, Any]:
    """Identify a packet-capture or Ethereal/Wireshark export on disk."""
    raw = path.read_bytes()[:256]
    magic = raw[:4]
    is_pcap = magic in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"}
    head = raw.decode("latin-1", errors="ignore").lower()
    is_ethereal = "ethereal" in head or "wireshark" in head or "pcap" in head
    return {
        "source": str(path),
        "parser": "capture-sniff",
        "size_bytes": path.stat().st_size,
        "is_pcap_magic": is_pcap,
        "is_capture_artifact": is_pcap or is_ethereal or path.name.lower() == "interception",
        "filename": path.name,
    }


def summarize_recycle_bin(path: Path, *, max_records: int = 200) -> dict[str, Any]:
    """Summarize recycle-bin evidence from a directory tree or a single metadata file."""
    if path.is_file():
        meta = parse_recycle_metadata_file(path)
        exes = meta.get("executables") or []
        if not exes and meta.get("original_paths"):
            exes = [p for p in meta["original_paths"] if str(p).lower().endswith(".exe")]
        return {
            **meta,
            "executable_count": meta.get("executable_count") or len(exes),
            "executables": exes,
            "deleted_file_count": meta.get("record_count", 0),
        }

    records: list[dict[str, Any]] = []
    executables: list[str] = []
    info2_count = 0
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if not child.is_file():
                continue
            lower = child.name.lower()
            if lower == "info2" or lower.startswith("$i"):
                info2_count += 1
                meta = parse_recycle_metadata_file(child)
                for exe in meta.get("executables") or []:
                    if exe not in executables:
                        executables.append(exe)
                records.append({"type": "metadata", "path": str(child.relative_to(path)), **meta})
            elif lower.startswith("dc") or lower.startswith("de"):
                records.append(
                    {
                        "type": "deleted_payload",
                        "path": str(child.relative_to(path)),
                        "size_bytes": child.stat().st_size,
                        "is_executable": lower.endswith(".exe") or "exe" in lower,
                    }
                )
            if len(records) >= max_records:
                break
    payload_exes = sum(1 for r in records if r.get("type") == "deleted_payload" and r.get("is_executable"))
    capped = cap_records(records, max_records)
    return {
        "source": str(path),
        "parser": "recycle-bin",
        "info2_files": info2_count,
        "executable_count": max(len(executables), payload_exes),
        "executables": executables[:50],
        **capped,
    }
