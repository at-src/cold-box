"""User-profile sensitive document discovery from MFT records."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_SENSITIVE_EXT = frozenset({".xls", ".xlsx", ".doc", ".docx", ".pdf", ".csv", ".pst"})
_USER_PATH = re.compile(
    r"(documents and settings|users)[/\\][^/\\]+[/\\]"
    r"(desktop|my documents|documents|recent|application data)[/\\]",
    re.IGNORECASE,
)
_PST_PATH = re.compile(r"outlook[/\\].+\.pst$", re.IGNORECASE)


def _record_path(row: dict[str, Any]) -> str:
    parent = str(row.get("ParentPath") or row.get("parent_path") or "").replace("\\", "/")
    name = str(row.get("FileName") or row.get("file_name") or row.get("name") or "")
    if parent in {".", ""}:
        return name.replace("\\", "/")
    return f"{parent}/{name}".replace("\\", "/").lstrip("./")


def _user_from_path(path: str) -> str | None:
    m = re.search(r"(?:documents and settings|users)[/\\]([^/\\]+)", path, re.IGNORECASE)
    return m.group(1) if m else None


def scan_mft_records(records: list[dict[str, Any]], *, max_hits: int = 30) -> dict[str, Any]:
    """Find sensitive user documents and Outlook PST paths in parsed MFT rows."""
    documents: list[dict[str, Any]] = []
    pst_paths: list[dict[str, Any]] = []

    for row in records:
        if row.get("IsDirectory") or row.get("is_directory"):
            continue
        path = _record_path(row)
        lower = path.lower()
        name = Path(path).name
        suffix = Path(name).suffix.lower()

        if suffix == ".pst" or _PST_PATH.search(lower):
            pst_paths.append(
                {
                    "relpath": path,
                    "filename": name,
                    "user": _user_from_path(path),
                    "size": row.get("FileSize") or row.get("size"),
                }
            )
            continue

        if suffix not in _SENSITIVE_EXT:
            continue
        if not _USER_PATH.search(lower):
            continue
        category = "user_document"
        if "/desktop/" in lower.replace("\\", "/"):
            category = "desktop"
        elif "/recent/" in lower.replace("\\", "/"):
            category = "recent"
        documents.append(
            {
                "relpath": path,
                "filename": name,
                "category": category,
                "user": _user_from_path(path),
                "size": row.get("FileSize") or row.get("size"),
                "modified": row.get("LastModified0x10") or row.get("last_modified"),
            }
        )
        if len(documents) + len(pst_paths) >= max_hits:
            break

    return {
        "parser": "mft-user-docs",
        "document_count": len(documents),
        "pst_count": len(pst_paths),
        "documents": documents[:max_hits],
        "pst_paths": pst_paths[:10],
        "record_count": len(documents) + len(pst_paths),
        "returned_count": min(max_hits, len(documents) + len(pst_paths)),
    }


def load_mft_records_from_json(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            records.append(row)
    if records:
        return records
    payload = json.loads(text)
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("records", "Entries", "entries", "Rows"):
            items = payload.get(key)
            if isinstance(items, list):
                return [r for r in items if isinstance(r, dict)]
    return []
