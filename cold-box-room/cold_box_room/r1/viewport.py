"""TableViewport — read-only channel through the glass."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from cold_box_room.r1.paths import TableError, case_slot
from cold_box_room.r1.seal import require_sealed


@dataclass(frozen=True)
class TableEntry:
    relpath: str
    is_dir: bool
    size: int


class TableViewport:
    CHANNEL = "table_viewport_v1"

    def __init__(self, case_id: str) -> None:
        require_sealed(case_id)
        self.case_id = case_id
        self._slot = case_slot(case_id).resolve()

    @property
    def slot(self) -> Path:
        return self._slot

    def _resolve(self, relpath: str) -> Path:
        rel = relpath.replace("\\", "/").lstrip("/")
        target = self._slot if rel in {".", ""} else (self._slot / rel).resolve()
        try:
            target.relative_to(self._slot)
        except ValueError as exc:
            raise TableError(f"Viewport path escapes table: {target}") from exc
        if not target.exists():
            raise TableError(f"Viewport path not found: {relpath!r}")
        return target

    def list_dir(self, relpath: str = ".") -> list[TableEntry]:
        target = self._resolve(relpath)
        if not target.is_dir():
            raise TableError(f"Not a directory: {relpath!r}")
        entries: list[TableEntry] = []
        for child in sorted(target.iterdir(), key=lambda p: p.name):
            rel = child.relative_to(self._slot).as_posix()
            entries.append(
                TableEntry(
                    relpath=rel,
                    is_dir=child.is_dir(),
                    size=child.stat().st_size if child.is_file() else 0,
                )
            )
        return entries

    def read_bytes(self, relpath: str, *, max_bytes: int = 16 * 1024 * 1024) -> bytes:
        target = self._resolve(relpath)
        if not target.is_file():
            raise TableError(f"Not a file: {relpath!r}")
        size = target.stat().st_size
        if size > max_bytes:
            raise TableError(
                f"File {relpath!r} is {size} bytes; max via viewport is {max_bytes}"
            )
        with target.open("rb") as handle:
            return handle.read()

    def sha256(self, relpath: str, *, chunk_size: int = 1024 * 1024) -> str:
        target = self._resolve(relpath)
        if not target.is_file():
            raise TableError(f"Not a file: {relpath!r}")
        digest = hashlib.sha256()
        with target.open("rb") as handle:
            while chunk := handle.read(chunk_size):
                digest.update(chunk)
        return digest.hexdigest()

    def iter_files(self) -> Iterator[tuple[str, int]]:
        for dirpath, dirnames, filenames in os.walk(self._slot):
            dirnames.sort()
            for name in sorted(filenames):
                file_path = Path(dirpath) / name
                rel = file_path.relative_to(self._slot).as_posix()
                yield rel, file_path.stat().st_size

    def stat_entry(self, relpath: str) -> dict[str, Any]:
        target = self._resolve(relpath)
        st = target.stat()
        return {
            "relpath": relpath if relpath not in {".", ""} else ".",
            "is_dir": target.is_dir(),
            "size": st.st_size,
            "channel": self.CHANNEL,
        }

    def abs_path(self, relpath: str) -> Path:
        return self._resolve(relpath)


def open_viewport(case_id: str) -> TableViewport:
    return TableViewport(case_id)
