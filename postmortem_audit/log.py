"""Append-only audit.jsonl writer and chain verification."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator


GENESIS_PREV_HASH = "0" * 64


def digest_result(result: Any) -> str:
    """SHA-256 digest of tool output (stored, not full output)."""
    payload = json.dumps(result, sort_keys=True, default=str).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass
class AuditEntry:
    audit_id: str
    ts: str
    tool: str
    args: dict[str, Any]
    result_digest: str
    iteration: int
    prev_hash: str = GENESIS_PREV_HASH
    entry_hash: str = field(default="", repr=False)

    def canonical_body(self) -> str:
        body = {k: v for k, v in asdict(self).items() if k != "entry_hash"}
        return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    """Append-only audit log. One file per investigation run."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._load_tail_hash()
        self._lock = threading.Lock()

    def _load_tail_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS_PREV_HASH

        with self.path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            chunk = 4096
            tail = b""
            while True:
                start = max(0, size - chunk)
                handle.seek(start)
                tail = handle.read(size - start)
                if start == 0 or b"\n" in tail[:-1]:
                    break
                if chunk >= size:
                    break
                chunk *= 2

        lines = tail.splitlines()
        if not lines:
            return GENESIS_PREV_HASH
        last = lines[-1] if lines[-1] else (lines[-2] if len(lines) > 1 else b"")
        if not last:
            return GENESIS_PREV_HASH
        return json.loads(last)["entry_hash"]

    @staticmethod
    def _utc_timestamp() -> str:
        now = time.time()
        whole, frac = divmod(now, 1)
        return time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime(whole)) + f"{int(frac * 1000):03d}Z"

    def append(
        self,
        tool: str,
        args: dict[str, Any],
        result: Any,
        iteration: int,
    ) -> str:
        """Record one tool call. Returns audit_id."""
        with self._lock:
            entry = AuditEntry(
                audit_id=secrets.token_hex(4),
                ts=self._utc_timestamp(),
                tool=tool,
                args=args,
                result_digest=digest_result(result),
                iteration=iteration,
                prev_hash=self._prev_hash,
            )
            entry.entry_hash = hashlib.sha256(entry.canonical_body().encode()).hexdigest()

            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(asdict(entry), sort_keys=True, default=str) + "\n")
                handle.flush()
                os.fsync(handle.fileno())

            self._prev_hash = entry.entry_hash
            return entry.audit_id

    def read_entries(self) -> list[dict[str, Any]]:
        return list(iter_entries(self.path))

    def lookup(self, audit_id: str) -> dict[str, Any] | None:
        for entry in iter_entries(self.path):
            if entry.get("audit_id") == audit_id:
                return entry
        return None


def iter_entries(path: str | Path) -> Iterator[dict[str, Any]]:
    log_path = Path(path)
    if not log_path.exists():
        return

    with log_path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            yield json.loads(raw)


def verify_chain(path: str | Path) -> tuple[bool, str]:
    """Walk hash chain end-to-end. Returns (ok, message)."""
    log_path = Path(path)
    if not log_path.exists():
        return False, f"audit log not found: {log_path}"

    prev = GENESIS_PREV_HASH
    count = 0
    with log_path.open("r", encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, 1):
            raw = raw.strip()
            if not raw:
                continue
            obj = json.loads(raw)
            if obj.get("prev_hash") != prev:
                return (
                    False,
                    f"line {lineno}: prev_hash mismatch "
                    f"(expected {prev[:10]}..., got {obj.get('prev_hash', '')[:10]}...)",
                )

            body = {k: v for k, v in obj.items() if k != "entry_hash"}
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
            recomputed = hashlib.sha256(canonical.encode()).hexdigest()
            if recomputed != obj.get("entry_hash"):
                return False, f"line {lineno}: entry_hash mismatch (audit_id={obj.get('audit_id')})"

            prev = obj["entry_hash"]
            count += 1

    if count == 0:
        return True, "chain verified: 0 entries (empty log)"

    return True, f"chain verified: {count} entries, tail={prev[:16]}..."
