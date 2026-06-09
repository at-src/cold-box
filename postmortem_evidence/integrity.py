"""Pre/post run integrity comparison."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from postmortem_evidence.manifest import build_manifest, manifest_digest

logger = logging.getLogger(__name__)


@dataclass
class IntegritySession:
    """Capture manifest at investigation start; verify unchanged at end."""

    case_root: Path
    baseline: dict[str, Any] | None = None
    baseline_digest: str | None = None
    started_at: str | None = None
    log: list[str] = field(default_factory=list)

    def begin(self) -> dict[str, Any]:
        self.baseline = build_manifest(self.case_root)
        self.baseline_digest = manifest_digest(self.baseline)
        self.started_at = datetime.now(timezone.utc).isoformat()
        msg = (
            f"integrity-begin case={self.case_root} "
            f"files={self.baseline['file_count']} digest={self.baseline_digest}"
        )
        self.log.append(msg)
        logger.info(msg)
        return self.baseline

    def check(self) -> dict[str, Any]:
        if self.baseline is None:
            raise RuntimeError("Call begin() before check()")

        current = build_manifest(self.case_root)
        current_digest = manifest_digest(current)

        baseline_map = {f["path"]: f["sha256"] for f in self.baseline["files"]}
        current_map = {f["path"]: f["sha256"] for f in current["files"]}

        changed = sorted(
            path
            for path in baseline_map
            if path in current_map and baseline_map[path] != current_map[path]
        )
        removed = sorted(set(baseline_map) - set(current_map))
        added = sorted(set(current_map) - set(baseline_map))
        intact = not (changed or removed or added)

        result = {
            "case_root": str(self.case_root),
            "started_at": self.started_at,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "baseline_digest": self.baseline_digest,
            "current_digest": current_digest,
            "intact": intact,
            "changed": changed,
            "added": added,
            "removed": removed,
        }

        status = "INTACT" if intact else "VIOLATION"
        msg = (
            f"integrity-check case={self.case_root} status={status} "
            f"changed={len(changed)} added={len(added)} removed={len(removed)}"
        )
        self.log.append(msg)
        logger.info(msg)
        return result

    def save_baseline(self, path: Path) -> None:
        if self.baseline is None:
            raise RuntimeError("No baseline to save")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.baseline, indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load_baseline(cls, case_root: Path, path: Path) -> IntegritySession:
        baseline = json.loads(path.read_text(encoding="utf-8"))
        session = cls(case_root=case_root.resolve())
        session.baseline = baseline
        session.baseline_digest = manifest_digest(baseline)
        session.started_at = baseline.get("generated_at")
        return session
