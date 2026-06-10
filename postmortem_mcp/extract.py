"""Raw disk-image ingest engine.

Turns a raw forensic image (E01/dd/raw/img) into the extracted artifact tree
that cold-box's typed parsers already consume. Read-only: uses The Sleuth Kit
(``mmls``/``fls``/``icat``) directly against the image — the evidence is never
mounted and never modified. Extracted artifacts are written to a separate,
writable ``EXTRACTED_ROOT`` and recorded in a SHA-256 manifest for audit.

Pipeline per image:
    ewfinfo/mmls  -> partition table
    fls -r -F     -> file listing (metadata-address -> path) per partition
    OS detection  -> windows | linux from sentinel paths
    icat          -> copy each targeted artifact, preserving its original path
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

TSK_TIMEOUT_SEC = 600
# A single full-volume NTFS metadata walk on a ~20 GB image takes ~20s; cap
# generously so large evidence still completes.
FLS_TIMEOUT_SEC = 900

# Metadata address of $MFT in every NTFS volume.
NTFS_MFT_INODE = "0"

_MMLS_ROW = re.compile(
    r"^\s*\d+:\s+(?P<slot>[-\w:]+)\s+(?P<start>\d+)\s+(?P<end>\d+)\s+(?P<length>\d+)\s+(?P<desc>.+?)\s*$"
)
# `fls -F -p -r` lines look like: ``r/r 58912-128-3:\tWindows/System32/config/SYSTEM``
_FLS_ROW = re.compile(r"^.{1,8}\s+(?P<inode>[\d\-]+):\s+(?P<path>.+)$")


class ExtractionError(RuntimeError):
    """Raised when image ingest fails irrecoverably."""


@dataclass(frozen=True)
class Partition:
    slot: str
    start: int          # start sector
    length: int         # sectors
    description: str

    @property
    def is_filesystem(self) -> bool:
        desc = self.description.lower()
        if "unallocated" in desc or "primary table" in desc or "extended" in desc:
            return False
        return self.length > 0


@dataclass(frozen=True)
class ArtifactTarget:
    """A path pattern to extract and the forensic kind it produces."""

    pattern: re.Pattern[str]
    kind: str
    cap: int = 0  # 0 = unlimited matches


@dataclass
class ExtractedArtifact:
    relpath: str          # path under EXTRACTED_ROOT (preserves original casing)
    kind: str
    inode: str
    size: int
    sha256: str
    partition: str


@dataclass
class ExtractionManifest:
    image: str
    image_sha256_note: str
    os_guess: str
    partitions: list[dict] = field(default_factory=list)
    artifacts: list[ExtractedArtifact] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        kinds: dict[str, int] = {}
        for art in self.artifacts:
            kinds[art.kind] = kinds.get(art.kind, 0) + 1
        return {
            "image": self.image,
            "image_note": self.image_sha256_note,
            "os_guess": self.os_guess,
            "partitions": self.partitions,
            "artifact_count": len(self.artifacts),
            "kinds_extracted": kinds,
            "artifacts": [
                {
                    "relpath": a.relpath,
                    "kind": a.kind,
                    "inode": a.inode,
                    "size": a.size,
                    "sha256": a.sha256,
                    "partition": a.partition,
                }
                for a in self.artifacts
            ],
            "warnings": self.warnings,
        }


# --- Windows artifact targets (paths are matched case-insensitively) ----------

def _ci(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


WINDOWS_TARGETS: tuple[ArtifactTarget, ...] = (
    ArtifactTarget(_ci(r"^windows/system32/config/(system|software|sam|security)$"), "registry_hive"),
    ArtifactTarget(_ci(r"^windows/appcompat/programs/amcache\.hve$"), "amcache"),
    ArtifactTarget(_ci(r"^windows/system32/winevt/logs/.+\.evtx$"), "evtx", cap=40),
    ArtifactTarget(_ci(r"^windows/prefetch/.+\.pf$"), "prefetch", cap=300),
    ArtifactTarget(_ci(r"^windows/inf/setupapi\.dev\.log$"), "setupapi_log"),
    ArtifactTarget(_ci(r"^windows/system32/tasks/.+$"), "scheduled_task", cap=200),
    ArtifactTarget(_ci(r"^users/[^/]+/ntuser\.dat$"), "registry_hive", cap=50),
    ArtifactTarget(
        _ci(r"^users/[^/]+/appdata/local/microsoft/windows/usrclass\.dat$"),
        "registry_hive",
        cap=50,
    ),
)

LINUX_TARGETS: tuple[ArtifactTarget, ...] = (
    ArtifactTarget(_ci(r"^(etc/)?var/log/(auth\.log|secure|syslog|messages|kern\.log).*$"), "linux_log", cap=50),
    ArtifactTarget(_ci(r"^var/log/(auth\.log|secure|syslog|messages|kern\.log).*$"), "linux_log", cap=50),
    ArtifactTarget(_ci(r"^etc/(crontab)$"), "linux_log"),
    ArtifactTarget(_ci(r"^etc/cron\.[^/]+/.+$"), "linux_log", cap=100),
    ArtifactTarget(_ci(r"^(root|home/[^/]+)/\.bash_history$"), "linux_log", cap=50),
    ArtifactTarget(_ci(r"^etc/passwd$"), "linux_log"),
)

# Sentinel paths used to identify the OS hosted on a partition.
_WINDOWS_SENTINELS = ("windows/system32/config/system", "windows/system32/ntoskrnl.exe")
_LINUX_SENTINELS = ("etc/passwd", "etc/shadow", "var/log/syslog", "etc/fstab")


def _run(cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        )
    except FileNotFoundError as exc:  # tool missing on host
        raise ExtractionError(f"Required tool not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ExtractionError(f"Timed out: {' '.join(cmd[:3])} …") from exc


def list_partitions(image: Path) -> list[Partition]:
    """Return filesystem partitions via ``mmls`` (TSK reads E01 natively)."""
    proc = _run(["mmls", str(image)], timeout=TSK_TIMEOUT_SEC)
    parts: list[Partition] = []
    if proc.returncode != 0:
        # No partition table (e.g. a single bare filesystem image). Treat the
        # whole image as one volume at offset 0.
        return [Partition(slot="bare", start=0, length=0, description="filesystem (no partition table)")]
    for line in proc.stdout.splitlines():
        m = _MMLS_ROW.match(line)
        if not m:
            continue
        parts.append(
            Partition(
                slot=m.group("slot"),
                start=int(m.group("start")),
                length=int(m.group("length")),
                description=m.group("desc"),
            )
        )
    return parts


def _fls_listing(image: Path, offset: int) -> list[tuple[str, str]]:
    """Return (inode, relpath) for every file in a volume via recursive ``fls``."""
    cmd = ["fls", "-F", "-p", "-r"]
    if offset:
        cmd += ["-o", str(offset)]
    cmd.append(str(image))
    proc = _run(cmd, timeout=FLS_TIMEOUT_SEC)
    if proc.returncode != 0 and not proc.stdout:
        raise ExtractionError(proc.stderr.strip() or "fls failed")
    rows: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        m = _FLS_ROW.match(line)
        if not m:
            continue
        rows.append((m.group("inode"), m.group("path").strip()))
    return rows


def _detect_os(paths: list[str]) -> str:
    lowered = {p.lower() for p in paths}
    if any(s in lowered for s in _WINDOWS_SENTINELS) or any(
        p.startswith("windows/") for p in lowered
    ):
        return "windows"
    if any(s in lowered for s in _LINUX_SENTINELS) or any(
        p.startswith("etc/") for p in lowered
    ):
        return "linux"
    return "unknown"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _icat(image: Path, offset: int, inode: str, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["icat"]
    if offset:
        cmd += ["-o", str(offset)]
    cmd += [str(image), inode]
    proc = subprocess.run(cmd, capture_output=True, check=False, timeout=TSK_TIMEOUT_SEC)
    if proc.returncode != 0 or not proc.stdout:
        return False
    dest.write_bytes(proc.stdout)
    return True


def _match_targets(
    path: str, targets: tuple[ArtifactTarget, ...]
) -> ArtifactTarget | None:
    for target in targets:
        if target.pattern.match(path):
            return target
    return None


def extract_image(
    image: Path,
    out_root: Path,
    *,
    targets_override: tuple[ArtifactTarget, ...] | None = None,
) -> ExtractionManifest:
    """Extract the standard artifact set from ``image`` into ``out_root``."""
    if not image.is_file():
        raise ExtractionError(f"Image not found: {image}")
    out_root.mkdir(parents=True, exist_ok=True)

    manifest = ExtractionManifest(
        image=str(image),
        image_sha256_note="image hash not recomputed (large evidence) — see evidence_manifest",
        os_guess="unknown",
    )

    partitions = list_partitions(image)
    extracted_count_by_kind: dict[str, int] = {}

    for part in partitions:
        if not part.is_filesystem:
            manifest.partitions.append(
                {"slot": part.slot, "start": part.start, "length": part.length,
                 "description": part.description, "skipped": "not a filesystem"}
            )
            continue
        try:
            listing = _fls_listing(image, part.start)
        except ExtractionError as exc:
            manifest.warnings.append(f"partition {part.slot}@{part.start}: {exc}")
            manifest.partitions.append(
                {"slot": part.slot, "start": part.start, "length": part.length,
                 "description": part.description, "error": str(exc)}
            )
            continue

        os_guess = _detect_os([p for _, p in listing])
        manifest.partitions.append(
            {"slot": part.slot, "start": part.start, "length": part.length,
             "description": part.description, "os_guess": os_guess,
             "file_count": len(listing)}
        )
        if manifest.os_guess == "unknown" and os_guess != "unknown":
            manifest.os_guess = os_guess

        if targets_override is not None:
            targets = targets_override
        elif os_guess == "windows":
            targets = WINDOWS_TARGETS
        elif os_guess == "linux":
            targets = LINUX_TARGETS
        else:
            continue

        # Explicitly grab $MFT (metadata address 0) on Windows/NTFS volumes —
        # it is not reliably surfaced by `fls -F`.
        if os_guess == "windows" and targets is WINDOWS_TARGETS:
            mft_dest = out_root / f"part{part.start}" / "$MFT"
            if _icat(image, part.start, NTFS_MFT_INODE, mft_dest) and mft_dest.stat().st_size:
                manifest.artifacts.append(
                    ExtractedArtifact(
                        relpath=mft_dest.relative_to(out_root).as_posix(),
                        kind="mft",
                        inode=NTFS_MFT_INODE,
                        size=mft_dest.stat().st_size,
                        sha256=_sha256_file(mft_dest),
                        partition=str(part.start),
                    )
                )

        for inode, path in listing:
            target = _match_targets(path, targets)
            if target is None:
                continue
            if target.cap and extracted_count_by_kind.get(target.kind, 0) >= target.cap:
                continue
            # Preserve original path under a per-partition subdir to avoid
            # collisions across volumes.
            dest = out_root / f"part{part.start}" / path
            if not _icat(image, part.start, inode, dest):
                manifest.warnings.append(f"icat failed: {path} (inode {inode})")
                continue
            size = dest.stat().st_size
            if size == 0:
                continue
            manifest.artifacts.append(
                ExtractedArtifact(
                    relpath=dest.relative_to(out_root).as_posix(),
                    kind=target.kind,
                    inode=inode,
                    size=size,
                    sha256=_sha256_file(dest),
                    partition=str(part.start),
                )
            )
            extracted_count_by_kind[target.kind] = (
                extracted_count_by_kind.get(target.kind, 0) + 1
            )

    return manifest
