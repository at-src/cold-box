"""Shared helpers for skill scripts executed via run_skill harness."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from cold_box_room.skills.skill_runtime import run_cmd


def ensure_case_dir(case_dir: str) -> Path:
    path = Path(case_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def artifact_path(image_path: str) -> str:
    """Prefer explicit artifact path from harness script_args, else the sandbox image."""
    if len(sys.argv) > 2:
        candidate = sys.argv[2]
        if os.path.isfile(candidate):
            return candidate
    return image_path


def scratch_relpath_for_artifact(artifact_path: str, case_dir: str) -> str | None:
    from cold_box_room.skills.skill_runtime import get_runtime

    target = Path(artifact_path).resolve()
    roots = [get_runtime().scratch_root(), Path(case_dir).resolve()]
    for root in roots:
        try:
            return str(target.relative_to(root))
        except ValueError:
            continue
    return None


def audit_disk_image(image_path: str) -> tuple[str, int]:
    """Minimum SIFT audit for disk-image skills."""
    return run_cmd(f"img_stat {image_path}")


def audit_artifact_file(artifact_path: str, case_dir: str, *, binary: str = "file") -> bool:
    """Route a scratch-local artifact through harness analysis tools."""
    rel = scratch_relpath_for_artifact(artifact_path, case_dir)
    if rel is None:
        return False
    args = [binary, rel]
    if binary == "strings":
        args = ["strings", "-a", rel]
    _, _, rc = run_cmd(args)
    return rc == 0


def detect_filesystem(image_path: str) -> str:
    """Return filesystem label from mmls (e.g. NTFS, FAT32) or empty string."""
    stdout, _, rc = run_cmd(f"mmls {image_path}")
    if rc != 0:
        return ""
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[2].isdigit():
            desc = " ".join(parts[5:]).upper()
            if "NTFS" in desc or parts[4] in {"0x07", "07"}:
                return "NTFS"
            if "FAT32" in desc or parts[4] in {"0x0c", "0c"}:
                return "FAT32"
            if "FAT" in desc or parts[4] in {"0x04", "04", "0x0b", "0b", "0x0e", "0e"}:
                return "FAT"
    return ""


def first_ntfs_offset(image_path: str, default: int = 63) -> int:
    stdout, _, rc = run_cmd(f"mmls {image_path}")
    if rc != 0:
        return default
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[2].isdigit():
            desc = " ".join(parts[5:]).upper()
            if "NTFS" in desc or parts[4] in {"0x07", "07"}:
                return int(parts[2])
    return default


def write_json_report(case_dir: str, name: str, payload: dict[str, Any]) -> str:
    path = ensure_case_dir(case_dir) / name
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return str(path)


_COMMON_PATH_ATTRS = (
    "security_log",
    "mft_file",
    "evtx",
    "evtx_file",
    "log",
    "log_file",
    "input",
    "input_file",
    "file",
    "artifact",
    "evidence",
    "pcap",
    "memory",
    "registry",
    "hive",
    "prefetch",
    "lnk_file",
    "image",
    "disk",
    "target",
    "path",
    "mailbox",
    "pst",
    "dbx",
    "profile",
    "database",
)


def harness_primary_path(image_path: str) -> str | None:
    target = artifact_path(image_path)
    if os.path.isfile(target):
        return target
    if os.path.isfile(image_path):
        return image_path
    return None


def patch_args_from_harness(args: Any) -> None:
    """Fill common argparse destinations from harness argv when flags were omitted."""
    primary = None
    if len(sys.argv) > 2 and os.path.isfile(sys.argv[2]):
        primary = sys.argv[2]
    elif len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        primary = sys.argv[1]
    if not primary:
        return

    namespace = vars(args)
    for key in _COMMON_PATH_ATTRS:
        if key in namespace and not namespace[key]:
            namespace[key] = primary
            return

    for key, value in namespace.items():
        if value not in (None, "", []):
            continue
        lowered = key.lower()
        if any(token in lowered for token in ("file", "log", "path", "artifact", "evidence", "input", "target", "hive", "image", "disk", "pcap", "memory")):
            namespace[key] = primary
            return


def delegated_main(main_fn) -> dict[str, Any]:
    """Call skill main() without letting SystemExit escape the harness."""
    result: dict[str, Any] = {"delegated": "main"}
    try:
        main_fn()
    except SystemExit as exc:
        result["main_exit_code"] = exc.code if exc.code is not None else 0
    except Exception as exc:
        result["main_error"] = str(exc)
    return result


def run_default_analyze_image(
    image_path: str,
    case_dir: str,
    *,
    skill_slug: str = "",
    main_fn=None,
) -> dict[str, Any]:
    """Canonical analyze_image body for bulk-fixed skills."""
    payload: dict[str, Any] = {
        "skill": skill_slug,
        "image": image_path,
        "target": harness_primary_path(image_path) or image_path,
    }
    ensure_case_dir(case_dir)
    audit_disk_image(image_path)
    target = payload["target"]
    if os.path.isfile(str(target)):
        payload["artifact_audited"] = audit_artifact_file(str(target), case_dir, binary="strings") or audit_artifact_file(
            str(target), case_dir, binary="file"
        )
    if callable(main_fn):
        payload.update(delegated_main(main_fn))
    write_json_report(case_dir, "harness_report.json", payload)
    return payload
