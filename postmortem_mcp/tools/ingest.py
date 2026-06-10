"""Raw-image ingest MCP tool.

``disk_extract_image`` is the front door for raw forensic images. It extracts
the standard artifact set from an E01/dd/raw/img into the per-case
``EXTRACTED_ROOT`` (writable, never under evidence), then every existing typed
parser can run against ``extracted/<path>`` exactly as it would on a
pre-extracted corpus. Evidence is read via The Sleuth Kit — never mounted,
never modified.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from postmortem_evidence.guard import EXTRACTED_ROOT_ENV, resolve_read_path
from postmortem_mcp.audit_tool import run_audited_tool
from postmortem_mcp.config import case_dir
from postmortem_mcp.extract import extract_image

RAW_IMAGE_SUFFIXES = {".e01", ".dd", ".raw", ".img", ".001", ".aff4", ".ex01"}


def disk_extract_image(
    case_id: str,
    image_relpath: str,
    *,
    iteration: int = 0,
) -> dict:
    """Extract artifacts from a raw disk image (E01/dd/raw) into the case workspace.

    Reads the image read-only via The Sleuth Kit (no mount). Populates
    EXTRACTED_ROOT so subsequent tools can address artifacts as
    ``extracted/<path>``. Returns a SHA-256 manifest of every extracted artifact.
    """
    args = {"case_id": case_id, "image_relpath": image_relpath}

    def execute() -> dict[str, Any]:
        image = resolve_read_path(image_relpath)
        if not image.is_file():
            raise ValueError(f"Image must be a file: {image}")
        suffix = image.suffix.lower()
        if suffix not in RAW_IMAGE_SUFFIXES:
            raise ValueError(
                f"Unsupported image type {suffix!r}; expected one of {sorted(RAW_IMAGE_SUFFIXES)}"
            )
        args["image_path"] = str(image)

        out_root = case_dir(case_id) / "extracted"
        out_root.mkdir(parents=True, exist_ok=True)
        manifest = extract_image(image, out_root)

        # Make extracted artifacts addressable as ``extracted/<path>`` for every
        # downstream tool in this server process.
        os.environ[EXTRACTED_ROOT_ENV] = str(out_root)

        payload = manifest.as_dict()
        payload["extracted_root"] = str(out_root)
        payload["next_step"] = (
            "Run evidence_survey to fold the extracted tree into the inventory, "
            "then point typed parsers at extracted/<path>."
        )

        # Persist the manifest alongside the audit log for traceability.
        manifest_path = case_dir(case_id) / "extracted_manifest.json"
        manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        return payload

    return run_audited_tool(
        case_id=case_id,
        tool="disk_extract_image",
        args=args,
        iteration=iteration,
        execute=execute,
    )
