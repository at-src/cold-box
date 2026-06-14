"""Port cold-box-final library batches into cold-box-room skills/library."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any

SOURCE_MANIFEST = Path("/opt/cold-box-final/cold_box/skills/skills_manifest.json")
SOURCE_LIBRARY = Path("/opt/cold-box-final/cold_box/skills/library")
DEST_ROOT = Path(__file__).resolve().parents[2] / "skills"
LIBRARY_DIR = DEST_ROOT / "library"
MANIFEST_PATH = DEST_ROOT / "manifest.json"

EXTERNAL_API_MARKERS = re.compile(
    r"\b(requests|urllib|httpx|boto3|splunk|shodan|virustotal|misp|"
    r"elastic\.|boto\.|azure\.|google\.cloud)\b",
    re.IGNORECASE,
)

TOOL_MAP_RE = re.compile(
    r"\|\s*`([^`]+)`\s*\|\s*`(SIFT-\d{3})`\s*\|",
    re.MULTILINE,
)

IMPORT_PATCH = (
    ("from cold_box.skills.skill_runtime", "from cold_box_room.skills.skill_runtime"),
    ("import cold_box.skills.skill_runtime", "import cold_box_room.skills.skill_runtime"),
)


def _map_subdomain_category(subdomain: str) -> str:
    mapping = {
        "digital-forensics": "windows-artifacts",
        "incident-response": "incident-response",
        "malware-analysis": "malware-analysis",
        "threat-hunting": "threat-hunting",
        "network-security": "network",
        "soc-operations": "soc-operations",
        "threat-intelligence": "threat-intelligence",
        "endpoint-security": "endpoint",
        "cloud-security": "cloud",
    }
    return mapping.get(subdomain, "methodology")


def _uses_external_api(script_body: str) -> bool:
    return bool(script_body and EXTERNAL_API_MARKERS.search(script_body))


def _is_reference_only(*, has_source_script: bool, script_body: str) -> bool:
    """Browse-only when script needs external services or source has no agent.py."""
    if not has_source_script:
        return True
    return _uses_external_api(script_body)


def _execution_mode(
    *,
    source: dict[str, Any],
    reference_only: bool,
) -> str:
    if reference_only:
        return "reference"
    source_mode = str(source.get("execution_mode") or "sift_runnable")
    if source_mode in {"reference", "partial"}:
        return "partial"
    return source_mode


def _patch_agent_script(body: str) -> str:
    for old, new in IMPORT_PATCH:
        body = body.replace(old, new)
    return body


def _extract_suggested_tool_ids(skill_md: str) -> list[str]:
    return sorted({tool_id for _, tool_id in TOOL_MAP_RE.findall(skill_md)})


def port_batch(
    *,
    start: int = 0,
    limit: int = 50,
    reset_library: bool = False,
) -> list[dict[str, Any]]:
    data = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8"))
    sources = data["skills"][start : start + limit]
    if not sources:
        raise ValueError(f"No skills in source slice start={start} limit={limit}")

    if reset_library and LIBRARY_DIR.exists():
        shutil.rmtree(LIBRARY_DIR)
    LIBRARY_DIR.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    for index, source in enumerate(sources, start=1):
        slug = source["skill_id"]
        journal_id = str(source.get("journal_id") or f"CB-SKL-{start + index:03d}")
        skill_id = f"SKILL-{start + index:03d}"

        src_dir = SOURCE_LIBRARY / slug
        dest_dir = LIBRARY_DIR / slug
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        dest_dir.mkdir(parents=True)

        skill_md_path = src_dir / "SKILL.md"
        if not skill_md_path.is_file():
            raise FileNotFoundError(f"Missing SKILL.md for {slug}")
        skill_md = skill_md_path.read_text(encoding="utf-8", errors="replace")
        (dest_dir / "SKILL.md").write_text(skill_md, encoding="utf-8")

        src_script = src_dir / "scripts" / "agent.py"
        has_source_script = src_script.is_file()
        script_body = (
            src_script.read_text(encoding="utf-8", errors="replace")
            if has_source_script
            else ""
        )
        reference_only = _is_reference_only(
            has_source_script=has_source_script,
            script_body=script_body,
        )
        has_script = has_source_script and not reference_only

        if has_script:
            scripts_dir = dest_dir / "scripts"
            scripts_dir.mkdir(parents=True)
            (scripts_dir / "agent.py").write_text(
                _patch_agent_script(script_body),
                encoding="utf-8",
            )

        subdomain = str(source.get("subdomain") or "")
        rows.append(
            {
                "skill_id": skill_id,
                "journal_id": journal_id,
                "library_slug": slug,
                "name": slug.removeprefix("cb-"),
                "description": str(source.get("description") or "")[:500],
                "tier": str(source.get("tier") or "core"),
                "execution_mode": _execution_mode(
                    source=source,
                    reference_only=reference_only,
                ),
                "category": _map_subdomain_category(subdomain),
                "subdomain": subdomain,
                "tags": list(source.get("tags") or [])[:16],
                "case_profiles": list(source.get("case_profiles") or []),
                "has_script": has_script,
                "reference_only": reference_only,
                "suggested_tool_ids": _extract_suggested_tool_ids(skill_md),
            }
        )

    return rows


def _load_existing_manifest() -> list[dict[str, Any]]:
    if not MANIFEST_PATH.is_file():
        return []
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return list(data.get("skills") or [])


def write_manifest(
    new_skills: list[dict[str, Any]],
    *,
    start: int,
    limit: int,
) -> Path:
    existing = _load_existing_manifest()
    end = start + limit
    keep = [row for row in existing if not (start < _skill_num(row["skill_id"]) <= end)]
    merged = keep + new_skills
    merged.sort(key=lambda row: _skill_num(row["skill_id"]))

    batch_end = start + len(new_skills)
    if batch_end <= 50:
        batches = [{"start": 1, "end": batch_end, "source": f"CB-SKL-001..{batch_end:03d}"}]
    else:
        batches = [
            {"start": 1, "end": 50, "source": "CB-SKL-001..050"},
            {"start": 51, "end": batch_end, "source": f"CB-SKL-051..{batch_end:03d}"},
        ]

    payload = {
        "schema": "cold_box_room.skills_manifest_v2",
        "count": len(merged),
        "batches": batches,
        "source": f"cold-box-final CB-SKL-001..{batch_end:03d}",
        "skills": merged,
    }
    MANIFEST_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return MANIFEST_PATH


def _skill_num(skill_id: str) -> int:
    return int(skill_id.split("-", 1)[1])


def main() -> None:
    parser = argparse.ArgumentParser(description="Port cold-box-final skills into cold-box-room")
    parser.add_argument("--start", type=int, default=0, help="Source manifest offset (0-based)")
    parser.add_argument("--limit", type=int, default=50, help="Number of skills to port")
    parser.add_argument(
        "--reset-library",
        action="store_true",
        help="Delete entire skills/library before porting",
    )
    args = parser.parse_args()

    skills = port_batch(start=args.start, limit=args.limit, reset_library=args.reset_library)
    path = write_manifest(skills, start=args.start, limit=args.limit)
    with_script = sum(1 for s in skills if s["has_script"])
    reference = sum(1 for s in skills if s["reference_only"])
    partial = sum(1 for s in skills if s["execution_mode"] == "partial")
    total = json.loads(path.read_text(encoding="utf-8"))["count"]
    print(f"Wrote batch start={args.start} limit={args.limit} -> {path}")
    print(f"  batch skills: {len(skills)}  catalog total: {total}")
    print(f"  with agent.py: {with_script}")
    print(f"  reference-only (browse): {reference}")
    print(f"  partial (script, limited SIFT): {partial}")


if __name__ == "__main__":
    main()
