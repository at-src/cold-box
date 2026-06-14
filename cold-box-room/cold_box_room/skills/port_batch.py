"""Port cold-box-final library (CB-SKL-001…050) into cold-box-room skills/library."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

SOURCE_MANIFEST = Path("/opt/cold-box-final/cold_box/skills/skills_manifest.json")
SOURCE_LIBRARY = Path("/opt/cold-box-final/cold_box/skills/library")
DEST_ROOT = Path(__file__).resolve().parents[2] / "skills"
LIBRARY_DIR = DEST_ROOT / "library"

EXTERNAL_API_MARKERS = re.compile(
    r"\b(requests|urllib|httpx|boto3|splunk|shodan|virustotal|misp|"
    r"elastic\.|boto\.|azure\.|google\.cloud)\b",
    re.IGNORECASE,
)

REFERENCE_ONLY_SLUGS = frozenset(
    {
        "cb-building-incident-response-dashboard",
        "cb-building-malware-incident-communication-template",
        "cb-containing-active-breach",
        "cb-eradicating-malware-from-infected-systems",
        "cb-configuring-windows-event-logging-for-detection",
        "cb-cloud-incident-containment-procedures",
        "cb-cloud-incident-response",
        "cb-cloud-native-threat-hunting-with-aws-detective",
        "cb-automating-ioc-enrichment",
        "cb-building-detection-rules-with-sigma",
        "cb-building-incident-response-playbook",
        "cb-building-incident-timeline-with-timesketch",
        "cb-building-soc-playbook-for-ransomware",
        "cb-cloud-forensics-investigation",
        "cb-cloud-storage-forensic-acquisition",
        "cb-collecting-indicators-of-compromise",
        "cb-detecting-azure-lateral-movement",
        "cb-detecting-credential-dumping-techniques",
        "cb-detecting-email-account-compromise",
    }
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


def _is_reference_only(source: dict[str, Any], script_body: str) -> bool:
    slug = source["skill_id"]
    if slug in REFERENCE_ONLY_SLUGS:
        return True
    if source.get("execution_mode") == "reference":
        return True
    if script_body and EXTERNAL_API_MARKERS.search(script_body):
        return True
    return False


def _patch_agent_script(body: str) -> str:
    for old, new in IMPORT_PATCH:
        body = body.replace(old, new)
    return body


def _extract_suggested_tool_ids(skill_md: str) -> list[str]:
    return sorted({tool_id for _, tool_id in TOOL_MAP_RE.findall(skill_md)})


def port_batch(*, start: int = 0, limit: int = 50) -> list[dict[str, Any]]:
    data = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8"))
    sources = data["skills"][start : start + limit]
    rows: list[dict[str, Any]] = []

    if LIBRARY_DIR.exists():
        shutil.rmtree(LIBRARY_DIR)
    LIBRARY_DIR.mkdir(parents=True)

    for offset, source in enumerate(sources, start=1):
        slug = source["skill_id"]
        journal_id = str(source.get("journal_id") or f"CB-SKL-{offset:03d}")
        skill_id = f"SKILL-{offset:03d}"

        src_dir = SOURCE_LIBRARY / slug
        dest_dir = LIBRARY_DIR / slug
        dest_dir.mkdir(parents=True)

        skill_md_path = src_dir / "SKILL.md"
        if not skill_md_path.is_file():
            raise FileNotFoundError(f"Missing SKILL.md for {slug}")
        skill_md = skill_md_path.read_text(encoding="utf-8", errors="replace")
        (dest_dir / "SKILL.md").write_text(skill_md, encoding="utf-8")

        src_script = src_dir / "scripts" / "agent.py"
        script_body = src_script.read_text(encoding="utf-8", errors="replace") if src_script.is_file() else ""
        reference_only = _is_reference_only(source, script_body)
        has_script = src_script.is_file() and not reference_only

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
                "execution_mode": (
                    "reference" if reference_only else str(source.get("execution_mode") or "sift_runnable")
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


def write_manifest(skills: list[dict[str, Any]]) -> Path:
    payload = {
        "schema": "cold_box_room.skills_manifest_v2",
        "count": len(skills),
        "batch": 1,
        "source": "cold-box-final CB-SKL-001..050",
        "skills": skills,
    }
    out = DEST_ROOT / "manifest.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out


def main() -> None:
    skills = port_batch(start=0, limit=50)
    path = write_manifest(skills)
    runnable = sum(1 for s in skills if s["has_script"])
    reference = sum(1 for s in skills if s["reference_only"])
    print(f"Wrote {len(skills)} skills to {path}")
    print(f"  library: {LIBRARY_DIR}")
    print(f"  runnable scripts: {runnable}")
    print(f"  reference-only: {reference}")


if __name__ == "__main__":
    main()
