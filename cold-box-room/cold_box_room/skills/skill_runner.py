"""Execute ported skill scripts through the harness with audit trail."""

from __future__ import annotations

import importlib.util
import sys
import traceback
from pathlib import Path
from typing import Any

from cold_box_room.r2.sandbox_input import resolve_sandbox_input_for_skill
from cold_box_room.skills.registry import LIBRARY_DIR, resolve_skill_ref
from cold_box_room.skills.skill_runtime import SkillRuntime, SkillRuntimeError, activate

SCRIPT_NAME = "agent.py"


def skill_script_path(library_slug: str) -> Path:
    return LIBRARY_DIR / library_slug / "scripts" / SCRIPT_NAME


def has_skill_script(library_slug: str) -> bool:
    return skill_script_path(library_slug).is_file()


def run_skill_script(
    *,
    case_id: str,
    skill_ref: str,
    input_relpath: str,
    journal_id: str = "",
    script_args: list[str] | None = None,
    skill_run_id: str = "",
) -> dict[str, Any]:
    """Load library/*/scripts/agent.py and run with SIFT-routed run_cmd/subprocess."""
    row = resolve_skill_ref(skill_ref)
    slug = row.library_slug
    jid = journal_id or row.journal_id or ""
    script = skill_script_path(slug)
    if not row.has_script or not script.is_file():
        return {
            "ok": False,
            "error": (
                f"Skill {row.skill_id!r} is reference-only — browse SKILL.md; "
                "no harness script is registered."
            ),
            "skill_id": row.skill_id,
            "reference_only": row.reference_only,
        }

    evidence = resolve_sandbox_input_for_skill(case_id, input_relpath)
    if not evidence.is_file():
        return {"ok": False, "error": f"Evidence not found: {input_relpath!r}"}

    runtime = SkillRuntime(
        case_id=case_id,
        journal_id=jid,
        skill_id=row.skill_id,
        input_relpath=input_relpath,
        evidence_abs_path=evidence,
        skill_run_id=skill_run_id,
    )

    argv = list(script_args or [])
    old_argv = sys.argv[:]
    sys.argv = [str(script), str(evidence), *argv]
    entry_ran = False
    try:
        with activate(runtime):
            spec = importlib.util.spec_from_file_location(
                f"cold_box_room_skill_{slug.replace('-', '_')}",
                script,
            )
            if spec is None or spec.loader is None:
                raise SkillRuntimeError(f"Could not load {script}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if hasattr(module, "analyze_image"):
                work = runtime.ensure_work_dir()
                module.analyze_image(str(evidence), str(work))
                entry_ran = True
            elif hasattr(module, "main"):
                try:
                    module.main()
                    entry_ran = True
                except SystemExit as exc:
                    code = exc.code if exc.code is not None else 0
                    if code not in (0, None):
                        raise SkillRuntimeError(
                            f"Skill script exited with code {code}"
                        ) from exc
            elif hasattr(module, "run"):
                work = runtime.ensure_work_dir()
                module.run(str(evidence), str(work))
                entry_ran = True
    except SystemExit as exc:
        code = exc.code if exc.code is not None else 0
        return {
            "ok": False,
            "error": f"Skill script exited with code {code}",
            "skill_id": row.skill_id,
            "journal_id": jid,
            "library_slug": slug,
            "audit_ids": runtime.audit_ids,
        }
    except Exception as exc:
        tb = traceback.format_exc(limit=8)
        return {
            "ok": False,
            "error": str(exc),
            "traceback": tb[-1500:],
            "skill_id": row.skill_id,
            "journal_id": jid,
            "library_slug": slug,
            "audit_ids": runtime.audit_ids,
        }
    finally:
        sys.argv = old_argv

    if not entry_ran:
        return {
            "ok": False,
            "error": (
                "Skill script has no harness entry point "
                "(expected analyze_image, main, or run)."
            ),
            "skill_id": row.skill_id,
            "journal_id": jid,
            "library_slug": slug,
            "audit_ids": runtime.audit_ids,
        }

    return {
        "ok": True,
        "skill_id": row.skill_id,
        "journal_id": jid,
        "library_slug": slug,
        "audit_ids": runtime.audit_ids,
        "audit_count": len(runtime.audit_ids),
        "work_dir": str(runtime.work_dir) if runtime.work_dir else "",
        "message": f"Skill script finished — {len(runtime.audit_ids)} harness tool run(s) logged.",
    }
