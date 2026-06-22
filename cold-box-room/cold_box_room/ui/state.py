"""Read-only dashboard projection over Cold Box case records."""

from __future__ import annotations

import ast
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PACKAGE_ROOT.parent

ROOMS = [
    {"id": "1", "label": "Raw file dump", "description": "Files provided for investigation enter the protected evidence room."},
    {"id": "A", "label": "Observe & plan extraction", "description": "Observe the files and plan what evidence should be extracted. No extraction occurs here."},
    {"id": "2", "label": "Evidence extraction", "description": "Observe the working copy and use selected forensic tools to extract evidence."},
    {"id": "B", "label": "Observe & plan evidence analysis", "description": "Review extracted evidence and decide which analysis should be performed."},
    {"id": "3", "label": "Evidence analysis", "description": "Analyze and correlate the extracted evidence before producing the final report."},
]
ROOM_INDEX = {room["id"]: index for index, room in enumerate(ROOMS)}


def records_roots() -> list[Path]:
    configured = Path(
        os.environ.get("COLD_BOX_ROOM_RECORDS", str(PACKAGE_ROOT / "records"))
    ).expanduser()
    roots = [configured.resolve()]
    sample = (REPO_ROOT / "docs" / "runs").resolve()
    if sample not in roots:
        roots.append(sample)
    return roots


def _safe_case_id(case_id: str) -> str:
    value = case_id.strip()
    if not value or len(value) > 128 or ".." in value or "/" in value or "\\" in value:
        raise ValueError("invalid case id")
    return value


def find_case_dir(case_id: str) -> Path:
    safe = _safe_case_id(case_id)
    for root in records_roots():
        candidate = root / safe
        if (candidate / "hallway.json").is_file():
            return candidate
    raise FileNotFoundError(f"case not found: {safe}")


def _json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _markdown_section(text: str, heading: str) -> str:
    match = re.search(
        rf"^##\s+{re.escape(heading)}\s*$\n+(.*?)(?=^##\s+|\Z)",
        text,
        re.MULTILINE | re.DOTALL | re.IGNORECASE,
    )
    return match.group(1).strip() if match else ""


def _report_body(content: str) -> str:
    """Lead the report with the analyst's actual findings.

    Strips the harness boilerplate that precedes the substance: the H1 title
    ("# Layer 2 — Analysis (analyst log)"), the "_Agent write-up…_" note, and
    the empty "## Findings" wrapper. Everything from the real analysis onward
    (the Layer 2 findings, then self-score/why/corrections) is kept.
    """
    marker = re.search(r"^##\s+Findings\s*$", content, re.MULTILINE)
    if marker:
        body = content[marker.end():].lstrip("\n")
        if body.strip():
            return body
    return content


def _report_for_display(raw: str) -> str:
    """Reshape any Layer 2 report for the dashboard, deterministically:

    1. lead with the analyst findings (drop harness boilerplate),
    2. relabel the confusing "Layer 2 Analysis" as "Final Analysis",
    3. lift the conclusion/synthesis section to the top as a "Bottom line"
       executive summary, with the per-step work under "Supporting analysis".

    Applies to every report (old and future runs); the raw file is untouched.
    """
    body = _report_body(raw)
    # Keep the procedural footer (self-score / why / corrections) at the bottom.
    meta_match = re.search(r"^##\s+Self-score\b", body, re.MULTILINE)
    main = body[:meta_match.start()].rstrip() if meta_match else body.rstrip()
    meta = body[meta_match.start():].strip() if meta_match else ""
    # Relabel any "Layer 2 …" title as "Final …" (covers "Layer 2 Analysis",
    # "Layer 2 Deep-Analysis", etc.) — only on the title line, not the body.
    title_match = re.match(r"(##\s+.*)", main)
    title = re.sub(r"Layer\s*2\b", "Final", title_match.group(1)) if title_match else "## Final Analysis"
    rest = main[title_match.end():].strip() if title_match else main
    headings = list(re.finditer(r"^###\s+(.*)$", rest, re.MULTILINE))
    if not headings:
        out = f"{title}\n\n{rest}"
    else:
        # Prefer an explicitly named conclusion; otherwise the agent always
        # synthesizes in the LAST section, so fall back to that.
        concl_idx = next(
            (i for i, h in enumerate(headings)
             if re.search(r"conclusion|synthesis|operational picture|bottom line|overall assessment",
                          h.group(1), re.IGNORECASE)),
            len(headings) - 1,
        )
        start = headings[concl_idx].start()
        end = headings[concl_idx + 1].start() if concl_idx + 1 < len(headings) else len(rest)
        concl_block = rest[start:end].strip()
        concl_body = re.sub(r"^###\s+.*\n?", "", concl_block, count=1).strip()
        support = (rest[:start] + rest[end:]).strip()
        out = f"{title}\n\n## Bottom line\n\n{concl_body}\n\n## Supporting analysis\n\n{support}"
    if meta:
        out += "\n\n" + meta
    return out.strip()


def _read_report(case_dir: Path) -> dict[str, Any]:
    # The final report is the Layer 2 analyst log, written only when Room 3
    # completes via submit_layer2_writeup. Do NOT fall back to the Layer 1
    # writeup — that would surface a "final report" before analysis is done.
    path = case_dir / "layer2_analyst_log.md"
    if not path.is_file():
        return {"available": False, "content": "", "findings": "", "source": ""}
    raw = path.read_text(encoding="utf-8", errors="replace")
    content = _report_for_display(raw)
    return {
        "available": True,
        "content": content,
        "findings": _markdown_section(raw, "Findings") or content,
        "why": _markdown_section(raw, "Why"),
        "corrections": _markdown_section(raw, "Corrections"),
        "source": path.name,
    }


def _read_text(path: Path, limit: int = 12000) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[:limit]


def _plan_steps(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            value = node.value
            payload: Any = None
            if isinstance(value, ast.Dict):
                payload = ast.literal_eval(value)
            elif (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr == "loads"
                and value.args
            ):
                payload = json.loads(ast.literal_eval(value.args[0]))
            if isinstance(payload, dict) and isinstance(payload.get("steps"), list):
                return payload["steps"]
    except (OSError, SyntaxError, ValueError, json.JSONDecodeError):
        return []
    return []


def _unlocked_rooms(hallway: dict[str, Any]) -> list[str]:
    out: list[str] = []
    if hallway.get("promoted_to_room_a_at"):
        out.append("A")
    if hallway.get("promoted_at"):
        out.append("2")
    if hallway.get("promoted_to_room_b_at"):
        out.append("B")
    if hallway.get("promoted_to_room3_at"):
        out.append("3")
    return out


def _to_relative(case_dir: Path, path_str: str) -> str | None:
    try:
        return str(Path(path_str).relative_to(case_dir))
    except (ValueError, TypeError):
        return None


def _evidence_names(hallway: dict[str, Any], case_dir: Path) -> list[str]:
    names = list((hallway.get("r1_checkpoint") or {}).get("non_empty_files") or [])
    if names:
        return [str(name) for name in names]
    manifest = _json(case_dir / "manifest.json", {}) or {}
    files = manifest.get("files") or manifest.get("entries") or []
    return [
        str(row.get("relative_path") or row.get("path") or row.get("name"))
        for row in files
        if isinstance(row, dict)
    ]


def _nonnull(data: dict[str, Any]) -> dict[str, Any]:
    """Drop keys whose value is None so the technical view never shows 'null'."""
    return {key: value for key, value in data.items() if value is not None}


def _event_from_audit(row: dict[str, Any]) -> dict[str, Any]:
    ok = int(row.get("exit_code", 1)) == 0
    tool = str(row.get("tool_name") or row.get("tool_id") or "forensic tool")
    purpose = str(row.get("purpose") or "Examining evidence")
    return {
        "id": str(row.get("audit_id") or ""),
        "ts": str(row.get("ts") or ""),
        "kind": "tool",
        "level": "success" if ok else "warning",
        "title": f"Completed {tool}" if ok else f"{tool} could not complete",
        "detail": purpose if ok else str(row.get("error") or purpose),
        "technical": _nonnull({
            "tool_id": row.get("tool_id"),
            "tool_name": row.get("tool_name"),
            "audit_id": row.get("audit_id"),
            "input": row.get("input_relpath"),
            "exit_code": row.get("exit_code"),
        }),
    }


def _event_from_agent(row: dict[str, Any], index: int) -> dict[str, Any] | None:
    kind = str(row.get("type") or "")
    if kind == "tool":
        name = str(row.get("tool") or "investigation step").replace("_", " ")
        args = row.get("input") or {}
        return {
            "id": f"agent-{index}",
            "ts": str(row.get("ts") or ""),
            "kind": "agent",
            "level": "active",
            "title": name.title(),
            "detail": str(args.get("purpose") or args.get("why") or "The analyst advanced the investigation."),
            "technical": _nonnull({"tool": row.get("tool"), "turn": row.get("turn")}),
        }
    if kind in {"session_start", "session_end", "finalize_error"}:
        return {
            "id": f"agent-{index}",
            "ts": str(row.get("ts") or ""),
            "kind": "system",
            "level": "warning" if kind == "finalize_error" else "info",
            "title": kind.replace("_", " ").title(),
            "detail": str(row.get("error") or "Investigation session state changed."),
            "technical": _nonnull({"turn": row.get("turn")}),
        }
    return None


def case_events(case_dir: Path) -> list[dict[str, Any]]:
    events = [_event_from_audit(row) for row in _jsonl(case_dir / "audit.jsonl")]
    for index, row in enumerate(_jsonl(case_dir / "AGENT_RUN.jsonl")):
        event = _event_from_agent(row, index)
        if event:
            events.append(event)
    return sorted(events, key=lambda row: row.get("ts") or "")


def case_skill_evidence(case_dir: Path) -> dict[str, Any]:
    """Room 3 skill runs, keyed by run_id (CB-skill-…), so the report's skill
    references resolve. Each run links to the tool audit_ids it triggered."""
    out: dict[str, Any] = {}
    for row in _jsonl(case_dir / "layer2_skill_log.jsonl"):
        run_id = row.get("run_id")
        if not run_id:
            continue
        out[str(run_id)] = _nonnull({
            "run_id": run_id,
            "skill_id": row.get("skill_id"),
            "journal_id": row.get("journal_id"),
            "library_slug": row.get("library_slug"),
            "input": row.get("input_relpath"),
            "outcome": row.get("outcome"),
            "exit_code": row.get("exit_code"),
            "purpose": row.get("purpose"),
            "why": row.get("why"),
            "error": row.get("error") or None,
            "audit_ids": list(row.get("audit_ids") or []),
            "plan_step_id": row.get("plan_step_id"),
        })
    return out


def _latest_activity(events: list[dict[str, Any]], room: str, complete: bool) -> dict[str, str]:
    if complete:
        return {"title": "Final report ready", "detail": "Evidence analysis has finished and the report is ready to open."}
    if events:
        latest = events[-1]
        return {"title": latest["title"], "detail": latest["detail"]}
    room_copy = next((item for item in ROOMS if item["id"] == room), ROOMS[0])
    return {"title": room_copy["label"], "detail": room_copy["description"]}


def case_snapshot(case_id: str) -> dict[str, Any]:
    case_dir = find_case_dir(case_id)
    hallway = _json(case_dir / "hallway.json", {}) or {}
    room = str(hallway.get("room") or "1").upper()
    report = _read_report(case_dir)
    layer2_state = _json(case_dir / "layer2_state.json", {}) or {}
    complete = bool(
        layer2_state.get("complete")  # key written by record_layer2_complete
        or layer2_state.get("layer2_complete")  # legacy spelling
        or hallway.get("complete")
        or (report["available"] and room == "3")
    )
    unlocked = _unlocked_rooms(hallway)
    events = case_events(case_dir)
    index = ROOM_INDEX.get(room, 0)
    progress = 100 if complete else round((index / (len(ROOMS) - 1)) * 92)
    evidence = _evidence_names(hallway, case_dir)
    revisits = list(hallway.get("room_revisits") or [])
    audit_rows = _jsonl(case_dir / "audit.jsonl")
    audit_evidence = {
        str(row.get("audit_id")): {
            "audit_id": row.get("audit_id"),
            "timestamp": row.get("ts"),
            "tool_id": row.get("tool_id"),
            "tool_name": row.get("tool_name"),
            "purpose": row.get("purpose"),
            "why": row.get("why"),
            "input": row.get("input_relpath"),
            "input_sha256": row.get("input_sha256"),
            "exit_code": row.get("exit_code"),
            "stdout_preview": row.get("stdout_preview"),
            "error": row.get("error"),
            "scratch_files": [
                r for r in (
                    _to_relative(case_dir, p)
                    for p in (row.get("output_files") or [])
                ) if r
            ],
        }
        for row in audit_rows
        if row.get("audit_id")
    }
    plan_a_md = _read_text(case_dir / "plan_a.md")
    plan_b_md = _read_text(case_dir / "plan_b.md")
    layer1 = _read_text(case_dir / "layer1_analyst_log.md")
    layer2 = report["content"]  # display-formatted (Bottom line first, "Final Analysis")
    seal = _json(case_dir / "seal.json", {}) or {}
    room_outputs = {
        "1": {
            "title": "Raw files received",
            "summary": f"{len(evidence)} file(s) provided for investigation and preserved in the sealed evidence room.",
            "content": "\n".join(evidence) or "Evidence intake details are not available in this record.",
            "artifacts": ["seal.json", "manifest.json", "hallway.json"],
            "data": seal or hallway.get("r1_checkpoint") or {},
        },
        "A": {
            "title": "Evidence extraction plan",
            "summary": f"{len(_plan_steps(case_dir / 'plan_a.py'))} planned extraction step(s), created after observing the provided files.",
            "content": plan_a_md or "The collection plan is not included in this case bundle.",
            "artifacts": ["plan_a.md", "plan_a.py"],
            "data": hallway.get("room_a_checkpoint") or {},
        },
        "2": {
            "title": "Extracted evidence",
            "summary": f"{len(audit_rows)} recorded forensic action(s) with evidence references.",
            "content": layer1 or "Layer 1 findings have not been submitted yet.",
            "artifacts": ["layer1_analyst_log.md", "layer1_tool_log.md", "audit.jsonl"],
            "data": hallway.get("layer1_checkpoint") or {},
        },
        "B": {
            "title": "Evidence analysis plan",
            "summary": f"{len(_plan_steps(case_dir / 'plan_b.py'))} planned analysis step(s).",
            "content": plan_b_md or "The analysis plan is not included in this case bundle.",
            "artifacts": ["plan_b.md", "plan_b.py"],
            "data": hallway.get("room_b_checkpoint") or {},
        },
        "3": {
            "title": "Evidence analysis",
            "summary": "Correlated findings and the completed incident assessment used to prepare the final report.",
            "content": layer2 or "Layer 2 analysis is still in progress.",
            "artifacts": ["layer2_analyst_log.md", "layer2_skill_log.md", "layer2_tool_log.md"],
            "data": layer2_state,
        },
    }
    # Rooms the investigation has not advanced to yet get a clear placeholder
    # instead of "not in this bundle" wording that reads like an error.
    for rid, out in room_outputs.items():
        if ROOM_INDEX.get(rid, 0) > index:
            out["summary"] = "Cold Box has not reached this room yet."
            out["content"] = "This room becomes active once the investigation advances here."
    return {
        "case_id": case_id,
        "room": room,
        "room_index": index,
        "complete": complete,
        "progress": progress,
        "rooms": ROOMS,
        "unlocked_rooms": unlocked,
        "activity": _latest_activity(events, room, complete),
        "evidence": evidence,
        "evidence_count": len(evidence),
        "events": events[-80:],
        "event_count": len(events),
        "audit_count": len(audit_rows),
        "files_produced": sum(
            1
            for path in case_dir.rglob("*")
            if path.is_file() and path.name not in {"hallway.json", "seal.json", "manifest.json"}
        ),
        "audit_evidence": audit_evidence,
        "skill_evidence": case_skill_evidence(case_dir),
        "revisits": revisits,
        "plans": {
            "collection": _plan_steps(case_dir / "plan_a.py"),
            "analysis": _plan_steps(case_dir / "plan_b.py"),
        },
        "report": report,
        "room_outputs": room_outputs,
        "updated_at": str(hallway.get("updated_at") or hallway.get("promoted_to_room3_at") or ""),
        "records_dir": str(case_dir),
    }


def list_cases() -> list[dict[str, Any]]:
    found: set[str] = set()
    for root in records_roots():
        if root.is_dir():
            found.update(
                child.name
                for child in root.iterdir()
                if child.is_dir() and (child / "hallway.json").is_file()
            )
    cases: list[dict[str, Any]] = []
    for case_id in found:
        try:
            snapshot = case_snapshot(case_id)
        except Exception:
            continue
        cases.append({
            "case_id": case_id,
            "room": snapshot["room"],
            "complete": snapshot["complete"],
            "progress": snapshot["progress"],
            "evidence_count": snapshot["evidence_count"],
            "updated_at": snapshot["updated_at"],
        })
    return sorted(cases, key=lambda item: item.get("updated_at") or "", reverse=True)


def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "cold-box-ui",
        "time": datetime.now(timezone.utc).isoformat(),
        "records_roots": [str(path) for path in records_roots()],
    }
