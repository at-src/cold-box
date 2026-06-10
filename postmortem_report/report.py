"""Build markdown and JSON investigation reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from postmortem_audit import verify_chain
from postmortem_report.gate import validate_findings


def load_progress_entries(progress_path: Path) -> list[dict[str, Any]]:
    if not progress_path.exists():
        return []
    entries = []
    for line in progress_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            entries.append(json.loads(line))
    return entries


def load_findings(findings_path: Path) -> list[dict[str, Any]]:
    payload = json.loads(findings_path.read_text(encoding="utf-8"))
    findings = payload.get("findings", payload)
    if not isinstance(findings, list):
        raise ValueError("findings.json must contain a findings list")
    return validate_findings(findings)


def build_json_report(
    *,
    case_id: str,
    findings: list[dict[str, Any]],
    progress: list[dict[str, Any]],
    audit_path: Path,
) -> dict[str, Any]:
    audit_ok, audit_message = verify_chain(audit_path) if audit_path.exists() else (False, "missing")
    confirmed = [f for f in findings if f["status"] == "confirmed"]
    inference = [f for f in findings if f["status"] == "inference"]
    unresolved = [f for f in findings if f["status"] == "unresolved"]
    last = progress[-1] if progress else {}

    return {
        "case_id": case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": _executive_summary(last, confirmed, unresolved),
        "hypothesis": last.get("hypothesis", ""),
        "confidence": last.get("confidence"),
        "timeline": [
            {
                "iteration": entry.get("iteration"),
                "ts": entry.get("ts"),
                "phase": entry.get("phase"),
                "notes": entry.get("notes"),
            }
            for entry in progress
        ],
        "confirmed": confirmed,
        "inference": inference,
        "unresolved": unresolved,
        "audit": {
            "path": str(audit_path),
            "verified": audit_ok,
            "message": audit_message,
        },
    }


def build_markdown_report(report: dict[str, Any], *, incident_markdown: str | None = None) -> str:
    lines = [
        "# cold-box Investigation Report",
        "",
        f"**Case:** `{report['case_id']}`  ",
        f"**Generated:** {report['generated_at']}",
        "",
        "## Executive Summary",
        "",
        report["executive_summary"],
        "",
    ]

    if incident_markdown and incident_markdown.strip():
        lines.extend([incident_markdown.strip(), ""])

    lines.extend(["## Investigation Timeline", ""])

    if not report["timeline"]:
        lines.append("_No progress entries._")
    else:
        for entry in report["timeline"]:
            lines.append(
                f"- **i{entry['iteration']}** `{entry['phase']}` ({entry['ts']}): {entry['notes']}"
            )

    lines.extend(["", "## Confirmed Findings", ""])
    lines.extend(_format_findings(report["confirmed"], empty="No confirmed findings."))

    lines.extend(["", "## Inference", ""])
    lines.extend(_format_findings(report["inference"], empty="No inference-only findings."))

    lines.extend(["", "## Unresolved", ""])
    lines.extend(_format_findings(report["unresolved"], empty="No unresolved items."))

    audit = report["audit"]
    lines.extend(
        [
            "",
            "## Audit Trail",
            "",
            f"- Log: `{audit['path']}`",
            f"- Chain verified: **{audit['verified']}**",
            f"- {audit['message']}",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(case_output_dir: Path, *, case_id: str) -> dict[str, Any]:
    """Validate findings and write report.json + report.md."""
    findings_path = case_output_dir / "findings.json"
    progress_path = case_output_dir / "progress.jsonl"
    audit_path = case_output_dir / "audit.jsonl"

    findings = load_findings(findings_path)
    progress = load_progress_entries(progress_path)
    report = build_json_report(
        case_id=case_id,
        findings=findings,
        progress=progress,
        audit_path=audit_path,
    )

    narrative_path = case_output_dir / "narrative.md"
    incident_markdown = (
        narrative_path.read_text(encoding="utf-8") if narrative_path.exists() else None
    )

    (case_output_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    (case_output_dir / "report.md").write_text(
        build_markdown_report(report, incident_markdown=incident_markdown) + "\n",
        encoding="utf-8",
    )
    return report


def _executive_summary(
    last_progress: dict[str, Any],
    confirmed: list[dict[str, Any]],
    unresolved: list[dict[str, Any]],
) -> str:
    hypothesis = last_progress.get("hypothesis", "No hypothesis recorded.")
    confidence = last_progress.get("confidence")
    parts = [hypothesis]
    if confidence is not None:
        parts.append(f"Final confidence: {confidence:.2f}.")
    parts.append(f"{len(confirmed)} confirmed finding(s), {len(unresolved)} unresolved item(s).")
    return " ".join(parts)


def _format_findings(findings: list[dict[str, Any]], *, empty: str) -> list[str]:
    if not findings:
        return [empty]
    lines: list[str] = []
    for finding in findings:
        aids = ", ".join(f"`{aid}`" for aid in finding["audit_ids"])
        title = finding.get("title")
        header = f"{finding['id']} — {title}" if title else finding["id"]
        meta = []
        if finding.get("severity"):
            meta.append(f"severity: {finding['severity']}")
        if finding.get("mitre"):
            meta.append("MITRE: " + ", ".join(finding["mitre"]))
        meta.append(f"confidence {finding['confidence']:.2f}")
        lines.append(
            f"- **{header}** ({finding['status']}; {'; '.join(meta)})  \n"
            f"  {finding['claim']}  \n"
            f"  _audit_ids:_ {aids}"
        )
    return lines
