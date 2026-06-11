"""Score agent findings against ground-truth JSON."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class MatchedFinding:
    expected_id: str
    finding_id: str
    claim: str
    match_reason: str


@dataclass
class ScoreReport:
    case_id: str
    recall: float
    precision: float
    required_recall: float
    matched: list[MatchedFinding] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    extra_findings: list[str] = field(default_factory=list)
    finding_count: int = 0
    required_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_ground_truth(path: Path | str) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if "expected_findings" not in payload:
        raise ValueError(f"ground truth missing expected_findings: {path}")
    return payload


def _finding_blob(finding: dict[str, Any]) -> str:
    tags = finding.get("tags") or []
    tag_text = " ".join(str(t) for t in tags)
    return f"{finding.get('claim', '')} {tag_text}".lower()


def _matches_expected(
    finding: dict[str, Any],
    expected: dict[str, Any],
    *,
    self_corrected: bool,
) -> str | None:
    blob = _finding_blob(finding)
    if expected.get("requires_self_correction") and self_corrected:
        return "self_corrected"
    rule_tags = expected.get("rule_tags") or []
    for tag in rule_tags:
        if tag.lower() in blob:
            return f"rule tag {tag}"
        tags = finding.get("tags") or []
        if any(str(t).upper() == tag.upper() for t in tags):
            return f"tag {tag}"
    keywords = expected.get("keywords") or []
    for keyword in keywords:
        if str(keyword).lower() in blob:
            return f"keyword {keyword!r}"
    return None


def score_findings(
    findings: list[dict[str, Any]],
    ground_truth: dict[str, Any],
    *,
    self_corrected: bool = False,
    confirmed_only: bool = True,
) -> ScoreReport:
    """Return recall/precision against expected_findings entries."""
    expected_list = ground_truth.get("expected_findings") or []
    case_id = str(ground_truth.get("case_id", "unknown"))

    pool = [
        f
        for f in findings
        if not confirmed_only or f.get("status") in {"confirmed", "inference"}
    ]

    matched: list[MatchedFinding] = []
    used_findings: set[str] = set()
    missed: list[str] = []

    def _match_expected(expected: dict[str, Any]) -> None:
        expected_id = str(expected.get("id", "?"))
        for finding in pool:
            fid = str(finding.get("id", ""))
            if fid in used_findings:
                continue
            reason = _matches_expected(finding, expected, self_corrected=self_corrected)
            if reason:
                matched.append(
                    MatchedFinding(
                        expected_id=expected_id,
                        finding_id=fid,
                        claim=str(finding.get("claim", ""))[:200],
                        match_reason=reason,
                    )
                )
                used_findings.add(fid)
                return
        if expected.get("required", True):
            missed.append(expected_id)

    required_expected = [e for e in expected_list if e.get("required", True)]
    optional_expected = [e for e in expected_list if not e.get("required", True)]
    for expected in required_expected:
        _match_expected(expected)
    for expected in optional_expected:
        _match_expected(expected)

    required = [e for e in expected_list if e.get("required", True)]
    required_hits = sum(1 for m in matched if m.expected_id in {e["id"] for e in required})
    required_count = len(required)
    required_recall = required_hits / required_count if required_count else 1.0

    expected_ids = {str(e["id"]) for e in expected_list}
    matched_expected = {m.expected_id for m in matched}
    recall = len(matched_expected & expected_ids) / len(expected_ids) if expected_ids else 1.0

    extra = [
        str(f.get("id", "?"))
        for f in pool
        if str(f.get("id", "")) not in used_findings
    ]
    precision = len(matched) / len(pool) if pool else 0.0

    return ScoreReport(
        case_id=case_id,
        recall=round(recall, 3),
        precision=round(precision, 3),
        required_recall=round(required_recall, 3),
        matched=matched,
        missed=missed,
        extra_findings=extra,
        finding_count=len(pool),
        required_count=required_count,
    )


def score_from_output_dir(
    output_dir: Path | str,
    ground_truth_path: Path | str,
    *,
    self_corrected: bool | None = None,
) -> ScoreReport:
    out = Path(output_dir)
    findings_path = out / "findings.json"
    if not findings_path.is_file():
        raise FileNotFoundError(f"findings.json not found under {out}")
    payload = json.loads(findings_path.read_text(encoding="utf-8"))
    findings = payload.get("findings") or payload
    gt = load_ground_truth(ground_truth_path)

    if self_corrected is None:
        progress = out / "progress.jsonl"
        self_corrected = False
        if progress.is_file():
            self_corrected = "self-correction" in progress.read_text(encoding="utf-8").lower()

    return score_findings(findings, gt, self_corrected=self_corrected)
