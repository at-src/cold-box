"""Finding schema validation — no finding enters a report without audit_ids."""

from __future__ import annotations

from typing import Any

REQUIRED_FIELDS = frozenset({"id", "claim", "audit_ids", "confidence", "status"})
ALLOWED_STATUS = frozenset({"confirmed", "inference", "unresolved"})


class FindingGateError(ValueError):
    """Finding failed the audit_id gate or schema check."""


def validate_finding(finding: dict[str, Any], *, index: int | None = None) -> dict[str, Any]:
    """Validate one finding. Returns normalized finding or raises."""
    prefix = f"finding[{index}]" if index is not None else "finding"
    if not isinstance(finding, dict):
        raise FindingGateError(f"{prefix}: must be an object")

    missing = REQUIRED_FIELDS - finding.keys()
    if missing:
        raise FindingGateError(f"{prefix}: missing fields: {sorted(missing)}")

    audit_ids = finding["audit_ids"]
    if not isinstance(audit_ids, list) or not audit_ids:
        raise FindingGateError(f"{prefix}: audit_ids must be a non-empty list")
    if not all(isinstance(aid, str) and aid.strip() for aid in audit_ids):
        raise FindingGateError(f"{prefix}: audit_ids must be non-empty strings")

    status = finding["status"]
    if status not in ALLOWED_STATUS:
        raise FindingGateError(f"{prefix}: invalid status {status!r}")

    claim = finding["claim"]
    if not isinstance(claim, str) or not claim.strip():
        raise FindingGateError(f"{prefix}: claim must be a non-empty string")

    confidence = finding["confidence"]
    if not isinstance(confidence, (int, float)) or not (0.0 <= float(confidence) <= 1.0):
        raise FindingGateError(f"{prefix}: confidence must be between 0 and 1")

    finding_id = finding["id"]
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise FindingGateError(f"{prefix}: id must be a non-empty string")

    normalized = {
        "id": finding_id,
        "claim": claim.strip(),
        "audit_ids": [aid.strip() for aid in audit_ids],
        "confidence": float(confidence),
        "status": status,
    }
    if "tags" in finding and isinstance(finding["tags"], list):
        normalized["tags"] = finding["tags"]
    return normalized


def validate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate all findings for report finalization."""
    if not findings:
        raise FindingGateError("findings list is empty")
    return [validate_finding(item, index=i) for i, item in enumerate(findings)]
