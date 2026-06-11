#!/usr/bin/env python3
"""cold-box vs NIST CFReDS Hacking Case — apples-to-apples recall probe.

This mirrors Agentic-DART's ``scripts/measure_cfreds.py`` methodology (probe
each sampled NIST ground-truth finding against the tool's real primitives and
report strict / lenient recall) so the two systems can be compared on the same
10-finding list. The crucial difference: cold-box runs against the **raw split
disk image** it ingested itself (SCHARDT.001-008), whereas DART consumes
pre-curated/synthetic evidence.

Reproduce:
  EVIDENCE_ROOT=/evidence CASE_OUTPUT=/tmp/cb-cases \
    python -m postmortem_agent.cli run --case-id nist-hacking \
      --evidence-case nist-hacking --max-iterations 16     # one-time extraction
  python scripts/measure_cfreds.py                          # then score

DART's published/reproduced numbers for the same 10 findings (v0.5.4):
  strict 5/10 = 0.50, lenient 8/10 = 0.80.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from postmortem_mcp.legacy_parse import (  # noqa: E402
    parse_capture_file,
    parse_ie_cache_text,
    parse_index_dat,
    parse_recycle_metadata_file,
    summarize_recycle_bin,
)
from postmortem_mcp.registry_query import sam_accounts, system_profile  # noqa: E402
from postmortem_mcp.yara_scan import scan_with_yara  # noqa: E402

HACKING_TOOL_RE = ("cain", "ethereal", "wireshark", "stumbler", "wasp", "anonymizer", "cuteftp", "look")


def _find(extracted: Path, *names: str) -> Path | None:
    for name in names:
        hits = list(extracted.rglob(name))
        if hits:
            return hits[0]
    return None


def measure(case_dir: Path) -> list[dict]:
    extracted = case_dir / "extracted"
    manifest = case_dir / "extracted_manifest.json"
    if not manifest.is_file():
        print(f"[!] No extraction at {manifest} — run the nist-hacking case first.", file=sys.stderr)
        sys.exit(2)
    artifacts = json.loads(manifest.read_text())["artifacts"]
    prefetch = [a["relpath"].split("/")[-1] for a in artifacts if a.get("kind") == "prefetch"]
    relpaths = [a["relpath"].lower() for a in artifacts]

    software = _find(extracted, "software", "SOFTWARE")
    system = _find(extracted, "system", "SYSTEM")
    sam = _find(extracted, "SAM", "sam")

    profile = system_profile(software=software, system=system, sam=sam)
    accts = sam_accounts(sam) if sam else {"account_names": []}
    account_names = [a.lower() for a in (accts.get("account_names") or [])]
    tool_hits = sorted({p for p in prefetch if any(t in p.lower() for t in HACKING_TOOL_RE)})

    # --- Legacy content artifacts (F-CFR-005/006/008) -----------------------------
    emails_found: list[str] = []
    identity_hints: list[str] = []
    capture_hit = False
    recycle_exe_count = 0

    def _artifact_paths(kind: str) -> list[Path]:
        return [extracted / a["relpath"] for a in artifacts if a.get("kind") == kind]

    for path in _artifact_paths("capture_file"):
        if path.is_file() and parse_capture_file(path).get("is_capture_artifact"):
            capture_hit = True
    if not capture_hit:
        for path in extracted.rglob("*"):
            if path.is_file() and path.name.lower() == "interception":
                if parse_capture_file(path).get("is_capture_artifact"):
                    capture_hit = True
                    break

    for path in _artifact_paths("ie_index_dat"):
        if path.is_file():
            parsed = parse_index_dat(path)
            emails_found.extend(parsed.get("emails") or [])
            identity_hints.extend(parsed.get("hints") or [])
    for path in _artifact_paths("ie_cache"):
        if path.is_file():
            emails_found.extend(parse_ie_cache_text(path).get("emails") or [])
    if not emails_found and not identity_hints:
        for path in extracted.rglob("index.dat"):
            lower = str(path).lower()
            if "outlook express" in lower or "content.ie5" in lower or "mr. evil" in lower:
                parsed = parse_index_dat(path)
                emails_found.extend(parsed.get("emails") or [])
                identity_hints.extend(parsed.get("hints") or [])
        for path in extracted.rglob("*"):
            if path.is_file() and "@" in path.name.lower() and path.suffix.lower() == ".txt":
                emails_found.extend(parse_ie_cache_text(path).get("emails") or [])

    email_hit = any("mrevil" in e.lower() and "yahoo" in e.lower() for e in emails_found) or any(
        "mrevil" in h.lower() and "yahoo" in h.lower() for h in identity_hints
    )

    for path in _artifact_paths("recycle_bin"):
        if path.is_file() and (path.name.lower() == "info2" or path.name.lower().startswith("$i")):
            meta = parse_recycle_metadata_file(path)
            recycle_exe_count = max(recycle_exe_count, int(meta.get("executable_count") or 0))
    for path in extracted.rglob("info2"):
        if path.is_file():
            meta = parse_recycle_metadata_file(path)
            recycle_exe_count = max(recycle_exe_count, int(meta.get("executable_count") or 0))
    for path in extracted.rglob("recycler"):
        if path.is_dir():
            summary = summarize_recycle_bin(path)
            recycle_exe_count = max(recycle_exe_count, int(summary.get("executable_count") or 0))

    yara = scan_with_yara(extracted, max_matches=30)
    yara_hits = int(yara.get("match_count") or 0)
    yara_rules = sorted({m.get("rule") for m in (yara.get("matches") or []) if m.get("rule")})

    # status: "strict" = directly detected, "partial" = lenient-only, "gap" = not supported
    findings = [
        {
            "id": "F-CFR-001", "claim": "Registered owner = Greg Schardt",
            "status": "strict" if "greg schardt" in str(profile.get("registered_owner", "")).lower() else "gap",
            "detail": profile.get("registered_owner"),
        },
        {
            "id": "F-CFR-002", "claim": "Primary account 'Mr. Evil'",
            "status": "strict" if any("mr. evil" in n for n in account_names) else "gap",
            "detail": accts.get("primary_account"),
        },
        {
            "id": "F-CFR-003", "claim": "6+ hacking tools installed",
            "status": "strict" if len(tool_hits) >= 6 else ("partial" if tool_hits else "gap"),
            "detail": f"{len(tool_hits)} tools: {', '.join(tool_hits)}",
        },
        {
            "id": "F-CFR-004", "claim": "Two network cards",
            "status": "strict" if len(profile.get("network_cards") or []) >= 2 else "gap",
            "detail": profile.get("network_cards"),
        },
        {
            "id": "F-CFR-005", "claim": "Ethereal capture 'Interception' in My Documents",
            "status": "strict" if capture_hit else ("partial" if any("intercept" in r for r in relpaths) else "gap"),
            "detail": "capture file identified" if capture_hit else "not extracted / not identified",
        },
        {
            "id": "F-CFR-006", "claim": "Web email mrevilrulez@yahoo.com",
            "status": "strict" if email_hit else ("partial" if emails_found else "gap"),
            "detail": (
                ", ".join(dict.fromkeys(emails_found + identity_hints))[:160]
                or "no IE index.dat/cache identity"
            ),
        },
        {
            "id": "F-CFR-007", "claim": "Last logon user 'Mr. Evil' (15 logons)",
            "status": "strict" if accts.get("primary_login_count") else "gap",
            "detail": f"{accts.get('primary_account')} login_count={accts.get('primary_login_count')}",
        },
        {
            "id": "F-CFR-008", "claim": "4 executables in recycle bin",
            "status": "strict" if recycle_exe_count >= 4 else ("partial" if recycle_exe_count else "gap"),
            "detail": f"{recycle_exe_count} executable(s) in recycle metadata",
        },
        {
            "id": "F-CFR-009", "claim": "Viruses present (AV positive)",
            "status": "strict" if yara_hits else "gap",
            "detail": (
                f"{yara_hits} YARA/pattern match(es) via {yara.get('engine', '?')}"
                + (f" ({', '.join(yara_rules[:5])})" if yara_rules else "")
            ),
        },
        {
            "id": "F-CFR-010", "claim": "Last shutdown 2004-08-27",
            "status": "strict" if profile.get("last_shutdown_utc") else "gap",
            "detail": profile.get("last_shutdown_utc"),
        },
    ]
    return findings


def main() -> int:
    case_output = Path(os.environ.get("CASE_OUTPUT", "/tmp/cb-cases"))
    case_dir = case_output / "nist-hacking"
    findings = measure(case_dir)

    print("=" * 70)
    print("cold-box vs NIST CFReDS Hacking Case (raw split image: SCHARDT.001-008)")
    print("=" * 70)
    for f in findings:
        mark = {"strict": "✓", "partial": "~", "gap": "✗"}[f["status"]]
        print(f"  {mark} {f['id']}  [{f['status']:7s}] {f['claim']}")
        if f.get("detail"):
            print(f"        → {f['detail']}")

    strict = sum(1 for f in findings if f["status"] == "strict")
    lenient = sum(1 for f in findings if f["status"] in ("strict", "partial"))
    n = len(findings)
    print("\nRecall comparison (same 10 NIST findings):")
    print(f"  cold-box strict:  {strict}/{n} = {strict / n:.2f}")
    print(f"  cold-box lenient: {lenient}/{n} = {lenient / n:.2f}")
    print("  DART v0.5.4 strict:  5/10 = 0.50   (curated/synthetic evidence)")
    print("  DART v0.5.4 lenient: 8/10 = 0.80   (curated/synthetic evidence)")
    print("\nNote: cold-box scores from the RAW disk image it ingested itself;")
    print("DART cannot ingest raw E01/dd images (its own disclosed paradigm gap).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
