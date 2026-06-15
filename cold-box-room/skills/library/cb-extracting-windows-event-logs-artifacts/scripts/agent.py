#!/usr/bin/env python3
# cold-box skill script — tool calls route through SIFT harness (run_skill_script).
from cold_box_room.skills.skill_runtime import run_cmd, patched_subprocess as subprocess


"""Windows Event Log artifact extraction agent using evtx library for EVTX parsing."""

import argparse
import csv
import json
import logging
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

try:
    from evtx import PyEvtxParser
    HAS_EVTX = True
except ImportError:
    PyEvtxParser = None
    HAS_EVTX = False

CRITICAL_EVENT_IDS = {
    "1102": "Audit Log Cleared",
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4634": "Logoff",
    "4648": "Explicit Credential Logon",
    "4672": "Special Privileges Assigned",
    "4688": "New Process Created",
    "4697": "Service Installed",
    "4698": "Scheduled Task Created",
    "4720": "User Account Created",
    "4724": "Password Reset Attempted",
    "4728": "Member Added to Global Group",
    "4732": "Member Added to Local Group",
    "4756": "Member Added to Universal Group",
    "7045": "New Service Installed (System)",
}

LOGON_TYPES = {
    "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)", "11": "CachedInteractive",
}

SUSPICIOUS_PROCESSES = [
    "mimikatz", "psexec", "procdump", "lazagne", "sharphound",
    "rubeus", "certutil", "powershell -enc", "bitsadmin",
    "wmic shadowcopy delete", "vssadmin delete", "bcdedit /set",
]


def parse_evtx_file(evtx_path: str) -> List[dict]:
    """Parse an EVTX file and return list of event records."""
    if not HAS_EVTX:
        logger.warning("python-evtx not installed — skipping EVTX parse for %s", evtx_path)
        return []
    if not os.path.isfile(evtx_path):
        logger.warning("EVTX file not found: %s", evtx_path)
        return []
    records = []
    try:
        parser = PyEvtxParser(evtx_path)
        for record in parser.records_json():
            try:
                data = json.loads(record["data"])
                event = data.get("Event", {})
                system = event.get("System", {})
                event_id = str(system.get("EventID", ""))
                if isinstance(system.get("EventID"), dict):
                    event_id = str(system["EventID"].get("#text", ""))
                timestamp = system.get("TimeCreated", {}).get("#attributes", {}).get("SystemTime", "")
                event_data = event.get("EventData", {})
                records.append({
                    "event_id": event_id, "timestamp": timestamp,
                    "channel": system.get("Channel", ""),
                    "computer": system.get("Computer", ""),
                    "event_data": event_data if isinstance(event_data, dict) else {},
                })
            except (json.JSONDecodeError, KeyError):
                continue
    except Exception as exc:
        logger.error("Error parsing %s: %s", evtx_path, exc)
    logger.info("Parsed %d records from %s", len(records), evtx_path)
    return records


def filter_critical_events(records: List[dict]) -> Dict[str, List[dict]]:
    """Filter records for critical security event IDs."""
    filtered = defaultdict(list)
    for r in records:
        if r["event_id"] in CRITICAL_EVENT_IDS:
            r["description"] = CRITICAL_EVENT_IDS[r["event_id"]]
            filtered[r["event_id"]].append(r)
    return dict(filtered)


def detect_lateral_movement(records: List[dict]) -> List[dict]:
    """Detect lateral movement indicators from logon events."""
    findings = []
    for r in records:
        if r["event_id"] != "4624":
            continue
        ed = r["event_data"]
        logon_type = str(ed.get("LogonType", ""))
        auth_pkg = str(ed.get("AuthenticationPackageName", ""))
        src_ip = ed.get("IpAddress", "-")
        user = ed.get("TargetUserName", "")
        if logon_type in ("3", "10") and src_ip not in ("-", "::1", "127.0.0.1"):
            findings.append({
                "timestamp": r["timestamp"], "type": "lateral_movement",
                "logon_type": LOGON_TYPES.get(logon_type, logon_type),
                "user": user, "source_ip": src_ip, "auth_package": auth_pkg,
                "pth_indicator": logon_type == "9" and "NTLM" in auth_pkg,
            })
    return findings


def detect_privilege_escalation(records: List[dict]) -> List[dict]:
    """Detect privilege escalation from group membership and special privilege events."""
    findings = []
    escalation_ids = {"4672", "4728", "4732", "4756", "4720"}
    for r in records:
        if r["event_id"] not in escalation_ids:
            continue
        ed = r["event_data"]
        findings.append({
            "timestamp": r["timestamp"], "type": "privilege_escalation",
            "event_id": r["event_id"], "description": CRITICAL_EVENT_IDS.get(r["event_id"], ""),
            "user": ed.get("TargetUserName", ed.get("SubjectUserName", "")),
            "group": ed.get("TargetDomainName", ""),
        })
    return findings


def detect_suspicious_processes(records: List[dict]) -> List[dict]:
    """Detect suspicious process creation events."""
    findings = []
    for r in records:
        if r["event_id"] != "4688":
            continue
        ed = r["event_data"]
        cmd = str(ed.get("CommandLine", ed.get("NewProcessName", ""))).lower()
        process_name = str(ed.get("NewProcessName", "")).lower()
        for pattern in SUSPICIOUS_PROCESSES:
            if pattern in cmd or pattern in process_name:
                findings.append({
                    "timestamp": r["timestamp"], "type": "suspicious_process",
                    "matched_pattern": pattern,
                    "process": ed.get("NewProcessName", ""),
                    "command_line": str(ed.get("CommandLine", ""))[:300],
                    "user": ed.get("SubjectUserName", ""),
                    "parent": ed.get("ParentProcessName", ""),
                })
                break
    return findings


def detect_log_clearing(records: List[dict]) -> List[dict]:
    """Detect audit log clearing events."""
    findings = []
    for r in records:
        if r["event_id"] in ("1102", "104"):
            findings.append({
                "timestamp": r["timestamp"], "type": "log_cleared",
                "event_id": r["event_id"], "channel": r.get("channel", ""),
                "user": r["event_data"].get("SubjectUserName", "SYSTEM"),
            })
    return findings


def detect_persistence(records: List[dict]) -> List[dict]:
    """Detect persistence mechanisms from service and scheduled task events."""
    findings = []
    for r in records:
        if r["event_id"] in ("4697", "7045"):
            ed = r["event_data"]
            findings.append({
                "timestamp": r["timestamp"], "type": "service_install",
                "service_name": ed.get("ServiceName", ""),
                "image_path": ed.get("ImagePath", ed.get("ServiceFileName", "")),
                "start_type": ed.get("StartType", ""),
                "user": ed.get("AccountName", ed.get("SubjectUserName", "")),
            })
        elif r["event_id"] == "4698":
            ed = r["event_data"]
            findings.append({
                "timestamp": r["timestamp"], "type": "scheduled_task",
                "task_name": ed.get("TaskName", ""),
                "user": ed.get("SubjectUserName", ""),
            })
    return findings


def generate_summary(records: List[dict], findings: dict) -> dict:
    """Generate analysis summary statistics."""
    event_counts = Counter(r["event_id"] for r in records)
    top_events = [(eid, count, CRITICAL_EVENT_IDS.get(eid, "Other"))
                  for eid, count in event_counts.most_common(15)]
    return {
        "total_records": len(records),
        "unique_event_ids": len(event_counts),
        "top_events": top_events,
        "lateral_movement_alerts": len(findings.get("lateral_movement", [])),
        "priv_esc_alerts": len(findings.get("privilege_escalation", [])),
        "suspicious_processes": len(findings.get("suspicious_processes", [])),
        "log_clearing": len(findings.get("log_clearing", [])),
        "persistence": len(findings.get("persistence", [])),
    }


def export_timeline_csv(records: List[dict], output_path: str) -> None:
    """Export critical events as a CSV timeline."""
    critical = [r for r in records if r["event_id"] in CRITICAL_EVENT_IDS]
    critical.sort(key=lambda r: r["timestamp"])
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event_id", "description", "computer", "details"])
        for r in critical:
            desc = CRITICAL_EVENT_IDS.get(r["event_id"], "")
            details = json.dumps(r["event_data"], default=str)[:300]
            writer.writerow([r["timestamp"], r["event_id"], desc, r["computer"], details])
    logger.info("Timeline exported: %d events to %s", len(critical), output_path)


def analyze_evtx(evtx_paths: List[str], output_dir: str) -> dict:
    """Run full EVTX analysis across multiple log files."""
    all_records = []
    for path in evtx_paths:
        all_records.extend(parse_evtx_file(path))

    all_records.sort(key=lambda r: r["timestamp"])
    findings = {
        "lateral_movement": detect_lateral_movement(all_records),
        "privilege_escalation": detect_privilege_escalation(all_records),
        "suspicious_processes": detect_suspicious_processes(all_records),
        "log_clearing": detect_log_clearing(all_records),
        "persistence": detect_persistence(all_records),
    }

    report = {
        "analysis_date": datetime.utcnow().isoformat(),
        "files_analyzed": evtx_paths,
        "summary": generate_summary(all_records, findings),
        "findings": findings,
        "critical_events": filter_critical_events(all_records),
    }

    export_timeline_csv(all_records, os.path.join(output_dir, "event_timeline.csv"))
    return report


def audit_legacy_evt_artifact(artifact_path: str, case_dir: str) -> dict:
    """Best-effort audit for Windows XP .Evt binaries when EVTX parser is unavailable."""
    from cold_box_room.skills.script_helpers import audit_artifact_file

    audited = audit_artifact_file(artifact_path, case_dir, binary="file") or audit_artifact_file(
        artifact_path, case_dir, binary="strings"
    )
    return {
        "path": artifact_path,
        "format": "legacy_evt",
        "audited": audited,
        "note": "Windows XP .Evt requires legacy parsers; strings/file audit only.",
    }


def _harness_artifact_paths(image_path: str) -> list[str]:
    """Scratch-local files passed via harness script_args (not the disk image)."""
    paths: list[str] = []
    image_abs = os.path.abspath(image_path)
    if len(sys.argv) > 2:
        for arg in sys.argv[2:]:
            if os.path.isfile(arg) and os.path.abspath(arg) != image_abs:
                paths.append(arg)
    return paths


def analyze_image(image_path, case_dir):
    """Harness entry — EVTX parse when available; legacy .Evt gets strings/file audit."""
    from cold_box_room.skills.script_helpers import (
        audit_disk_image,
        ensure_case_dir,
        write_json_report,
    )

    ensure_case_dir(case_dir)
    audit_disk_image(image_path)
    artifacts = _harness_artifact_paths(image_path)
    payload: dict = {
        "skill": "cb-extracting-windows-event-logs-artifacts",
        "image": image_path,
        "artifacts": artifacts,
        "evtx_available": HAS_EVTX,
    }

    if artifacts:
        legacy_reports = [audit_legacy_evt_artifact(path, case_dir) for path in artifacts]
        payload["legacy_evt_audit"] = legacy_reports
        payload["summary"] = {
            "files_analyzed": artifacts,
            "format": "legacy_evt",
            "evtx_parser": "unavailable" if not HAS_EVTX else "skipped_for_legacy",
            "audited_count": sum(1 for row in legacy_reports if row.get("audited")),
            "recommendation": "Layer 1 icat extracts audited via strings/file; full XP .Evt parse needs evtparse.",
        }
        write_json_report(case_dir, "evtx_report.json", payload)
        print(json.dumps(payload["summary"], indent=2, default=str))
        return payload

    target = image_path
    if str(target).lower().endswith(".evtx") and os.path.isfile(str(target)):
        report = analyze_evtx([str(target)], case_dir)
        payload.update(report)
        write_json_report(case_dir, "evtx_report.json", payload)
        print(json.dumps(report.get("summary", {}), indent=2, default=str))
        return payload

    payload["summary"] = {
        "files_analyzed": [],
        "note": "No EVTX/EVT artifact path supplied — pass extracted log via script_args.",
    }
    write_json_report(case_dir, "evtx_report.json", payload)
    print(json.dumps(payload["summary"], indent=2, default=str))
    return payload


def main():
    parser = argparse.ArgumentParser(description="Windows Event Log Artifact Extraction Agent")
    parser.add_argument("--evtx-dir", default="", help="Directory containing EVTX files")
    parser.add_argument("--evtx-files", nargs="*", default=[], help="Specific EVTX files to parse")
    parser.add_argument("--evt-files", nargs="*", default=[], help="Legacy Windows XP .Evt files")
    parser.add_argument("--output-dir", default=".", help="Output directory")
    parser.add_argument("--output", default="evtx_report.json")
    args = parser.parse_args()

    from cold_box_room.skills.script_helpers import patch_args_from_harness
    patch_args_from_harness(args)

    os.makedirs(args.output_dir, exist_ok=True)
    evtx_paths = list(args.evtx_files)
    evt_paths = list(args.evt_files)
    if args.evtx_dir and os.path.isdir(args.evtx_dir):
        for f in os.listdir(args.evtx_dir):
            lower = f.lower()
            if lower.endswith(".evtx"):
                evtx_paths.append(os.path.join(args.evtx_dir, f))
            elif lower.endswith(".evt"):
                evt_paths.append(os.path.join(args.evtx_dir, f))

    if not evtx_paths and not evt_paths:
        logger.warning("No EVTX/EVT files specified — writing empty summary")
        report = {
            "analysis_date": datetime.utcnow().isoformat(),
            "files_analyzed": [],
            "summary": {"total_records": 0, "note": "No log files specified"},
            "findings": {},
        }
    elif evtx_paths and HAS_EVTX:
        report = analyze_evtx(evtx_paths, args.output_dir)
        if evt_paths:
            report.setdefault("legacy_evt_audit", []).extend(
                audit_legacy_evt_artifact(path, args.output_dir) for path in evt_paths
            )
    else:
        report = {
            "analysis_date": datetime.utcnow().isoformat(),
            "files_analyzed": evt_paths or evtx_paths,
            "summary": {
                "total_records": 0,
                "format": "legacy_evt" if evt_paths else "evtx_unavailable",
                "note": "EVTX parser unavailable or only legacy .Evt supplied",
            },
            "legacy_evt_audit": [
                audit_legacy_evt_artifact(path, args.output_dir) for path in evt_paths
            ],
            "findings": {},
        }

    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report.get("summary", report), indent=2, default=str))

if __name__ == "__main__":
    main()
