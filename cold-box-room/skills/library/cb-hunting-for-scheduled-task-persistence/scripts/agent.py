#!/usr/bin/env python3
# cold-box skill script — tool calls route through SIFT harness (run_skill_script).
from cold_box_room.skills.skill_runtime import run_cmd, patched_subprocess as subprocess


"""Agent for hunting scheduled task persistence mechanisms (T1053.005)."""

import json
import argparse
import re
import csv
from io import StringIO
from datetime import datetime

SUSPICIOUS_TASK_PATTERNS = [
    r"powershell.*-enc", r"powershell.*downloadstring", r"powershell.*iex",
    r"cmd\.exe\s+/c", r"mshta\.exe", r"rundll32\.exe", r"regsvr32\.exe",
    r"certutil.*-decode", r"bitsadmin.*transfer",
    r"wscript\.exe", r"cscript\.exe",
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\local\\temp",
    r"\\users\\public\\", r"\\programdata\\",
    r"base64", r"http://", r"https://.*\.exe",
]

LEGITIMATE_TASK_PREFIXES = [
    r"\\Microsoft\\", r"\\Adobe\\", r"\\Google\\", r"\\Apple\\",
    r"\\Mozilla\\", r"\\Intel\\", r"\\NVIDIA\\",
]


def enumerate_tasks():
    """Enumerate all scheduled tasks and flag suspicious ones."""
    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True, text=True, timeout=60
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"error": str(e)}
    findings = []
    reader = csv.DictReader(StringIO(proc.stdout))
    for row in reader:
        task_name = row.get("TaskName", "")
        action = row.get("Task To Run", "")
        author = row.get("Author", "")
        schedule = row.get("Schedule Type", "")
        status = row.get("Status", "")
        is_legit = any(re.search(p, task_name, re.I) for p in LEGITIMATE_TASK_PREFIXES)
        is_suspicious = any(re.search(p, action, re.I) for p in SUSPICIOUS_TASK_PATTERNS)
        risk = "high" if is_suspicious else ("low" if is_legit else "medium")
        findings.append({
            "task_name": task_name,
            "action": action[:500],
            "author": author,
            "schedule": schedule,
            "status": status,
            "last_run": row.get("Last Run Time", ""),
            "next_run": row.get("Next Run Time", ""),
            "run_as_user": row.get("Run As User", ""),
            "risk": risk,
            "suspicious_match": is_suspicious,
        })
    suspicious = [f for f in findings if f["risk"] in ("high", "medium")]
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "total_tasks": len(findings),
        "high_risk": sum(1 for f in findings if f["risk"] == "high"),
        "medium_risk": sum(1 for f in findings if f["risk"] == "medium"),
        "suspicious_tasks": [f for f in findings if f["suspicious_match"]],
        "non_vendor_tasks": [f for f in findings if f["risk"] == "medium"],
    }


def scan_event_log_4698(evtx_file):
    """Parse Security EVTX for Event ID 4698 (Scheduled Task Created)."""
    try:
        import Evtx.Evtx as evtx_lib
    except ImportError:
        return {"error": "python-evtx not installed"}
    findings = []
    with evtx_lib.Evtx(evtx_file) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID>4698</EventID>" not in xml:
                continue
            suspicious = any(re.search(p, xml, re.I) for p in SUSPICIOUS_TASK_PATTERNS)
            findings.append({
                "record_id": record.record_num(),
                "suspicious": suspicious,
                "xml_snippet": xml[:1000],
            })
    return {
        "file": evtx_file,
        "task_creation_events": len(findings),
        "suspicious_events": sum(1 for f in findings if f["suspicious"]),
        "findings": findings[:200],
    }


def export_task_xml(task_name):
    """Export a specific scheduled task's XML configuration for analysis."""
    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/tn", task_name, "/xml"],
            capture_output=True, text=True, timeout=10
        )
        if proc.returncode == 0:
            return {"task_name": task_name, "xml": proc.stdout}
        return {"error": proc.stderr.strip()}
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Hunt for scheduled task persistence")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("enumerate", help="Enumerate and risk-score scheduled tasks")
    e = sub.add_parser("events", help="Scan Security EVTX for task creation events")
    e.add_argument("--evtx-file", required=False)
    x = sub.add_parser("export", help="Export task XML for analysis")
    x.add_argument("--task-name", required=False)
    args = parser.parse_args()
    from cold_box_room.skills.script_helpers import patch_args_from_harness
    patch_args_from_harness(args)

    if args.command == "enumerate":
        result = enumerate_tasks()
    elif args.command == "events":
        result = scan_event_log_4698(args.evtx_file)
    elif args.command == "export":
        result = export_task_xml(args.task_name)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))



# cold-box harness entry
def analyze_image(image_path, case_dir):
    from cold_box_room.skills.script_helpers import run_default_analyze_image

    return run_default_analyze_image(
        image_path,
        case_dir,
        skill_slug='cb-hunting-for-scheduled-task-persistence',
        main_fn=main,
    )

if __name__ == "__main__":
    main()
