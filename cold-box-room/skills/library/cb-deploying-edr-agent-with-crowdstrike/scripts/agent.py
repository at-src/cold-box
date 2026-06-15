#!/usr/bin/env python3
# cold-box skill script — tool calls route through SIFT harness (run_skill_script).
from cold_box_room.skills.skill_runtime import run_cmd, patched_subprocess as subprocess


"""CrowdStrike EDR deployment and monitoring agent using FalconPy."""

import json
import sys
import argparse
from datetime import datetime

try:
    from falconpy import Hosts, Detections

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False


def list_hosts(client_id, client_secret, filter_query=None):
    """List managed hosts with sensor details."""
    hosts = Hosts(client_id=client_id, client_secret=client_secret)
    params = {"limit": 100}
    if filter_query:
        params["filter"] = filter_query
    id_resp = hosts.query_devices_by_filter(**params)
    if id_resp["status_code"] != 200:
        return []
    device_ids = id_resp["body"]["resources"]
    if not device_ids:
        return []
    detail_resp = hosts.get_device_details(ids=device_ids)
    results = []
    for device in detail_resp["body"].get("resources", []):
        results.append({
            "hostname": device.get("hostname", ""),
            "device_id": device.get("device_id", ""),
            "platform": device.get("platform_name", ""),
            "os_version": device.get("os_version", ""),
            "sensor_version": device.get("agent_version", ""),
            "status": device.get("status", ""),
            "last_seen": device.get("last_seen", ""),
        })
    return results


def get_detections(client_id, client_secret, severity=None):
    """Retrieve recent detections."""
    detections = Detections(client_id=client_id, client_secret=client_secret)
    params = {"limit": 50, "sort": "last_behavior|desc"}
    if severity:
        params["filter"] = f"max_severity_displayname:'{severity}'"
    id_resp = detections.query_detects(**params)
    if id_resp["status_code"] != 200:
        return []
    detect_ids = id_resp["body"]["resources"]
    if not detect_ids:
        return []
    detail_resp = detections.get_detect_summaries(body={"ids": detect_ids})
    results = []
    for det in detail_resp["body"].get("resources", []):
        results.append({
            "detection_id": det.get("detection_id", ""),
            "hostname": det.get("device", {}).get("hostname", ""),
            "severity": det.get("max_severity_displayname", ""),
            "tactic": det.get("behaviors", [{}])[0].get("tactic", "") if det.get("behaviors") else "",
            "technique": det.get("behaviors", [{}])[0].get("technique", "") if det.get("behaviors") else "",
            "status": det.get("status", ""),
            "timestamp": det.get("last_behavior", ""),
        })
    return results


def check_sensor_versions(hosts_data):
    """Audit sensor version compliance across fleet."""
    versions = {}
    for host in hosts_data:
        ver = host.get("sensor_version", "unknown")
        versions[ver] = versions.get(ver, 0) + 1
    return {"version_distribution": versions, "total_hosts": len(hosts_data)}


def run_audit(client_id, client_secret):
    """Execute CrowdStrike EDR audit."""
    if not HAS_FALCONPY:
        return {
            "skipped": True,
            "reason": "crowdstrike-falconpy not installed; API credentials required for live audit",
            "hosts": 0,
            "versions": {},
            "detections": [],
        }
    print(f"\n{'='*60}")
    print(f"  CROWDSTRIKE EDR DEPLOYMENT AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    hosts_data = list_hosts(client_id, client_secret)
    print(f"--- MANAGED HOSTS ({len(hosts_data)}) ---")
    for h in hosts_data[:10]:
        print(f"  {h['hostname']}: {h['platform']} v{h['sensor_version']} ({h['status']})")

    versions = check_sensor_versions(hosts_data)
    print(f"\n--- SENSOR VERSIONS ---")
    for ver, count in sorted(versions["version_distribution"].items()):
        print(f"  {ver}: {count} hosts")

    detections = get_detections(client_id, client_secret)
    print(f"\n--- RECENT DETECTIONS ({len(detections)}) ---")
    for d in detections[:10]:
        print(f"  [{d['severity']}] {d['hostname']}: {d['tactic']} / {d['technique']}")

    return {"hosts": len(hosts_data), "versions": versions, "detections": detections}


def main():
    parser = argparse.ArgumentParser(description="CrowdStrike EDR Agent")
    parser.add_argument("--client-id", required=False, help="CrowdStrike API client ID")
    parser.add_argument("--client-secret", required=False, help="CrowdStrike API client secret")
    parser.add_argument("--audit", action="store_true", help="Run full audit")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    from cold_box_room.skills.script_helpers import patch_args_from_harness
    patch_args_from_harness(args)

    if args.audit:
        report = run_audit(args.client_id, args.client_secret)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n[+] Report saved to {args.output}")
    else:
        parser.print_help()



# cold-box harness entry
def analyze_image(image_path, case_dir):
    from cold_box_room.skills.script_helpers import ensure_case_dir, audit_disk_image, write_json_report

    ensure_case_dir(case_dir)
    audit_disk_image(image_path)
    report = {
        "skill": "cb-deploying-edr-agent-with-crowdstrike",
        "image": image_path,
        "falconpy_available": HAS_FALCONPY,
        "note": "CrowdStrike API audit requires credentials; disk image audited only",
        "audit": {
            "skipped": True,
            "reason": "Harness run — provide --client-id/--client-secret for live Falcon API audit",
        },
    }
    write_json_report(case_dir, "harness_report.json", report)
    return report

if __name__ == "__main__":
    main()
