---
name: cb-implementing-ot-network-traffic-analysis-with-nozomi
skill_id: cb-implementing-ot-network-traffic-analysis-with-nozomi
journal_id: CB-SKL-274
description: Cold-box analyst playbook — Implementing Ot Network Traffic Analysis
  With Nozomi. Deploy Nozomi Networks Guardian sensors for passive OT network traffic
  analysis to achieve comprehensive asset visibility, real-time threat detection,
  and vulnerability assessment across industrial control systems without disrupting
  operati
domain: cold-box
subdomain: ot-ics-security
tier: adjacent
case_profiles:
- network_pcap
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- ot-security
- ics
- nozomi
- guardian
- network-monitoring
- asset-visibility
- anomaly-detection
- ndr
cold_box_version: 2
inspired_by: implementing-ot-network-traffic-analysis-with-nozomi
---

# Implementing Ot Network Traffic Analysis With Nozomi (cold-box)

> **Journal ID:** `CB-SKL-274` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-274`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-ot-network-traffic-analysis-with-nozomi")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-ot-network-traffic-analysis-with-nozomi")` → note **`CB-SKL-274`**
2. `log_skill(case_id, journal_id="CB-SKL-274", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-274` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying passive OT network monitoring using Nozomi Networks Guardian sensors
- When requiring asset visibility without active scanning in sensitive ICS environments
- When building a Nozomi-based OT SOC with centralized management via Vantage or CMC
- When integrating OT network monitoring with Fortinet, Splunk, or ServiceNow ecosystems
- When monitoring compliance with IEC 62443 network segmentation policies

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `dd` | `SIFT-034` | no | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `dd` → `SIFT-034`

```json
{
  "tool_id": "SIFT-034",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-274] dd per playbook step",
  "why": "Executing cb-implementing-ot-network-traffic-analysis-with-nozomi \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-274` (`cb-implementing-ot-network-traffic-analysis-with-nozomi`)

- **action:** adopted | step | finding | deferred | completed
- **note:** What you did or concluded under this playbook
- **related_audit_ids:** (optional) CB-… from run_sift_tool
```

Or call MCP: `log_skill(case_id, journal_id="{journal_id}", action="adopted", note="...")`

## Cold-box path translation

When the procedure below uses host paths, translate as follows:

| Procedure path | Cold-box equivalent |
|----------------|---------------------|
| `C:\Evidence\...` / `/cases/...` | `{input_relpath}` on the sealed table (via viewport) |
| `C:\Output\...` / `/analysis/...` | `records/{case_id}/scratch/` (tool stdout/files) |
| Live SIEM / cloud console steps | **Reference only** on cold-box — note capability gap in journal |

Do not copy evidence off the table except into `records/{case_id}/scratch/` via `run_sift_tool`.


## Procedure

## When to Use

- When deploying passive OT network monitoring using Nozomi Networks Guardian sensors
- When requiring asset visibility without active scanning in sensitive ICS environments
- When building a Nozomi-based OT SOC with centralized management via Vantage or CMC
- When integrating OT network monitoring with Fortinet, Splunk, or ServiceNow ecosystems
- When monitoring compliance with IEC 62443 network segmentation policies

**Do not use** for active vulnerability scanning of OT devices (see performing-ot-vulnerability-scanning-safely), for environments standardized on Dragos (see implementing-dragos-platform-for-ot-monitoring), or for IT-only network monitoring.

## Prerequisites

- Nozomi Networks Guardian sensor (hardware, VM, or container)
- Network TAP or SPAN port configured on monitored OT network segments
- Nozomi Vantage (cloud) or Central Management Console for multi-sensor management
- Nozomi Threat Intelligence subscription for updated detection signatures
- Network architecture documentation for sensor placement planning

## Workflow

### Step 1: Deploy Guardian Sensors for Passive Monitoring

```python
#!/usr/bin/env python3
"""Nozomi Guardian Deployment Manager and Alert Analyzer.

Manages Nozomi Guardian sensor deployment validation, asset inventory
extraction, and threat alert analysis for OT environments.
"""

import json
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


class NozomiGuardianManager:
    """Manages Nozomi Networks Guardian for OT monitoring."""

    def __init__(self, guardian_url: str, api_token: str, verify_ssl: bool = False):
        self.guardian_url = guardian_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        })
        self.session.verify = verify_ssl

    def get_nodes(self, node_type: Optional[str] = None) -> List[Dict]:
        """Retrieve discovered network nodes (assets)."""
        params = {}
        if node_type:
            params["type"] = node_type
        resp = self.session.get(f"{self.guardian_url}/api/v1/nodes", params=params)
        resp.raise_for_status()
        return resp.json().get("result", [])

    def get_alerts(self, severity: str = "high", limit: int = 100) -> List[Dict]:
        """Retrieve security alerts."""
        params = {"severity": severity, "limit": limit, "status": "open"}
        resp = self.session.get(f"{self.guardian_url}/api/v1/alerts", params=params)
        resp.raise_for_status()
        return resp.json().get("result", [])

    def get_links(self) -> List[Dict]:
        """Retrieve communication links between nodes."""
        resp = self.session.get(f"{self.guardian_url}/api/v1/links")
        resp.raise_for_status()
        return resp.json().get("result", [])

    def get_vulnerabilities(self) -> List[Dict]:
        """Retrieve detected vulnerabilities."""
        resp = self.session.get(f"{self.guardian_url}/api/v1/vulnerabilities")
        resp.raise_for_status()
        return resp.json().get("result", [])

    def validate_deployment(self):
        """Validate Guardian sensor deployment and coverage."""
        print(f"\n{'='*65}")
        print("NOZOMI GUARDIAN DEPLOYMENT VALIDATION")
        print(f"{'='*65}")
        print(f"Guardian URL: {self.guardian_url}")
        print(f"Validation Time: {datetime.now().isoformat()}")

        # Check system status
        try:
            resp = self.session.get(f"{self.guardian_url}/api/v1/system/status")
            if resp.status_code == 200:
                status = resp.json()
                print(f"\n--- SYSTEM STATUS ---")
                print(f"  Version: {status.get('version', 'N/A')}")
                print(f"  Uptime: {status.get('uptime', 'N/A')}")
                print(f"  Packets Processed: {status.get('packets_processed', 'N/A')}")
                print(f"  Threat Intelligence: {status.get('threat_intelligence_version', 'N/A')}")
        except requests.RequestException as e:
            print(f"  [!] System status unavailable: {e}")

        # Asset discovery summary
        nodes = self.get_nodes()
        print(f"\n--- ASSET DISCOVERY ---")
        print(f"  Total Nodes Discovered: {len(nodes)}")

        type_counts = defaultdict(int)
        vendor_counts = defaultdict(int)
        protocol_set = set()
        for node in nodes:
            type_counts[node.get("type", "unknown")] += 1
            vendor_counts[node.get("vendor", "Unknown")] += 1
            for proto in node.get("protocols", []):
                protocol_set.add(proto)

        print(f"\n  By Type:")
        for ntype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"    {ntype}: {count}")

        print(f"\n  By Vendor:")
        for vendor, count in sorted(vendor_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"    {vendor}: {count}")

        print(f"\n  Protocols Observed: {', '.join(sorted(protocol_set))}")

        # Alert summary
        alerts = self.get_alerts(severity="high")
        print(f"\n--- ALERT SUMMARY ---")
        print(f"  High/Critical Alerts: {len(alerts)}")

        alert_types = defaultdict(int)
        for alert in alerts:
            alert_types[alert.get("type_id", "unknown")] += 1

        for atype, count in sorted(alert_types.items(), key=lambda x: -x[1])[:10]:
            print(f"    {atype}: {count}")

        # Vulnerability summary
        vulns = self.get_vulnerabilities()
        print(f"\n--- VULNERABILITY SUMMARY ---")
        print(f"  Total Vulnerabilities: {len(vulns)}")

        sev_counts = defaultdict(int)
        for vuln in vulns:
            sev_counts[vuln.get("severity", "unknown")] += 1

        for sev in ["critical", "high", "medium", "low"]:
            if sev in sev_counts:
                print(f"    {sev.capitalize()}: {sev_counts[sev]}")

    def analyze_communication_patterns(self):
        """Analyze OT communication patterns for anomalies."""
        links = self.get_links()
        nodes = {n.get("id"): n for n in self.get_nodes()}

        print(f"\n--- COMMUNICATION ANALYSIS ---")
        print(f"  Total Communication Links: {len(links)}")

        # Identify cross-zone communications
        cross_zone = []
        for link in links:
            src_node = nodes.get(link.get("source_id"), {})
            dst_node = nodes.get(link.get("destination_id"), {})
            src_zone = src_node.get("zone", "unknown")
            dst_zone = dst_node.get("zone", "unknown")

            if src_zone != dst_zone and src_zone != "unknown" and dst_zone != "unknown":
                cross_zone.append({
                    "source": src_node.get("label", "Unknown"),
                    "source_zone": src_zone,
                    "destination": dst_node.get("label", "Unknown"),
                    "dest_zone": dst_zone,
                    "protocols": link.get("protocols", []),
                })

        if cross_zone:
            print(f"\n  Cross-Zone Communications: {len(cross_zone)}")
            for comm in cross_zone[:10]:
                print(f"    {comm['source']} ({comm['source_zone']}) -> "
                      f"{comm['destination']} ({comm['dest_zone']}) "
                      f"via {', '.join(comm['protocols'])}")


if __name__ == "__main__":
    manager = NozomiGuardianManager(
        guardian_url="https://nozomi-guardian.plant.local",
        api_token="your-api-token",
    )

    manager.validate_deployment()
    manager.analyze_communication_patterns()
```

## Key Concepts

| Term | Definition |
|------|------------|
| Guardian | Nozomi Networks passive sensor that monitors OT network traffic via SPAN/TAP without generating additional traffic |
| Vantage | Nozomi cloud-based central management platform for aggregating data across multiple Guardian sensors |
| Behavioral Anomaly Detection (BAD) | Nozomi's AI-driven approach to detecting deviations from learned normal OT network behavior |
| Smart Polling | Nozomi's active query feature using native protocols to safely extract additional device details |
| Asset Intelligence | Nozomi's automatic identification and classification of OT/IoT assets from network traffic |
| Threat Intelligence Feed | Nozomi Labs-maintained feed of OT-specific threat indicators, updated based on global honeypot data |

## Output Format

```
NOZOMI GUARDIAN OT MONITORING REPORT
=======================================
Site: [site name]
Date: YYYY-MM-DD

ASSET VISIBILITY:
  Total Assets: [count]
  PLCs: [count] | HMIs: [count] | Switches: [count]
  Protocols: [list]
  Vendors: [top 5]

THREAT DETECTION:
  Critical Alerts: [count]
  High Alerts: [count]
  Top Alert Categories: [list]

VULNERABILITIES:
  Critical: [count]
  High: [count]

NETWORK ANALYSIS:
  Communication Links: [count]
  Cross-Zone Flows: [count]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
