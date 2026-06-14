---
name: cb-implementing-soar-automation-with-phantom
skill_id: cb-implementing-soar-automation-with-phantom
journal_id: CB-SKL-061
description: Cold-box analyst playbook — Implementing Soar Automation With Phantom.
  Implements Security Orchestration, Automation, and Response (SOAR) workflows using
  Splunk SOAR (formerly Phantom) to automate alert triage, IOC enrichment, containment
  actions, and incident response playbooks. Use when SOC teams need to red
domain: cold-box
subdomain: soc-operations
tier: core
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- soc
- soar
- phantom
- splunk-soar
- automation
- playbook
- orchestration
- incident-response
cold_box_version: 2
inspired_by: implementing-soar-automation-with-phantom
---

# Implementing Soar Automation With Phantom (cold-box)

> **Journal ID:** `CB-SKL-061` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-061`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-soar-automation-with-phantom")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-soar-automation-with-phantom")` → note **`CB-SKL-061`**
2. `log_skill(case_id, journal_id="CB-SKL-061", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-061` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- SOC teams need to automate repetitive triage and enrichment tasks for high-volume alerts
- Manual response times exceed SLA requirements and automation can reduce MTTR
- Multiple security tools (SIEM, EDR, firewall, TIP) need orchestrated response actions
- Playbook standardization is required to ensure consistent analyst response across shifts

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `handle` | `SIFT-178` | no | no |
| `sort` | `SIFT-020` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `handle` → `SIFT-178`

```json
{
  "tool_id": "SIFT-178",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-061] handle per playbook step",
  "why": "Executing cb-implementing-soar-automation-with-phantom \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-061] sort per playbook step",
  "why": "Executing cb-implementing-soar-automation-with-phantom \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-061] file per playbook step",
  "why": "Executing cb-implementing-soar-automation-with-phantom \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-061` (`cb-implementing-soar-automation-with-phantom`)

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

Use this skill when:
- SOC teams need to automate repetitive triage and enrichment tasks for high-volume alerts
- Manual response times exceed SLA requirements and automation can reduce MTTR
- Multiple security tools (SIEM, EDR, firewall, TIP) need orchestrated response actions
- Playbook standardization is required to ensure consistent analyst response across shifts

**Do not use** for fully autonomous containment without human approval gates — always include analyst decision points for high-impact actions like account disabling or host isolation.

## Prerequisites

- Splunk SOAR (Phantom) 6.x+ deployed with web interface access
- App connectors configured: VirusTotal, CrowdStrike, ServiceNow, Active Directory, Splunk ES
- Splunk ES integration for ingesting notable events as SOAR events
- API credentials for each integrated tool stored in SOAR asset configuration
- Python knowledge for custom playbook actions

## Workflow

### Step 1: Configure Asset Connections

Set up integrations with security tools via SOAR Apps:

**VirusTotal Asset Configuration:**
```json
{
  "app": "VirusTotal v3",
  "asset_name": "virustotal_prod",
  "configuration": {
    "api_key": "YOUR_VT_API_KEY",
    "rate_limit": true,
    "max_requests_per_minute": 4
  },
  "product_vendor": "VirusTotal",
  "product_name": "VirusTotal"
}
```

**CrowdStrike Falcon Asset:**
```json
{
  "app": "CrowdStrike Falcon",
  "asset_name": "crowdstrike_prod",
  "configuration": {
    "client_id": "CS_CLIENT_ID",
    "client_secret": "CS_CLIENT_SECRET",
    "base_url": "https://api.crowdstrike.com"
  }
}
```

**Active Directory Asset:**
```json
{
  "app": "Active Directory",
  "asset_name": "ad_prod",
  "configuration": {
    "server": "dc01.company.com",
    "username": "soar_service@company.com",
    "password": "SERVICE_ACCOUNT_PASSWORD",
    "ssl": true
  }
}
```

### Step 2: Build Phishing Triage Playbook

Create an automated phishing response playbook in Python (Phantom playbook format):

```python
"""
Phishing Triage Automation Playbook
Trigger: New phishing email reported via Splunk ES notable or email ingestion
"""

import phantom.rules as phantom
import json

def on_start(container):
    # Extract artifacts (URLs, file hashes, sender) from the container
    artifacts = phantom.get_artifacts(container_id=container["id"])

    for artifact in artifacts:
        artifact_type = artifact.get("cef", {}).get("type", "")

        if artifact_type == "url":
            phantom.act("url reputation", targets=artifact,
                        assets=["virustotal_prod"],
                        callback=url_reputation_callback,
                        name="url_reputation")

        elif artifact_type == "hash":
            phantom.act("file reputation", targets=artifact,
                        assets=["virustotal_prod"],
                        callback=hash_reputation_callback,
                        name="file_reputation")

        elif artifact_type == "ip":
            phantom.act("ip reputation", targets=artifact,
                        assets=["virustotal_prod"],
                        callback=ip_reputation_callback,
                        name="ip_reputation")

def url_reputation_callback(action, success, container, results, handle):
    if not success:
        phantom.comment(container, "URL reputation check failed")
        return

    for result in results:
        data = result.get("data", [{}])[0]
        malicious_count = data.get("summary", {}).get("malicious", 0)
        total_engines = data.get("summary", {}).get("total_engines", 0)

        if malicious_count > 5:
            # High confidence malicious — auto-block and escalate
            phantom.act("block url", targets=result,
                        assets=["palo_alto_prod"],
                        name="block_malicious_url")

            phantom.set_severity(container, "high")
            phantom.set_status(container, "open")
            phantom.comment(container,
                f"URL flagged by {malicious_count}/{total_engines} engines. "
                f"Blocked on firewall. Escalating to Tier 2.")

            # Create ServiceNow ticket
            phantom.act("create ticket", targets=container,
                        assets=["servicenow_prod"],
                        parameters=[{
                            "short_description": f"Phishing - Malicious URL detected",
                            "urgency": "2",
                            "impact": "2"
                        }],
                        name="create_incident_ticket")

        elif malicious_count > 0:
            # Medium confidence — request analyst review
            phantom.promote(container, template="Phishing Investigation")
            phantom.comment(container,
                f"URL flagged by {malicious_count}/{total_engines} engines. "
                f"Requires analyst review.")

        else:
            # Clean — close with comment
            phantom.set_status(container, "closed")
            phantom.comment(container,
                f"URL clean: 0/{total_engines} engines flagged. Auto-closed.")

def hash_reputation_callback(action, success, container, results, handle):
    if not success:
        return

    for result in results:
        data = result.get("data", [{}])[0]
        positives = data.get("summary", {}).get("positives", 0)

        if positives > 10:
            # Known malware — quarantine and block
            phantom.act("quarantine device", targets=result,
                        assets=["crowdstrike_prod"],
                        name="isolate_endpoint")
            phantom.set_severity(container, "high")

def ip_reputation_callback(action, success, container, results, handle):
    if not success:
        return

    for result in results:
        data = result.get("data", [{}])[0]
        malicious = data.get("summary", {}).get("malicious", 0)

        if malicious > 3:
            phantom.act("block ip", targets=result,
                        assets=["palo_alto_prod"],
                        name="block_malicious_ip")
```

### Step 3: Build Alert Enrichment Playbook

Automate enrichment for all incoming SIEM alerts:

```python
"""
Universal Alert Enrichment Playbook
Runs on every new event to add context before analyst review
"""

import phantom.rules as phantom

def on_start(container):
    # Get all artifacts
    success, message, artifacts = phantom.get_artifacts(
        container_id=container["id"], full_data=True
    )

    ip_artifacts = [a for a in artifacts if a.get("cef", {}).get("sourceAddress")]
    domain_artifacts = [a for a in artifacts if a.get("cef", {}).get("destinationDnsDomain")]

    # Enrich IPs in parallel
    for artifact in ip_artifacts:
        ip = artifact["cef"]["sourceAddress"]

        # VirusTotal lookup
        phantom.act("ip reputation",
                    parameters=[{"ip": ip}],
                    assets=["virustotal_prod"],
                    callback=enrich_ip_callback,
                    name=f"vt_ip_{ip}")

        # GeoIP lookup
        phantom.act("geolocate ip",
                    parameters=[{"ip": ip}],
                    assets=["maxmind_prod"],
                    callback=geoip_callback,
                    name=f"geo_{ip}")

        # Whois lookup
        phantom.act("whois ip",
                    parameters=[{"ip": ip}],
                    assets=["whois_prod"],
                    name=f"whois_{ip}")

    # Enrich domains
    for artifact in domain_artifacts:
        domain = artifact["cef"]["destinationDnsDomain"]
        phantom.act("domain reputation",
                    parameters=[{"domain": domain}],
                    assets=["virustotal_prod"],
                    name=f"vt_domain_{domain}")

def enrich_ip_callback(action, success, container, results, handle):
    """Update container with enrichment data"""
    if success:
        for result in results:
            summary = result.get("summary", {})
            phantom.add_artifact(container, {
                "cef": {
                    "vt_malicious": summary.get("malicious", 0),
                    "vt_suspicious": summary.get("suspicious", 0),
                    "enrichment_source": "VirusTotal"
                },
                "label": "enrichment",
                "name": "VT IP Enrichment"
            })
```

### Step 4: Implement Approval Gates for High-Impact Actions

Add human-in-the-loop for critical actions:

```python
def containment_decision(action, success, container, results, handle):
    """Present analyst with containment options"""
    phantom.prompt(
        container=container,
        user="soc_tier2",
        message=(
            "Confirmed malicious activity detected.\n"
            f"Host: {container['artifacts'][0]['cef'].get('sourceAddress')}\n"
            f"Threat: {results[0]['summary'].get('threat_name')}\n\n"
            "Select containment action:"
        ),
        respond_in_mins=15,
        options=["Isolate Host", "Disable Account", "Both", "Monitor Only"],
        callback=execute_containment
    )

def execute_containment(action, success, container, results, handle):
    response = results.get("response", "Monitor Only")

    if response in ["Isolate Host", "Both"]:
        phantom.act("quarantine device",
                    parameters=[{"hostname": container["artifacts"][0]["cef"]["sourceHostName"]}],
                    assets=["crowdstrike_prod"],
                    name="isolate_host")

    if response in ["Disable Account", "Both"]:
        phantom.act("disable user",
                    parameters=[{"username": container["artifacts"][0]["cef"]["sourceUserName"]}],
                    assets=["ad_prod"],
                    name="disable_account")

    phantom.comment(container, f"Analyst approved: {response}")
```

### Step 5: Configure Playbook Scheduling and Triggers

Set up event triggers in SOAR:

```json
{
  "playbook_name": "phishing_triage_automation",
  "trigger": {
    "type": "event_created",
    "conditions": {
      "label": ["phishing", "notable"],
      "severity": ["high", "medium"]
    }
  },
  "active": true,
  "run_as": "automation_user"
}
```

### Step 6: Monitor Playbook Performance

Track automation effectiveness with SOAR metrics:

```python
# Query SOAR API for playbook execution stats
import requests

headers = {"ph-auth-token": "YOUR_SOAR_TOKEN"}
response = requests.get(
    "https://soar.company.com/rest/playbook_run",
    headers=headers,
    params={
        "page_size": 100,
        "filter": '{"status":"success"}',
        "sort": "create_time",
        "order": "desc"
    }
)
runs = response.json()["data"]

# Calculate automation metrics
total_runs = len(runs)
avg_duration = sum(r["end_time"] - r["start_time"] for r in runs) / total_runs
auto_closed = sum(1 for r in runs if r.get("auto_resolved"))
print(f"Total runs: {total_runs}")
print(f"Avg duration: {avg_duration:.1f}s")
print(f"Auto-resolved: {auto_closed}/{total_runs} ({auto_closed/total_runs*100:.0f}%)")
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **SOAR** | Security Orchestration, Automation, and Response — platform integrating security tools with automated playbooks |
| **Playbook** | Automated workflow defining sequential and parallel actions triggered by security events |
| **Asset** | SOAR configuration for a connected security tool (API endpoint, credentials, connection parameters) |
| **Container** | SOAR event object containing artifacts (IOCs) from an ingested alert or incident |
| **Artifact** | Individual IOC or data point within a container (IP, hash, URL, domain, email) |
| **Approval Gate** | Human-in-the-loop step requiring analyst decision before executing high-impact automated actions |

## Tools & Systems

- **Splunk SOAR (Phantom)**: Enterprise SOAR platform with 300+ app integrations and visual playbook editor
- **Splunk ES**: SIEM platform feeding notable events into SOAR as containers for automated triage
- **CrowdStrike Falcon**: EDR platform integrated via SOAR for automated host isolation and threat hunting
- **ServiceNow**: ITSM platform integrated for automated incident ticket creation and tracking
- **Palo Alto NGFW**: Firewall integrated for automated IP/URL blocking via SOAR playbooks

## Common Scenarios

- **Phishing Triage**: Auto-extract URLs/attachments, detonate in sandbox, block malicious, create ticket
- **Malware Alert Enrichment**: Auto-enrich file hashes across VT/MalwareBazaar, isolate if confirmed malicious
- **Brute Force Response**: Auto-check if attack succeeded, disable account if compromised, block source IP
- **Threat Intel IOC Processing**: Auto-ingest TI feed IOCs, check against internal logs, create blocks for matches
- **Vulnerability Alert Response**: Auto-query asset database for affected systems, create patching ticket with priority

## Output Format

```
SOAR PLAYBOOK EXECUTION REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Playbook:     Phishing Triage Automation v2.3
Container:    SOAR-2024-08921
Trigger:      Notable event from Splunk ES (phishing)

Actions Executed:
  [1] URL Reputation (VirusTotal)     — 14/90 engines malicious    [2.1s]
  [2] IP Reputation (AbuseIPDB)       — Confidence: 85%            [1.3s]
  [3] Block URL (Palo Alto)           — Blocked on PA-5260         [0.8s]
  [4] Block IP (Palo Alto)            — Blocked on PA-5260         [0.7s]
  [5] Create Ticket (ServiceNow)      — INC0012345 created         [1.5s]
  [6] Prompt Analyst (Tier 2)         — Response: "Isolate Host"   [4m 12s]
  [7] Quarantine Device (CrowdStrike) — WORKSTATION-042 isolated   [3.2s]

Total Duration:    4m 22s (vs 35min avg manual triage)
Time Saved:        ~31 minutes
Disposition:       True Positive — Escalated to IR
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
