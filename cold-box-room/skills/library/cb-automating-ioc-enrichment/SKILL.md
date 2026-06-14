---
name: cb-automating-ioc-enrichment
skill_id: cb-automating-ioc-enrichment
journal_id: CB-SKL-002
description: Cold-box analyst playbook — Automating Ioc Enrichment. Automates the
  enrichment of raw indicators of compromise with multi-source threat intelligence
  context using SOAR platforms, Python pipelines, or TIP playbooks to reduce analyst
  triage time and standardize enrichment outputs. Use when build
domain: cold-box
subdomain: threat-intelligence
tier: core
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- SOAR
- enrichment
- IOC
- Cortex-XSOAR
- Splunk-SOAR
- VirusTotal
- automation
- CTI
- NIST-CSF
cold_box_version: 2
inspired_by: automating-ioc-enrichment
---

# Automating Ioc Enrichment (cold-box)

> **Journal ID:** `CB-SKL-002` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-002`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-automating-ioc-enrichment")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-automating-ioc-enrichment")` → note **`CB-SKL-002`**
2. `log_skill(case_id, journal_id="CB-SKL-002", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-002` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Building a SOAR playbook that automatically enriches SIEM alerts with threat intelligence context before routing to analysts
- Creating a Python pipeline for bulk IOC enrichment from phishing email submissions
- Reducing analyst mean time to triage (MTTT) by pre-populating alert context with VT, Shodan, and MISP data

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `handle` | `SIFT-178` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `handle` → `SIFT-178`

```json
{
  "tool_id": "SIFT-178",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-002] handle per playbook step",
  "why": "Executing cb-automating-ioc-enrichment \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-002] file per playbook step",
  "why": "Executing cb-automating-ioc-enrichment \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-002` (`cb-automating-ioc-enrichment`)

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
- Building a SOAR playbook that automatically enriches SIEM alerts with threat intelligence context before routing to analysts
- Creating a Python pipeline for bulk IOC enrichment from phishing email submissions
- Reducing analyst mean time to triage (MTTT) by pre-populating alert context with VT, Shodan, and MISP data

**Do not use** this skill for fully automated blocking decisions without human review — enrichment automation should inform decisions, not execute blocks autonomously for high-impact actions.

## Prerequisites

- SOAR platform (Cortex XSOAR, Splunk SOAR, Tines, or n8n) or Python 3.9+ environment
- API keys: VirusTotal, AbuseIPDB, Shodan, and at minimum one TIP (MISP or OpenCTI)
- SIEM integration endpoint for alert consumption
- Rate limit budgets documented per API (VT: 4/min free, 500/min enterprise)

## Workflow

### Step 1: Design Enrichment Pipeline Architecture

Define the enrichment flow for each IOC type:
```
SIEM Alert → Extract IOCs → Classify Type → Route to enrichment functions
  IP Address → AbuseIPDB + Shodan + VirusTotal IP + MISP
  Domain → VirusTotal Domain + PassiveTotal + Shodan + MISP
  URL → URLScan.io + VirusTotal URL + Google Safe Browse
  File Hash → VirusTotal Files + MalwareBazaar + MISP
→ Aggregate results → Calculate confidence score → Update alert → Notify analyst
```

### Step 2: Implement Python Enrichment Functions

```python
import requests
import time
from dataclasses import dataclass, field
from typing import Optional

RATE_LIMIT_DELAY = 0.25  # 4 requests/second for VT free tier

@dataclass
class EnrichmentResult:
    ioc_value: str
    ioc_type: str
    vt_malicious: int = 0
    vt_total: int = 0
    abuse_confidence: int = 0
    shodan_ports: list = field(default_factory=list)
    misp_events: list = field(default_factory=list)
    confidence_score: int = 0

def enrich_ip(ip: str, vt_key: str, abuse_key: str, shodan_key: str) -> EnrichmentResult:
    result = EnrichmentResult(ip, "ip")

    # VirusTotal IP lookup
    vt_resp = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": vt_key}
    )
    if vt_resp.status_code == 200:
        stats = vt_resp.json()["data"]["attributes"]["last_analysis_stats"]
        result.vt_malicious = stats.get("malicious", 0)
        result.vt_total = sum(stats.values())

    time.sleep(RATE_LIMIT_DELAY)

    # AbuseIPDB
    abuse_resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": abuse_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90}
    )
    if abuse_resp.status_code == 200:
        result.abuse_confidence = abuse_resp.json()["data"]["abuseConfidenceScore"]

    # Calculate composite confidence score
    result.confidence_score = min(
        (result.vt_malicious / max(result.vt_total, 1)) * 60 +
        (result.abuse_confidence / 100) * 40, 100
    )

    return result

def enrich_hash(sha256: str, vt_key: str) -> EnrichmentResult:
    result = EnrichmentResult(sha256, "sha256")
    vt_resp = requests.get(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": vt_key}
    )
    if vt_resp.status_code == 200:
        stats = vt_resp.json()["data"]["attributes"]["last_analysis_stats"]
        result.vt_malicious = stats.get("malicious", 0)
        result.vt_total = sum(stats.values())
        result.confidence_score = int((result.vt_malicious / max(result.vt_total, 1)) * 100)
    return result
```

### Step 3: Build SOAR Playbook (Cortex XSOAR)

In Cortex XSOAR, create an enrichment playbook:
1. **Trigger**: Alert created in SIEM (via webhook or polling)
2. **Extract IOCs**: Use "Extract Indicators" task with regex patterns for IP, domain, URL, hash
3. **Parallel enrichment**: Fan-out to multiple enrichment tasks simultaneously
4. **VT Enrichment**: Call `!vt-file-scan` or `!vt-ip-scan` commands
5. **AbuseIPDB check**: Call `!abuseipdb-check-ip` command
6. **MISP Lookup**: Call `!misp-search` for cross-referencing
7. **Score aggregation**: Python transform task computing composite score
8. **Conditional routing**: If score ≥70 → High Priority queue; if 40–69 → Medium; <40 → Auto-close with note
9. **Alert enrichment**: Write enrichment results to alert context for analyst view

### Step 4: Handle Rate Limiting and Failures

```python
import time
from functools import wraps

def rate_limited(max_per_second):
    min_interval = 1.0 / max_per_second
    def decorator(func):
        last_called = [0.0]
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            wait = min_interval - elapsed
            if wait > 0:
                time.sleep(wait)
            result = func(*args, **kwargs)
            last_called[0] = time.time()
            return result
        return wrapper
    return decorator

def retry_on_429(max_retries=3):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                response = func(*args, **kwargs)
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    time.sleep(retry_after)
                else:
                    return response
        return wrapper
    return decorator
```

### Step 5: Metrics and Tuning

Track pipeline performance weekly:
- **Enrichment latency**: Target <30 seconds from alert trigger to enriched output
- **API success rate**: Target >99% (identify rate limit or outage events)
- **True positive rate**: Track analyst overrides of automated confidence scores
- **Cost**: Track API call volume against budget (VT Enterprise: $X per 1M lookups)

## Key Concepts

| Term | Definition |
|------|-----------|
| **SOAR** | Security Orchestration, Automation, and Response — platform for automating security workflows and integrating disparate tools |
| **Enrichment Playbook** | Automated workflow sequence that adds contextual intelligence to raw security events |
| **Rate Limiting** | API provider restrictions on request frequency (e.g., VT free: 4 requests/minute); pipelines must respect these limits |
| **Composite Confidence Score** | Single score aggregating signals from multiple enrichment sources using weighted formula |
| **Fan-out Pattern** | Parallel execution of multiple enrichment queries simultaneously to minimize total enrichment latency |

## Tools & Systems

- **Cortex XSOAR (Palo Alto)**: Enterprise SOAR with 700+ marketplace integrations including VT, MISP, Shodan, and AbuseIPDB
- **Splunk SOAR (Phantom)**: SOAR platform with Python-based playbooks; native Splunk SIEM integration
- **Tines**: No-code SOAR platform with webhook-driven automation; cost-effective for smaller teams
- **TheHive + Cortex**: Open-source IR/enrichment platform with observable enrichment via Cortex analyzers

## Common Pitfalls

- **Blocking on enrichment latency**: If enrichment takes >5 minutes, analysts start working unenriched alerts, defeating the purpose. Set timeout limits and provide partial results.
- **No caching**: Querying the same IOC 50 times generates unnecessary API costs. Cache enrichment results for 24 hours by default.
- **Ignoring API failures silently**: Failed enrichment calls should be logged and trigger fallback logic, not silently produce empty results that appear as clean IOCs.
- **Automating blocks on enrichment score alone**: Composite scores contain false positives; require human confirmation for blocking decisions against shared infrastructure.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
