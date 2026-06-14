---
name: cb-threat-intelligence-feeds
skill_id: cb-threat-intelligence-feeds
journal_id: CB-SKL-330
description: Cold-box analyst playbook — Threat Intelligence Feeds. Analyzes structured
  and unstructured threat intelligence feeds to extract actionable indicators, adversary
  tactics, and campaign context. Use when ingesting commercial or open-source CTI
  feeds, evaluating feed quality, normalizing data into
domain: cold-box
subdomain: threat-intelligence
tier: adjacent
case_profiles:
- threat_intel
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- STIX
- TAXII
- MITRE-ATT&CK
- IOC
- ThreatConnect
- Recorded-Future
- MISP
- CTI
- NIST-CSF
cold_box_version: 2
inspired_by: analyzing-threat-intelligence-feeds
---

# Threat Intelligence Feeds (cold-box)

> **Journal ID:** `CB-SKL-330` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-330`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-threat-intelligence-feeds")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-threat-intelligence-feeds")` → note **`CB-SKL-330`**
2. `log_skill(case_id, journal_id="CB-SKL-330", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-330` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Ingesting new commercial or OSINT threat feeds and assessing their signal-to-noise ratio
- Normalizing heterogeneous IOC formats (STIX 2.1, OpenIOC, YARA, Sigma) into a unified schema
- Evaluating feed freshness, fidelity, and relevance to the organization's threat profile
- Building automated enrichment pipelines that correlate IOCs against SIEM events

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `yara` | `SIFT-045` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `yara` → `SIFT-045`

```json
{
  "tool_id": "SIFT-045",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-330] yara per playbook step",
  "why": "Executing cb-threat-intelligence-feeds \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-330] file per playbook step",
  "why": "Executing cb-threat-intelligence-feeds \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-330` (`cb-threat-intelligence-feeds`)

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
- Ingesting new commercial or OSINT threat feeds and assessing their signal-to-noise ratio
- Normalizing heterogeneous IOC formats (STIX 2.1, OpenIOC, YARA, Sigma) into a unified schema
- Evaluating feed freshness, fidelity, and relevance to the organization's threat profile
- Building automated enrichment pipelines that correlate IOCs against SIEM events

**Do not use** this skill for raw packet capture analysis or live incident triage without first establishing a CTI baseline.

## Prerequisites

- Access to a Threat Intelligence Platform (TIP) such as ThreatConnect, MISP, or OpenCTI
- API keys for at least one commercial feed (Recorded Future, Mandiant Advantage, or VirusTotal Enterprise)
- TAXII 2.1 client library (taxii2-client Python package or equivalent)
- Role with read/write permissions to the TIP's indicator database

## Workflow

### Step 1: Enumerate and Prioritize Feed Sources

List all available feeds categorized by type (commercial, government, ISAC, OSINT):
- Commercial: Recorded Future, Mandiant Advantage, CrowdStrike Falcon Intelligence
- Government: CISA AIS (Automated Indicator Sharing), FBI InfraGard, MS-ISAC
- OSINT: AlienVault OTX, Abuse.ch, PhishTank, Emerging Threats

Score each feed on: update frequency, historical accuracy rate, coverage of your sector, and attribution depth. Use a weighted scoring matrix with criteria from NIST SP 800-150 (Guide to Cyber Threat Information Sharing).

### Step 2: Ingest via TAXII 2.1 or API

For TAXII-enabled feeds:
```
taxii2-client discover https://feed.example.com/taxii/
taxii2-client get-collection --collection-id <id> --since 2024-01-01
```

For REST API feeds (e.g., Recorded Future):
- Query `/v2/indicator/search` with `risk_score_min=65` to filter low-confidence IOCs
- Apply rate limiting and exponential backoff for API resilience

### Step 3: Normalize to STIX 2.1

Convert each IOC to STIX 2.1 objects using the OASIS standard schema:
- IP address → `indicator` object with `pattern: "[ipv4-addr:value = '...']"`
- Domain → `indicator` with `pattern: "[domain-name:value = '...']"`
- File hash → `indicator` with `pattern: "[file:hashes.SHA-256 = '...']"`

Attach `relationship` objects linking indicators to `threat-actor` or `malware` objects. Use `confidence` field (0–100) based on source fidelity rating.

### Step 4: Deduplicate and Enrich

Run deduplication against existing TIP database using normalized value + type as composite key. Enrich surviving IOCs:
- VirusTotal: detection ratio, sandbox behavior reports
- PassiveTotal (RiskIQ): WHOIS history, passive DNS, SSL certificate chains
- Shodan: banner data, open ports, geographic location

### Step 5: Distribute to Consuming Systems

Export enriched indicators via TAXII 2.1 push to SIEM (Splunk, Microsoft Sentinel), firewalls (Palo Alto XSOAR playbooks), and EDR platforms. Set TTL (time-to-live) per indicator type: IP addresses 30 days, domains 90 days, file hashes 1 year.

## Key Concepts

| Term | Definition |
|------|-----------|
| **STIX 2.1** | Structured Threat Information Expression — OASIS standard JSON schema for CTI objects including indicators, threat actors, campaigns, and relationships |
| **TAXII 2.1** | Trusted Automated eXchange of Intelligence Information — HTTPS-based protocol for sharing STIX content between servers and clients |
| **IOC** | Indicator of Compromise — observable artifact (IP, domain, hash, URL) that indicates a system may have been breached |
| **TLP** | Traffic Light Protocol — color-coded classification (RED/AMBER/GREEN/WHITE) defining sharing restrictions for CTI |
| **Confidence Score** | Numeric value (0–100 in STIX) reflecting the producer's certainty about an indicator's malicious attribution |
| **Feed Fidelity** | Historical accuracy rate of a feed measured by true positive rate in production detections |

## Tools & Systems

- **ThreatConnect TC Exchange**: Aggregates 100+ commercial and OSINT feeds; provides automated playbooks for IOC enrichment
- **MISP (Malware Information Sharing Platform)**: Open-source TIP supporting STIX/TAXII; widely used by ISACs and government CERTs
- **OpenCTI**: Open-source platform with native MITRE ATT&CK integration and graph-based relationship visualization
- **Recorded Future**: Commercial feed with AI-powered risk scoring and real-time dark web monitoring
- **taxii2-client**: Python library for TAXII 2.0/2.1 client operations (pip install taxii2-client)
- **PyMISP**: Python API for MISP feed management and IOC submission

## Common Pitfalls

- **IOC age staleness**: IP addresses and domains rotate frequently; applying 1-year-old IOCs generates false positives. Enforce TTL policies.
- **Missing context**: Blocking an IOC without understanding the associated campaign or adversary can disrupt legitimate business traffic (e.g., CDN IPs shared with malicious actors).
- **Feed overlap without deduplication**: Ingesting the same IOC from five feeds without deduplication inflates indicator counts and SIEM rule complexity.
- **TLP violation**: Redistributing RED-classified intelligence outside authorized boundaries violates sharing agreements and trust relationships.
- **Over-blocking on low-confidence indicators**: Indicators with confidence below 50 should trigger detection-only rules, not blocking, to avoid operational disruption.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
