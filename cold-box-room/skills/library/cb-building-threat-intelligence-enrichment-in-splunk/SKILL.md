---
name: cb-building-threat-intelligence-enrichment-in-splunk
skill_id: cb-building-threat-intelligence-enrichment-in-splunk
journal_id: CB-SKL-149
description: Cold-box analyst playbook — Building Threat Intelligence Enrichment In
  Splunk. Build automated threat intelligence enrichment pipelines in Splunk Enterprise
  Security using lookup tables, modular inputs, and the Threat Intelligence Framework.
domain: cold-box
subdomain: soc-operations
tier: adjacent
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- splunk
- threat-intelligence
- enrichment
- ioc
- lookup
- siem
- soc
- enterprise-security
cold_box_version: 2
inspired_by: building-threat-intelligence-enrichment-in-splunk
---

# Building Threat Intelligence Enrichment In Splunk (cold-box)

> **Journal ID:** `CB-SKL-149` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-149`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-building-threat-intelligence-enrichment-in-splunk")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-building-threat-intelligence-enrichment-in-splunk")` → note **`CB-SKL-149`**
2. `log_skill(case_id, journal_id="CB-SKL-149", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-149` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring building threat intelligence enrichment in splunk capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `head` | `SIFT-011` | yes | yes |
| `sort` | `SIFT-020` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `head` → `SIFT-011`

```json
{
  "tool_id": "SIFT-011",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-149] head per playbook step",
  "why": "Executing cb-building-threat-intelligence-enrichment-in-splunk \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-149] sort per playbook step",
  "why": "Executing cb-building-threat-intelligence-enrichment-in-splunk \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-149] file per playbook step",
  "why": "Executing cb-building-threat-intelligence-enrichment-in-splunk \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-149` (`cb-building-threat-intelligence-enrichment-in-splunk`)

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

## Overview

Splunk's Threat Intelligence Framework in Enterprise Security enables SOC teams to automatically correlate indicators of compromise (IOCs) against security events. The framework ingests threat feeds, normalizes indicators into KV Store collections, and uses lookup-based correlation searches to flag matching events. Splunk Threat Intelligence Management centralizes collection, normalization, and enrichment from multiple sources, reducing triage time by providing analysts with immediate context.


## When to Use

- When deploying or configuring building threat intelligence enrichment in splunk capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Splunk Enterprise Security (ES) 7.x or later
- Threat Intelligence Management add-on or Threat Intelligence Framework
- API keys for external threat intelligence feeds (MISP, OTX, VirusTotal, AbuseIPDB)
- KV Store enabled and properly configured
- Admin access for modular input configuration

## Threat Intelligence Framework Architecture

```
External TI Sources (STIX/TAXII, CSV, API)
    |
    v
Modular Inputs (download and parse feeds)
    |
    v
KV Store Collections (normalized IOC storage)
    |-- ip_intel
    |-- domain_intel
    |-- file_intel
    |-- url_intel
    |-- email_intel
    |
    v
Threat Intelligence Lookups
    |
    v
Correlation Searches (match events against IOCs)
    |
    v
Notable Events (enriched with TI context)
```

## Configuring Threat Intelligence Sources

### STIX/TAXII Feed Integration

```conf
# inputs.conf - TAXII feed configuration
[threatlist://taxii_feed_example]
description = TAXII 2.1 Threat Feed
type = taxii
url = https://threatfeed.example.com/taxii2/
collection = threat-indicators-v21
polling_interval = 3600
api_key = <encrypted_api_key>
disabled = false
```

### CSV-Based Threat List

```conf
# inputs.conf - CSV threat list
[threatlist://custom_blocklist]
description = Internal threat blocklist
type = csv
url = https://internal.company.com/threat-feeds/blocklist.csv
polling_interval = 1800
disabled = false
```

### Custom Modular Input for API-Based Feeds

```python
# bin/threatfeed_otx.py - OTX AlienVault feed collector
import json
import sys
import requests
from splunklib.modularinput import Script, Scheme, Argument, Event


class OTXFeedInput(Script):
    def get_scheme(self):
        scheme = Scheme("OTX AlienVault Feed")
        scheme.description = "Collects IOCs from AlienVault OTX"
        scheme.use_external_validation = False
        scheme.streaming_mode = Scheme.streaming_mode_xml

        api_key_arg = Argument("api_key")
        api_key_arg.data_type = Argument.data_type_string
        api_key_arg.required_on_create = True
        scheme.add_argument(api_key_arg)

        pulse_days_arg = Argument("pulse_days")
        pulse_days_arg.data_type = Argument.data_type_number
        pulse_days_arg.required_on_create = False
        scheme.add_argument(pulse_days_arg)

        return scheme

    def stream_events(self, inputs, ew):
        for input_name, input_item in inputs.inputs.items():
            api_key = input_item["api_key"]
            pulse_days = int(input_item.get("pulse_days", 30))

            headers = {"X-OTX-API-KEY": api_key}
            url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={pulse_days}d"

            try:
                response = requests.get(url, headers=headers, timeout=60)
                response.raise_for_status()
                data = response.json()

                for pulse in data.get("results", []):
                    for indicator in pulse.get("indicators", []):
                        event = Event()
                        event.stanza = input_name
                        event.data = json.dumps({
                            "indicator": indicator["indicator"],
                            "type": indicator["type"],
                            "pulse_name": pulse["name"],
                            "pulse_id": pulse["id"],
                            "description": indicator.get("description", ""),
                            "created": indicator.get("created", ""),
                            "threat_source": "OTX",
                            "confidence": pulse.get("adversary", "unknown"),
                        })
                        ew.write_event(event)
            except requests.RequestException as e:
                ew.log("ERROR", f"OTX feed collection failed: {str(e)}")


if __name__ == "__main__":
    sys.exit(OTXFeedInput().run(sys.argv))
```

## Building Enrichment Lookups

### KV Store Collection Configuration

```conf
# collections.conf
[ip_threat_intel]
field.ip = string
field.threat_type = string
field.confidence = number
field.source = string
field.description = string
field.first_seen = time
field.last_seen = time
field.severity = string

[domain_threat_intel]
field.domain = string
field.threat_type = string
field.confidence = number
field.source = string
field.whois_registrar = string
field.whois_created = string

[file_hash_intel]
field.file_hash = string
field.hash_type = string
field.malware_family = string
field.confidence = number
field.source = string
field.detection_names = string
```

### Lookup Table Definitions

```conf
# transforms.conf
[ip_threat_intel_lookup]
external_type = kvstore
collection = ip_threat_intel
fields_list = ip, threat_type, confidence, source, description, severity

[domain_threat_intel_lookup]
external_type = kvstore
collection = domain_threat_intel
fields_list = domain, threat_type, confidence, source

[file_hash_intel_lookup]
external_type = kvstore
collection = file_hash_intel
fields_list = file_hash, hash_type, malware_family, confidence, source
```

## Enrichment Correlation Searches

### IP-Based Threat Intelligence Correlation

```spl
| tstats summariesonly=true count from datamodel=Network_Traffic
    where All_Traffic.action=allowed
    by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port, _time span=5m
| rename "All_Traffic.*" as *
| lookup ip_threat_intel_lookup ip as dest_ip OUTPUT threat_type, confidence, source as ti_source, severity as ti_severity
| where isnotnull(threat_type)
| lookup asset_lookup ip as src_ip OUTPUT asset_name, asset_owner, asset_priority
| eval urgency=case(
    ti_severity=="critical" AND asset_priority=="critical", "critical",
    ti_severity=="high" OR asset_priority=="critical", "high",
    ti_severity=="medium", "medium",
    true(), "low"
)
| eval description="Connection from ".src_ip." (".asset_name.") to known malicious IP ".dest_ip." (".threat_type.") - Source: ".ti_source
```

### Domain-Based Threat Intelligence Correlation

```spl
index=dns sourcetype=stream:dns query_type=A OR query_type=AAAA
| lookup domain_threat_intel_lookup domain as query OUTPUT threat_type as domain_threat, confidence as domain_confidence, source as ti_source
| where isnotnull(domain_threat) AND domain_confidence > 70
| stats count dc(src_ip) as unique_sources values(src_ip) as source_ips by query, domain_threat, ti_source
| eval severity=case(domain_confidence > 90, "critical", domain_confidence > 70, "high", true(), "medium")
| eval description="DNS queries to malicious domain ".query." from ".unique_sources." hosts - Threat: ".domain_threat
```

### File Hash Correlation

```spl
index=endpoint sourcetype=sysmon EventCode=1
| lookup file_hash_intel_lookup file_hash as Hashes OUTPUT malware_family, confidence as hash_confidence, source as ti_source
| where isnotnull(malware_family)
| stats count values(ParentCommandLine) as parent_commands by Computer, User, Image, malware_family, ti_source
| eval severity="critical"
| eval description="Known malware ".malware_family." executed on ".Computer." by ".User." - Binary: ".Image
```

## Multi-Source Enrichment Pipeline

```spl
index=firewall sourcetype=pan:traffic action=allowed
| eval indicators=mvappend(src_ip, dest_ip)
| mvexpand indicators
| lookup ip_threat_intel_lookup ip as indicators OUTPUT threat_type as ip_threat, confidence as ip_confidence, source as ip_ti_source
| lookup geo_ip_lookup ip as indicators OUTPUT country, city, latitude, longitude
| lookup whois_lookup ip as indicators OUTPUT org as ip_org, asn as ip_asn
| where isnotnull(ip_threat)
| stats count
    values(ip_threat) as threat_types
    values(ip_ti_source) as intel_sources
    values(country) as countries
    values(ip_org) as organizations
    latest(_time) as last_seen
    earliest(_time) as first_seen
    by src_ip, dest_ip, dest_port
| eval enrichment_context="Threat: ".mvjoin(threat_types, ", ")." | Geo: ".mvjoin(countries, ", ")." | Org: ".mvjoin(organizations, ", ")
```

## Threat Intelligence Dashboards

### IOC Coverage Statistics

```spl
| inputlookup ip_threat_intel_lookup
| stats count by source, threat_type
| sort -count
| head 20
```

### Feed Freshness Monitoring

```spl
| inputlookup ip_threat_intel_lookup
| eval age_days=round((now() - strptime(last_seen, "%Y-%m-%dT%H:%M:%S")) / 86400, 0)
| stats count avg(age_days) as avg_age_days max(age_days) as max_age_days by source
| eval status=case(avg_age_days > 30, "STALE", avg_age_days > 7, "AGING", true(), "FRESH")
```

## References

- [Splunk Threat Intelligence Framework Documentation](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.2/threat-intelligence/overview-of-threat-intelligence-in-splunk-enterprise-security)
- [Splunk Lantern - Threat Intelligence Enrichment](https://lantern.splunk.com/Security/UCE/Guided_Insights/Threat_intelligence)
- [Integrated Intelligence Enrichment - Splunk Blog](https://www.splunk.com/en_us/blog/security/integrated-intelligence-enrichment-with-threat-intelligence-management.html)
- [Cisco Talos Threat Intelligence in Splunk](https://www.splunk.com/en_us/blog/security/cisco-talos-threat-intelligence-splunk-security.html)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
