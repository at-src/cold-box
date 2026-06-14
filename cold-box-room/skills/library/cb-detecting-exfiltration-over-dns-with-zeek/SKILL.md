---
name: cb-detecting-exfiltration-over-dns-with-zeek
skill_id: cb-detecting-exfiltration-over-dns-with-zeek
journal_id: CB-SKL-186
description: Cold-box analyst playbook — Detecting Exfiltration Over Dns With Zeek.
  Detect DNS-based data exfiltration by analyzing Zeek dns.log for high-entropy subdomains
  and anomalous query patterns
domain: cold-box
subdomain: network-security
tier: adjacent
case_profiles:
- network_pcap
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- dns-exfiltration
- zeek
- entropy-analysis
- threat-hunting
cold_box_version: 2
inspired_by: detecting-exfiltration-over-dns-with-zeek
---

# Detecting Exfiltration Over Dns With Zeek (cold-box)

> **Journal ID:** `CB-SKL-186` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-186`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-exfiltration-over-dns-with-zeek")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-exfiltration-over-dns-with-zeek")` → note **`CB-SKL-186`**
2. `log_skill(case_id, journal_id="CB-SKL-186", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-186` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require detecting exfiltration over dns with zeek
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `zeek` | `SIFT-119` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `zeek` → `SIFT-119`

```json
{
  "tool_id": "SIFT-119",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-186] zeek per playbook step",
  "why": "Executing cb-detecting-exfiltration-over-dns-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-186] file per playbook step",
  "why": "Executing cb-detecting-exfiltration-over-dns-with-zeek \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-186` (`cb-detecting-exfiltration-over-dns-with-zeek`)

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

DNS tunneling and exfiltration is a technique used by attackers to bypass firewalls and DLP controls by encoding stolen data into DNS query subdomains. Legitimate DNS queries have predictable entropy and length patterns, while exfiltration queries contain encoded data with high Shannon entropy, unusually long subdomain labels, and high volumes of unique subdomains per parent domain.

This skill analyzes Zeek dns.log files (TSV format) to detect exfiltration indicators. The agent computes Shannon entropy for each subdomain component, identifies queries exceeding the 63-character DNS label limit, counts unique subdomains per parent domain, and flags domains that exceed configurable thresholds. These techniques detect tools like dnscat2, iodine, dns2tcp, and custom DNS tunneling implementations.


## When to Use

- When investigating security incidents that require detecting exfiltration over dns with zeek
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Python 3.9 or later with math and collections modules (stdlib)
- Zeek dns.log files in TSV format with standard field headers
- Network capture data processed by Zeek 5.0+ or later
- Understanding of DNS protocol structure and query types

## Steps

1. **Parse Zeek dns.log headers**: Read the TSV file, extract the `#fields` header line to identify column positions for `ts`, `id.orig_h`, `query`, `qtype_name`, `rcode_name`, and `answers`.

2. **Extract and decompose queries**: For each DNS query, split the FQDN into subdomain labels and parent domain. Skip queries to known safe domains and internal zones.

3. **Compute Shannon entropy**: Calculate the information entropy of each subdomain label. Legitimate subdomains typically have entropy below 3.5, while encoded/encrypted data produces entropy above 4.0.

4. **Detect long labels**: Flag DNS labels exceeding 52 characters (approaching the 63-character maximum). Long labels are a strong indicator of data tunneling.

5. **Count unique subdomains per domain**: Track how many distinct subdomains each parent domain receives. Domains with more than 50 unique subdomains within the log window are suspicious.

6. **Identify query volume anomalies**: Calculate queries-per-minute per source IP per domain. Exfiltration tools generate sustained high-volume query streams that differ from normal browsing.

7. **Score and rank domains**: Combine entropy, label length, uniqueness count, and query volume into a composite risk score. Rank domains by score and output the top suspicious domains.

8. **Generate detection report**: Produce a JSON report with flagged domains, their evidence indicators, originating source IPs, and recommended response actions.

## Expected Output

```json
{
  "analysis_summary": {
    "total_queries_analyzed": 145832,
    "unique_domains": 3421,
    "flagged_domains": 3,
    "entropy_threshold": 3.5
  },
  "flagged_domains": [
    {
      "domain": "data.evil-c2.com",
      "unique_subdomains": 892,
      "avg_entropy": 4.72,
      "max_label_length": 61,
      "source_ips": ["10.0.1.45"],
      "risk_score": 9.4,
      "indicators": ["high_entropy", "long_labels", "high_subdomain_count"]
    }
  ]
}
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
