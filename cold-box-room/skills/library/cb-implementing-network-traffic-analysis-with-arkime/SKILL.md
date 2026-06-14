---
name: cb-implementing-network-traffic-analysis-with-arkime
skill_id: cb-implementing-network-traffic-analysis-with-arkime
journal_id: CB-SKL-058
description: Cold-box analyst playbook — Implementing Network Traffic Analysis With
  Arkime. Deploy and query Arkime (formerly Moloch) for full packet capture network
  traffic analysis. Uses the Arkime API v3 to search sessions, download PCAPs, analyze
  connection patterns, detect beaconing behavior, and identify suspicious network
  f
domain: cold-box
subdomain: network-security
tier: core
case_profiles:
- network_pcap
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- network-security
- arkime
- full-packet-capture
- nta
- pcap-analysis
- network-forensics
cold_box_version: 2
inspired_by: implementing-network-traffic-analysis-with-arkime
---

# Implementing Network Traffic Analysis With Arkime (cold-box)

> **Journal ID:** `CB-SKL-058` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-058`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-network-traffic-analysis-with-arkime")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-network-traffic-analysis-with-arkime")` → note **`CB-SKL-058`**
2. `log_skill(case_id, journal_id="CB-SKL-058", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-058` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring implementing network traffic analysis with arkime capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Tool map (SIFT via MCP)

**Execution mode:** `reference` — procedure steps target external platforms (SIEM, cloud, etc.).
Use for investigation guidance; log `{journal_id}` and note gaps when SIFT cannot run a step.

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

_No SIFT tools mapped for this playbook on cold-box._
Follow the procedure for reasoning; document external-platform gaps in the journal.

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-058` (`cb-implementing-network-traffic-analysis-with-arkime`)

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

- When deploying or configuring implementing network traffic analysis with arkime capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Familiarity with network security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install requests`
2. Configure Arkime viewer URL and credentials.
3. Run the agent to query Arkime sessions and analyze traffic:
   - Search sessions by IP, port, protocol, or expression
   - Download PCAP data for forensic analysis
   - Detect C2 beaconing via connection interval analysis
   - Identify DNS tunneling through query length statistics
   - Flag connections to known-bad TLS certificate issuers

```bash
python scripts/agent.py --arkime-url https://arkime.local:8005 --user admin --password secret --output arkime_report.json
```

## Examples

### Beaconing Detection
```
Source: 10.1.2.50 -> 185.220.101.34:443
Sessions: 288 over 24 hours
Avg interval: 300s, Jitter: 4.2%
Verdict: HIGH confidence C2 beaconing (jitter < 5%)
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
