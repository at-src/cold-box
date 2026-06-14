---
name: cb-network-packets-with-scapy
skill_id: cb-network-packets-with-scapy
journal_id: CB-SKL-092
description: Cold-box analyst playbook — Network Packets With Scapy. Craft, send,
  sniff, and dissect network packets using Scapy for protocol analysis, network reconnaissance,
  and traffic anomaly detection in authorized security testing
domain: cold-box
subdomain: network-security
tier: core
case_profiles:
- network_pcap
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- scapy
- packet-analysis
- network-forensics
- protocol-dissection
- pcap
- traffic-analysis
cold_box_version: 2
inspired_by: analyzing-network-packets-with-scapy
---

# Network Packets With Scapy (cold-box)

> **Journal ID:** `CB-SKL-092` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-092`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-network-packets-with-scapy")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-network-packets-with-scapy")` → note **`CB-SKL-092`**
2. `log_skill(case_id, journal_id="CB-SKL-092", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-092` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing network packets with scapy
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-092] file per playbook step",
  "why": "Executing cb-network-packets-with-scapy \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-092` (`cb-network-packets-with-scapy`)

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

Scapy is a Python packet manipulation library that enables crafting, sending, sniffing, and dissecting network packets at granular protocol layers. This skill covers using Scapy for security-relevant tasks including TCP/UDP/ICMP packet crafting, pcap file analysis, protocol field extraction, SYN scan implementation, DNS query analysis, and detecting anomalous traffic patterns such as unusually fragmented packets or malformed headers.


## When to Use

- When investigating security incidents that require analyzing network packets with scapy
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Python 3.8+ with `scapy` library installed (`pip install scapy`)
- Root/administrator privileges for raw socket operations (sniffing, sending)
- Npcap (Windows) or libpcap (Linux) for packet capture
- Authorization to perform packet operations on target network

## Steps

1. Read and parse pcap/pcapng files with `rdpcap()` for offline analysis
2. Extract protocol layers (IP, TCP, UDP, DNS, HTTP) and field values
3. Compute traffic statistics: top talkers, protocol distribution, port frequency
4. Detect SYN flood patterns by analyzing TCP flag ratios
5. Identify DNS exfiltration indicators via query length and entropy analysis
6. Craft custom probe packets for authorized network testing
7. Export findings as structured JSON report

## Expected Output

JSON report containing packet statistics, protocol distribution, top source/destination IPs, detected anomalies (SYN floods, DNS tunneling indicators, fragmentation attacks), and per-flow summaries.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
