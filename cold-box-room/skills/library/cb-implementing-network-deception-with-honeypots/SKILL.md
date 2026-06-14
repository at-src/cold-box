---
name: cb-implementing-network-deception-with-honeypots
skill_id: cb-implementing-network-deception-with-honeypots
journal_id: CB-SKL-270
description: Cold-box analyst playbook — Implementing Network Deception With Honeypots.
  Deploy and manage network honeypots using OpenCanary, T-Pot, or Cowrie to detect
  unauthorized access, lateral movement, and attacker reconnaissance.
domain: cold-box
subdomain: deception-technology
tier: adjacent
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- deception
- honeypot
- opencanary
- cowrie
- t-pot
- detection
- lateral-movement
- network-security
cold_box_version: 2
inspired_by: implementing-network-deception-with-honeypots
---

# Implementing Network Deception With Honeypots (cold-box)

> **Journal ID:** `CB-SKL-270` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-270`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-network-deception-with-honeypots")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-network-deception-with-honeypots")` → note **`CB-SKL-270`**
2. `log_skill(case_id, journal_id="CB-SKL-270", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-270` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying deception technology to detect lateral movement
- To create early warning indicators for network intrusion
- During security architecture design to add detection depth
- When monitoring for unauthorized internal scanning or credential theft
- To gather threat intelligence on attacker techniques and tools

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
  "purpose": "[CB-SKL-270] file per playbook step",
  "why": "Executing cb-implementing-network-deception-with-honeypots \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-270` (`cb-implementing-network-deception-with-honeypots`)

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

- When deploying deception technology to detect lateral movement
- To create early warning indicators for network intrusion
- During security architecture design to add detection depth
- When monitoring for unauthorized internal scanning or credential theft
- To gather threat intelligence on attacker techniques and tools

## Prerequisites

- Linux server or VM for honeypot deployment (Ubuntu 22.04+ recommended)
- Python 3.8+ with pip for OpenCanary installation
- Docker for T-Pot or containerized deployment
- Network segment with appropriate VLAN configuration
- SIEM integration for alert forwarding (syslog, webhook, or file-based)
- Firewall rules allowing inbound connections to honeypot services

## Workflow

1. **Plan Deployment**: Select honeypot types and network placement strategy.
2. **Install Honeypot**: Deploy OpenCanary, Cowrie, or T-Pot on dedicated host.
3. **Configure Services**: Enable emulated services (SSH, HTTP, SMB, FTP, RDP).
4. **Set Up Alerting**: Configure log forwarding to SIEM and alert channels.
5. **Deploy Canary Tokens**: Place credential files, shares, and DNS entries.
6. **Monitor Interactions**: Analyze honeypot logs for attacker activity.
7. **Tune and Maintain**: Update configurations based on detection results.

## Key Concepts

| Concept | Description |
|---------|-------------|
| OpenCanary | Lightweight Python honeypot with modular service emulation |
| Cowrie | Medium-interaction SSH/Telnet honeypot capturing commands |
| T-Pot | Multi-honeypot platform with ELK stack visualization |
| Canary Token | Tripwire credential or file that alerts when accessed |
| Low-Interaction | Emulates services at protocol level without full OS |
| High-Interaction | Full OS honeypot capturing complete attacker sessions |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| OpenCanary | Modular honeypot daemon with service emulation |
| Cowrie | SSH/Telnet honeypot with session recording |
| T-Pot | All-in-one multi-honeypot platform |
| Dionaea | Malware-capturing honeypot for exploit detection |
| Splunk/Elastic | SIEM for honeypot alert aggregation |

## Output Format

```
Alert: HONEYPOT-[SERVICE]-[DATE]-[SEQ]
Honeypot: [Hostname/IP]
Service: [SSH/HTTP/SMB/FTP/RDP]
Source IP: [Attacker IP]
Interaction: [Login attempt/Port scan/File access]
Credentials Used: [Username:Password if applicable]
Commands Executed: [For SSH honeypots]
Risk Level: [Critical/High/Medium/Low]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
