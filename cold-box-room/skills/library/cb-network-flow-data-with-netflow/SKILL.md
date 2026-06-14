---
name: cb-network-flow-data-with-netflow
skill_id: cb-network-flow-data-with-netflow
journal_id: CB-SKL-303
description: Cold-box analyst playbook — Network Flow Data With Netflow. Parse NetFlow
  v9 and IPFIX records to detect volumetric anomalies, port scanning, data exfiltration,
  and C2 beaconing patterns. Uses the Python netflow library to decode flow records,
  builds traffic baselines, and applies statistical analys
domain: cold-box
subdomain: network-security
tier: adjacent
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- analyzing
- network
- flow
- data
cold_box_version: 2
inspired_by: analyzing-network-flow-data-with-netflow
---

# Network Flow Data With Netflow (cold-box)

> **Journal ID:** `CB-SKL-303` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-303`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-network-flow-data-with-netflow")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-network-flow-data-with-netflow")` → note **`CB-SKL-303`**
2. `log_skill(case_id, journal_id="CB-SKL-303", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-303` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing network flow data with netflow
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
  "purpose": "[CB-SKL-303] file per playbook step",
  "why": "Executing cb-network-flow-data-with-netflow \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-303` (`cb-network-flow-data-with-netflow`)

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

- When investigating security incidents that require analyzing network flow data with netflow
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with network security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install netflow`
2. Collect NetFlow/IPFIX data from routers or use the built-in collector: `python -m netflow.collector -p 9995`
3. Parse captured flow data using `netflow.parse_packet()`.
4. Analyze flows for:
   - Port scanning: single source to many destinations on same port
   - Data exfiltration: high byte-count outbound flows to unusual destinations
   - C2 beaconing: periodic connections with consistent intervals
   - Volumetric anomalies: traffic spikes beyond baseline thresholds
5. Generate a prioritized findings report.

```bash
python scripts/agent.py --flow-file captured_flows.json --output netflow_report.json
```

## Examples

### Parse NetFlow v9 Packet
```python
import netflow
data, _ = netflow.parse_packet(raw_bytes, templates={})
for flow in data.flows:
    print(flow.IPV4_SRC_ADDR, flow.IPV4_DST_ADDR, flow.IN_BYTES)
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
