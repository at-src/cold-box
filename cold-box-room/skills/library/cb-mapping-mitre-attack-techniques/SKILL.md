---
name: cb-mapping-mitre-attack-techniques
skill_id: cb-mapping-mitre-attack-techniques
journal_id: CB-SKL-082
description: Cold-box analyst playbook — Mapping Mitre Attack Techniques. Maps observed
  adversary behaviors, security alerts, and detection rules to MITRE ATT&CK techniques
  and sub-techniques to quantify detection coverage and guide control prioritization.
  Use when building an ATT&CK-based coverage heatmap, taggi
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
- MITRE-ATT&CK
- ATT&CK-Navigator
- Sigma
- D3FEND
- TTP
- detection-engineering
- NIST-CSF
cold_box_version: 2
inspired_by: mapping-mitre-attack-techniques
---

# Mapping Mitre Attack Techniques (cold-box)

> **Journal ID:** `CB-SKL-082` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-082`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-mapping-mitre-attack-techniques")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-mapping-mitre-attack-techniques")` → note **`CB-SKL-082`**
2. `log_skill(case_id, journal_id="CB-SKL-082", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-082` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Generating an ATT&CK coverage heatmap to show which techniques your detection stack addresses
- Tagging existing SIEM use cases or Sigma rules with ATT&CK technique IDs for structured reporting
- Aligning your security program roadmap to specific adversary groups known to target your sector

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-082] powershell per playbook step",
  "why": "Executing cb-mapping-mitre-attack-techniques \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-082] file per playbook step",
  "why": "Executing cb-mapping-mitre-attack-techniques \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-082` (`cb-mapping-mitre-attack-techniques`)

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
- Generating an ATT&CK coverage heatmap to show which techniques your detection stack addresses
- Tagging existing SIEM use cases or Sigma rules with ATT&CK technique IDs for structured reporting
- Aligning your security program roadmap to specific adversary groups known to target your sector

**Do not use** this skill for real-time incident triage — ATT&CK mapping is an analytical activity best performed post-detection or during threat hunting planning.

## Prerequisites

- Access to MITRE ATT&CK knowledge base (https://attack.mitre.org) or local ATT&CK STIX data bundle
- ATT&CK Navigator web app or local installation (https://mitre-attack.github.io/attack-navigator/)
- Inventory of existing detection rules (Sigma, Splunk, Sentinel KQL) to assess current coverage
- ATT&CK Python library: `pip install mitreattack-python`

## Workflow

### Step 1: Obtain Current ATT&CK Data

Download the latest ATT&CK STIX bundle for the relevant matrix (Enterprise, Mobile, ICS):
```bash
curl -o enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

Use the mitreattack-python library to query techniques programmatically:
```python
from mitreattack.stix20 import MitreAttackData

mitre = MitreAttackData("enterprise-attack.json")
techniques = mitre.get_techniques(remove_revoked_deprecated=True)
for t in techniques[:5]:
    print(t["external_references"][0]["external_id"], t["name"])
```

### Step 2: Map Existing Detections to Techniques

For each SIEM rule or Sigma file, assign ATT&CK technique IDs. Sigma rules support native ATT&CK tagging:
```yaml
tags:
  - attack.execution
  - attack.t1059.001  # PowerShell
  - attack.t1059.003  # Windows Command Shell
```

Create a coverage matrix: list each technique ID and mark as: Detected (alert fires), Logged (data present but no alert), Blind (no data source).

### Step 3: Prioritize Coverage Gaps Using Threat Intelligence

Cross-reference coverage gaps with adversary groups targeting your sector. Use ATT&CK Groups data:
```python
groups = mitre.get_groups()
apt29 = mitre.get_object_by_attack_id("G0016", "groups")
apt29_techniques = mitre.get_techniques_used_by_group(apt29)
for t in apt29_techniques:
    print(t["object"]["external_references"][0]["external_id"])
```

Prioritize adding detection for techniques used by high-priority threat groups where your coverage is blind.

### Step 4: Build Navigator Heatmap

Export coverage scores as ATT&CK Navigator JSON layer:
```python
import json

layer = {
    "name": "SOC Detection Coverage Q1 2025",
    "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
    "domain": "enterprise-attack",
    "techniques": [
        {"techniqueID": "T1059.001", "score": 100, "comment": "Splunk rule: PS_Encoded_Command"},
        {"techniqueID": "T1071.001", "score": 50, "comment": "Logged only, no alert"},
        {"techniqueID": "T1055", "score": 0, "comment": "No coverage — blind spot"}
    ],
    "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100}
}
with open("coverage_layer.json", "w") as f:
    json.dump(layer, f)
```

Import layer into ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/) for visualization.

### Step 5: Generate Executive Coverage Report

Summarize coverage by tactic category (Initial Access, Execution, Persistence, etc.) with counts and percentages. Provide a risk-ranked list of top 10 blind-spot techniques based on adversary group usage frequency. Recommend data source additions (e.g., "Enable PowerShell Script Block Logging to address 12 Execution sub-technique gaps").

## Key Concepts

| Term | Definition |
|------|-----------|
| **ATT&CK Technique** | Specific adversary method identified by T-number (e.g., T1059 = Command and Scripting Interpreter) |
| **Sub-technique** | More granular variant of a technique (e.g., T1059.001 = PowerShell, T1059.003 = Windows Command Shell) |
| **Tactic** | Adversary goal category in ATT&CK: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, C&C, Exfiltration, Impact |
| **Data Source** | ATT&CK v10+ component identifying telemetry required to detect a technique (e.g., Process Creation, Network Traffic) |
| **Coverage Score** | Numeric (0–100) representing detection completeness for a technique: 0=blind, 50=logged only, 100=alerted |
| **MITRE D3FEND** | Defensive countermeasure ontology complementing ATT&CK — maps defensive techniques to attack techniques they mitigate |

## Tools & Systems

- **ATT&CK Navigator**: Browser-based heatmap visualization tool for layering coverage scores and annotations on the ATT&CK matrix
- **mitreattack-python**: Official MITRE Python library for programmatic access to ATT&CK STIX data (techniques, groups, software, mitigations)
- **Atomic Red Team**: MITRE-aligned test library providing atomic test cases to validate detection for each technique
- **Sigma**: Detection rule format with ATT&CK tagging support; translatable to Splunk, Sentinel, QRadar, Elastic
- **ATT&CK Workbench**: Self-hosted ATT&CK knowledge base for organizations maintaining custom technique extensions

## Common Pitfalls

- **Over-claiming coverage**: Logging a data source (e.g., process creation events) does not mean the associated technique is detected — a rule must actually fire on malicious patterns.
- **Mapping at tactic level only**: Tagging a rule as "attack.execution" without a specific technique ID prevents granular gap analysis.
- **Ignoring sub-techniques**: Many adversaries use specific sub-techniques. Coverage of T1059 (parent) doesn't imply coverage of T1059.005 (Visual Basic).
- **Static mapping without updates**: ATT&CK releases major versions annually. Coverage maps go stale as techniques are added, revised, or deprecated.
- **Not mapping to adversary groups**: Generic coverage maps don't distinguish between techniques used by APTs targeting your sector vs. commodity malware.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
