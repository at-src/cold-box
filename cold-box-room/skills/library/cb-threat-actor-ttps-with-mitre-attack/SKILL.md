---
name: cb-threat-actor-ttps-with-mitre-attack
skill_id: cb-threat-actor-ttps-with-mitre-attack
journal_id: CB-SKL-328
description: Cold-box analyst playbook — Threat Actor Ttps With Mitre Attack. MITRE
  ATT&CK is a globally-accessible knowledge base of adversary tactics, techniques,
  and procedures (TTPs) based on real-world observations. This skill covers systematically
  mapping threat actor beh
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
- threat-intelligence
- cti
- ioc
- mitre-attack
- stix
- ttp-analysis
- threat-actors
cold_box_version: 2
inspired_by: analyzing-threat-actor-ttps-with-mitre-attack
---

# Threat Actor Ttps With Mitre Attack (cold-box)

> **Journal ID:** `CB-SKL-328` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-328`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-threat-actor-ttps-with-mitre-attack")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-threat-actor-ttps-with-mitre-attack")` → note **`CB-SKL-328`**
2. `log_skill(case_id, journal_id="CB-SKL-328", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-328` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing threat actor ttps with mitre attack
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `find` | `SIFT-009` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-328] find per playbook step",
  "why": "Executing cb-threat-actor-ttps-with-mitre-attack \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-328` (`cb-threat-actor-ttps-with-mitre-attack`)

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

MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations. This skill covers systematically mapping threat actor behavior to the ATT&CK framework, building technique coverage heatmaps using the ATT&CK Navigator, identifying detection gaps, and producing actionable intelligence reports that link observed IOCs to specific adversary techniques across the Enterprise, Mobile, and ICS matrices.


## When to Use

- When investigating security incidents that require analyzing threat actor ttps with mitre attack
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Python 3.9+ with `mitreattack-python`, `attackcti`, `stix2` libraries
- MITRE ATT&CK Navigator (web-based or local deployment)
- Understanding of ATT&CK matrix structure: Tactics, Techniques, Sub-techniques
- Access to threat intelligence reports or MISP/OpenCTI for threat actor data
- Familiarity with STIX 2.1 Attack Pattern objects

## Key Concepts

### ATT&CK Matrix Structure

The ATT&CK Enterprise matrix organizes adversary behavior into 14 Tactics (the "why") containing Techniques (the "how") and Sub-techniques (specific implementations). Each technique has associated data sources, detections, mitigations, and real-world procedure examples from observed threat groups.

### Threat Group Profiles

ATT&CK catalogs over 140 threat groups (e.g., APT28, APT29, Lazarus Group, FIN7) with documented technique usage. Each group profile includes aliases, targeted sectors, associated campaigns, software used, and technique mappings with procedure-level detail.

### ATT&CK Navigator

The ATT&CK Navigator is a web-based tool for creating custom ATT&CK matrix visualizations. Analysts create layers (JSON files) that annotate techniques with scores, colors, comments, and metadata to visualize threat actor coverage, detection capabilities, or risk assessments.

## Workflow

### Step 1: Query ATT&CK Data Programmatically

```python
from attackcti import attack_client
import json

# Initialize ATT&CK client (queries MITRE TAXII server)
lift = attack_client()

# Get all Enterprise techniques
enterprise_techniques = lift.get_enterprise_techniques()
print(f"Total Enterprise techniques: {len(enterprise_techniques)}")

# Get all threat groups
groups = lift.get_groups()
print(f"Total threat groups: {len(groups)}")

# Get specific group by name
apt29 = [g for g in groups if 'APT29' in g.get('name', '')]
if apt29:
    group = apt29[0]
    print(f"Group: {group['name']}")
    print(f"Aliases: {group.get('aliases', [])}")
    print(f"Description: {group.get('description', '')[:200]}")
```

### Step 2: Map Threat Actor to ATT&CK Techniques

```python
from attackcti import attack_client

lift = attack_client()

# Get techniques used by APT29
apt29_techniques = lift.get_techniques_used_by_group("G0016")  # APT29 group ID

technique_map = {}
for entry in apt29_techniques:
    tech_id = entry.get("external_references", [{}])[0].get("external_id", "")
    tech_name = entry.get("name", "")
    description = entry.get("description", "")
    tactic_refs = [
        phase.get("phase_name", "")
        for phase in entry.get("kill_chain_phases", [])
    ]

    technique_map[tech_id] = {
        "name": tech_name,
        "tactics": tactic_refs,
        "description": description[:300],
    }

print(f"\nAPT29 uses {len(technique_map)} techniques:")
for tid, info in sorted(technique_map.items()):
    print(f"  {tid}: {info['name']} [{', '.join(info['tactics'])}]")
```

### Step 3: Generate ATT&CK Navigator Layer

```python
import json

def create_navigator_layer(group_name, technique_map, description=""):
    """Generate ATT&CK Navigator layer JSON for a threat group."""
    techniques_list = []
    for tech_id, info in technique_map.items():
        techniques_list.append({
            "techniqueID": tech_id,
            "tactic": info["tactics"][0] if info["tactics"] else "",
            "color": "#ff6666",  # Red for observed techniques
            "comment": info["description"][:200],
            "enabled": True,
            "score": 100,
            "metadata": [
                {"name": "group", "value": group_name},
            ],
        })

    layer = {
        "name": f"{group_name} TTP Coverage",
        "versions": {
            "attack": "16.1",
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": description or f"Techniques attributed to {group_name}",
        "filters": {"platforms": ["Windows", "Linux", "macOS", "Cloud"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques_list,
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Observed technique", "color": "#ff6666"},
            {"label": "Not observed", "color": "#ffffff"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }

    return layer


# Generate and save layer
layer = create_navigator_layer("APT29", technique_map, "APT29 (Cozy Bear) TTP analysis")
with open("apt29_navigator_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
print("[+] Navigator layer saved to apt29_navigator_layer.json")
```

### Step 4: Identify Detection Gaps

```python
from attackcti import attack_client

lift = attack_client()

# Get all techniques with data sources
all_techniques = lift.get_enterprise_techniques()

# Build data source coverage map
data_source_coverage = {}
for tech in all_techniques:
    tech_id = tech.get("external_references", [{}])[0].get("external_id", "")
    data_sources = tech.get("x_mitre_data_sources", [])

    for ds in data_sources:
        if ds not in data_source_coverage:
            data_source_coverage[ds] = []
        data_source_coverage[ds].append(tech_id)

# Compare threat actor techniques against available detections
detected_techniques = {"T1059", "T1071", "T1566"}  # Example: techniques you can detect
actor_techniques = set(technique_map.keys())

covered = actor_techniques.intersection(detected_techniques)
gaps = actor_techniques - detected_techniques

print(f"\n=== Detection Gap Analysis for APT29 ===")
print(f"Actor techniques: {len(actor_techniques)}")
print(f"Detected: {len(covered)} ({len(covered)/len(actor_techniques)*100:.0f}%)")
print(f"Gaps: {len(gaps)} ({len(gaps)/len(actor_techniques)*100:.0f}%)")
print(f"\nUndetected techniques:")
for tech_id in sorted(gaps):
    if tech_id in technique_map:
        print(f"  {tech_id}: {technique_map[tech_id]['name']}")
```

### Step 5: Cross-Group Technique Comparison

```python
from attackcti import attack_client

lift = attack_client()

# Compare techniques across multiple groups
groups_to_compare = {
    "G0016": "APT29",
    "G0007": "APT28",
    "G0032": "Lazarus Group",
}

group_techniques = {}
for gid, gname in groups_to_compare.items():
    techs = lift.get_techniques_used_by_group(gid)
    tech_ids = set()
    for t in techs:
        tid = t.get("external_references", [{}])[0].get("external_id", "")
        if tid:
            tech_ids.add(tid)
    group_techniques[gname] = tech_ids

# Find common and unique techniques
all_groups = list(group_techniques.keys())
common_to_all = set.intersection(*group_techniques.values())
print(f"\nTechniques common to all {len(all_groups)} groups: {len(common_to_all)}")
for tid in sorted(common_to_all):
    print(f"  {tid}")

for gname, techs in group_techniques.items():
    unique = techs - set.union(*[t for n, t in group_techniques.items() if n != gname])
    print(f"\nUnique to {gname}: {len(unique)} techniques")
```

## Validation Criteria

- ATT&CK data successfully queried via TAXII server or local copy
- Threat actor mapped to specific techniques with procedure examples
- ATT&CK Navigator layer JSON is valid and renders correctly
- Detection gap analysis identifies unmonitored techniques
- Cross-group comparison reveals shared and unique TTPs
- Output is actionable for detection engineering prioritization

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [attackcti Python Library](https://github.com/OTRF/ATTACK-Python-Client)
- [ATT&CK STIX Data](https://github.com/mitre/cti)
- [ATT&CK Groups](https://attack.mitre.org/groups/)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
