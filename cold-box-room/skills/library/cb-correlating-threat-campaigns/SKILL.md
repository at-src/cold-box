---
name: cb-correlating-threat-campaigns
skill_id: cb-correlating-threat-campaigns
journal_id: CB-SKL-162
description: Cold-box analyst playbook — Correlating Threat Campaigns. Correlates
  disparate security incidents, IOCs, and adversary behaviors across time and organizations
  to identify unified threat campaigns, attribute them to common threat actors, and
  extract shared indicators for improved detection. Use whe
domain: cold-box
subdomain: threat-intelligence
tier: adjacent
case_profiles:
- threat_intel
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- campaign-analysis
- correlation
- MISP
- ATT&CK
- threat-actor
- intrusion-set
- clustering
- CTI
cold_box_version: 2
inspired_by: correlating-threat-campaigns
---

# Correlating Threat Campaigns (cold-box)

> **Journal ID:** `CB-SKL-162` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-162`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-correlating-threat-campaigns")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-correlating-threat-campaigns")` → note **`CB-SKL-162`**
2. `log_skill(case_id, journal_id="CB-SKL-162", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-162` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Multiple unrelated-appearing incidents share IOCs (same C2 IP, same malware hash, similar TTPs)
- An ISAC partner shares indicators from an incident that match your own historical events
- Building a campaign report linking adversary activity over weeks or months to a single operation

## Tool map (SIFT via MCP)

**Execution mode:** `reference` — Limited SIFT coverage; treat remaining steps as reference.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `yara` | `SIFT-045` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `yara` → `SIFT-045`

```json
{
  "tool_id": "SIFT-045",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-162] yara per playbook step",
  "why": "Executing cb-correlating-threat-campaigns \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-162` (`cb-correlating-threat-campaigns`)

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
- Multiple unrelated-appearing incidents share IOCs (same C2 IP, same malware hash, similar TTPs)
- An ISAC partner shares indicators from an incident that match your own historical events
- Building a campaign report linking adversary activity over weeks or months to a single operation

**Do not use** this skill to force correlation based on weak signals — false campaign attribution misleads defenders and wastes resources on incorrect threat models.

## Prerequisites

- TIP or SIEM with historical indicator and event data (90+ days recommended)
- MISP correlation engine enabled with event sharing configured
- Graph analysis tool (Maltego, Neo4j, or OpenCTI) for relationship visualization
- Reference to MITRE ATT&CK intrusion set and campaign objects for structuring output

## Workflow

### Step 1: Collect and Normalize Events

Gather all candidate events for correlation from:
- Internal SIEM (raw events, alert history)
- TIP (historical indicators and events)
- ISAC sharing (partner-submitted events in MISP or TAXII)
- Commercial intelligence (Recorded Future, Mandiant, CrowdStrike reports)

Normalize all events to STIX 2.1 schema with consistent timestamp (UTC), indicator types, and confidence scores. Ensure all indicators have source attribution and collection date.

### Step 2: Identify Correlation Pivot Points

Apply systematic pivot analysis across four dimensions:

**Infrastructure pivots**:
- Same IP address or /24 subnet across events
- Same domain registrant email or WHOIS organization
- Same ASN or hosting provider with same account fingerprint
- Same SSL certificate fingerprint or serial number across C2 domains

**Capability pivots**:
- Same malware hash or YARA signature match
- Same C2 communication protocol (Cobalt Strike beacon config, Sliver implant parameters)
- Same exploit code or weaponized document template
- Same obfuscation method or packer fingerprint

**Temporal pivots**:
- Events occurring within same time window (operational hours suggesting same timezone)
- Sequential events with logical kill chain progression
- Malware compilation timestamps clustering in same date range

**Victimology pivots**:
- Same target sector (healthcare, energy, financial)
- Same target geography
- Same targeted technology (specific ERP vendor, VPN appliance brand)

### Step 3: Calculate Correlation Confidence

Apply weighted scoring for campaign attribution:
```python
def calculate_campaign_confidence(events: list) -> float:
    scores = []

    # Infrastructure overlap (highest weight — most discriminating)
    infra_overlap = count_shared_infra(events) / len(events)
    scores.append(infra_overlap * 40)

    # Capability overlap (high weight — TTPs are durable)
    capability_overlap = count_shared_ttps(events) / len(events)
    scores.append(capability_overlap * 35)

    # Temporal proximity (moderate weight)
    temporal_score = assess_temporal_clustering(events)
    scores.append(temporal_score * 15)

    # Victimology alignment (lower weight — many actors target same sector)
    victim_score = assess_victim_pattern(events)
    scores.append(victim_score * 10)

    total = sum(scores)
    if total >= 70: return "HIGH"
    elif total >= 45: return "MEDIUM"
    else: return "LOW"
```

### Step 4: Build Campaign Graph

In OpenCTI or Maltego, construct campaign graph:
- Campaign object (STIX) as central node
- Intrusion Set → uses → Malware objects
- Intrusion Set → uses → Infrastructure objects
- Intrusion Set → targets → Identity objects (victim organizations/sectors)
- Campaign → attributed-to → Threat Actor (if attribution achieved)
- Indicators → indicates → Malware (linking technical observables to capabilities)

Label each relationship with evidence reference and confidence.

### Step 5: Produce Campaign Intelligence Report

Structure the campaign report:
1. **Campaign name**: Assign descriptive codename based on targeting theme or tooling
2. **Timeline**: First/last observed dates with activity phases
3. **Attribution**: Suspected threat actor with confidence level
4. **Target profile**: Industry verticals, geographies, organization sizes
5. **TTPs summary**: ATT&CK Navigator heatmap for campaign-specific techniques
6. **Shared indicators**: IOCs that span multiple incidents (highest confidence for blocking)
7. **Detection guidance**: Sigma/YARA rules specific to this campaign

## Key Concepts

| Term | Definition |
|------|-----------|
| **Campaign** | STIX object representing a grouping of adversarial behaviors with common objectives over a defined time period |
| **Intrusion Set** | STIX object grouping related intrusion activity by common objectives, even when actor identity is uncertain |
| **Pivot** | Using a single data point (IOC, infrastructure, TTP) to discover related events or adversary artifacts |
| **Clustering** | Machine learning or manual grouping of incidents based on feature similarity to identify campaign boundaries |
| **False Correlation** | Incorrect linking of unrelated incidents due to shared infrastructure (CDNs, shared hosting) or common tools |

## Tools & Systems

- **MISP Correlation Engine**: Automatic correlation of events sharing attribute values across the MISP instance and federated instances
- **OpenCTI Graph**: Interactive relationship graph for visualizing campaign linkages with STIX object types
- **Maltego**: Link analysis for infrastructure and capability pivoting across multiple data sources
- **Neo4j**: Graph database with Cypher queries for large-scale campaign correlation (millions of events)

## Common Pitfalls

- **CDN/Shared hosting false positives**: Cloudflare, AWS CloudFront, and bulletproof hosters serve multiple threat actors. Shared IP alone does not establish campaign linkage.
- **Common malware conflation**: Multiple threat actors use Cobalt Strike. Shared capability does not indicate same actor without additional corroboration.
- **Premature attribution**: Forcing campaign-to-actor attribution before evidence threshold is reached produces incorrect intelligence that persists in reports.
- **Missing temporal analysis**: Events from different years may share infrastructure that was recycled by a different actor, not the same campaign.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
