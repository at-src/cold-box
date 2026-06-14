---
name: cb-profiling-threat-actor-groups
skill_id: cb-profiling-threat-actor-groups
journal_id: CB-SKL-313
description: Cold-box analyst playbook — Profiling Threat Actor Groups. Develops comprehensive
  threat actor profiles for APT groups, criminal organizations, and hacktivist collectives
  by aggregating TTP documentation, historical campaign data, tooling fingerprints,
  and attribution indicators from multiple intel
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
- MITRE-ATT&CK
- threat-actor
- APT
- CrowdStrike
- Mandiant
- attribution
- kill-chain
- NIST-CSF
cold_box_version: 2
inspired_by: profiling-threat-actor-groups
---

# Profiling Threat Actor Groups (cold-box)

> **Journal ID:** `CB-SKL-313` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-313`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-profiling-threat-actor-groups")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-profiling-threat-actor-groups")` → note **`CB-SKL-313`**
2. `log_skill(case_id, journal_id="CB-SKL-313", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-313` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Updating the organization's threat model with profiles of adversary groups recently observed targeting your sector
- Preparing an executive briefing on APT groups that align with geopolitical events affecting your business
- Enabling SOC analysts to understand attacker objectives and TTPs to improve detection tuning

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
  "purpose": "[CB-SKL-313] yara per playbook step",
  "why": "Executing cb-profiling-threat-actor-groups \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-313` (`cb-profiling-threat-actor-groups`)

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
- Updating the organization's threat model with profiles of adversary groups recently observed targeting your sector
- Preparing an executive briefing on APT groups that align with geopolitical events affecting your business
- Enabling SOC analysts to understand attacker objectives and TTPs to improve detection tuning

**Do not use** this skill for real-time incident attribution — attribution during active incidents should be deprioritized in favor of containment. Profile refinement occurs post-incident.

## Prerequisites

- Access to MITRE ATT&CK Groups database (https://attack.mitre.org/groups/)
- Commercial threat intelligence subscription (Mandiant Advantage, CrowdStrike Falcon Intelligence, or Recorded Future)
- Sector-specific ISAC membership for targeted intelligence (FS-ISAC, H-ISAC, E-ISAC)
- Structured profile template (see workflow below)

## Workflow

### Step 1: Identify Relevant Threat Actors

Cross-reference your organization's sector, geography, and technology stack against known adversary targeting patterns. Sources:
- MITRE ATT&CK Groups: 130+ documented nation-state and criminal groups with TTP mappings
- CrowdStrike Annual Threat Report: adversary naming by nation-state (BEAR=Russia, PANDA=China, KITTEN=Iran, CHOLLIMA=North Korea)
- Mandiant M-Trends: annual report with sector-specific targeting statistics
- CISA Known Exploited Vulnerabilities (KEV) catalog: identifies vulnerabilities actively exploited by specific threat actors

Shortlist 5–10 groups most likely to target your organization based on sector alignment and recent activity.

### Step 2: Collect Profile Data

For each adversary, document across standard dimensions:

**Identity**: ATT&CK Group ID (e.g., G0016 for APT29), aliases (Cozy Bear, The Dukes, Midnight Blizzard), suspected nation-state sponsor

**Motivations**: Espionage, financial gain, disruption, intellectual property theft

**Targeting**: Sectors, geographies, organization sizes, technology targets (OT/IT, cloud, supply chain)

**Capabilities**: Custom malware (e.g., APT29's SUNBURST, MiniDuke), exploitation of 0-days vs. known CVEs, supply chain attack capability

**Campaign History**: Notable operations with dates (SolarWinds 2020, Exchange Server 2021, etc.)

**TTPs by ATT&CK Phase**: Document top 5 techniques per tactic phase

### Step 3: Map TTPs to ATT&CK

Using mitreattack-python:
```python
from mitreattack.stix20 import MitreAttackData

mitre = MitreAttackData("enterprise-attack.json")
apt29 = mitre.get_object_by_attack_id("G0016", "groups")
techniques = mitre.get_techniques_used_by_group(apt29)

profile = {}
for item in techniques:
    tech = item["object"]
    tid = tech["external_references"][0]["external_id"]
    tactic = [p["phase_name"] for p in tech.get("kill_chain_phases", [])]
    profile[tid] = {"name": tech["name"], "tactics": tactic}
```

### Step 4: Assess Detection Coverage Against Profile

Compare the adversary's technique list against your detection coverage matrix (from ATT&CK Navigator layer). Identify:
- Techniques used by this group where you have no detection (critical gaps)
- Techniques where you have partial coverage (logging but no alerting)
- Compensating controls where detection is not feasible (network segmentation as mitigation for lateral movement)

### Step 5: Package Profile for Distribution

Structure the final profile for different audiences:
- **Executive summary** (1 page): Who, motivation, recent campaigns, top risk to our organization, recommended priority actions
- **SOC analyst brief** (3–5 pages): Full TTP list with detection status, IOC list, hunt hypotheses
- **Technical appendix**: YARA rules, Sigma detections, STIX JSON object for TIP import

Classify TLP:AMBER for internal distribution; seek ISAC approval before external sharing.

## Key Concepts

| Term | Definition |
|------|-----------|
| **APT** | Advanced Persistent Threat — well-resourced, sophisticated adversary (typically nation-state or sophisticated criminal) conducting long-term targeted operations |
| **TTPs** | Tactics, Techniques, Procedures — behavioral fingerprint of an adversary group, more durable than IOCs which change frequently |
| **Aliases** | Threat actors receive different names from different vendors (APT29 = Cozy Bear = The Dukes = Midnight Blizzard = YTTRIUM) |
| **Attribution** | Process of associating an attack with a specific threat actor; requires multiple independent corroborating data points and carries inherent uncertainty |
| **Cluster** | A group of related intrusion activity that may or may not be attributable to a single actor; used when attribution is uncertain |
| **Intrusion Set** | STIX SDO type representing a grouped set of adversarial behaviors with common objectives, even if actor identity is unknown |

## Tools & Systems

- **MITRE ATT&CK Groups**: Free, community-maintained database of 130+ documented adversary groups with referenced campaign reports
- **Mandiant Advantage Threat Intelligence**: Commercial platform with detailed APT profiles, malware families, and campaign analysis
- **CrowdStrike Falcon Intelligence**: Commercial feed with adversary-centric profiles and real-time attribution updates
- **Recorded Future Threat Intelligence**: Combines OSINT, dark web, and technical intelligence for adversary profiling
- **OpenCTI**: Graph-based visualization of threat actor relationships, tooling, and campaign linkages

## Common Pitfalls

- **IOC-centric profiles**: Building profiles around IP addresses and domains rather than TTPs means the profile becomes stale within weeks as infrastructure rotates.
- **Vendor alias confusion**: Conflating two different threat actor groups due to shared malware or infrastructure leads to incorrect threat model assumptions.
- **Binary attribution**: Treating attribution as certain when it is probabilistic. Always qualify attribution confidence level (Low/Medium/High).
- **Neglecting insider and criminal groups**: Overemphasis on nation-state APTs while ignoring ransomware groups (Cl0p, LockBit, ALPHV) which represent higher probability threats for most organizations.
- **Profile staleness**: Adversary TTPs evolve. Profiles not updated quarterly may miss technique changes, new malware, or targeting shifts.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
