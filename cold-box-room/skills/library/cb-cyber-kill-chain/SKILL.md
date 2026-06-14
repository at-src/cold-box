---
name: cb-cyber-kill-chain
skill_id: cb-cyber-kill-chain
journal_id: CB-SKL-163
description: Cold-box analyst playbook — Cyber Kill Chain. Analyzes intrusion activity
  against the Lockheed Martin Cyber Kill Chain framework to identify which phases
  an adversary has completed, where defenses succeeded or failed, and what controls
  would have interrupted the attack at earlier phase
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
- kill-chain
- Lockheed-Martin
- MITRE-ATT&CK
- intrusion-analysis
- defense-in-depth
- NIST-CSF
cold_box_version: 2
inspired_by: analyzing-cyber-kill-chain
---

# Cyber Kill Chain (cold-box)

> **Journal ID:** `CB-SKL-163` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-163`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-cyber-kill-chain")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-cyber-kill-chain")` → note **`CB-SKL-163`**
2. `log_skill(case_id, journal_id="CB-SKL-163", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-163` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Conducting post-incident analysis to determine how far an adversary progressed through an attack sequence
- Designing layered defensive controls with the goal of interrupting attacks at the earliest possible phase
- Producing threat intelligence reports that communicate attack progression to non-technical stakeholders

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
## {timestamp} — skill `CB-SKL-163` (`cb-cyber-kill-chain`)

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
- Conducting post-incident analysis to determine how far an adversary progressed through an attack sequence
- Designing layered defensive controls with the goal of interrupting attacks at the earliest possible phase
- Producing threat intelligence reports that communicate attack progression to non-technical stakeholders

**Do not use** this skill as a standalone framework — combine with MITRE ATT&CK for technique-level granularity beyond what the 7-phase kill chain provides.

## Prerequisites

- Complete incident timeline with forensic artifacts mapped to specific adversary actions
- MITRE ATT&CK Enterprise matrix for technique-level mapping within each kill chain phase
- Access to threat intelligence on the suspected adversary group's typical kill chain progression
- Post-incident report or IR timeline from responding team

## Workflow

### Step 1: Map Observed Actions to Kill Chain Phases

The Lockheed Martin Cyber Kill Chain consists of seven phases. Map all observed adversary actions:

**Phase 1 - Reconnaissance**: Adversary gathers target information before attack.
- Indicators: DNS queries from adversary IP, LinkedIn scraping, job posting analysis, Shodan scans of organization infrastructure

**Phase 2 - Weaponization**: Adversary creates attack tool (malware + exploit).
- Indicators: Malware compilation timestamps, exploit document metadata, builder artifacts in malware samples

**Phase 3 - Delivery**: Adversary transmits weapon to target.
- Indicators: Phishing emails, malicious attachments, drive-by downloads, USB drops, supply chain compromise

**Phase 4 - Exploitation**: Adversary exploits vulnerability to execute code.
- Indicators: CVE exploitation events in application/OS logs, memory corruption artifacts, shellcode execution

**Phase 5 - Installation**: Adversary establishes persistence on target.
- Indicators: New scheduled tasks, registry run keys, service installation, web shells, bootkits

**Phase 6 - Command & Control (C2)**: Adversary communicates with compromised system.
- Indicators: Beaconing traffic (regular intervals), DNS tunneling, HTTPS to uncommon domains, C2 framework signatures (Cobalt Strike, Sliver)

**Phase 7 - Actions on Objectives**: Adversary achieves goals.
- Indicators: Data staging/exfiltration, lateral movement, ransomware execution, destructive activity

### Step 2: Identify Phase Completion and Detection Points

Create a phase matrix for the incident:
```
Phase 1: Recon        → Completed (undetected)
Phase 2: Weaponize    → Completed (undetected — pre-attack)
Phase 3: Delivery     → Completed; phishing email bypassed SEG
Phase 4: Exploit      → Completed; CVE-2023-23397 exploited
Phase 5: Install      → DETECTED: EDR flagged scheduled task creation (attack stalled here)
Phase 6: C2           → Not achieved (installation blocked)
Phase 7: Objectives   → Not achieved
```

For each phase completed without detection, document the defensive control gap.

### Step 3: Map to MITRE ATT&CK for Technique Detail

Each kill chain phase maps to multiple ATT&CK tactics:
- Delivery → Initial Access (TA0001)
- Exploitation → Execution (TA0002)
- Installation → Persistence (TA0003), Privilege Escalation (TA0004)
- C2 → Command and Control (TA0011)
- Actions on Objectives → Exfiltration (TA0010), Impact (TA0040)

Within each phase, enumerate specific ATT&CK techniques observed and map to existing detections.

### Step 4: Identify Courses of Action per Phase

For each phase, document applicable defensive courses of action (COAs):
- **Detect COA**: What detection would alert on adversary activity in this phase?
- **Deny COA**: What control would prevent the adversary from completing this phase?
- **Disrupt COA**: What control would interrupt the adversary mid-phase?
- **Degrade COA**: What control would reduce the adversary's effectiveness in this phase?
- **Deceive COA**: What deception (honeypots, canary tokens) would expose activity in this phase?
- **Destroy COA**: What active defense capability would neutralize adversary infrastructure?

### Step 5: Produce Kill Chain Analysis Report

Structure findings as:
1. Attack narrative (timeline of phases)
2. Phase-by-phase analysis with evidence
3. Detection point analysis (what worked, what failed)
4. Defensive recommendation per phase prioritized by cost/effectiveness
5. Control improvement roadmap

## Key Concepts

| Term | Definition |
|------|-----------|
| **Kill Chain** | Sequential model of adversary intrusion phases; breaking any link theoretically stops the attack |
| **Courses of Action (COA)** | Defensive responses mapped to each kill chain phase: detect, deny, disrupt, degrade, deceive, destroy |
| **Beaconing** | Regular, periodic C2 check-in pattern from compromised host to adversary server; detectable by frequency analysis |
| **Phase Completion** | Adversary successfully finishes a kill chain phase and progresses to the next; defense-in-depth aims to prevent this |
| **Intelligence Gain/Loss** | Analysis of whether detecting at Phase 5 (vs. Phase 3) reduced intelligence about adversary capabilities or intent |

## Tools & Systems

- **MITRE ATT&CK Navigator**: Overlay kill chain phases with ATT&CK technique coverage for integrated analysis
- **Elastic Security EQL**: Event Query Language for querying multi-phase attack sequences in Elastic SIEM
- **Splunk ES**: Timeline visualization and correlation searches for kill chain phase sequencing
- **MISP**: Kill chain tagging via galaxy clusters for structured incident event documentation

## Common Pitfalls

- **Linear assumption**: Adversaries don't always progress linearly — they may skip phases (weaponization already complete from previous campaign) or loop back (re-establish C2 after detection).
- **Ignoring Phases 1 and 2**: Reconnaissance and weaponization occur before the defender has visibility. Intelligence about these phases requires external sources (OSINT, threat intelligence).
- **Missing insider threats**: The kill chain was designed for external adversaries. Insider threats may skip directly to Phase 7 without traversing earlier phases.
- **Confusing with ATT&CK tactics**: The 7-phase kill chain and 14 ATT&CK tactics are complementary but not directly equivalent. Maintain distinction to prevent analytic confusion.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
