---
name: cb-implementing-diamond-model-analysis
skill_id: cb-implementing-diamond-model-analysis
journal_id: CB-SKL-258
description: Cold-box analyst playbook — Implementing Diamond Model Analysis. The
  Diamond Model of Intrusion Analysis provides a structured framework for analyzing
  cyber intrusions by examining four core features - Adversary, Capability, Infrastructure,
  and Victim. This skill covers implementing the Diamond Model pro
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
- diamond-model
- intrusion-analysis
cold_box_version: 2
inspired_by: implementing-diamond-model-analysis
---

# Implementing Diamond Model Analysis (cold-box)

> **Journal ID:** `CB-SKL-258` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-258`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-diamond-model-analysis")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-diamond-model-analysis")` → note **`CB-SKL-258`**
2. `log_skill(case_id, journal_id="CB-SKL-258", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-258` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring implementing diamond model analysis capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

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
  "purpose": "[CB-SKL-258] find per playbook step",
  "why": "Executing cb-implementing-diamond-model-analysis \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-258` (`cb-implementing-diamond-model-analysis`)

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

The Diamond Model of Intrusion Analysis provides a structured framework for analyzing cyber intrusions by examining four core features: Adversary, Capability, Infrastructure, and Victim. This skill covers implementing the Diamond Model programmatically to classify and correlate intrusion events, build activity threads linking related events, create activity-attack graphs, and generate pivot-ready intelligence from intrusion data.


## When to Use

- When deploying or configuring implementing diamond model analysis capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Python 3.9+ with `networkx`, `stix2`, `graphviz` libraries
- Understanding of the Diamond Model core and meta-features
- Access to threat intelligence data (MISP/OpenCTI events)
- Familiarity with MITRE ATT&CK for capability mapping

## Key Concepts

### Diamond Model Core Features
- **Adversary**: The threat actor or operator conducting the intrusion
- **Capability**: The tools, techniques, and malware used (maps to ATT&CK)
- **Infrastructure**: C2 servers, domains, email addresses, hosting providers
- **Victim**: Target organization, system, person, or data asset

### Meta-Features
- **Timestamp**: When the event occurred
- **Phase**: Kill chain stage (recon, delivery, exploitation, etc.)
- **Result**: Success, failure, or unknown
- **Direction**: Adversary-to-infrastructure, infrastructure-to-victim, etc.
- **Methodology**: Social engineering, technical exploit, insider threat
- **Resources**: Financial, human, technical resources required

### Activity Threads and Groups
- **Activity Thread**: Sequence of Diamond events from a single adversary operation
- **Activity Group**: Cluster of threads attributed to the same adversary

## Workflow

### Step 1: Define Diamond Event Data Structure

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json
import uuid

@dataclass
class DiamondEvent:
    adversary: str = ""
    capability: str = ""
    infrastructure: str = ""
    victim: str = ""
    timestamp: str = ""
    phase: str = ""
    result: str = ""
    direction: str = ""
    methodology: str = ""
    confidence: int = 0
    notes: str = ""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    mitre_techniques: list = field(default_factory=list)
    iocs: list = field(default_factory=list)

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "adversary": self.adversary,
            "capability": self.capability,
            "infrastructure": self.infrastructure,
            "victim": self.victim,
            "timestamp": self.timestamp,
            "phase": self.phase,
            "result": self.result,
            "direction": self.direction,
            "methodology": self.methodology,
            "confidence": self.confidence,
            "mitre_techniques": self.mitre_techniques,
            "iocs": self.iocs,
            "notes": self.notes,
        }
```

### Step 2: Build Activity Thread from Events

```python
import networkx as nx

class DiamondAnalysis:
    def __init__(self):
        self.events = []
        self.graph = nx.DiGraph()

    def add_event(self, event: DiamondEvent):
        self.events.append(event)
        self.graph.add_node(event.event_id, **event.to_dict())

    def build_activity_thread(self):
        """Link events chronologically into activity threads."""
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)
        for i in range(len(sorted_events) - 1):
            self.graph.add_edge(
                sorted_events[i].event_id,
                sorted_events[i + 1].event_id,
                relationship="followed_by",
            )

    def find_pivots(self):
        """Find pivot points where events share infrastructure or capabilities."""
        pivots = {"infrastructure": {}, "capability": {}, "adversary": {}}

        for event in self.events:
            if event.infrastructure:
                pivots["infrastructure"].setdefault(event.infrastructure, []).append(event.event_id)
            if event.capability:
                pivots["capability"].setdefault(event.capability, []).append(event.event_id)
            if event.adversary:
                pivots["adversary"].setdefault(event.adversary, []).append(event.event_id)

        return {
            k: {pk: pv for pk, pv in v.items() if len(pv) > 1}
            for k, v in pivots.items()
        }

    def generate_report(self):
        return {
            "total_events": len(self.events),
            "unique_adversaries": len(set(e.adversary for e in self.events if e.adversary)),
            "unique_victims": len(set(e.victim for e in self.events if e.victim)),
            "unique_infrastructure": len(set(e.infrastructure for e in self.events if e.infrastructure)),
            "pivots": self.find_pivots(),
            "events": [e.to_dict() for e in self.events],
        }
```

## Validation Criteria

- Diamond events capture all four core features with meta-features
- Activity threads link related events chronologically
- Pivot analysis identifies shared infrastructure and capabilities across events
- Graph visualization renders the activity-attack graph correctly
- Events map to MITRE ATT&CK techniques for capability classification

## References

- [Diamond Model Paper](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [STIX 2.1 Campaign Object](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
