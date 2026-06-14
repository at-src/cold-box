---
name: cb-indicator-lifecycle-management
skill_id: cb-indicator-lifecycle-management
journal_id: CB-SKL-290
description: Cold-box analyst playbook — Indicator Lifecycle Management. Indicator
  lifecycle management tracks IOCs from initial discovery through validation, enrichment,
  deployment, monitoring, and eventual retirement. This skill covers implementing
  systematic processes f
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
- indicator-lifecycle
- ioc-management
cold_box_version: 2
inspired_by: performing-indicator-lifecycle-management
---

# Indicator Lifecycle Management (cold-box)

> **Journal ID:** `CB-SKL-290` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-290`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-indicator-lifecycle-management")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-indicator-lifecycle-management")` → note **`CB-SKL-290`**
2. `log_skill(case_id, journal_id="CB-SKL-290", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-290` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing indicator lifecycle management
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

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
  "purpose": "[CB-SKL-290] file per playbook step",
  "why": "Executing cb-indicator-lifecycle-management \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-290` (`cb-indicator-lifecycle-management`)

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

Indicator lifecycle management tracks IOCs from initial discovery through validation, enrichment, deployment, monitoring, and eventual retirement. This skill covers implementing systematic processes for IOC quality assessment, aging policies, confidence scoring decay, false positive tracking, hit-rate monitoring, and automated expiration to maintain a high-quality, actionable indicator database that minimizes analyst fatigue and maximizes detection efficacy.


## When to Use

- When conducting security assessments that involve performing indicator lifecycle management
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Python 3.9+ with `pymisp`, `requests`, `stix2` libraries
- MISP or OpenCTI instance for indicator storage
- SIEM with IOC watchlist capabilities (Splunk, Elastic)
- Understanding of IOC types, confidence scoring, and TLP classifications

## Key Concepts

### Indicator Lifecycle Phases
1. **Discovery**: IOC first identified from threat intelligence, malware analysis, or incident response
2. **Validation**: IOC verified against enrichment sources (VirusTotal, Shodan)
3. **Enrichment**: Additional context added (WHOIS, passive DNS, threat actor attribution)
4. **Deployment**: IOC pushed to detection systems (SIEM, IDS, firewall)
5. **Monitoring**: Track hit rates, false positive rates, detection efficacy
6. **Review**: Periodic assessment of IOC relevance and accuracy
7. **Retirement**: IOC expired or removed based on aging policy

### Confidence Decay
Indicator confidence decreases over time as adversaries rotate infrastructure. A time-based decay function reduces confidence scores automatically, ensuring old indicators do not generate excessive alerts. Typical half-life: IP addresses (30 days), domains (90 days), file hashes (365 days).

### Quality Metrics
- **Hit Rate**: Percentage of deployed IOCs generating true positive alerts
- **False Positive Rate**: Percentage of IOC alerts that are benign
- **Coverage**: Percentage of known threat techniques with IOC coverage
- **Freshness**: Average age of active indicators in the database

## Workflow

### Step 1: Implement IOC Lifecycle State Machine

```python
from datetime import datetime, timedelta
from enum import Enum

class IOCState(Enum):
    DISCOVERED = "discovered"
    VALIDATED = "validated"
    ENRICHED = "enriched"
    DEPLOYED = "deployed"
    MONITORING = "monitoring"
    UNDER_REVIEW = "under_review"
    RETIRED = "retired"

class IOCLifecycle:
    def __init__(self, ioc_type, value, source, initial_confidence=50):
        self.ioc_type = ioc_type
        self.value = value
        self.source = source
        self.confidence = initial_confidence
        self.state = IOCState.DISCOVERED
        self.created = datetime.utcnow()
        self.last_updated = datetime.utcnow()
        self.last_seen = None
        self.hit_count = 0
        self.false_positive_count = 0
        self.history = [{"state": "discovered", "timestamp": self.created.isoformat()}]

    def transition(self, new_state: IOCState, reason=""):
        self.state = new_state
        self.last_updated = datetime.utcnow()
        self.history.append({
            "state": new_state.value,
            "timestamp": self.last_updated.isoformat(),
            "reason": reason,
        })

    def apply_decay(self):
        """Apply confidence decay based on IOC type half-life."""
        half_lives = {"ip": 30, "domain": 90, "hash": 365, "url": 60}
        half_life = half_lives.get(self.ioc_type, 90)
        age_days = (datetime.utcnow() - self.created).days
        decay_factor = 0.5 ** (age_days / half_life)
        self.confidence = max(0, int(self.confidence * decay_factor))

    def record_hit(self, is_true_positive=True):
        self.hit_count += 1
        self.last_seen = datetime.utcnow()
        if not is_true_positive:
            self.false_positive_count += 1
            if self.false_positive_count > 3:
                self.transition(IOCState.UNDER_REVIEW, "Excessive false positives")

    def should_retire(self):
        max_ages = {"ip": 90, "domain": 180, "hash": 730, "url": 120}
        max_age = max_ages.get(self.ioc_type, 180)
        age_days = (datetime.utcnow() - self.created).days
        return age_days > max_age and self.hit_count == 0
```

## Validation Criteria

- IOC lifecycle state machine transitions correctly between phases
- Confidence decay reduces scores based on IOC type half-life
- Hit rate and false positive tracking functional
- Aging policy automatically flags indicators for review/retirement
- Quality metrics dashboard shows IOC database health

## References

- [MISP Indicator Lifecycle](https://www.misp-project.org/)
- [STIX Indicator Valid From/Until](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [IOC Quality Framework](https://www.first.org/)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
