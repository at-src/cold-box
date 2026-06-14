---
name: cb-building-detection-rules-with-sigma
skill_id: cb-building-detection-rules-with-sigma
journal_id: CB-SKL-004
description: Cold-box analyst playbook — Building Detection Rules With Sigma. Builds
  vendor-agnostic detection rules using the Sigma rule format for threat detection
  across SIEM platforms including Splunk, Elastic, and Microsoft Sentinel. Use when
  creating portable detection logic from threat intelligence, mapping ru
domain: cold-box
subdomain: soc-operations
tier: core
case_profiles:
- soc_siem
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- soc
- sigma
- detection-rules
- siem
- mitre-attack
- splunk
- elastic
- sentinel
cold_box_version: 2
inspired_by: building-detection-rules-with-sigma
---

# Building Detection Rules With Sigma (cold-box)

> **Journal ID:** `CB-SKL-004` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-004`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-building-detection-rules-with-sigma")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-building-detection-rules-with-sigma")` → note **`CB-SKL-004`**
2. `log_skill(case_id, journal_id="CB-SKL-004", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-004` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- SOC engineers need to create detection rules portable across multiple SIEM platforms
- Threat intelligence reports describe TTPs requiring new detection coverage
- Existing vendor-specific rules need standardization into a shareable format
- The team adopts Sigma as a detection-as-code standard in CI/CD pipelines

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
## {timestamp} — skill `CB-SKL-004` (`cb-building-detection-rules-with-sigma`)

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
- SOC engineers need to create detection rules portable across multiple SIEM platforms
- Threat intelligence reports describe TTPs requiring new detection coverage
- Existing vendor-specific rules need standardization into a shareable format
- The team adopts Sigma as a detection-as-code standard in CI/CD pipelines

**Do not use** for real-time streaming detection (Sigma is for batch/scheduled searches) or when the target SIEM has native detection features that Sigma cannot express (e.g., Splunk RBA risk scoring).

## Prerequisites

- Python 3.8+ with `pySigma` and appropriate backend (`pySigma-backend-splunk`, `pySigma-backend-elasticsearch`, `pySigma-backend-microsoft365defender`)
- Sigma rule repository cloned: `git clone https://github.com/SigmaHQ/sigma.git`
- MITRE ATT&CK framework knowledge for technique mapping
- Understanding of target SIEM log source field mappings

## Workflow

### Step 1: Define Detection Logic from Threat Intelligence

Start with a threat report or ATT&CK technique. Example: detecting Mimikatz credential dumping (T1003.001 — LSASS Memory):

```yaml
title: Mimikatz Credential Dumping via LSASS Access
id: 0d894093-71bc-43c3-8d63-bf520e73a7c5
status: stable
level: high
description: Detects process accessing lsass.exe memory, indicative of credential dumping tools like Mimikatz
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://github.com/gentilkiwi/mimikatz
author: mahipal
date: 2024/03/15
modified: 2024/03/15
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1fffff'
            - '0x40'
    filter_main_svchost:
        SourceImage|endswith: '\svchost.exe'
    filter_main_csrss:
        SourceImage|endswith: '\csrss.exe'
    filter_main_wininit:
        SourceImage|endswith: '\wininit.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate security tools accessing LSASS
    - Windows Defender scanning
    - CrowdStrike Falcon sensor
```

### Step 2: Validate Sigma Rule Syntax

Use `sigma check` to validate the rule:

```bash
# Install pySigma and validators
pip install pySigma pySigma-validators-sigmaHQ

# Validate rule
sigma check rule.yml
```

Alternatively, validate with Python:

```python
from sigma.rule import SigmaRule
from sigma.validators.core import SigmaValidator

rule = SigmaRule.from_yaml(open("rule.yml").read())
validator = SigmaValidator()
issues = validator.validate_rule(rule)
for issue in issues:
    print(f"{issue.severity}: {issue.message}")
```

### Step 3: Convert to Target SIEM Query

**Convert to Splunk SPL:**

```python
from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline

pipeline = splunk_windows_pipeline()
backend = SplunkBackend(pipeline)

rule = SigmaRule.from_yaml(open("rule.yml").read())
splunk_query = backend.convert_rule(rule)
print(splunk_query[0])
```

Output:
```spl
TargetImage="*\\lsass.exe" (GrantedAccess="*0x1010*" OR GrantedAccess="*0x1038*"
OR GrantedAccess="*0x1fffff*" OR GrantedAccess="*0x40*")
NOT (SourceImage="*\\svchost.exe") NOT (SourceImage="*\\csrss.exe")
NOT (SourceImage="*\\wininit.exe")
```

**Convert to Elastic Query (Lucene):**

```python
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.elasticsearch import ecs_windows_pipeline

pipeline = ecs_windows_pipeline()
backend = LuceneBackend(pipeline)
elastic_query = backend.convert_rule(rule)
print(elastic_query[0])
```

**Convert to Microsoft Sentinel KQL:**

```python
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend

backend = Microsoft365DefenderBackend()
kql_query = backend.convert_rule(rule)
print(kql_query[0])
```

### Step 4: Map to MITRE ATT&CK and Add Coverage Metadata

Tag every rule with ATT&CK technique IDs in the `tags` field:

```yaml
tags:
    - attack.credential_access        # Tactic
    - attack.t1003.001                # Sub-technique
    - attack.t1003                    # Parent technique
```

Track detection coverage using the ATT&CK Navigator:

```python
import json

# Generate ATT&CK Navigator layer from Sigma rules
layer = {
    "name": "SOC Detection Coverage",
    "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
    "domain": "enterprise-attack",
    "techniques": []
}

# Parse Sigma rules directory for technique tags
import os
from sigma.rule import SigmaRule

for root, dirs, files in os.walk("sigma/rules/windows/"):
    for f in files:
        if f.endswith(".yml"):
            rule = SigmaRule.from_yaml(open(os.path.join(root, f)).read())
            for tag in rule.tags:
                if str(tag).startswith("attack.t"):
                    technique_id = str(tag).replace("attack.", "").upper()
                    layer["techniques"].append({
                        "techniqueID": technique_id,
                        "color": "#31a354",
                        "score": 1
                    })

with open("coverage_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
```

### Step 5: Test Rule Against Sample Data

Create test data and validate the rule catches the expected events:

```bash
# Use sigma test framework
sigma test rule.yml --target splunk --pipeline splunk_windows

# Or manually test in Splunk with sample data
# Upload Sysmon process_access log with known Mimikatz signature
```

Validate false positive rate by running against 7 days of production data in a non-alerting saved search.

### Step 6: Deploy to Production SIEM

Deploy the converted query as a scheduled search or correlation rule:

**Splunk ES Correlation Search:**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes
  where Processes.process_name="*\\lsass.exe"
  by Processes.src, Processes.user, Processes.process_name, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| where count > 0
```

**Elastic Security Rule (TOML format):**
```toml
[rule]
name = "LSASS Memory Access - Credential Dumping"
description = "Detects suspicious access to LSASS process memory"
risk_score = 73
severity = "high"
type = "eql"
query = '''
process where event.action == "access" and
  process.name == "lsass.exe" and
  not process.executable : ("*\\svchost.exe", "*\\csrss.exe")
'''

[rule.threat]
framework = "MITRE ATT&CK"
[[rule.threat.technique]]
id = "T1003"
name = "OS Credential Dumping"
```

### Step 7: Version Control and CI/CD Integration

Store rules in Git with automated testing:

```yaml
# .github/workflows/sigma-ci.yml
name: Sigma Rule CI
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install pySigma pySigma-validators-sigmaHQ
      - run: sigma check rules/
      - run: sigma convert -t splunk -p splunk_windows rules/ > /dev/null
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Sigma** | Vendor-agnostic detection rule format (YAML-based) that compiles to SIEM-specific queries via backends |
| **pySigma** | Python library replacing legacy sigmac for rule conversion, validation, and pipeline processing |
| **Backend** | pySigma plugin that translates Sigma detection logic into a target platform query language (SPL, KQL, Lucene) |
| **Pipeline** | Field mapping configuration that translates generic Sigma field names to SIEM-specific field names |
| **Logsource** | Sigma rule section defining the category (process_creation, network_connection) and product (windows, linux) of the target data |
| **Detection-as-Code** | Practice of managing detection rules in version control with CI/CD testing and automated deployment |

## Tools & Systems

- **SigmaHQ**: Official Sigma rule repository with 3,000+ community-maintained detection rules on GitHub
- **pySigma**: Python-based Sigma rule processing framework with modular backends and pipelines
- **ATT&CK Navigator**: MITRE tool for visualizing detection coverage mapped to ATT&CK techniques
- **Uncoder.IO**: Web-based Sigma rule converter supporting 30+ SIEM platforms for quick translation

## Common Scenarios

- **New CVE Detection**: Write Sigma rule for exploitation indicators (e.g., Log4Shell JNDI lookup patterns in web logs)
- **Hunting Rule Promotion**: Convert ad-hoc Splunk hunting query into Sigma rule for ongoing automated detection
- **Multi-SIEM Migration**: Converting 500+ Splunk correlation searches to Sigma for migration to Elastic Security
- **Purple Team Output**: Convert red team findings into Sigma rules for immediate defensive coverage
- **Threat Intel Operationalization**: Transform IOC-based threat reports into behavioral Sigma rules

## Output Format

```
SIGMA RULE DEPLOYMENT REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Rule ID:      0d894093-71bc-43c3-8d63-bf520e73a7c5
Title:        Mimikatz Credential Dumping via LSASS Access
ATT&CK:       T1003.001 - LSASS Memory
Severity:     High
Status:       Deployed to Production

Conversions:
  Splunk SPL:    PASS — Saved search "sigma_lsass_access" created
  Elastic EQL:   PASS — Detection rule ID elastic-0d894093 enabled
  Sentinel KQL:  PASS — Analytics rule deployed via ARM template

Testing:
  True Positives:    4/4 test cases matched
  False Positives:   2 in 7-day backtest (svchost edge case — filter added)
  Performance:       Avg execution 3.2s on 50M events/day
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
