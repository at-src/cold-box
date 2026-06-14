---
name: cb-processing-stix-taxii-feeds
skill_id: cb-processing-stix-taxii-feeds
journal_id: CB-SKL-312
description: Cold-box analyst playbook — Processing Stix Taxii Feeds. Processes STIX
  2.1 threat intelligence bundles delivered via TAXII 2.1 servers, normalizing objects
  into platform-native schemas and routing them to appropriate consuming systems.
  Use when onboarding new TAXII collection endpoints, automati
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
- STIX-2.1
- TAXII-2.1
- OASIS
- MISP
- CTI
- IOC
- threat-intelligence
- NIST-SP-800-150
cold_box_version: 2
inspired_by: processing-stix-taxii-feeds
---

# Processing Stix Taxii Feeds (cold-box)

> **Journal ID:** `CB-SKL-312` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-312`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-processing-stix-taxii-feeds")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-processing-stix-taxii-feeds")` → note **`CB-SKL-312`**
2. `log_skill(case_id, journal_id="CB-SKL-312", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-312` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Onboarding a new TAXII 2.1 collection from a government feed (CISA AIS, FS-ISAC) or commercial provider
- Validating that ingested STIX bundles conform to the OASIS STIX 2.1 specification before import
- Building automated pipelines that parse STIX relationship objects to reconstruct campaign context

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
## {timestamp} — skill `CB-SKL-312` (`cb-processing-stix-taxii-feeds`)

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
- Onboarding a new TAXII 2.1 collection from a government feed (CISA AIS, FS-ISAC) or commercial provider
- Validating that ingested STIX bundles conform to the OASIS STIX 2.1 specification before import
- Building automated pipelines that parse STIX relationship objects to reconstruct campaign context

**Do not use** this skill for proprietary vendor feed formats (Recorded Future JSON, CrowdStrike IOC lists) that require vendor-specific parsers rather than STIX processing.

## Prerequisites

- Python 3.9+ with `stix2` library (pip install stix2) and `taxii2-client` library
- Network access to TAXII 2.1 server endpoint with valid credentials
- Target TIP or SIEM with import API (MISP, OpenCTI, or Splunk ES)

## Workflow

### Step 1: Discover TAXII Server Collections

```python
from taxii2client.v21 import Server, as_pages

server = Server("https://cti.example.com/taxii/",
                user="apiuser", password="apikey")
api_root = server.api_roots[0]
for collection in api_root.collections:
    print(collection.id, collection.title, collection.can_read)
```

Select collections relevant to your threat profile. CISA AIS provides collections segmented by sector (financial, energy, healthcare).

### Step 2: Fetch STIX Bundles with Pagination

```python
from taxii2client.v21 import Collection
from datetime import datetime, timedelta, timezone

collection = Collection(
    "https://cti.example.com/taxii/api1/collections/<id>/objects/",
    user="apiuser", password="apikey")

# Fetch only objects added in the last 24 hours
added_after = datetime.now(timezone.utc) - timedelta(hours=24)
for bundle_page in as_pages(collection.get_objects,
                             added_after=added_after, per_request=100):
    process_bundle(bundle_page)
```

### Step 3: Parse and Validate STIX Objects

```python
import stix2

def process_bundle(bundle_dict):
    bundle = stix2.parse(bundle_dict, allow_custom=True)
    for obj in bundle.objects:
        if obj.type == "indicator":
            validate_indicator(obj)
        elif obj.type == "threat-actor":
            upsert_threat_actor(obj)
        elif obj.type == "relationship":
            link_objects(obj)

def validate_indicator(indicator):
    required = ["id", "type", "spec_version", "created",
                "modified", "pattern", "pattern_type", "valid_from"]
    for field in required:
        if not hasattr(indicator, field):
            raise ValueError(f"Missing required field: {field}")
    # Check confidence range
    if hasattr(indicator, "confidence"):
        assert 0 <= indicator.confidence <= 100
```

### Step 4: Route Objects to Consuming Platforms

Map STIX object types to destination systems:
- `indicator` objects → SIEM lookup tables and firewall blocklists
- `malware` objects → EDR threat intelligence library
- `threat-actor` / `campaign` objects → TIP for analyst context
- `course-of-action` objects → Security team wiki or SOAR playbook triggers

Use TLP marking definitions to enforce sharing restrictions:
```python
for marking in obj.get("object_marking_refs", []):
    if "tlp-red" in marking:
        route_to_restricted_platform_only(obj)
```

### Step 5: Publish Back to TAXII (Bi-directional Sharing)

```python
# Add validated local intelligence back to shared collection
new_indicator = stix2.Indicator(
    name="Malicious C2 Domain",
    pattern="[domain-name:value = 'evil-c2.example.com']",
    pattern_type="stix",
    valid_from="2025-01-15T00:00:00Z",
    confidence=80,
    labels=["malicious-activity"],
    object_marking_refs=["marking-definition--34098fce-860f-479c-ae..."]  # TLP:GREEN
)
collection.add_objects(stix2.Bundle(new_indicator))
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **STIX Bundle** | Top-level STIX container object (type: "bundle") holding any number of STIX Domain Objects (SDOs) and STIX Relationship Objects (SROs) |
| **SDO** | STIX Domain Object — core intelligence types: indicator, threat-actor, malware, campaign, attack-pattern, course-of-action |
| **SRO** | STIX Relationship Object — links two SDOs with a labeled relationship (e.g., "uses", "attributed-to", "indicates") |
| **Pattern Language** | STIX pattern syntax for indicator conditions: `[network-traffic:dst_port = 443 AND ipv4-addr:value = '10.0.0.1']` |
| **Marking Definition** | STIX object encoding TLP or statement restrictions on intelligence sharing |
| **added_after** | TAXII 2.1 filter parameter (RFC 3339 timestamp) for incremental polling of new objects |

## Tools & Systems

- **stix2 (Python)**: Official OASIS Python library for creating, parsing, and validating STIX 2.0/2.1 objects
- **taxii2-client (Python)**: Client library for TAXII 2.0/2.1 server discovery, collection enumeration, and object retrieval
- **MISP**: Open-source TIP with native TAXII 2.1 server and client; MISP-TAXII-Server plugin for publishing MISP events
- **OpenCTI**: CTI platform with built-in TAXII 2.1 connector; supports STIX 2.1 import/export natively
- **Cabby**: Legacy Python TAXII 1.x client for older government feeds still on TAXII 1.1

## Common Pitfalls

- **Ignoring `spec_version` field**: STIX 2.0 and 2.1 have incompatible schemas (2.1 adds `confidence`, `object_marking_refs` at bundle level). Always check `spec_version` before parsing.
- **No pagination handling**: TAXII servers cap responses at 100–1000 objects per request. Missing pagination (via `next` link header) causes silent data loss.
- **Clock skew on `added_after`**: Server and client time misalignment causes missed objects at interval boundaries. Use UTC exclusively and add 5-minute overlap windows.
- **Storing raw STIX blobs without indexing**: Storing bundles as opaque JSON prevents querying by indicator type or campaign. Parse into relational or graph database.
- **Sharing TLP:RED content inadvertently**: Automated pipelines must filter marking definitions before routing to any shared platform or SIEM with broad analyst access.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
