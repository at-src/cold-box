---
name: cb-building-ioc-enrichment-pipeline-with-opencti
skill_id: cb-building-ioc-enrichment-pipeline-with-opencti
journal_id: CB-SKL-143
description: Cold-box analyst playbook — Building Ioc Enrichment Pipeline With Opencti.
  OpenCTI is an open-source platform for managing cyber threat intelligence knowledge,
  built on STIX 2.1 as its native data model. This skill covers building an automated
  IOC enrichment pipeline using O
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
- opencti
- enrichment
- virustotal
cold_box_version: 2
inspired_by: building-ioc-enrichment-pipeline-with-opencti
---

# Building Ioc Enrichment Pipeline With Opencti (cold-box)

> **Journal ID:** `CB-SKL-143` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-143`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-building-ioc-enrichment-pipeline-with-opencti")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-building-ioc-enrichment-pipeline-with-opencti")` → note **`CB-SKL-143`**
2. `log_skill(case_id, journal_id="CB-SKL-143", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-143` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring building ioc enrichment pipeline with opencti capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

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
  "purpose": "[CB-SKL-143] file per playbook step",
  "why": "Executing cb-building-ioc-enrichment-pipeline-with-opencti \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-143` (`cb-building-ioc-enrichment-pipeline-with-opencti`)

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

OpenCTI is an open-source platform for managing cyber threat intelligence knowledge, built on STIX 2.1 as its native data model. This skill covers building an automated IOC enrichment pipeline using OpenCTI's connector ecosystem to enrich indicators with context from VirusTotal, Shodan, AbuseIPDB, GreyNoise, and other sources. The pipeline automatically enriches newly ingested indicators, correlates them with known threat actors and campaigns, and scores them for analyst prioritization.


## When to Use

- When deploying or configuring building ioc enrichment pipeline with opencti capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Docker and Docker Compose for OpenCTI deployment
- Python 3.9+ with `pycti` library
- API keys for enrichment services: VirusTotal, Shodan, AbuseIPDB, GreyNoise
- Understanding of STIX 2.1 data model and relationships
- ElasticSearch or OpenSearch for OpenCTI backend
- RabbitMQ or Redis for connector messaging

## Key Concepts

### OpenCTI Architecture

OpenCTI uses a GraphQL API frontend backed by ElasticSearch for storage and Redis/RabbitMQ for connector communication. Data is natively stored as STIX 2.1 objects with relationships. Connectors are categorized as: External Import (feed ingestion), Internal Import (file parsing), Internal Enrichment (context addition), and Stream (real-time export).

### Enrichment Connector Model

Internal enrichment connectors are triggered automatically when new observables are created or manually by analysts. Each connector receives STIX objects, queries external services, and returns STIX 2.1 bundles that augment the original observable with additional context, labels, and relationships.

### Confidence Scoring

OpenCTI uses a 0-100 confidence scale for indicators. Enrichment connectors can update confidence scores based on external validation: VirusTotal detection ratios, Shodan exposure data, AbuseIPDB report counts, and GreyNoise classification results.

## Workflow

### Step 1: Deploy OpenCTI with Docker Compose

```yaml
# docker-compose.yml (key services)
version: '3'
services:
  opencti:
    image: opencti/platform:6.4.4
    environment:
      - APP__PORT=8080
      - APP__ADMIN__EMAIL=admin@opencti.io
      - APP__ADMIN__PASSWORD=ChangeMeNow
      - APP__ADMIN__TOKEN=your-admin-token-uuid
      - ELASTICSEARCH__URL=http://elasticsearch:9200
      - MINIO__ENDPOINT=minio
      - RABBITMQ__HOSTNAME=rabbitmq
    ports:
      - "8080:8080"
    depends_on:
      - elasticsearch
      - minio
      - rabbitmq
      - redis

  connector-virustotal:
    image: opencti/connector-virustotal:6.4.4
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=your-admin-token-uuid
      - CONNECTOR_ID=connector-virustotal-id
      - CONNECTOR_NAME=VirusTotal
      - CONNECTOR_SCOPE=StixFile,Artifact,IPv4-Addr,Domain-Name,Url
      - CONNECTOR_AUTO=true
      - VIRUSTOTAL_TOKEN=your-vt-api-key
      - VIRUSTOTAL_MAX_TLP=TLP:AMBER

  connector-shodan:
    image: opencti/connector-shodan:6.4.4
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=your-admin-token-uuid
      - CONNECTOR_ID=connector-shodan-id
      - CONNECTOR_NAME=Shodan
      - CONNECTOR_SCOPE=IPv4-Addr
      - CONNECTOR_AUTO=true
      - SHODAN_TOKEN=your-shodan-api-key
      - SHODAN_MAX_TLP=TLP:AMBER

  connector-abuseipdb:
    image: opencti/connector-abuseipdb:6.4.4
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=your-admin-token-uuid
      - CONNECTOR_ID=connector-abuseipdb-id
      - CONNECTOR_NAME=AbuseIPDB
      - CONNECTOR_SCOPE=IPv4-Addr
      - CONNECTOR_AUTO=true
      - ABUSEIPDB_API_KEY=your-abuseipdb-key
```

### Step 2: Build Custom Enrichment Connector

```python
import os
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import (
    Bundle, Indicator, Note, Relationship,
    IPv4Address, DomainName
)
import requests


class CustomEnrichmentConnector:
    def __init__(self):
        config = {
            "opencti": {
                "url": os.environ.get("OPENCTI_URL"),
                "token": os.environ.get("OPENCTI_TOKEN"),
            },
            "connector": {
                "id": os.environ.get("CONNECTOR_ID"),
                "name": "CustomEnrichment",
                "scope": "IPv4-Addr,Domain-Name,Url",
                "auto": True,
                "type": "INTERNAL_ENRICHMENT",
            },
        }
        self.helper = OpenCTIConnectorHelper(config)
        self.helper.listen(self._process_message)

    def _process_message(self, data):
        entity_id = data["entity_id"]
        stix_object = self.helper.api.stix_cyber_observable.read(id=entity_id)

        if not stix_object:
            return "Observable not found"

        observable_type = stix_object["entity_type"]
        observable_value = stix_object.get("value", "")

        enrichment_results = []

        if observable_type == "IPv4-Addr":
            enrichment_results = self._enrich_ip(observable_value, entity_id)
        elif observable_type == "Domain-Name":
            enrichment_results = self._enrich_domain(observable_value, entity_id)

        if enrichment_results:
            bundle = Bundle(objects=enrichment_results, allow_custom=True)
            self.helper.send_stix2_bundle(bundle.serialize())

        return "Enrichment completed"

    def _enrich_ip(self, ip_address, entity_id):
        """Enrich IP address with GreyNoise, AbuseIPDB context."""
        objects = []

        # GreyNoise Community API
        try:
            gn_response = requests.get(
                f"https://api.greynoise.io/v3/community/{ip_address}",
                headers={"key": os.environ.get("GREYNOISE_API_KEY")},
                timeout=30,
            )
            if gn_response.status_code == 200:
                gn_data = gn_response.json()
                classification = gn_data.get("classification", "unknown")
                noise = gn_data.get("noise", False)
                riot = gn_data.get("riot", False)

                note_content = (
                    f"## GreyNoise Enrichment\n"
                    f"- Classification: {classification}\n"
                    f"- Internet Noise: {noise}\n"
                    f"- RIOT (Benign Service): {riot}\n"
                    f"- Name: {gn_data.get('name', 'N/A')}\n"
                    f"- Last Seen: {gn_data.get('last_seen', 'N/A')}"
                )

                note = Note(
                    content=note_content,
                    object_refs=[entity_id],
                    abstract=f"GreyNoise: {classification}",
                    allow_custom=True,
                )
                objects.append(note)

                # Add labels based on classification
                if classification == "malicious":
                    self.helper.api.stix_cyber_observable.add_label(
                        id=entity_id, label_name="greynoise:malicious"
                    )
                elif riot:
                    self.helper.api.stix_cyber_observable.add_label(
                        id=entity_id, label_name="greynoise:benign-service"
                    )

        except Exception as e:
            self.helper.log_error(f"GreyNoise enrichment failed: {e}")

        return objects

    def _enrich_domain(self, domain, entity_id):
        """Enrich domain with WHOIS and DNS context."""
        objects = []

        try:
            # Use SecurityTrails API for domain enrichment
            st_response = requests.get(
                f"https://api.securitytrails.com/v1/domain/{domain}",
                headers={"APIKEY": os.environ.get("SECURITYTRAILS_API_KEY")},
                timeout=30,
            )
            if st_response.status_code == 200:
                st_data = st_response.json()
                current_dns = st_data.get("current_dns", {})

                a_records = [
                    r.get("ip") for r in current_dns.get("a", {}).get("values", [])
                ]

                note_content = (
                    f"## SecurityTrails Enrichment\n"
                    f"- A Records: {', '.join(a_records)}\n"
                    f"- Alexa Rank: {st_data.get('alexa_rank', 'N/A')}\n"
                    f"- Hostname: {st_data.get('hostname', 'N/A')}"
                )

                note = Note(
                    content=note_content,
                    object_refs=[entity_id],
                    abstract=f"SecurityTrails: {domain}",
                    allow_custom=True,
                )
                objects.append(note)

        except Exception as e:
            self.helper.log_error(f"SecurityTrails enrichment failed: {e}")

        return objects


if __name__ == "__main__":
    connector = CustomEnrichmentConnector()

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
