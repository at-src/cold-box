---
name: cb-building-threat-intelligence-platform
skill_id: cb-building-threat-intelligence-platform
journal_id: CB-SKL-151
description: Cold-box analyst playbook — Building Threat Intelligence Platform. Building
  a Threat Intelligence Platform (TIP) involves deploying and integrating multiple
  CTI tools into a unified system for collecting, analyzing, enriching, and disseminating
  threat intelligence. T
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
- threat-intelligence
- cti
- ioc
- mitre-attack
- stix
- platform-building
- misp
- opencti
cold_box_version: 2
inspired_by: building-threat-intelligence-platform
---

# Building Threat Intelligence Platform (cold-box)

> **Journal ID:** `CB-SKL-151` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-151`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-building-threat-intelligence-platform")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-building-threat-intelligence-platform")` → note **`CB-SKL-151`**
2. `log_skill(case_id, journal_id="CB-SKL-151", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-151` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying or configuring building threat intelligence platform capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

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
## {timestamp} — skill `CB-SKL-151` (`cb-building-threat-intelligence-platform`)

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

Building a Threat Intelligence Platform (TIP) involves deploying and integrating multiple CTI tools into a unified system for collecting, analyzing, enriching, and disseminating threat intelligence. This skill covers designing TIP architecture using open-source tools (MISP, OpenCTI, TheHive, Cortex), configuring feed ingestion pipelines, establishing enrichment workflows, implementing STIX/TAXII interoperability, and building analyst dashboards for CTI operations.


## When to Use

- When deploying or configuring building threat intelligence platform capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Docker and Docker Compose for deploying platform components
- Python 3.9+ with `pymisp`, `pycti`, `thehive4py` libraries
- Elasticsearch/OpenSearch cluster for data storage
- Redis and RabbitMQ for message queuing
- Understanding of STIX 2.1 data model and TAXII 2.1 transport
- API keys for enrichment services (VirusTotal, Shodan, AbuseIPDB)

## Key Concepts

### TIP Architecture Components
1. **Collection Layer**: Feed ingestion from OSINT, commercial, and internal sources
2. **Storage Layer**: Elasticsearch/OpenSearch for indexed CTI data with STIX 2.1 schema
3. **Analysis Layer**: OpenCTI for knowledge graph analysis and MISP for IOC correlation
4. **Enrichment Layer**: Cortex analyzers for automated IOC enrichment
5. **Response Layer**: TheHive for case management and incident response integration
6. **Sharing Layer**: TAXII server for outbound intelligence sharing

### Platform Integration Points
- **MISP <-> OpenCTI**: Bidirectional sync via OpenCTI MISP connector
- **OpenCTI <-> TheHive**: Alert/case creation from high-confidence indicators
- **TheHive <-> Cortex**: Automated analysis and enrichment of case observables
- **All <-> SIEM**: Real-time IOC push to Splunk/Elastic via API or Kafka

## Workflow

### Step 1: Deploy Platform with Docker Compose

```yaml
version: '3.8'
services:
  # --- Storage Layer ---
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
    ports:
      - "9200:9200"
    volumes:
      - es-data:/usr/share/elasticsearch/data

  redis:
    image: redis:7
    ports:
      - "6379:6379"

  rabbitmq:
    image: rabbitmq:3-management
    ports:
      - "5672:5672"
      - "15672:15672"

  minio:
    image: minio/minio
    command: server /data --console-address ":9001"
    ports:
      - "9000:9000"
      - "9001:9001"

  # --- MISP ---
  misp:
    image: ghcr.io/misp/misp-docker/misp-core:latest
    ports:
      - "8443:443"
    environment:
      - MISP_ADMIN_EMAIL=admin@tip.local
      - MISP_BASEURL=https://localhost:8443
    volumes:
      - misp-data:/var/www/MISP/app/files

  # --- OpenCTI ---
  opencti:
    image: opencti/platform:6.4.4
    environment:
      - APP__PORT=8080
      - APP__ADMIN__EMAIL=admin@tip.local
      - APP__ADMIN__PASSWORD=TIPAdminPassword
      - APP__ADMIN__TOKEN=tip-opencti-token-uuid
      - ELASTICSEARCH__URL=http://elasticsearch:9200
      - MINIO__ENDPOINT=minio
      - RABBITMQ__HOSTNAME=rabbitmq
      - REDIS__HOSTNAME=redis
    ports:
      - "8080:8080"
    depends_on:
      - elasticsearch
      - redis
      - rabbitmq
      - minio

  # --- TheHive ---
  thehive:
    image: strangebee/thehive:5.3
    environment:
      - TH_CORTEX_URL=http://cortex:9001
    ports:
      - "9000:9000"
    depends_on:
      - elasticsearch

  # --- Cortex ---
  cortex:
    image: thehiveproject/cortex:3.1.8
    ports:
      - "9001:9001"
    depends_on:
      - elasticsearch

volumes:
  es-data:
  misp-data:
```

### Step 2: Configure Feed Ingestion Pipeline

```python
from pymisp import PyMISP
from pycti import OpenCTIApiClient
import json

class TIPFeedManager:
    """Manage threat intelligence feed ingestion across platform components."""

    def __init__(self, misp_url, misp_key, opencti_url, opencti_token):
        self.misp = PyMISP(misp_url, misp_key, ssl=False)
        self.opencti = OpenCTIApiClient(opencti_url, opencti_token)

    def configure_osint_feeds(self):
        """Enable default OSINT feeds in MISP."""
        osint_feeds = [
            {"name": "CIRCL OSINT", "id": 1},
            {"name": "Botvrij.eu", "id": 2},
            {"name": "abuse.ch URLhaus", "id": 5},
            {"name": "abuse.ch Feodo Tracker", "id": 6},
        ]
        for feed in osint_feeds:
            try:
                self.misp.enable_feed(feed["id"])
                self.misp.fetch_feed(feed["id"])
                print(f"[+] Enabled feed: {feed['name']}")
            except Exception as e:
                print(f"[-] Failed: {feed['name']}: {e}")

    def configure_opencti_connectors(self):
        """List and verify OpenCTI connector status."""
        connectors = self.opencti.connector.list()
        for conn in connectors:
            print(
                f"  Connector: {conn['name']} - "
                f"Active: {conn['active']} - "
                f"Type: {conn['connector_type']}"
            )

    def sync_misp_to_opencti(self):
        """Verify MISP-OpenCTI sync is operational."""
        # OpenCTI MISP connector handles this automatically
        # Check connector status
        connectors = self.opencti.connector.list()
        misp_connector = [
            c for c in connectors if "misp" in c["name"].lower()
        ]
        if misp_connector:
            print(f"[+] MISP connector active: {misp_connector[0]['active']}")
        else:
            print("[-] MISP connector not found - configure in Docker Compose")
```

### Step 3: Build Enrichment Pipeline with Cortex

```python
import requests

class CortexEnrichment:
    """Integrate Cortex analyzers for automated enrichment."""

    def __init__(self, cortex_url, cortex_key):
        self.url = cortex_url
        self.headers = {"Authorization": f"Bearer {cortex_key}"}

    def list_analyzers(self):
        """List available Cortex analyzers."""
        resp = requests.get(
            f"{self.url}/api/analyzer",
            headers=self.headers,
            timeout=30,
        )
        if resp.status_code == 200:
            analyzers = resp.json()
            for a in analyzers:
                print(f"  {a['name']}: {a.get('description', '')[:60]}")
            return analyzers
        return []

    def analyze_observable(self, observable_type, observable_value, analyzer_id):
        """Submit an observable for analysis."""
        job = {
            "data": observable_value,
            "dataType": observable_type,
            "tlp": 2,
            "message": "TIP automated enrichment",
        }
        resp = requests.post(
            f"{self.url}/api/analyzer/{analyzer_id}/run",
            json=job,
            headers=self.headers,
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json()
        return None

    def get_job_report(self, job_id):
        """Get the report for a completed analysis job."""
        resp = requests.get(
            f"{self.url}/api/job/{job_id}/report",
            headers=self.headers,
            timeout=60,
        )
        if resp.status_code == 200:
            return resp.json()
        return None
```

### Step 4: Implement Analyst Dashboard Metrics

```python
class TIPMetrics:
    """Collect platform metrics for analyst dashboards."""

    def __init__(self, misp, opencti):
        self.misp = misp
        self.opencti = opencti

    def get_platform_stats(self):
        """Collect statistics across all platform components."""
        stats = {}

        # MISP stats
        misp_stats = self.misp.get_server_statistics()
        stats["misp"] = {
            "total_events": misp_stats.get("event_count", 0),
            "total_attributes": misp_stats.get("attribute_count", 0),
            "active_feeds": len([
                f for f in self.misp.feeds()
                if f.get("Feed", {}).get("enabled")
            ]),
        }

        # OpenCTI stats via GraphQL
        stats["opencti"] = {
            "total_indicators": self.opencti.indicator.list(
                first=0, withPagination=True
            ).get("pagination", {}).get("globalCount", 0),
            "total_reports": self.opencti.report.list(
                first=0, withPagination=True
            ).get("pagination", {}).get("globalCount", 0),
        }

        return stats
```

## Validation Criteria

- All platform components (MISP, OpenCTI, TheHive, Cortex) deployed and accessible
- MISP-OpenCTI bidirectional sync operational
- At least 3 OSINT feeds ingesting data
- Cortex analyzers configured and returning enrichment results
- Platform metrics dashboard showing real-time statistics
- STIX/TAXII export functional for intelligence sharing

## References

- [OpenCTI Documentation](https://docs.opencti.io/)
- [MISP Project](https://www.misp-project.org/)
- [TheHive Project](https://thehive-project.org/)
- [Cortex Documentation](https://github.com/TheHive-Project/Cortex)
- [MISP-OpenCTI Integration](https://docs.opencti.io/latest/deployment/connectors/)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
