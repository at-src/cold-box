---
name: cb-tracking-threat-actor-infrastructure
skill_id: cb-tracking-threat-actor-infrastructure
journal_id: CB-SKL-335
description: Cold-box analyst playbook — Tracking Threat Actor Infrastructure. Threat
  actor infrastructure tracking involves monitoring and mapping adversary-controlled
  assets including command-and-control (C2) servers, phishing domains, exploit kit
  hosts, bulletproof hosting, a
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
- infrastructure-tracking
- shodan
- censys
- passive-dns
cold_box_version: 2
inspired_by: tracking-threat-actor-infrastructure
---

# Tracking Threat Actor Infrastructure (cold-box)

> **Journal ID:** `CB-SKL-335` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-335`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-tracking-threat-actor-infrastructure")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-tracking-threat-actor-infrastructure")` → note **`CB-SKL-335`**
2. `log_skill(case_id, journal_id="CB-SKL-335", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-335` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When managing security operations that require tracking threat actor infrastructure
- When improving security program maturity and operational processes
- When establishing standardized procedures for security team workflows
- When integrating threat intelligence or vulnerability data into operations

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `sort` | `SIFT-020` | yes | yes |
| `find` | `SIFT-009` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-335] sort per playbook step",
  "why": "Executing cb-tracking-threat-actor-infrastructure \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-335] find per playbook step",
  "why": "Executing cb-tracking-threat-actor-infrastructure \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-335` (`cb-tracking-threat-actor-infrastructure`)

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

Threat actor infrastructure tracking involves monitoring and mapping adversary-controlled assets including command-and-control (C2) servers, phishing domains, exploit kit hosts, bulletproof hosting, and staging servers. This skill covers using passive DNS, certificate transparency logs, Shodan/Censys scanning, WHOIS analysis, and network fingerprinting to discover, track, and pivot across threat actor infrastructure over time.


## When to Use

- When managing security operations that require tracking threat actor infrastructure
- When improving security program maturity and operational processes
- When establishing standardized procedures for security team workflows
- When integrating threat intelligence or vulnerability data into operations

## Prerequisites

- Python 3.9+ with `shodan`, `censys`, `requests`, `stix2` libraries
- API keys: Shodan, Censys, VirusTotal, SecurityTrails, PassiveTotal
- Understanding of DNS, TLS/SSL certificates, IP allocation, ASN structure
- Familiarity with passive DNS and certificate transparency concepts
- Access to domain registration (WHOIS) lookup services

## Key Concepts

### Infrastructure Pivoting
Pivoting is the technique of using one known indicator to discover related infrastructure. Starting from a known C2 IP address, analysts can pivot via: passive DNS (find domains), reverse WHOIS (find related registrations), SSL certificates (find shared certs), SSH key fingerprints, HTTP response fingerprints, JARM/JA3S hashes, and WHOIS registrant data.

### Passive DNS
Passive DNS databases record DNS query/response data observed at recursive resolvers. This allows analysts to find historical domain-to-IP mappings, discover domains hosted on a known C2 IP, and identify fast-flux or domain generation algorithm (DGA) behavior.

### Certificate Transparency
Certificate Transparency (CT) logs publicly record all SSL/TLS certificates issued by CAs. Monitoring CT logs reveals new certificates registered for suspicious domains, helping identify phishing sites and C2 infrastructure before they become active.

### Network Fingerprinting
- **JARM**: Active TLS server fingerprint (hash of TLS handshake responses)
- **JA3S**: Passive TLS server fingerprint (hash of Server Hello)
- **HTTP Headers**: Server banners, custom headers, response patterns
- **Favicon Hash**: Hash of HTTP favicon for server identification

## Workflow

### Step 1: Shodan Infrastructure Discovery

```python
import shodan

api = shodan.Shodan("YOUR_SHODAN_API_KEY")

def discover_infrastructure(ip_address):
    """Discover services and metadata for a target IP."""
    try:
        host = api.host(ip_address)
        return {
            "ip": host["ip_str"],
            "org": host.get("org", ""),
            "asn": host.get("asn", ""),
            "isp": host.get("isp", ""),
            "country": host.get("country_name", ""),
            "city": host.get("city", ""),
            "os": host.get("os"),
            "ports": host.get("ports", []),
            "vulns": host.get("vulns", []),
            "hostnames": host.get("hostnames", []),
            "domains": host.get("domains", []),
            "tags": host.get("tags", []),
            "services": [
                {
                    "port": svc.get("port"),
                    "transport": svc.get("transport"),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "ssl_cert": svc.get("ssl", {}).get("cert", {}).get("subject", {}),
                    "jarm": svc.get("ssl", {}).get("jarm", ""),
                }
                for svc in host.get("data", [])
            ],
        }
    except shodan.APIError as e:
        print(f"[-] Shodan error: {e}")
        return None

def search_c2_framework(framework_name):
    """Search Shodan for known C2 framework signatures."""
    c2_queries = {
        "cobalt-strike": 'product:"Cobalt Strike Beacon"',
        "metasploit": 'product:"Metasploit"',
        "covenant": 'http.html:"Covenant" http.title:"Covenant"',
        "sliver": 'ssl.cert.subject.cn:"multiplayer" ssl.cert.issuer.cn:"operators"',
        "havoc": 'http.html_hash:-1472705893',
    }

    query = c2_queries.get(framework_name.lower(), framework_name)
    results = api.search(query, limit=100)

    hosts = []
    for match in results.get("matches", []):
        hosts.append({
            "ip": match["ip_str"],
            "port": match["port"],
            "org": match.get("org", ""),
            "country": match.get("location", {}).get("country_name", ""),
            "asn": match.get("asn", ""),
            "timestamp": match.get("timestamp", ""),
        })

    return hosts
```

### Step 2: Passive DNS Pivoting

```python
import requests

def passive_dns_lookup(indicator, api_key, indicator_type="ip"):
    """Query SecurityTrails for passive DNS records."""
    base_url = "https://api.securitytrails.com/v1"
    headers = {"APIKEY": api_key, "Accept": "application/json"}

    if indicator_type == "ip":
        url = f"{base_url}/search/list"
        payload = {
            "filter": {"ipv4": indicator}
        }
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
    else:
        url = f"{base_url}/domain/{indicator}/subdomains"
        resp = requests.get(url, headers=headers, timeout=30)

    if resp.status_code == 200:
        return resp.json()
    return None


def query_passive_total(indicator, user, api_key):
    """Query PassiveTotal for passive DNS and WHOIS data."""
    base_url = "https://api.passivetotal.org/v2"
    auth = (user, api_key)

    # Passive DNS
    pdns_resp = requests.get(
        f"{base_url}/dns/passive",
        params={"query": indicator},
        auth=auth,
        timeout=30,
    )

    # WHOIS
    whois_resp = requests.get(
        f"{base_url}/whois",
        params={"query": indicator},
        auth=auth,
        timeout=30,
    )

    results = {}
    if pdns_resp.status_code == 200:
        results["passive_dns"] = pdns_resp.json().get("results", [])
    if whois_resp.status_code == 200:
        results["whois"] = whois_resp.json()

    return results
```

### Step 3: Certificate Transparency Monitoring

```python
import requests

def search_ct_logs(domain):
    """Search Certificate Transparency logs via crt.sh."""
    resp = requests.get(
        f"https://crt.sh/?q=%.{domain}&output=json",
        timeout=30,
    )

    if resp.status_code == 200:
        certs = resp.json()
        unique_domains = set()
        cert_info = []

        for cert in certs:
            name_value = cert.get("name_value", "")
            for name in name_value.split("\n"):
                unique_domains.add(name.strip())

            cert_info.append({
                "id": cert.get("id"),
                "issuer": cert.get("issuer_name", ""),
                "common_name": cert.get("common_name", ""),
                "name_value": name_value,
                "not_before": cert.get("not_before", ""),
                "not_after": cert.get("not_after", ""),
                "serial_number": cert.get("serial_number", ""),
            })

        return {
            "domain": domain,
            "total_certificates": len(certs),
            "unique_domains": sorted(unique_domains),
            "certificates": cert_info[:50],
        }
    return None


def monitor_new_certs(domains, interval_hours=1):
    """Monitor for newly issued certificates for a list of domains."""
    from datetime import datetime, timedelta

    cutoff = (datetime.utcnow() - timedelta(hours=interval_hours)).isoformat()
    new_certs = []

    for domain in domains:
        result = search_ct_logs(domain)
        if result:
            for cert in result.get("certificates", []):
                if cert.get("not_before", "") > cutoff:
                    new_certs.append({
                        "domain": domain,
                        "cert": cert,
                    })

    return new_certs
```

### Step 4: Infrastructure Correlation and Timeline

```python
from datetime import datetime

def build_infrastructure_timeline(indicators):
    """Build a timeline of infrastructure changes."""
    timeline = []

    for ind in indicators:
        if "passive_dns" in ind:
            for record in ind["passive_dns"]:
                timeline.append({
                    "timestamp": record.get("firstSeen", ""),
                    "event": "dns_resolution",
                    "source": record.get("resolve", ""),
                    "target": record.get("value", ""),
                    "record_type": record.get("recordType", ""),
                })

        if "certificates" in ind:
            for cert in ind["certificates"]:
                timeline.append({
                    "timestamp": cert.get("not_before", ""),
                    "event": "certificate_issued",
                    "domain": cert.get("common_name", ""),
                    "issuer": cert.get("issuer", ""),
                })

    timeline.sort(key=lambda x: x.get("timestamp", ""))
    return timeline
```

## Validation Criteria

- Shodan/Censys queries return infrastructure details for target IPs
- Passive DNS reveals historical domain-IP mappings
- Certificate transparency search finds associated domains
- Infrastructure pivoting discovers new related indicators
- Timeline shows infrastructure evolution over time
- Results are exportable as STIX 2.1 Infrastructure objects

## References

- [Shodan API Documentation](https://developer.shodan.io/api)
- [Censys Search API](https://search.censys.io/api)
- [SecurityTrails API](https://securitytrails.com/corp/api)
- [crt.sh Certificate Transparency](https://crt.sh/)
- [PassiveTotal API](https://api.passivetotal.org/api/docs/)
- [JARM Fingerprinting](https://github.com/salesforce/jarm)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
