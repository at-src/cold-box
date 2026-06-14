---
name: cb-certificate-transparency-for-phishing
skill_id: cb-certificate-transparency-for-phishing
journal_id: CB-SKL-153
description: Cold-box analyst playbook — Certificate Transparency For Phishing. Monitor
  Certificate Transparency logs using crt.sh and Certstream to detect phishing domains,
  lookalike certificates, and unauthorized certificate issuance targeting your organization.
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
- certificate-transparency
- ct-logs
- phishing
- crt-sh
- certstream
- ssl
- domain-monitoring
- threat-intelligence
cold_box_version: 2
inspired_by: analyzing-certificate-transparency-for-phishing
---

# Certificate Transparency For Phishing (cold-box)

> **Journal ID:** `CB-SKL-153` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-153`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-certificate-transparency-for-phishing")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-certificate-transparency-for-phishing")` → note **`CB-SKL-153`**
2. `log_skill(case_id, journal_id="CB-SKL-153", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-153` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing certificate transparency for phishing
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

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
  "purpose": "[CB-SKL-153] find per playbook step",
  "why": "Executing cb-certificate-transparency-for-phishing \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-153` (`cb-certificate-transparency-for-phishing`)

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

Certificate Transparency (CT) is an Internet security standard that creates a public, append-only log of all issued SSL/TLS certificates. Monitoring CT logs enables early detection of phishing domains that register certificates mimicking legitimate brands, unauthorized certificate issuance for owned domains, and certificate-based attack infrastructure. This skill covers querying CT logs via crt.sh, real-time monitoring with Certstream, building automated alerting for suspicious certificates, and integrating findings into threat intelligence workflows.


## When to Use

- When investigating security incidents that require analyzing certificate transparency for phishing
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Python 3.9+ with `requests`, `certstream`, `tldextract`, `Levenshtein` libraries
- Access to crt.sh (https://crt.sh/) for historical CT log queries
- Certstream (https://certstream.calidog.io/) for real-time monitoring
- List of organization domains and brand keywords to monitor
- Understanding of SSL/TLS certificate structure and issuance process

## Key Concepts

### Certificate Transparency Logs

CT logs are cryptographically assured, publicly auditable, append-only records of TLS certificate issuance. Major CAs (Let's Encrypt, DigiCert, Sectigo, Google Trust Services) submit all issued certificates to multiple CT logs. As of 2025, Chrome and Safari require CT for all publicly trusted certificates.

### Phishing Detection via CT

Attackers register lookalike domains and obtain free certificates (often from Let's Encrypt) to make phishing sites appear legitimate with HTTPS. CT monitoring detects these early because the certificate appears in logs before the phishing campaign launches, providing a window for proactive blocking.

### crt.sh Database

crt.sh is a free web interface and PostgreSQL database operated by Sectigo that indexes CT logs. It supports wildcard searches (`%.example.com`), direct SQL queries, and JSON API responses. It tracks certificate issuance, expiration, and revocation across all major CT logs.

## Workflow

### Step 1: Query crt.sh for Certificate History

```python
import requests
import json
from datetime import datetime
import tldextract

class CTLogMonitor:
    CRT_SH_URL = "https://crt.sh"

    def __init__(self, monitored_domains, brand_keywords):
        self.monitored_domains = monitored_domains
        self.brand_keywords = [k.lower() for k in brand_keywords]

    def query_crt_sh(self, domain, include_expired=False):
        """Query crt.sh for certificates matching a domain."""
        params = {
            "q": f"%.{domain}",
            "output": "json",
        }
        if not include_expired:
            params["exclude"] = "expired"

        resp = requests.get(self.CRT_SH_URL, params=params, timeout=30)
        if resp.status_code == 200:
            certs = resp.json()
            print(f"[+] crt.sh: {len(certs)} certificates for *.{domain}")
            return certs
        return []

    def find_suspicious_certs(self, domain):
        """Find certificates that may be phishing attempts."""
        certs = self.query_crt_sh(domain)
        suspicious = []

        for cert in certs:
            common_name = cert.get("common_name", "").lower()
            name_value = cert.get("name_value", "").lower()
            issuer = cert.get("issuer_name", "")
            not_before = cert.get("not_before", "")
            not_after = cert.get("not_after", "")

            # Check for exact domain matches (legitimate)
            extracted = tldextract.extract(common_name)
            cert_domain = f"{extracted.domain}.{extracted.suffix}"
            if cert_domain == domain:
                continue  # Legitimate certificate

            # Flag suspicious patterns
            flags = []
            if domain.replace(".", "") in common_name.replace(".", ""):
                flags.append("contains target domain string")
            if any(kw in common_name for kw in self.brand_keywords):
                flags.append("contains brand keyword")
            if "let's encrypt" in issuer.lower():
                flags.append("free CA (Let's Encrypt)")

            if flags:
                suspicious.append({
                    "common_name": cert.get("common_name", ""),
                    "name_value": cert.get("name_value", ""),
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "serial": cert.get("serial_number", ""),
                    "flags": flags,
                    "crt_sh_id": cert.get("id", ""),
                    "crt_sh_url": f"https://crt.sh/?id={cert.get('id', '')}",
                })

        print(f"[+] Found {len(suspicious)} suspicious certificates")
        return suspicious

monitor = CTLogMonitor(
    monitored_domains=["mycompany.com", "mycompany.org"],
    brand_keywords=["mycompany", "mybrand", "myproduct"],
)
suspicious = monitor.find_suspicious_certs("mycompany.com")
for cert in suspicious[:5]:
    print(f"  [{cert['common_name']}] Flags: {cert['flags']}")
```

### Step 2: Real-Time Monitoring with Certstream

```python
import certstream
import Levenshtein
import re
from datetime import datetime

class CertstreamMonitor:
    def __init__(self, watched_domains, brand_keywords, similarity_threshold=0.8):
        self.watched_domains = [d.lower() for d in watched_domains]
        self.brand_keywords = [k.lower() for k in brand_keywords]
        self.threshold = similarity_threshold
        self.alerts = []

    def start_monitoring(self, max_alerts=100):
        """Start real-time CT log monitoring."""
        print("[*] Starting Certstream monitoring...")
        print(f"    Watching: {self.watched_domains}")
        print(f"    Keywords: {self.brand_keywords}")

        def callback(message, context):
            if message["message_type"] == "certificate_update":
                data = message["data"]
                leaf = data.get("leaf_cert", {})
                all_domains = leaf.get("all_domains", [])

                for domain in all_domains:
                    domain_lower = domain.lower().strip("*.")
                    if self._is_suspicious(domain_lower):
                        alert = {
                            "domain": domain,
                            "all_domains": all_domains,
                            "issuer": leaf.get("issuer", {}).get("O", ""),
                            "fingerprint": leaf.get("fingerprint", ""),
                            "not_before": leaf.get("not_before", ""),
                            "detected_at": datetime.now().isoformat(),
                            "reason": self._get_reason(domain_lower),
                        }
                        self.alerts.append(alert)
                        print(f"  [ALERT] {domain} - {alert['reason']}")

                        if len(self.alerts) >= max_alerts:
                            raise KeyboardInterrupt

        try:
            certstream.listen_for_events(callback, url="wss://certstream.calidog.io/")
        except KeyboardInterrupt:
            print(f"\n[+] Monitoring stopped. {len(self.alerts)} alerts collected.")
        return self.alerts

    def _is_suspicious(self, domain):
        """Check if domain is suspicious relative to watched domains."""
        for watched in self.watched_domains:
            # Exact keyword match
            watched_base = watched.split(".")[0]
            if watched_base in domain and domain != watched:
                return True

            # Levenshtein distance (typosquatting detection)
            domain_base = tldextract.extract(domain).domain
            similarity = Levenshtein.ratio(watched_base, domain_base)
            if similarity >= self.threshold and domain_base != watched_base:
                return True

        # Brand keyword match
        for keyword in self.brand_keywords:
            if keyword in domain:
                return True

        return False

    def _get_reason(self, domain):
        """Determine why domain was flagged."""
        reasons = []
        for watched in self.watched_domains:
            watched_base = watched.split(".")[0]
            if watched_base in domain:
                reasons.append(f"contains '{watched_base}'")
            domain_base = tldextract.extract(domain).domain
            similarity = Levenshtein.ratio(watched_base, domain_base)
            if similarity >= self.threshold and domain_base != watched_base:
                reasons.append(f"similar to '{watched}' ({similarity:.0%})")
        for kw in self.brand_keywords:
            if kw in domain:
                reasons.append(f"brand keyword '{kw}'")
        return "; ".join(reasons) if reasons else "unknown"

cs_monitor = CertstreamMonitor(
    watched_domains=["mycompany.com"],
    brand_keywords=["mycompany", "mybrand"],
    similarity_threshold=0.75,
)
alerts = cs_monitor.start_monitoring(max_alerts=50)
```

### Step 3: Enumerate Subdomains from CT Logs

```python
def enumerate_subdomains_ct(domain):
    """Discover all subdomains from Certificate Transparency logs."""
    params = {"q": f"%.{domain}", "output": "json"}
    resp = requests.get("https://crt.sh", params=params, timeout=30)

    if resp.status_code != 200:
        return []

    certs = resp.json()
    subdomains = set()
    for cert in certs:
        name_value = cert.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name.endswith(f".{domain}") or name == domain:
                name = name.lstrip("*.")
                subdomains.add(name)

    sorted_subs = sorted(subdomains)
    print(f"[+] CT subdomain enumeration for {domain}: {len(sorted_subs)} subdomains")
    return sorted_subs

subdomains = enumerate_subdomains_ct("example.com")
for sub in subdomains[:20]:
    print(f"  {sub}")
```

### Step 4: Generate CT Intelligence Report

```python
def generate_ct_report(suspicious_certs, certstream_alerts, domain):
    report = f"""# Certificate Transparency Intelligence Report
## Target Domain: {domain}
## Generated: {datetime.now().isoformat()}

## Summary
- Suspicious certificates found: {len(suspicious_certs)}
- Real-time alerts triggered: {len(certstream_alerts)}

## Suspicious Certificates (crt.sh)
| Common Name | Issuer | Flags | crt.sh Link |
|------------|--------|-------|-------------|
"""
    for cert in suspicious_certs[:20]:
        flags = "; ".join(cert.get("flags", []))
        report += (f"| {cert['common_name']} | {cert['issuer'][:30]} "
                   f"| {flags} | [View]({cert['crt_sh_url']}) |\n")

    report += f"""
## Real-Time Certstream Alerts
| Domain | Issuer | Reason | Detected |
|--------|--------|--------|----------|
"""
    for alert in certstream_alerts[:20]:
        report += (f"| {alert['domain']} | {alert['issuer']} "
                   f"| {alert['reason']} | {alert['detected_at'][:19]} |\n")

    report += """
## Recommendations
1. Add flagged domains to DNS sinkhole / web proxy blocklist
2. Submit takedown requests for confirmed phishing domains
3. Monitor CT logs continuously for new certificate registrations
4. Implement CAA DNS records to restrict certificate issuance for your domains
5. Deploy DMARC to prevent email spoofing from lookalike domains
"""
    with open(f"ct_report_{domain.replace('.','_')}.md", "w") as f:
        f.write(report)
    print(f"[+] CT report saved")
    return report

generate_ct_report(suspicious, alerts if 'alerts' in dir() else [], "mycompany.com")
```

## Validation Criteria

- crt.sh queries return certificate data for target domains
- Suspicious certificates identified based on lookalike patterns
- Certstream real-time monitoring detects new phishing certificates
- Subdomain enumeration produces comprehensive list from CT logs
- Alerts generated with reason classification
- CT intelligence report created with actionable recommendations

## References

- [crt.sh Certificate Search](https://crt.sh/)
- [Certstream Real-Time CT Monitor](https://certstream.calidog.io/)
- [River Security: CT Logs for Attack Surface Discovery](https://riversecurity.eu/finding-attack-surface-and-fraudulent-domains-via-certificate-transparency-logs/)
- [Let's Encrypt: Certificate Transparency Logs](https://letsencrypt.org/docs/ct-logs/)
- [SSLMate Cert Spotter](https://sslmate.com/certspotter/)
- [CyberSierra: CT Logs as Early Warning System](https://cybersierra.co/blog/ssl-certificate-transparency-logs/)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
