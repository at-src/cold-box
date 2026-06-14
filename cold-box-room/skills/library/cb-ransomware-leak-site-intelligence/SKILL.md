---
name: cb-ransomware-leak-site-intelligence
skill_id: cb-ransomware-leak-site-intelligence
journal_id: CB-SKL-315
description: Cold-box analyst playbook — Ransomware Leak Site Intelligence. Monitor
  and analyze ransomware group data leak sites (DLS) to track victim postings, extract
  threat intelligence on group tactics, and assess sector-specific ransomware risk
  for proactive defense.
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
- ransomware
- leak-site
- data-leak
- extortion
- threat-intelligence
- leak-site-monitoring
- dls
- victim-tracking
cold_box_version: 2
inspired_by: analyzing-ransomware-leak-site-intelligence
---

# Ransomware Leak Site Intelligence (cold-box)

> **Journal ID:** `CB-SKL-315` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-315`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-ransomware-leak-site-intelligence")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-ransomware-leak-site-intelligence")` → note **`CB-SKL-315`**
2. `log_skill(case_id, journal_id="CB-SKL-315", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-315` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing ransomware leak site intelligence
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

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
  "purpose": "[CB-SKL-315] file per playbook step",
  "why": "Executing cb-ransomware-leak-site-intelligence \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-315` (`cb-ransomware-leak-site-intelligence`)

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

Ransomware groups operating under double-extortion models maintain data leak sites (DLS) on Tor hidden services where they post victim names, stolen data samples, and countdown timers to pressure payment. In H1 2025, 96 unique ransomware groups were active, listing approximately 535 victims per month. Monitoring these sites provides intelligence on active threat groups, targeted sectors, geographic patterns, and emerging ransomware families. This skill covers safely collecting DLS intelligence, extracting structured data, tracking group activity trends, and producing sector-specific risk assessments.


## When to Use

- When investigating security incidents that require analyzing ransomware leak site intelligence
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Python 3.9+ with `requests`, `beautifulsoup4`, `pandas`, `matplotlib` libraries
- Tor proxy (SOCKS5) for accessing .onion sites or commercial DLS monitoring feeds
- Understanding of ransomware double-extortion business model
- Familiarity with major ransomware families (Qilin, Akira, LockBit, BlackCat, Clop)
- Access to ransomware tracking feeds (Ransomwatch, RansomLook, DarkFeed)

## Key Concepts

### Double Extortion Model

Modern ransomware groups encrypt victim data AND exfiltrate it before encryption. Leak sites serve as public pressure: victims are listed with a countdown timer, partial data samples, and file trees. If ransom is not paid, full data is published. Some groups have moved to triple extortion, adding DDoS threats or contacting victims' customers directly.

### DLS Intelligence Value

Leak sites provide: victim identification (company name, sector, country), attack timeline (when listed, deadline, data published), data volume estimates, group capability assessment (sectors targeted, attack frequency, operational tempo), and trend analysis (new groups emerging, groups rebranding, law enforcement takedowns).

### Safe Collection Practices

Never directly access DLS sites in a production environment. Use purpose-built monitoring services (Ransomwatch, DarkFeed, KELA, Flashpoint), Tor-isolated research VMs, commercial threat intelligence platforms, or community-maintained datasets. All analysis should be conducted in isolated environments with proper authorization.

## Workflow

### Step 1: Ingest Ransomware Leak Site Data from Public Feeds

```python
import requests
import json
import pandas as pd
from datetime import datetime, timedelta
from collections import Counter

class RansomwareIntelCollector:
    """Collect ransomware DLS intelligence from public tracking sources."""

    RANSOMWATCH_API = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    RANSOMWATCH_GROUPS = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"

    def __init__(self):
        self.posts = []
        self.groups = []

    def fetch_ransomwatch_data(self):
        """Fetch ransomware victim posts from ransomwatch."""
        resp = requests.get(self.RANSOMWATCH_API, timeout=30)
        if resp.status_code == 200:
            self.posts = resp.json()
            print(f"[+] Loaded {len(self.posts)} victim posts from ransomwatch")
        else:
            print(f"[-] Failed to fetch posts: {resp.status_code}")

        resp = requests.get(self.RANSOMWATCH_GROUPS, timeout=30)
        if resp.status_code == 200:
            self.groups = resp.json()
            print(f"[+] Loaded {len(self.groups)} ransomware group profiles")

        return self.posts

    def get_recent_victims(self, days=30):
        """Get victims posted in the last N days."""
        cutoff = datetime.now() - timedelta(days=days)
        recent = []
        for post in self.posts:
            try:
                discovered = datetime.fromisoformat(
                    post.get("discovered", "").replace("Z", "+00:00")
                )
                if discovered.replace(tzinfo=None) >= cutoff:
                    recent.append(post)
            except (ValueError, TypeError):
                continue
        print(f"[+] {len(recent)} victims in last {days} days")
        return recent

    def get_group_activity(self, group_name):
        """Get all posts by a specific ransomware group."""
        group_posts = [
            p for p in self.posts
            if p.get("group_name", "").lower() == group_name.lower()
        ]
        print(f"[+] {group_name}: {len(group_posts)} total victims")
        return group_posts

collector = RansomwareIntelCollector()
collector.fetch_ransomwatch_data()
recent = collector.get_recent_victims(days=30)
```

### Step 2: Analyze Group Activity and Trends

```python
def analyze_group_trends(posts, top_n=15):
    """Analyze ransomware group activity trends."""
    group_counts = Counter(p.get("group_name", "unknown") for p in posts)
    monthly_activity = {}

    for post in posts:
        try:
            date = datetime.fromisoformat(
                post.get("discovered", "").replace("Z", "+00:00")
            )
            month_key = date.strftime("%Y-%m")
            group = post.get("group_name", "unknown")
            if month_key not in monthly_activity:
                monthly_activity[month_key] = Counter()
            monthly_activity[month_key][group] += 1
        except (ValueError, TypeError):
            continue

    analysis = {
        "total_posts": len(posts),
        "unique_groups": len(group_counts),
        "top_groups": group_counts.most_common(top_n),
        "monthly_totals": {
            month: sum(counts.values())
            for month, counts in sorted(monthly_activity.items())
        },
        "monthly_top_groups": {
            month: counts.most_common(5)
            for month, counts in sorted(monthly_activity.items())
        },
    }

    print(f"\n=== Ransomware Group Activity ===")
    print(f"Total victims tracked: {analysis['total_posts']}")
    print(f"Active groups: {analysis['unique_groups']}")
    print(f"\nTop {top_n} Groups:")
    for group, count in analysis["top_groups"]:
        print(f"  {group}: {count} victims")

    return analysis

trends = analyze_group_trends(collector.posts)
```

### Step 3: Sector and Geographic Risk Assessment

```python
def assess_sector_risk(posts, target_sector=None, target_country=None):
    """Assess ransomware risk for specific sector or geography."""
    sector_data = {}
    country_data = {}

    for post in posts:
        # Extract sector if available (not all feeds include this)
        sector = post.get("sector", post.get("industry", "unknown"))
        country = post.get("country", "unknown")

        if sector not in sector_data:
            sector_data[sector] = {"count": 0, "groups": Counter(), "recent": []}
        sector_data[sector]["count"] += 1
        sector_data[sector]["groups"][post.get("group_name", "")] += 1

        if country not in country_data:
            country_data[country] = {"count": 0, "groups": Counter()}
        country_data[country]["count"] += 1
        country_data[country]["groups"][post.get("group_name", "")] += 1

    # Sector risk scoring
    total = len(posts)
    risk_assessment = {
        "total_victims": total,
        "sectors": {},
        "countries": {},
    }

    for sector, data in sorted(sector_data.items(), key=lambda x: -x[1]["count"]):
        pct = (data["count"] / total * 100) if total > 0 else 0
        risk_assessment["sectors"][sector] = {
            "victim_count": data["count"],
            "percentage": round(pct, 1),
            "top_groups": data["groups"].most_common(5),
            "risk_level": (
                "critical" if pct > 15
                else "high" if pct > 8
                else "medium" if pct > 3
                else "low"
            ),
        }

    for country, data in sorted(country_data.items(), key=lambda x: -x[1]["count"]):
        pct = (data["count"] / total * 100) if total > 0 else 0
        risk_assessment["countries"][country] = {
            "victim_count": data["count"],
            "percentage": round(pct, 1),
            "top_groups": data["groups"].most_common(5),
        }

    return risk_assessment

risk = assess_sector_risk(collector.posts)
```

### Step 4: Track Emerging and Rebranding Groups

```python
def track_new_groups(posts, lookback_days=90):
    """Identify newly emerged ransomware groups."""
    group_first_seen = {}
    for post in posts:
        group = post.get("group_name", "")
        try:
            date = datetime.fromisoformat(
                post.get("discovered", "").replace("Z", "+00:00")
            )
            if group not in group_first_seen or date < group_first_seen[group]["first_seen"]:
                group_first_seen[group] = {
                    "first_seen": date,
                    "first_victim": post.get("post_title", ""),
                }
        except (ValueError, TypeError):
            continue

    cutoff = datetime.now() - timedelta(days=lookback_days)
    new_groups = {
        group: info for group, info in group_first_seen.items()
        if info["first_seen"].replace(tzinfo=None) >= cutoff
    }

    # Count total victims per new group
    for group in new_groups:
        victims = [p for p in posts if p.get("group_name") == group]
        new_groups[group]["total_victims"] = len(victims)
        new_groups[group]["avg_per_month"] = round(
            len(victims) / max(1, lookback_days / 30), 1
        )

    print(f"\n=== New Groups (last {lookback_days} days) ===")
    for group, info in sorted(new_groups.items(), key=lambda x: -x[1]["total_victims"]):
        print(f"  {group}: {info['total_victims']} victims, "
              f"first seen {info['first_seen'].strftime('%Y-%m-%d')}")

    return new_groups

new_groups = track_new_groups(collector.posts, lookback_days=90)
```

### Step 5: Generate Intelligence Report

```python
def generate_ransomware_intel_report(trends, risk, new_groups):
    """Generate ransomware threat intelligence report."""
    report = f"""# Ransomware Threat Intelligence Report
Generated: {datetime.now().isoformat()}

## Executive Summary
- **Total victims tracked**: {trends['total_posts']}
- **Active ransomware groups**: {trends['unique_groups']}
- **New groups (last 90 days)**: {len(new_groups)}

## Top Active Groups
| Rank | Group | Victims |
|------|-------|---------|
"""
    for i, (group, count) in enumerate(trends["top_groups"][:10], 1):
        report += f"| {i} | {group} | {count} |\n"

    report += "\n## New Emerging Groups\n"
    for group, info in sorted(new_groups.items(), key=lambda x: -x[1]["total_victims"])[:10]:
        report += f"- **{group}**: {info['total_victims']} victims since {info['first_seen'].strftime('%Y-%m-%d')}\n"

    report += "\n## Sector Risk Assessment\n"
    report += "| Sector | Victims | % | Risk Level |\n|--------|---------|---|------------|\n"
    for sector, data in list(risk["sectors"].items())[:10]:
        report += f"| {sector} | {data['victim_count']} | {data['percentage']}% | {data['risk_level'].upper()} |\n"

    report += """
## Recommendations
1. Monitor DLS feeds daily for your organization and supply chain partners
2. Prioritize patching vulnerabilities exploited by top active groups
3. Implement offline backup strategy to reduce extortion leverage
4. Conduct tabletop exercises for ransomware scenario response
5. Share indicators with sector ISACs and threat sharing communities
"""
    with open("ransomware_intel_report.md", "w") as f:
        f.write(report)
    print("[+] Report saved: ransomware_intel_report.md")
    return report

generate_ransomware_intel_report(trends, risk, new_groups)
```

## Validation Criteria

- Ransomware victim data ingested from public tracking feeds
- Group activity trends analyzed with monthly breakdowns
- Sector and geographic risk assessment produced
- New and emerging groups identified with activity metrics
- Intelligence report generated with actionable recommendations
- All collection conducted through authorized public sources

## References

- [Ransomwatch GitHub](https://github.com/joshhighet/ransomwatch)
- [SOCRadar: Top Ransomware Statistics 2025](https://socradar.io/blog/top-20-ransomware-statistics-to-know-2025/)
- [Bitsight: Ransomware & Deep Web Trends](https://www.bitsight.com/underground/ransomware)
- [Sophos: Threat Intelligence Report 2025](https://www.sophos.com/en-us/blog/threat-intelligence-executive-report-volume-2025-number-6)
- [H-ISAC: Ransomware Data Leak Sites Report](https://www.aha.org/h-isac-green-reports/2025-08-26-h-isac-tlp-ransomware-data-leak-sites-report-august-26-2025)
- [CYFIRMA: Weekly Intelligence Reports](https://www.cyfirma.com/news/weekly-intelligence-report-16-january-2026/)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
