---
name: cb-extracting-config-from-agent-tesla-rat
skill_id: cb-extracting-config-from-agent-tesla-rat
journal_id: CB-SKL-220
description: Cold-box analyst playbook — Extracting Config From Agent Tesla Rat. Extract
  embedded configuration from Agent Tesla RAT samples including SMTP/FTP/Telegram
  exfiltration credentials, keylogger settings, and C2 endpoints using .NET decompilation
  and memory analysis.
domain: cold-box
subdomain: malware-analysis
tier: adjacent
case_profiles:
- memory
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- agent-tesla
- rat
- config-extraction
- dotnet
- malware-analysis
- keylogger
- credential-theft
cold_box_version: 2
inspired_by: extracting-config-from-agent-tesla-rat
---

# Extracting Config From Agent Tesla Rat (cold-box)

> **Journal ID:** `CB-SKL-220` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-220`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-extracting-config-from-agent-tesla-rat")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-extracting-config-from-agent-tesla-rat")` → note **`CB-SKL-220`**
2. `log_skill(case_id, journal_id="CB-SKL-220", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-220` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When performing authorized security testing that involves extracting config from agent tesla rat
- When analyzing malware samples or attack artifacts in a controlled environment
- When conducting red team exercises or penetration testing engagements
- When building detection capabilities based on offensive technique understanding

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `strings` | `SIFT-044` | yes | yes |
| `find` | `SIFT-009` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-220] strings per playbook step",
  "why": "Executing cb-extracting-config-from-agent-tesla-rat \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-220] find per playbook step",
  "why": "Executing cb-extracting-config-from-agent-tesla-rat \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-220` (`cb-extracting-config-from-agent-tesla-rat`)

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

Agent Tesla is a .NET-based Remote Access Trojan (RAT) and keylogger that ranked among the top 10 malware variants in 2024, impacting 6.3% of corporate networks globally. It exfiltrates stolen credentials via SMTP email, FTP upload, Telegram bot API, or Discord webhooks. The malware configuration is embedded in the .NET assembly, typically obfuscated using string encryption, resource encryption, or custom loaders that decrypt and execute Agent Tesla in memory via .NET Reflection (fileless). Configuration extraction involves decompiling the .NET assembly with dnSpy or ILSpy, identifying the decryption routine for configuration strings, and extracting SMTP server addresses, credentials, FTP endpoints, Telegram bot tokens, and targeted applications.


## When to Use

- When performing authorized security testing that involves extracting config from agent tesla rat
- When analyzing malware samples or attack artifacts in a controlled environment
- When conducting red team exercises or penetration testing engagements
- When building detection capabilities based on offensive technique understanding

## Prerequisites

- dnSpy or ILSpy for .NET decompilation
- Python 3.9+ with `dnlib` or `pythonnet` for automated extraction
- de4dot for .NET deobfuscation
- Understanding of .NET IL code and Reflection
- Sandbox for dynamic analysis (ANY.RUN, CAPE)

## Workflow

### Step 1: Deobfuscate and Extract Configuration

```python
#!/usr/bin/env python3
"""Extract Agent Tesla RAT configuration from .NET assemblies."""
import re
import sys
import json
import base64
import hashlib
from pathlib import Path


def extract_strings_from_dotnet(filepath):
    """Extract readable strings from .NET binary for config analysis."""
    with open(filepath, 'rb') as f:
        data = f.read()

    # Extract US (User Strings) heap from .NET metadata
    strings = []

    # Look for common Agent Tesla config patterns
    patterns = {
        "smtp_server": re.compile(rb'smtp[\.\-][\w\.\-]+\.\w{2,}', re.I),
        "email": re.compile(rb'[\w\.\-]+@[\w\.\-]+\.\w{2,}'),
        "ftp_url": re.compile(rb'ftp://[\w\.\-:/]+', re.I),
        "telegram_token": re.compile(rb'\d{8,10}:[A-Za-z0-9_-]{35}'),
        "telegram_chat": re.compile(rb'(?:chat_id=|chatid[=:])[\-]?\d{5,15}', re.I),
        "discord_webhook": re.compile(rb'https://discord\.com/api/webhooks/\d+/[\w-]+'),
        "password": re.compile(rb'(?:pass(?:word)?|pwd)[=:]\s*[\w!@#$%^&*]{4,}', re.I),
        "port": re.compile(rb'(?:port|smtp_port)[=:]\s*\d{2,5}', re.I),
    }

    results = {}
    for name, pattern in patterns.items():
        matches = pattern.findall(data)
        if matches:
            results[name] = [m.decode('utf-8', errors='replace') for m in matches]

    # Extract Base64-encoded strings (common obfuscation)
    b64_pattern = re.compile(rb'[A-Za-z0-9+/]{20,}={0,2}')
    b64_decoded = []
    for match in b64_pattern.finditer(data):
        try:
            decoded = base64.b64decode(match.group())
            text = decoded.decode('utf-8', errors='strict')
            if text.isprintable() and len(text) > 5:
                b64_decoded.append(text)
        except Exception:
            pass

    if b64_decoded:
        results["base64_decoded_strings"] = b64_decoded[:30]

    return results


def decrypt_agenttesla_strings(data, key_hex):
    """Decrypt Agent Tesla encrypted configuration strings."""
    key = bytes.fromhex(key_hex)
    # Agent Tesla V1: Simple XOR with key
    decrypted_strings = []

    # Find encrypted blobs (high-entropy byte sequences)
    blob_pattern = re.compile(rb'[\x80-\xff]{16,256}')
    for match in blob_pattern.finditer(data):
        blob = match.group()
        # Try XOR decryption
        decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))
        try:
            text = decrypted.decode('utf-8', errors='strict')
            if text.isprintable() and len(text.strip()) > 3:
                decrypted_strings.append(text.strip())
        except UnicodeDecodeError:
            pass

    # V2: SHA256-based key derivation then AES
    sha256_key = hashlib.sha256(key).digest()

    return decrypted_strings


def analyze_exfiltration_config(config):
    """Analyze extracted configuration for exfiltration methods."""
    methods = []

    if config.get("smtp_server"):
        methods.append({
            "type": "SMTP",
            "servers": config["smtp_server"],
            "emails": config.get("email", []),
        })

    if config.get("ftp_url"):
        methods.append({
            "type": "FTP",
            "urls": config["ftp_url"],
        })

    if config.get("telegram_token"):
        methods.append({
            "type": "Telegram",
            "tokens": config["telegram_token"],
            "chat_ids": config.get("telegram_chat", []),
        })

    if config.get("discord_webhook"):
        methods.append({
            "type": "Discord",
            "webhooks": config["discord_webhook"],
        })

    return methods


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <agent_tesla_sample>")
        sys.exit(1)

    config = extract_strings_from_dotnet(sys.argv[1])
    methods = analyze_exfiltration_config(config)

    report = {"raw_config": config, "exfiltration_methods": methods}
    print(json.dumps(report, indent=2))
```

## Validation Criteria

- Exfiltration method identified (SMTP/FTP/Telegram/Discord)
- Server addresses and credentials extracted from config
- Targeted applications list recovered
- Keylogger and screenshot capture settings documented
- Persistence mechanism identified
- IOCs suitable for network blocking extracted

## References

- [Splunk - Agent Tesla Detection and Analysis](https://www.splunk.com/en_us/blog/security/inside-the-mind-of-a-rat-agent-tesla-detection-and-analysis.html)
- [Qualys - Catching the RAT Agent Tesla](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/02/catching-the-rat-called-agent-tesla)
- [ANY.RUN Agent Tesla Analysis](https://any.run/malware-trends/agenttesla/)
- [Trustwave - Agent Tesla Novel Loader](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/agent-teslas-new-ride-the-rise-of-a-novel-loader/)
- [Malpedia - Agent Tesla](https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
