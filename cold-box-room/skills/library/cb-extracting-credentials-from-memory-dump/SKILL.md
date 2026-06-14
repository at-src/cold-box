---
name: cb-extracting-credentials-from-memory-dump
skill_id: cb-extracting-credentials-from-memory-dump
journal_id: CB-SKL-042
description: Cold-box analyst playbook — Extracting Credentials From Memory Dump.
  Extract cached credentials, password hashes, Kerberos tickets, and authentication
  tokens from memory dumps using Volatility and Mimikatz for forensic investigation.
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- memory
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- forensics
- credential-extraction
- memory-forensics
- volatility
- mimikatz
- password-hashes
- incident-response
cold_box_version: 2
inspired_by: extracting-credentials-from-memory-dump
---

# Extracting Credentials From Memory Dump (cold-box)

> **Journal ID:** `CB-SKL-042` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-042`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-extracting-credentials-from-memory-dump")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-extracting-credentials-from-memory-dump")` → note **`CB-SKL-042`**
2. `log_skill(case_id, journal_id="CB-SKL-042", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-042` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- During incident response to determine what credentials an attacker had access to
- When assessing the scope of credential compromise after a breach
- For identifying accounts that need immediate password resets
- When investigating lateral movement and pass-the-hash/pass-the-ticket attacks
- For recovering encryption keys or authentication tokens from process memory

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `sha256sum` | `SIFT-018` | yes | yes |
| `procdump` | `SIFT-180` | no | no |
| `strings` | `SIFT-044` | yes | yes |
| `pslist` | `SIFT-182` | no | no |
| `grep` | `SIFT-010` | yes | yes |
| `file` | `SIFT-008` | yes | yes |
| `vol` | `SIFT-173` | no | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `sha256sum` → `SIFT-018`

```json
{
  "tool_id": "SIFT-018",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-042] sha256sum per playbook step",
  "why": "Executing cb-extracting-credentials-from-memory-dump \u2014 see Procedure section",
  "extra_args": []
}
```

### `procdump` → `SIFT-180`

```json
{
  "tool_id": "SIFT-180",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-042] procdump per playbook step",
  "why": "Executing cb-extracting-credentials-from-memory-dump \u2014 see Procedure section",
  "extra_args": []
}
```

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-042] strings per playbook step",
  "why": "Executing cb-extracting-credentials-from-memory-dump \u2014 see Procedure section",
  "extra_args": []
}
```

### `pslist` → `SIFT-182`

```json
{
  "tool_id": "SIFT-182",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-042] pslist per playbook step",
  "why": "Executing cb-extracting-credentials-from-memory-dump \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-042] grep per playbook step",
  "why": "Executing cb-extracting-credentials-from-memory-dump \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-042] file per playbook step",
  "why": "Executing cb-extracting-credentials-from-memory-dump \u2014 see Procedure section",
  "extra_args": []
}
```

### `vol` → `SIFT-173`

```json
{
  "tool_id": "SIFT-173",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-042] vol per playbook step",
  "why": "Executing cb-extracting-credentials-from-memory-dump \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-042` (`cb-extracting-credentials-from-memory-dump`)

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
- During incident response to determine what credentials an attacker had access to
- When assessing the scope of credential compromise after a breach
- For identifying accounts that need immediate password resets
- When investigating lateral movement and pass-the-hash/pass-the-ticket attacks
- For recovering encryption keys or authentication tokens from process memory

## Prerequisites
- Memory dump in raw, ELF, or crash dump format
- Volatility 3 with Windows symbol tables
- Mimikatz (for offline analysis of extracted LSASS dumps)
- pypykatz (Python implementation of Mimikatz for Linux-based analysis)
- Understanding of Windows authentication (NTLM, Kerberos, DPAPI)
- Appropriate legal authorization for credential extraction

## Workflow

### Step 1: Prepare Tools and Verify Memory Dump

```bash
# Install analysis tools
pip install volatility3 pypykatz

# Verify memory dump integrity
sha256sum /cases/case-2024-001/memory/memory.raw

# Identify the OS version
vol -f /cases/case-2024-001/memory/memory.raw windows.info

# Verify LSASS process exists in memory
vol -f /cases/case-2024-001/memory/memory.raw windows.pslist | grep -i lsass

# Output:
# PID    PPID   ImageFileName   Offset(V)        Threads  Handles  SessionId
# 684    564    lsass.exe       0xffffe00123456   35       1234     0
```

### Step 2: Extract Credential Hashes with Volatility

```bash
# Dump SAM database hashes from memory
vol -f /cases/case-2024-001/memory/memory.raw windows.hashdump \
   | tee /cases/case-2024-001/analysis/hashdump.txt

# Output format:
# User           RID    LM Hash                          NTLM Hash
# Administrator  500    aad3b435b51404eeaad3b435b51404ee  fc525c9683e8fe067095ba2ddc971889
# Guest          501    aad3b435b51404eeaad3b435b51404ee  31d6cfe0d16ae931b73c59d7e0c089c0
# DefaultAccount 503    aad3b435b51404eeaad3b435b51404ee  31d6cfe0d16ae931b73c59d7e0c089c0
# svcbackup      1001   aad3b435b51404eeaad3b435b51404ee  2b576acbe6bcfda7294d6bd18041b8fe

# Extract LSA secrets
vol -f /cases/case-2024-001/memory/memory.raw windows.lsadump \
   | tee /cases/case-2024-001/analysis/lsadump.txt

# Extract cached domain credentials
vol -f /cases/case-2024-001/memory/memory.raw windows.cachedump \
   | tee /cases/case-2024-001/analysis/cachedump.txt
```

### Step 3: Dump LSASS Process Memory for Detailed Analysis

```bash
# Dump LSASS process memory (PID from Step 1)
vol -f /cases/case-2024-001/memory/memory.raw windows.memmap --pid 684 --dump \
   -o /cases/case-2024-001/analysis/lsass_dump/

# Alternative: Dump all files associated with LSASS
vol -f /cases/case-2024-001/memory/memory.raw windows.dumpfiles --pid 684 \
   -o /cases/case-2024-001/analysis/lsass_files/

# Use procdump plugin for cleaner process dump
vol -f /cases/case-2024-001/memory/memory.raw windows.dumpfiles \
   --pid 684 -o /cases/case-2024-001/analysis/

# Rename the dump file for pypykatz/mimikatz
mv /cases/case-2024-001/analysis/lsass_dump/pid.684.dmp \
   /cases/case-2024-001/analysis/lsass.dmp
```

### Step 4: Extract Credentials with pypykatz

```bash
# Run pypykatz against the full memory dump
pypykatz lsa minidump /cases/case-2024-001/analysis/lsass.dmp \
   > /cases/case-2024-001/analysis/pypykatz_results.txt 2>&1

# Run pypykatz against the raw memory dump directly
pypykatz rekall /cases/case-2024-001/memory/memory.raw \
   > /cases/case-2024-001/analysis/pypykatz_full.txt 2>&1

# Parse pypykatz output for structured analysis
python3 << 'PYEOF'
import json

# pypykatz can also output JSON
import subprocess
result = subprocess.run(
    ['pypykatz', 'lsa', 'minidump', '/cases/case-2024-001/analysis/lsass.dmp', '-j'],
    capture_output=True, text=True
)

if result.stdout:
    data = json.loads(result.stdout)

    print("=== EXTRACTED CREDENTIALS ===\n")

    for session_key, session in data.get('logon_sessions', {}).items():
        username = session.get('username', 'Unknown')
        domain = session.get('domainname', '')
        logon_server = session.get('logon_server', '')
        logon_time = session.get('logon_time', '')
        sid = session.get('sid', '')

        if username and username != '(null)':
            print(f"Session: {domain}\\{username}")
            print(f"  SID: {sid}")
            print(f"  Logon Server: {logon_server}")
            print(f"  Logon Time: {logon_time}")

            # NTLM hashes
            msv = session.get('msv_creds', [])
            for cred in msv:
                nt = cred.get('NThash', '')
                lm = cred.get('LMHash', '')
                if nt:
                    print(f"  NTLM Hash: {nt}")
                if lm:
                    print(f"  LM Hash: {lm}")

            # Kerberos tickets
            kerb = session.get('kerberos_creds', [])
            for cred in kerb:
                password = cred.get('password', '')
                if password:
                    print(f"  Kerberos Password: {password}")
                tickets = cred.get('tickets', [])
                for ticket in tickets:
                    print(f"  Kerberos Ticket: {ticket.get('server', '')} (type: {ticket.get('enc_type', '')})")

            # WDigest (plaintext on older systems)
            wdigest = session.get('wdigest_creds', [])
            for cred in wdigest:
                pwd = cred.get('password', '')
                if pwd:
                    print(f"  WDigest Password: {pwd}")

            # DPAPI master keys
            dpapi = session.get('dpapi_creds', [])
            for cred in dpapi:
                mk = cred.get('masterkey', '')
                if mk:
                    print(f"  DPAPI Master Key: {mk[:40]}...")

            print()
PYEOF
```

### Step 5: Extract Kerberos Tickets and Tokens

```bash
# Extract Kerberos tickets from memory
python3 << 'PYEOF'
import subprocess, json

result = subprocess.run(
    ['pypykatz', 'lsa', 'minidump', '/cases/case-2024-001/analysis/lsass.dmp', '-j', '-k', '/cases/case-2024-001/analysis/kerberos/'],
    capture_output=True, text=True
)

# pypykatz exports .kirbi files to the specified directory
import os
kirbi_dir = '/cases/case-2024-001/analysis/kerberos/'
if os.path.exists(kirbi_dir):
    for f in os.listdir(kirbi_dir):
        if f.endswith('.kirbi'):
            filepath = os.path.join(kirbi_dir, f)
            size = os.path.getsize(filepath)
            print(f"  Kerberos ticket: {f} ({size} bytes)")
PYEOF

# Search process memory for authentication tokens and API keys
vol -f /cases/case-2024-001/memory/memory.raw windows.strings --pid 684 | \
   grep -iE '(bearer |authorization:|api[_-]key|token=|password=|secret=)' \
   > /cases/case-2024-001/analysis/auth_strings.txt

# Search for cloud credentials in memory
vol -f /cases/case-2024-001/memory/memory.raw windows.strings | \
   grep -iE '(AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|aws_secret_access_key)' \
   > /cases/case-2024-001/analysis/aws_credentials.txt

# Search for browser session tokens
vol -f /cases/case-2024-001/memory/memory.raw windows.strings | \
   grep -iE '(session_id=|PHPSESSID=|JSESSIONID=|_ga=|sid=)' \
   > /cases/case-2024-001/analysis/session_tokens.txt
```

### Step 6: Compile Credential Findings Report

```bash
# Generate credential compromise assessment
python3 << 'PYEOF'
print("""
CREDENTIAL EXTRACTION REPORT
==============================
Case: 2024-001
Source: memory.raw (16 GB Windows 10 memory dump)
Analysis Date: 2024-01-20

COMPROMISED ACCOUNTS:
=====================

1. Local Accounts (SAM):
   - Administrator (RID 500): NTLM hash extracted
   - svcbackup (RID 1001): NTLM hash extracted
   - SQLService (RID 1002): NTLM hash extracted

2. Domain Accounts (LSASS):
   - CORP\\admin.user: NTLM hash + Kerberos TGT
   - CORP\\svc.backup: NTLM hash + plaintext password (WDigest)
   - CORP\\domain.admin: Kerberos TGS tickets for 3 services

3. Cached Domain Credentials:
   - CORP\\helpdesk.user: DCC2 hash
   - CORP\\it.manager: DCC2 hash

4. Cloud Credentials:
   - AWS Access Key: AKIA... found in process memory (PID 3456)
   - Azure AD token found in browser process memory

IMMEDIATE ACTIONS REQUIRED:
- Reset passwords for all listed accounts
- Revoke and rotate AWS access keys
- Invalidate all active Kerberos tickets (krbtgt reset)
- Review DPAPI-protected data for additional exposure
""")
PYEOF
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| LSASS (Local Security Authority) | Windows process managing authentication, storing credentials in memory |
| NTLM hash | NT LAN Manager hash of user password used for authentication |
| Kerberos TGT | Ticket Granting Ticket allowing request of service tickets |
| WDigest | Legacy authentication protocol storing plaintext passwords in memory (pre-Win8.1) |
| DPAPI | Data Protection API using master keys derived from user credentials |
| DCC2 (Domain Cached Credentials) | Cached domain password hashes for offline logon |
| LSA Secrets | Encrypted service account passwords and other secrets stored by LSA |
| Pass-the-Hash | Attack technique using extracted NTLM hashes without knowing the plaintext password |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Volatility 3 | Memory forensics framework with hashdump, lsadump, cachedump plugins |
| pypykatz | Python implementation of Mimikatz for cross-platform LSASS analysis |
| Mimikatz | Windows credential extraction tool (used offline against dumps) |
| secretsdump.py | Impacket tool for extracting secrets from SAM/SYSTEM/SECURITY |
| hashcat | Password hash cracking for recovered NTLM and DCC2 hashes |
| John the Ripper | Alternative password cracking tool |
| Rubeus | Kerberos ticket manipulation and extraction tool |
| Impacket | Python toolkit for working with Windows network protocols and credentials |

## Common Scenarios

**Scenario 1: Post-Breach Credential Assessment**
Extract all cached credentials from LSASS memory to determine which accounts were exposed, prioritize password resets based on privilege level, check for golden ticket material (krbtgt hash), assess if cloud credentials were accessible.

**Scenario 2: Lateral Movement Investigation**
Extract NTLM hashes and Kerberos tickets to understand how the attacker moved between systems, identify pass-the-hash/pass-the-ticket artifacts, correlate extracted credentials with network logon events in event logs.

**Scenario 3: Ransomware Operator Credential Theft**
Analyze pre-encryption memory dump for Mimikatz execution evidence, extract all available credential types, determine if domain admin credentials were obtained, assess if krbtgt was compromised (golden ticket), plan credential rotation strategy.

**Scenario 4: Cloud Credential Theft from Endpoint**
Search endpoint memory for AWS access keys, Azure tokens, and GCP service account keys stored by CLI tools and browsers, identify exposed cloud permissions, immediately rotate discovered credentials, audit cloud audit logs for unauthorized access.

## Output Format

```
Credential Extraction Summary:
  Source: memory.raw (16 GB, Windows 10 Build 19041)
  LSASS PID: 684

  Credentials Recovered:
    Local NTLM Hashes:        4 accounts
    Domain NTLM Hashes:       3 accounts
    Kerberos TGTs:             2 tickets
    Kerberos TGS:              5 service tickets
    Plaintext Passwords:       1 (WDigest - svc.backup)
    Cached Domain Creds:       2 DCC2 hashes
    LSA Secrets:               3 service account passwords
    DPAPI Master Keys:         4 keys recovered
    Cloud Credentials:         1 AWS access key, 1 Azure token

  Highest Privilege Compromised: Domain Admin (CORP\domain.admin)

  Recommended Actions:
    - Immediate: Reset all extracted account passwords
    - Immediate: Rotate AWS access key AKIA...
    - Urgent: Double krbtgt password reset (golden ticket mitigation)
    - High: Revoke all Kerberos tickets via krbtgt rotation
    - Medium: Audit DPAPI-protected data exposure
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
