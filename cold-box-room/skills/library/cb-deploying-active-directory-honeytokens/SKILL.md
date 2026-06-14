---
name: cb-deploying-active-directory-honeytokens
skill_id: cb-deploying-active-directory-honeytokens
journal_id: CB-SKL-168
description: Cold-box analyst playbook — Deploying Active Directory Honeytokens. Deploys
  deception-based honeytokens in Active Directory including fake privileged accounts
  with AdminCount=1, fake SPNs for Kerberoasting detection (honeyroasting), decoy
  GPOs with cpassword traps, and fake BloodHound paths. Monitors Window
domain: cold-box
subdomain: deception-technology
tier: adjacent
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- active-directory
- honeytokens
- kerberoasting
- deception
- detection
- bloodhound
- gpo
cold_box_version: 2
inspired_by: deploying-active-directory-honeytokens
---

# Deploying Active Directory Honeytokens (cold-box)

> **Journal ID:** `CB-SKL-168` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-168`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-deploying-active-directory-honeytokens")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-deploying-active-directory-honeytokens")` → note **`CB-SKL-168`**
2. `log_skill(case_id, journal_id="CB-SKL-168", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-168` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying deception-based detection in Active Directory environments
- When detecting Kerberoasting attacks via fake SPN honeytokens (honeyroasting)
- When creating tripwire accounts to detect credential theft and lateral movement
- When building decoy GPOs to detect Group Policy Preference password harvesting
- When creating deceptive BloodHound paths to misdirect and detect attackers
- When supplementing existing AD monitoring with high-fidelity detection signals

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `sort` | `SIFT-020` | yes | yes |
| `find` | `SIFT-009` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-168] powershell per playbook step",
  "why": "Executing cb-deploying-active-directory-honeytokens \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-168] sort per playbook step",
  "why": "Executing cb-deploying-active-directory-honeytokens \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-168] find per playbook step",
  "why": "Executing cb-deploying-active-directory-honeytokens \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-168` (`cb-deploying-active-directory-honeytokens`)

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

- When deploying deception-based detection in Active Directory environments
- When detecting Kerberoasting attacks via fake SPN honeytokens (honeyroasting)
- When creating tripwire accounts to detect credential theft and lateral movement
- When building decoy GPOs to detect Group Policy Preference password harvesting
- When creating deceptive BloodHound paths to misdirect and detect attackers
- When supplementing existing AD monitoring with high-fidelity detection signals

## Prerequisites

- Domain Admin or delegated AD administration privileges
- Active Directory domain (Windows Server 2016+ recommended)
- Windows Event Log forwarding to SIEM (Splunk, Sentinel, Elastic)
- PowerShell 5.1+ with ActiveDirectory module
- Group Policy Management Console (GPMC)
- Understanding of AD security, Kerberos, and BloodHound attack paths

## Background

### Why AD Honeytokens

Traditional signature-based detection misses novel attack techniques. Honeytokens
provide high-fidelity detection with near-zero false positives because any interaction
with a decoy object is inherently suspicious. In Active Directory:

- **Fake privileged accounts** detect credential dumping (DCSync, NTDS.dit extraction)
- **Fake SPNs** detect Kerberoasting reconnaissance (TGS requests for nonexistent services)
- **Decoy GPOs** detect Group Policy Preference password harvesting
- **Fake BloodHound paths** mislead attackers using graph-based AD analysis

### Key Detection Event IDs

| Event ID | Description | Honeytoken Use |
|----------|-------------|----------------|
| 4769 | Kerberos TGS ticket requested | Detect Kerberoast against honey SPN |
| 4625 | Failed logon attempt | Detect use of fake credentials from decoy GPO |
| 4662 | Directory service object accessed | Detect DACL read on honeytoken user |
| 5136 | Directory service object modified | Detect modification of decoy GPO |
| 5137 | Directory service object created | Detect GPO creation mimicking decoy |
| 4768 | Kerberos TGT requested | Detect AS-REP roasting of honey account |

### Making Honeytokens Realistic

Per Trimarc Security research, effective honeytokens must appear legitimate:

- **Age the account**: Repurpose old inactive accounts (10-15 year old accounts in
  similarly aged domains appear authentic)
- **Set AdminCount=1**: Flags the account as having elevated AD rights, making it
  an attractive Kerberoasting target
- **Use realistic naming**: Match organizational naming conventions (svc_sqlbackup,
  admin.maintenance, svc_exchange_legacy)
- **Set old password date**: Password age of 10+ years with an SPN looks like a
  high-value, neglected service account to attackers
- **Add group memberships**: Place in visible groups like "Remote Desktop Users" or
  a custom "Backup Operators" to increase attacker interest
- **Avoid detection tells**: Attackers check creation date vs. last logon vs.
  password change date for consistency

## Instructions

### Step 1: Deploy Fake Privileged Admin Account

Create a honeytoken account that mimics a legacy privileged service account.

```powershell
# Import the deployment module
Import-Module .\scripts\Deploy-ADHoneytokens.ps1

# Create a honeytoken admin account
$honeyAdmin = New-HoneytokenAdmin `
    -SamAccountName "svc_sqlbackup_legacy" `
    -DisplayName "SQL Backup Service (Legacy)" `
    -Description "Legacy SQL Server backup service account - DO NOT DELETE" `
    -OU "OU=Service Accounts,DC=corp,DC=example,DC=com" `
    -PasswordLength 128 `
    -SetAdminCount $true

Write-Host "Honeytoken admin created: $($honeyAdmin.DistinguishedName)"
```

### Step 2: Deploy Fake SPN for Kerberoasting Detection

Assign a realistic but fake SPN to the honeytoken account. Any TGS request
for this SPN is definitively malicious (honeyroasting).

```powershell
# Add fake SPN to honeytoken account
$honeySPN = Add-HoneytokenSPN `
    -SamAccountName "svc_sqlbackup_legacy" `
    -ServiceClass "MSSQLSvc" `
    -Hostname "sql-legacy-bak01.corp.example.com" `
    -Port 1433

Write-Host "Honey SPN registered: $($honeySPN.SPN)"
Write-Host "Monitor Event ID 4769 for TGS requests targeting this SPN"
```

### Step 3: Deploy Decoy GPO with Credential Trap

Create a fake GPO in SYSVOL with an embedded cpassword (Group Policy Preference
password). Attackers using tools like Get-GPPPassword or gpp-decrypt will find
and attempt to use these credentials, triggering detection.

```powershell
# Create decoy GPO with cpassword trap
$decoyGPO = New-DecoyGPO `
    -GPOName "Server Maintenance Policy (Legacy)" `
    -DecoyUsername "admin_maintenance" `
    -DecoyDomain "CORP" `
    -SYSVOLPath "\\corp.example.com\SYSVOL\corp.example.com\Policies" `
    -EnableAuditSACL $true

Write-Host "Decoy GPO created: $($decoyGPO.GPOGuid)"
Write-Host "SACL audit enabled - any read attempt will generate Event ID 4663"
```

### Step 4: Create Deceptive BloodHound Paths

Set ACL permissions that create fake attack paths visible to BloodHound/SharpHound
reconnaissance, leading attackers toward monitored honeytokens.

```powershell
# Create fake BloodHound attack path
$deceptivePath = New-DeceptiveBloodHoundPath `
    -HoneytokenSamAccount "svc_sqlbackup_legacy" `
    -TargetHighValueGroup "Domain Admins" `
    -IntermediateOU "OU=Service Accounts,DC=corp,DC=example,DC=com"

Write-Host "Deceptive path created: $($deceptivePath.PathDescription)"
```

### Step 5: Configure Detection Rules

Set up SIEM detection rules to alert on any honeytoken interaction.

```python
# Using the Python detection agent
from agent import ADHoneytokenMonitor

monitor = ADHoneytokenMonitor(config_path="honeytoken_config.json")

# Register all honeytokens for monitoring
monitor.register_honeytoken("svc_sqlbackup_legacy", token_type="admin_account")
monitor.register_honeytoken("MSSQLSvc/sql-legacy-bak01.corp.example.com:1433", token_type="spn")
monitor.register_honeytoken("admin_maintenance", token_type="gpo_credential")

# Generate SIEM detection rules
splunk_rules = monitor.generate_detection_rules(siem="splunk")
sentinel_rules = monitor.generate_detection_rules(siem="sentinel")
sigma_rules = monitor.generate_detection_rules(siem="sigma")

for rule in sigma_rules:
    print(f"Rule: {rule['title']}")
    print(f"  Detection: {rule['detection_logic']}")
```

### Step 6: Validate Deployment

Test the honeytokens to ensure detection fires correctly.

```powershell
# Validate honeytoken deployment
$validation = Test-HoneytokenDeployment `
    -SamAccountName "svc_sqlbackup_legacy" `
    -ValidateAdminCount `
    -ValidateSPN `
    -ValidateGPODecoy `
    -ValidateAuditPolicy

$validation | Format-Table Check, Status, Details -AutoSize
```

## Examples

### Full Deployment Pipeline

```powershell
Import-Module .\scripts\Deploy-ADHoneytokens.ps1

# Deploy complete honeytoken suite
$deployment = Deploy-FullHoneytokenSuite `
    -Environment "Production" `
    -ServiceAccountOU "OU=Service Accounts,DC=corp,DC=example,DC=com" `
    -SYSVOLPath "\\corp.example.com\SYSVOL\corp.example.com\Policies" `
    -TokenCount 3 `
    -IncludeSPN $true `
    -IncludeGPODecoy $true `
    -IncludeBloodHoundPath $true `
    -SIEMType "Splunk"

# Output deployment report
$deployment.Tokens | Format-Table Name, Type, SPN, DetectionRule -AutoSize
$deployment | Export-Csv "honeytoken_deployment_report.csv" -NoTypeInformation
```

### Kerberoasting Detection Query (Splunk)

```spl
index=wineventlog EventCode=4769 ServiceName="svc_sqlbackup_legacy"
| eval alert_severity="critical"
| eval alert_type="honeytoken_kerberoast"
| table _time, src_ip, Account_Name, ServiceName, Ticket_Encryption_Type
| sort - _time
```

### Microsoft Sentinel KQL Detection

```kql
SecurityEvent
| where EventID == 4769
| where ServiceName in ("svc_sqlbackup_legacy", "svc_exchange_legacy")
| extend AlertType = "Honeytoken Kerberoast Detected"
| project TimeGenerated, Computer, Account, ServiceName, IpAddress, TicketEncryptionType
```

## References

- Trimarc Security - The Art of the Honeypot Account: https://www.hub.trimarcsecurity.com/post/the-art-of-the-honeypot-account-making-the-unusual-look-normal
- ADSecurity.org - Detecting Kerberoasting Activity Part 2 (Honeypot): https://adsecurity.org/?p=3513
- Microsoft Defender for Identity Honeytokens: https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/deceptive-defense-best-practices-for-identity-based-honeytokens-in-microsoft-def/3851641
- SpecterOps - Kerberoasting and AES-256: https://specterops.io/blog/2025/10/21/is-kerberoasting-still-a-risk-when-aes-256-kerberos-encryption-is-enabled/
- APT29a Blog - Deploying Honeytokens in AD: https://apt29a.blogspot.com/2019/11/deploying-honeytokens-in-active.html
- ADSecurity.org - Detecting Kerberoasting Activity: https://adsecurity.org/?p=3458

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
