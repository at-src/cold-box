---
name: cb-service-account-credential-rotation
skill_id: cb-service-account-credential-rotation
journal_id: CB-SKL-323
description: Cold-box analyst playbook — Service Account Credential Rotation. Automate
  credential rotation for service accounts across Active Directory, cloud platforms,
  and application databases to eliminate stale secrets and reduce compromise risk.
domain: cold-box
subdomain: identity-access-management
tier: adjacent
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- service-accounts
- credential-rotation
- secrets-management
- pam
- automation
- vault
cold_box_version: 2
inspired_by: performing-service-account-credential-rotation
---

# Service Account Credential Rotation (cold-box)

> **Journal ID:** `CB-SKL-323` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-323`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-service-account-credential-rotation")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-service-account-credential-rotation")` → note **`CB-SKL-323`**
2. `log_skill(case_id, journal_id="CB-SKL-323", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-323` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing service account credential rotation
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `find` | `SIFT-009` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-323] powershell per playbook step",
  "why": "Executing cb-service-account-credential-rotation \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-323] find per playbook step",
  "why": "Executing cb-service-account-credential-rotation \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-323] file per playbook step",
  "why": "Executing cb-service-account-credential-rotation \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-323` (`cb-service-account-credential-rotation`)

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

Service accounts are non-human identities used by applications, daemons, CI/CD pipelines, and automated processes to authenticate to systems and APIs. These accounts often have elevated privileges and their credentials (passwords, API keys, certificates, tokens) are frequently long-lived and shared across teams, making them prime targets for attackers. Credential rotation is the systematic process of replacing these secrets on a scheduled basis, propagating new credentials to all dependent systems, and verifying service continuity after rotation.


## When to Use

- When conducting security assessments that involve performing service account credential rotation
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Inventory of all service accounts across AD, cloud, and applications
- Secrets management platform (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or CyberArk)
- Service dependency mapping (which services use which credentials)
- Change management process for rotation windows
- Monitoring for service health post-rotation

## Core Concepts

### Service Account Types

| Type | Platform | Credential | Rotation Method |
|------|----------|-----------|-----------------|
| Active Directory Service Account | Windows/AD | Password | gMSA (automatic) or PAM-managed |
| AWS IAM User | AWS | Access Key/Secret Key | AWS Secrets Manager rotation Lambda |
| GCP Service Account | GCP | JSON key file | Key rotation via IAM API |
| Azure Service Principal | Azure | Client secret/certificate | Key Vault + rotation policy |
| Database Service Account | SQL/Oracle/Postgres | Password | Vault dynamic secrets |
| API Key | SaaS applications | API token | Application-specific API |

### Group Managed Service Accounts (gMSA)

Windows gMSAs provide automatic password management by Active Directory:
- AD automatically rotates the password every 30 days
- Password is 240 bytes, cryptographically random
- Multiple servers can use the same gMSA simultaneously
- No administrator knows or manages the password
- Eliminates manual rotation for Windows services

### Rotation Architecture

```
Secrets Manager / Vault
        │
        ├── Rotation Trigger (schedule or on-demand)
        │
        ├── Generate new credential
        │
        ├── Update credential at source (AD, cloud IAM, database)
        │
        ├── Update credential in all consumers:
        │   ├── Application configuration
        │   ├── CI/CD pipeline secrets
        │   ├── Kubernetes secrets
        │   └── Other dependent services
        │
        ├── Verify service health
        │   ├── Health check endpoints
        │   ├── Authentication test
        │   └── Functional smoke test
        │
        └── Revoke old credential (after grace period)
```

## Workflow

### Step 1: Discover and Inventory Service Accounts

Enumerate all service accounts and their dependencies:

```powershell
# Active Directory: Find all service accounts
Get-ADServiceAccount -Filter * -Properties *
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName,PasswordLastSet,LastLogonDate

# Find accounts with passwords older than 90 days
$threshold = (Get-Date).AddDays(-90)
Get-ADUser -Filter {PasswordLastSet -lt $threshold -and Enabled -eq $true} -Properties PasswordLastSet,ServicePrincipalName |
    Where-Object {$_.ServicePrincipalName} |
    Select-Object Name, PasswordLastSet, ServicePrincipalName
```

### Step 2: Implement gMSA for Windows Services

```powershell
# Create KDS Root Key (one-time, domain-wide)
Add-KdsRootKey -EffectiveImmediately

# Create the gMSA account
New-ADServiceAccount -Name "svc-webapp-gmsa" `
    -DNSHostName "svc-webapp-gmsa.corp.example.com" `
    -PrincipalsAllowedToRetrieveManagedPassword "WebServerGroup" `
    -KerberosEncryptionType AES128,AES256

# Install on target server
Install-ADServiceAccount -Identity "svc-webapp-gmsa"

# Test the account
Test-ADServiceAccount -Identity "svc-webapp-gmsa"

# Configure IIS Application Pool to use gMSA
# Set identity to: CORP\svc-webapp-gmsa$
```

### Step 3: AWS Access Key Rotation with Secrets Manager

```python
import boto3
import json

def rotate_iam_access_key(secret_arn, iam_username):
    """Rotate an IAM user's access key via Secrets Manager."""
    iam = boto3.client("iam")
    sm = boto3.client("secretsmanager")

    # Create new access key
    new_key = iam.create_access_key(UserName=iam_username)
    new_access_key = new_key["AccessKey"]["AccessKeyId"]
    new_secret_key = new_key["AccessKey"]["SecretAccessKey"]

    # Store new credentials in Secrets Manager
    sm.put_secret_value(
        SecretId=secret_arn,
        SecretString=json.dumps({
            "accessKeyId": new_access_key,
            "secretAccessKey": new_secret_key,
            "username": iam_username,
        })
    )

    # List old access keys and deactivate them
    keys = iam.list_access_keys(UserName=iam_username)
    for key in keys["AccessKeyMetadata"]:
        if key["AccessKeyId"] != new_access_key and key["Status"] == "Active":
            iam.update_access_key(
                UserName=iam_username,
                AccessKeyId=key["AccessKeyId"],
                Status="Inactive"
            )

    return {"new_key_id": new_access_key, "old_keys_deactivated": True}
```

### Step 4: Database Credential Rotation with Vault

```python
import hvac

def configure_vault_database_rotation(vault_url, vault_token, db_config):
    """Configure HashiCorp Vault for automatic database credential rotation."""
    client = hvac.Client(url=vault_url, token=vault_token)

    # Enable database secrets engine
    client.sys.enable_secrets_engine(
        backend_type="database",
        path="database"
    )

    # Configure database connection
    client.secrets.database.configure(
        name=db_config["name"],
        plugin_name="postgresql-database-plugin",
        connection_url=f"postgresql://{{{{username}}}}:{{{{password}}}}@"
                       f"{db_config['host']}:{db_config['port']}/{db_config['database']}",
        allowed_roles=[db_config["role_name"]],
        username=db_config["admin_user"],
        password=db_config["admin_password"],
    )

    # Create a role for dynamic credentials
    client.secrets.database.create_role(
        name=db_config["role_name"],
        db_name=db_config["name"],
        creation_statements=[
            "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{{{name}}}}\";"
        ],
        default_ttl="1h",
        max_ttl="24h",
    )

    return {"status": "configured", "role": db_config["role_name"]}
```

### Step 5: Post-Rotation Verification

After every rotation, verify service continuity:

```python
import requests
import time

def verify_service_health(service_endpoints, max_retries=3, delay=10):
    """Check that services are healthy after credential rotation."""
    results = []
    for endpoint in service_endpoints:
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    endpoint["health_url"],
                    timeout=10,
                    headers=endpoint.get("headers", {})
                )
                healthy = response.status_code == 200
                results.append({
                    "service": endpoint["name"],
                    "status": "healthy" if healthy else f"unhealthy ({response.status_code})",
                    "attempt": attempt + 1,
                })
                if healthy:
                    break
            except requests.RequestException as e:
                results.append({
                    "service": endpoint["name"],
                    "status": f"error: {str(e)}",
                    "attempt": attempt + 1,
                })
            if attempt < max_retries - 1:
                time.sleep(delay)

    return results
```

## Validation Checklist

- [ ] Complete inventory of service accounts with dependency mapping
- [ ] gMSA implemented for all eligible Windows service accounts
- [ ] Cloud access keys rotated via secrets manager (AWS, GCP, Azure)
- [ ] Database credentials managed via dynamic secrets (Vault) or rotation policy
- [ ] Rotation schedule defined (30-90 days depending on risk level)
- [ ] Post-rotation health checks automated
- [ ] Alerting configured for rotation failures
- [ ] Old credentials revoked after grace period
- [ ] Rotation events logged and auditable
- [ ] Rollback procedure documented and tested

## References

- [Google Cloud Service Account Key Rotation](https://cloud.google.com/iam/docs/key-rotation)
- [AWS Secrets Manager Rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html)
- [Microsoft gMSA Documentation](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [HashiCorp Vault Database Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/databases)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
