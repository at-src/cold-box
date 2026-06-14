---
name: cb-docker-container-forensics
skill_id: cb-docker-container-forensics
journal_id: CB-SKL-037
description: Cold-box analyst playbook — Docker Container Forensics. Investigate compromised
  Docker containers by analyzing images, layers, volumes, logs, and runtime artifacts
  to identify malicious activity and evidence.
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- cloud
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- forensics
- docker
- container-forensics
- container-security
- image-analysis
- runtime-investigation
cold_box_version: 2
inspired_by: analyzing-docker-container-forensics
---

# Docker Container Forensics (cold-box)

> **Journal ID:** `CB-SKL-037` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-037`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-docker-container-forensics")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-docker-container-forensics")` → note **`CB-SKL-037`**
2. `log_skill(case_id, journal_id="CB-SKL-037", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-037` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating a compromised Docker container or container host
- For analyzing malicious Docker images pulled from registries
- During incident response involving containerized application breaches
- When examining container escape attempts or privilege escalation
- For auditing container configurations and identifying misconfigurations

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `sha256sum` | `SIFT-018` | yes | yes |
| `mount` | `SIFT-075` | no | yes |
| `head` | `SIFT-011` | yes | yes |
| `find` | `SIFT-009` | yes | yes |
| `diff` | `SIFT-007` | yes | yes |
| `file` | `SIFT-008` | yes | yes |
| `tar` | `SIFT-003` | yes | yes |
| `ls` | `SIFT-014` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `sha256sum` → `SIFT-018`

```json
{
  "tool_id": "SIFT-018",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-037] sha256sum per playbook step",
  "why": "Executing cb-docker-container-forensics \u2014 see Procedure section",
  "extra_args": []
}
```

### `mount` → `SIFT-075`

```json
{
  "tool_id": "SIFT-075",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-037] mount per playbook step",
  "why": "Executing cb-docker-container-forensics \u2014 see Procedure section",
  "extra_args": []
}
```

### `head` → `SIFT-011`

```json
{
  "tool_id": "SIFT-011",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-037] head per playbook step",
  "why": "Executing cb-docker-container-forensics \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-037] find per playbook step",
  "why": "Executing cb-docker-container-forensics \u2014 see Procedure section",
  "extra_args": []
}
```

### `diff` → `SIFT-007`

```json
{
  "tool_id": "SIFT-007",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-037] diff per playbook step",
  "why": "Executing cb-docker-container-forensics \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-037] file per playbook step",
  "why": "Executing cb-docker-container-forensics \u2014 see Procedure section",
  "extra_args": []
}
```

### `tar` → `SIFT-003`

```json
{
  "tool_id": "SIFT-003",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-037] tar per playbook step",
  "why": "Executing cb-docker-container-forensics \u2014 see Procedure section",
  "extra_args": []
}
```

### `ls` → `SIFT-014`

```json
{
  "tool_id": "SIFT-014",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-037] ls per playbook step",
  "why": "Executing cb-docker-container-forensics \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-037` (`cb-docker-container-forensics`)

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
- When investigating a compromised Docker container or container host
- For analyzing malicious Docker images pulled from registries
- During incident response involving containerized application breaches
- When examining container escape attempts or privilege escalation
- For auditing container configurations and identifying misconfigurations

## Prerequisites
- Docker CLI access on the forensic workstation
- Access to the Docker host file system (forensic image or live)
- Understanding of Docker layered file system (overlay2, aufs)
- dive, docker-explorer, or container-diff for image analysis
- Knowledge of Docker daemon configuration and socket security
- Trivy or Grype for vulnerability scanning of container images

## Workflow

### Step 1: Preserve Container State and Evidence

```bash
# List all containers (including stopped)
docker ps -a --no-trunc > /cases/case-2024-001/docker/container_list.txt

# Inspect the compromised container
CONTAINER_ID="abc123def456"
docker inspect $CONTAINER_ID > /cases/case-2024-001/docker/container_inspect.json

# Export container filesystem as tarball (preserves current state)
docker export $CONTAINER_ID > /cases/case-2024-001/docker/container_export.tar

# Create an image from the container's current state
docker commit $CONTAINER_ID forensic-evidence:case-2024-001
docker save forensic-evidence:case-2024-001 > /cases/case-2024-001/docker/container_image.tar

# Capture container logs
docker logs $CONTAINER_ID --timestamps > /cases/case-2024-001/docker/container_logs.txt 2>&1

# Capture running processes (if container is still running)
docker top $CONTAINER_ID > /cases/case-2024-001/docker/container_processes.txt

# Capture network connections
docker exec $CONTAINER_ID netstat -tlnp 2>/dev/null > /cases/case-2024-001/docker/container_network.txt

# Copy specific files from the container
docker cp $CONTAINER_ID:/var/log/ /cases/case-2024-001/docker/container_var_log/
docker cp $CONTAINER_ID:/tmp/ /cases/case-2024-001/docker/container_tmp/
docker cp $CONTAINER_ID:/etc/passwd /cases/case-2024-001/docker/container_passwd

# Hash all exported evidence
sha256sum /cases/case-2024-001/docker/*.tar > /cases/case-2024-001/docker/evidence_hashes.txt
```

### Step 2: Analyze Container Image Layers

```bash
# Install dive for image layer analysis
wget https://github.com/wagoodman/dive/releases/latest/download/dive_linux_amd64.deb
sudo dpkg -i dive_linux_amd64.deb

# Analyze image layers interactively
dive forensic-evidence:case-2024-001

# Non-interactive layer analysis
dive forensic-evidence:case-2024-001 --ci --json /cases/case-2024-001/docker/dive_analysis.json

# Extract and examine individual layers
mkdir -p /cases/case-2024-001/docker/layers/
tar -xf /cases/case-2024-001/docker/container_image.tar -C /cases/case-2024-001/docker/layers/

# List the image manifest and layer order
cat /cases/case-2024-001/docker/layers/manifest.json | python3 -m json.tool

# Examine each layer for changes
for layer in /cases/case-2024-001/docker/layers/*/layer.tar; do
    echo "=== Layer: $(dirname $layer | xargs basename) ==="
    tar -tf "$layer" | head -20
    echo "..."
done

# Use container-diff to compare with original base image
# Install container-diff
curl -LO https://storage.googleapis.com/container-diff/latest/container-diff-linux-amd64
chmod +x container-diff-linux-amd64

# Compare committed image with original
./container-diff-linux-amd64 diff daemon://nginx:latest daemon://forensic-evidence:case-2024-001 \
   --type=file --type=apt --type=history --json \
   > /cases/case-2024-001/docker/container_diff.json
```

### Step 3: Examine Docker Host Artifacts

```bash
# Docker data directory (default: /var/lib/docker/)
DOCKER_ROOT="/mnt/evidence/var/lib/docker"

# Examine overlay2 filesystem layers
ls -la $DOCKER_ROOT/overlay2/

# Find the container's merged filesystem
CONTAINER_HASH=$(docker inspect $CONTAINER_ID --format '{{.GraphDriver.Data.MergedDir}}' 2>/dev/null)
# Or manually from forensic image:
# Look in /var/lib/docker/containers/<container_id>/config.v2.json

# Analyze container configuration files
cat $DOCKER_ROOT/containers/$CONTAINER_ID/config.v2.json | python3 -m json.tool \
   > /cases/case-2024-001/docker/container_config.json

# Check Docker daemon configuration
cat /mnt/evidence/etc/docker/daemon.json 2>/dev/null > /cases/case-2024-001/docker/daemon_config.json

# Examine Docker events log
cat $DOCKER_ROOT/containers/$CONTAINER_ID/*.log > /cases/case-2024-001/docker/container_json_logs.txt

# Check for volume mounts (potential host filesystem access)
python3 << 'PYEOF'
import json

with open('/cases/case-2024-001/docker/container_inspect.json') as f:
    data = json.load(f)

inspect = data[0] if isinstance(data, list) else data

print("=== CONTAINER SECURITY ANALYSIS ===\n")

# Check mounts
print("Volume Mounts:")
for mount in inspect.get('Mounts', []):
    rw = "READ-WRITE" if mount.get('RW') else "READ-ONLY"
    print(f"  {mount.get('Source', 'N/A')} -> {mount.get('Destination', 'N/A')} ({rw})")
    if mount.get('Source') in ('/', '/etc', '/var', '/root') and mount.get('RW'):
        print(f"    WARNING: Sensitive host path mounted read-write!")

# Check privileged mode
host_config = inspect.get('HostConfig', {})
if host_config.get('Privileged'):
    print("\nWARNING: Container was running in PRIVILEGED mode!")

# Check capabilities
cap_add = host_config.get('CapAdd', [])
if cap_add:
    print(f"\nAdded Capabilities: {cap_add}")
    dangerous_caps = ['SYS_ADMIN', 'SYS_PTRACE', 'NET_ADMIN', 'SYS_MODULE']
    for cap in cap_add:
        if cap in dangerous_caps:
            print(f"  WARNING: Dangerous capability: {cap}")

# Check PID namespace
if host_config.get('PidMode') == 'host':
    print("\nWARNING: Container shares host PID namespace!")

# Check network mode
if host_config.get('NetworkMode') == 'host':
    print("\nWARNING: Container shares host network namespace!")

# Check user
user = inspect.get('Config', {}).get('User', 'root (default)')
print(f"\nRunning as user: {user}")

# Check environment variables for secrets
env_vars = inspect.get('Config', {}).get('Env', [])
print(f"\nEnvironment Variables: {len(env_vars)}")
for env in env_vars:
    key = env.split('=')[0]
    if any(s in key.upper() for s in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL']):
        print(f"  SENSITIVE: {key}=***REDACTED***")
PYEOF
```

### Step 4: Analyze Container File System Changes

```bash
# Compare container filesystem to original image
docker diff $CONTAINER_ID > /cases/case-2024-001/docker/filesystem_changes.txt

# A = Added, C = Changed, D = Deleted
# Analyze changes
python3 << 'PYEOF'
added = []
changed = []
deleted = []

with open('/cases/case-2024-001/docker/filesystem_changes.txt') as f:
    for line in f:
        line = line.strip()
        if line.startswith('A '):
            added.append(line[2:])
        elif line.startswith('C '):
            changed.append(line[2:])
        elif line.startswith('D '):
            deleted.append(line[2:])

print(f"Files Added: {len(added)}")
print(f"Files Changed: {len(changed)}")
print(f"Files Deleted: {len(deleted)}")

# Flag suspicious additions
suspicious = [f for f in added if any(s in f for s in
    ['/tmp/', '/dev/shm/', '/root/', '.sh', '.py', '.elf', 'reverse', 'shell', 'backdoor'])]
if suspicious:
    print(f"\nSuspicious Added Files:")
    for f in suspicious:
        print(f"  {f}")

# Flag suspicious changes
sus_changed = [f for f in changed if any(s in f for s in
    ['/etc/passwd', '/etc/shadow', '/etc/crontab', '/etc/ssh', '.bashrc'])]
if sus_changed:
    print(f"\nSuspicious Changed Files:")
    for f in sus_changed:
        print(f"  {f}")
PYEOF

# Extract and examine the container export
mkdir -p /cases/case-2024-001/docker/container_fs/
tar -xf /cases/case-2024-001/docker/container_export.tar -C /cases/case-2024-001/docker/container_fs/

# Scan for webshells and malicious files
find /cases/case-2024-001/docker/container_fs/tmp/ -type f -exec file {} \;
find /cases/case-2024-001/docker/container_fs/ -name "*.php" -newer /cases/case-2024-001/docker/container_fs/etc/hostname
```

### Step 5: Scan for Vulnerabilities and Generate Report

```bash
# Scan the image for known vulnerabilities
trivy image forensic-evidence:case-2024-001 \
   --format json \
   --output /cases/case-2024-001/docker/vulnerability_scan.json

# Scan the exported filesystem
trivy fs /cases/case-2024-001/docker/container_fs/ \
   --format table \
   --output /cases/case-2024-001/docker/fs_vulnerabilities.txt

# Check for secrets in the image
trivy image forensic-evidence:case-2024-001 \
   --scanners secret \
   --format json \
   --output /cases/case-2024-001/docker/secrets_scan.json
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Image layers | Read-only filesystem layers stacked to form the container image |
| overlay2 | Default Docker storage driver using union filesystem for layers |
| Container diff | Comparison of runtime filesystem changes against the original image |
| Privileged mode | Container with full host capabilities (bypasses most isolation) |
| Docker socket | Unix socket (/var/run/docker.sock) controlling the Docker daemon |
| Container escape | Technique for breaking out of container isolation to the host |
| Volume mounts | Host filesystem paths made accessible inside the container |
| Image history | Record of Dockerfile instructions used to build each layer |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| docker inspect | Detailed container configuration and state information |
| docker diff | Show filesystem changes made in a running/stopped container |
| dive | Interactive Docker image layer analysis tool |
| container-diff | Google tool for comparing container image contents |
| Trivy | Vulnerability scanner for container images and filesystems |
| docker-explorer | Forensic tool for offline Docker artifact analysis |
| Sysdig | Container runtime security monitoring and forensics |
| Falco | Runtime threat detection for containers and Kubernetes |

## Common Scenarios

**Scenario 1: Web Application Container Compromise**
Export the container filesystem, identify webshells in web root, analyze access logs for exploitation attempts, check for added files and modified configurations, examine network connections for C2 communication, review container capabilities for escalation paths.

**Scenario 2: Supply Chain Attack via Malicious Image**
Analyze image layers with dive to identify which layer added malicious content, compare with the official base image using container-diff, check image history for suspicious RUN commands, scan for embedded backdoors and cryptocurrency miners, trace the image pull from registry logs.

**Scenario 3: Container Escape Investigation**
Check if container ran privileged or with dangerous capabilities, examine host filesystem mount points for unauthorized access, review Docker socket mount enabling Docker-in-Docker abuse, analyze host system logs for container escape indicators, check for kernel exploit artifacts.

**Scenario 4: Cryptojacking in Container Environment**
Identify high-CPU containers, export and analyze the container image for mining binaries, check for unauthorized images in the registry, review container creation events for rogue deployments, examine network connections for mining pool communications.

## Output Format

```
Docker Container Forensics Summary:
  Container: abc123def456 (nginx-app)
  Image: company/web-app:v2.1
  Status: Running (started 2024-01-10 09:00 UTC)
  Host: docker-host-01.corp.local

  Security Configuration:
    Privileged: No
    Capabilities Added: NET_ADMIN (WARNING)
    Volume Mounts: /var/log -> /host-logs (RW)
    Network Mode: bridge
    User: root (WARNING)

  Filesystem Changes:
    Added: 23 files (5 suspicious)
    Changed: 12 files (2 suspicious)
    Deleted: 0 files

  Suspicious Findings:
    /tmp/reverse.sh - Reverse shell script (Added)
    /var/www/html/.hidden/shell.php - PHP webshell (Added)
    /etc/crontab - Modified (persistence cron entry added)
    /root/.ssh/authorized_keys - Modified (unauthorized key added)

  Vulnerability Scan:
    Critical: 3 (CVE-2024-xxxx in base image)
    High: 12
    Medium: 34

  Evidence: /cases/case-2024-001/docker/
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
