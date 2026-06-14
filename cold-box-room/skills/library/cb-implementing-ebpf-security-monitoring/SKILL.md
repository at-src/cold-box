---
name: cb-implementing-ebpf-security-monitoring
skill_id: cb-implementing-ebpf-security-monitoring
journal_id: CB-SKL-259
description: Cold-box analyst playbook — Implementing Ebpf Security Monitoring. Implements
  eBPF-based security monitoring using Cilium Tetragon for real-time process execution
  tracking, network connection observability, file access auditing, and runtime enforcement.
  Covers TracingPolicy CRD authoring with kprobe/tracep
domain: cold-box
subdomain: security-operations
tier: adjacent
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- ebpf
- tetragon
- cilium
- runtime-security
- observability
- kernel-security
- kubernetes-security
cold_box_version: 2
inspired_by: implementing-ebpf-security-monitoring
---

# Implementing Ebpf Security Monitoring (cold-box)

> **Journal ID:** `CB-SKL-259` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-259`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-ebpf-security-monitoring")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-ebpf-security-monitoring")` → note **`CB-SKL-259`**
2. `log_skill(case_id, journal_id="CB-SKL-259", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-259` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When deploying kernel-level runtime security monitoring on Linux hosts or Kubernetes clusters
- When you need sub-millisecond visibility into process execution, network connections, and file access
- When traditional userspace monitoring tools introduce unacceptable performance overhead
- When building detection pipelines that require in-kernel filtering before events reach userspace
- When enforcing runtime security policies (kill process, send signal) at the kernel level

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `head` | `SIFT-011` | yes | yes |
| `tail` | `SIFT-023` | yes | yes |
| `file` | `SIFT-008` | yes | yes |
| `tar` | `SIFT-003` | yes | yes |
| `jq` | `SIFT-013` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `head` → `SIFT-011`

```json
{
  "tool_id": "SIFT-011",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-259] head per playbook step",
  "why": "Executing cb-implementing-ebpf-security-monitoring \u2014 see Procedure section",
  "extra_args": []
}
```

### `tail` → `SIFT-023`

```json
{
  "tool_id": "SIFT-023",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-259] tail per playbook step",
  "why": "Executing cb-implementing-ebpf-security-monitoring \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-259] file per playbook step",
  "why": "Executing cb-implementing-ebpf-security-monitoring \u2014 see Procedure section",
  "extra_args": []
}
```

### `tar` → `SIFT-003`

```json
{
  "tool_id": "SIFT-003",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-259] tar per playbook step",
  "why": "Executing cb-implementing-ebpf-security-monitoring \u2014 see Procedure section",
  "extra_args": []
}
```

### `jq` → `SIFT-013`

```json
{
  "tool_id": "SIFT-013",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-259] jq per playbook step",
  "why": "Executing cb-implementing-ebpf-security-monitoring \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-259` (`cb-implementing-ebpf-security-monitoring`)

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

- When deploying kernel-level runtime security monitoring on Linux hosts or Kubernetes clusters
- When you need sub-millisecond visibility into process execution, network connections, and file access
- When traditional userspace monitoring tools introduce unacceptable performance overhead
- When building detection pipelines that require in-kernel filtering before events reach userspace
- When enforcing runtime security policies (kill process, send signal) at the kernel level

## Prerequisites

- Linux kernel 5.3+ with BTF (BPF Type Format) support enabled
- Kubernetes 1.24+ cluster (for Kubernetes deployment) or standalone Linux host
- Helm 3.x installed (for Kubernetes deployment)
- `kubectl` configured with cluster access
- `tetra` CLI installed for local event streaming
- Python 3.8+ with `requests`, `kubernetes`, `pyyaml` dependencies
- Root or CAP_BPF/CAP_SYS_ADMIN capabilities for eBPF program loading

## Instructions

### 1. Install Tetragon on Kubernetes

Deploy Tetragon via Helm to get default process lifecycle observability:

```bash
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system \
  --set tetragon.enableProcessCred=true \
  --set tetragon.enableProcessNs=true
```

Verify the installation:

```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | head -20
```

### 2. Install Tetragon on Standalone Linux

For non-Kubernetes Linux hosts, install from the tarball release:

```bash
curl -LO https://github.com/cilium/tetragon/releases/latest/download/tetragon-linux-amd64.tar.gz
tar xzf tetragon-linux-amd64.tar.gz
sudo cp tetragon /usr/local/bin/
sudo cp tetra /usr/local/bin/

# Start tetragon daemon
sudo tetragon --btf /sys/kernel/btf/vmlinux &

# Stream events
tetra getevents -o compact
```

### 3. Monitor Process Execution (Default)

Tetragon generates `process_exec` and `process_exit` events by default without any TracingPolicy:

```bash
# Stream process events in compact format
tetra getevents -o compact

# Stream in JSON for SIEM ingestion
tetra getevents -o json | jq '.process_exec // .process_exit'
```

Example `process_exec` JSON event:

```json
{
  "process_exec": {
    "process": {
      "binary": "/usr/bin/curl",
      "arguments": "https://malicious.example.com/payload",
      "cwd": "/tmp",
      "uid": 1000,
      "pod": {
        "namespace": "default",
        "name": "webapp-7b4d9f8c6-x2k9p"
      },
      "parent": {
        "binary": "/bin/bash",
        "pid": 1234
      }
    }
  }
}
```

### 4. Author TracingPolicy for File Access Monitoring

Create a TracingPolicy CRD to monitor access to sensitive files via the `sys_openat` kprobe:

```yaml
# file-access-monitor.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-sensitive-file-access
spec:
  kprobes:
    - call: "fd_install"
      syscall: false
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "file"
      selectors:
        - matchArgs:
            - index: 1
              operator: "Prefix"
              values:
                - "/etc/shadow"
                - "/etc/passwd"
                - "/etc/sudoers"
                - "/root/.ssh/"
                - "/etc/kubernetes/pki/"
          matchActions:
            - action: Post
```

Apply and observe:

```bash
kubectl apply -f file-access-monitor.yaml
tetra getevents -o compact --process-filter "event_set:PROCESS_KPROBE"
```

### 5. Author TracingPolicy for Network Connection Monitoring

Monitor outbound TCP connections using the `tcp_connect` kprobe:

```yaml
# network-monitor.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-tcp-connections
spec:
  kprobes:
    - call: "tcp_connect"
      syscall: false
      args:
        - index: 0
          type: "sock"
      selectors:
        - matchActions:
            - action: Post
```

### 6. Author TracingPolicy for Privilege Escalation Detection

Detect setuid/setgid calls that may indicate privilege escalation:

```yaml
# privilege-escalation-detect.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-privilege-escalation
spec:
  kprobes:
    - call: "__sys_setuid"
      syscall: false
      args:
        - index: 0
          type: "int"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Equal"
              values:
                - "0"
          matchActions:
            - action: Post
    - call: "commit_creds"
      syscall: false
      args:
        - index: 0
          type: "cred"
      selectors:
        - matchActions:
            - action: Post
```

### 7. Runtime Enforcement with Sigkill Action

Block unauthorized binary execution by killing the process in-kernel:

```yaml
# enforce-binary-allowlist.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: enforce-no-crypto-miners
spec:
  kprobes:
    - call: "sys_execve"
      syscall: true
      args:
        - index: 0
          type: "string"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Postfix"
              values:
                - "xmrig"
                - "minerd"
                - "cpuminer"
                - "cryptonight"
          matchActions:
            - action: Sigkill
```

### 8. Export Events to SIEM

Configure Tetragon to export JSON events to a file sink for Fluentd/Filebeat/Vector ingestion:

```bash
# Helm values for file export
helm upgrade tetragon cilium/tetragon -n kube-system \
  --set tetragon.exportFilename=/var/log/tetragon/tetragon.log \
  --set tetragon.exportFileMaxSizeMB=100 \
  --set tetragon.exportFileMaxBackups=5
```

Then configure your log shipper (e.g., Filebeat) to tail `/var/log/tetragon/tetragon.log` and send to your SIEM.

### 9. Kubernetes-Aware Namespace Filtering

Use `TracingPolicyNamespaced` to scope monitoring to specific namespaces:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: monitor-production-file-access
  namespace: production
spec:
  kprobes:
    - call: "fd_install"
      syscall: false
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "file"
      selectors:
        - matchArgs:
            - index: 1
              operator: "Prefix"
              values:
                - "/etc/shadow"
                - "/etc/passwd"
```

## Examples

### Detect Reverse Shell Connections

```yaml
# reverse-shell-detect.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-reverse-shells
spec:
  kprobes:
    - call: "tcp_connect"
      syscall: false
      args:
        - index: 0
          type: "sock"
      selectors:
        - matchBinaries:
            - operator: "In"
              values:
                - "/bin/bash"
                - "/bin/sh"
                - "/usr/bin/python3"
                - "/usr/bin/perl"
                - "/usr/bin/nc"
                - "/usr/bin/ncat"
          matchActions:
            - action: Post
```

### Monitor Container Escape Attempts

```yaml
# container-escape-detect.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-container-escape
spec:
  kprobes:
    - call: "sys_openat"
      syscall: true
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "string"
      selectors:
        - matchArgs:
            - index: 1
              operator: "Prefix"
              values:
                - "/proc/1/root"
                - "/proc/1/ns"
                - "/sys/kernel/security"
                - "/proc/sysrq-trigger"
          matchActions:
            - action: Post
    - call: "sys_mount"
      syscall: true
      args:
        - index: 0
          type: "string"
        - index: 1
          type: "string"
        - index: 2
          type: "string"
      selectors:
        - matchActions:
            - action: Post
```

### Full Event Pipeline: Tetragon to Elasticsearch

```bash
# Use tetra CLI to pipe events through jq into Elasticsearch
tetra getevents -o json | jq -c 'select(.process_kprobe != null)' | \
  while IFS= read -r line; do
    curl -s -X POST "http://elasticsearch:9200/tetragon-events/_doc" \
      -H "Content-Type: application/json" \
      -d "$line"
  done
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
