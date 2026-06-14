---
name: cb-implementing-ransomware-kill-switch-detection
skill_id: cb-implementing-ransomware-kill-switch-detection
journal_id: CB-SKL-279
description: Cold-box analyst playbook — Implementing Ransomware Kill Switch Detection.
  Detects and exploits ransomware kill switch mechanisms including mutex-based execution
  guards, domain-based kill switches, and registry-based termination checks. Implements
  proactive mutex vaccination and kill switch domain monitoring to pr
domain: cold-box
subdomain: ransomware-defense
tier: adjacent
case_profiles:
- malware_analysis
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- ransomware
- kill-switch
- mutex
- detection
- WannaCry
- malware-analysis
cold_box_version: 2
inspired_by: implementing-ransomware-kill-switch-detection
---

# Implementing Ransomware Kill Switch Detection (cold-box)

> **Journal ID:** `CB-SKL-279` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-279`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-ransomware-kill-switch-detection")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-ransomware-kill-switch-detection")` → note **`CB-SKL-279`**
2. `log_skill(case_id, journal_id="CB-SKL-279", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-279` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Analyzing a ransomware sample to determine if it contains a kill switch mechanism (mutex, domain, registry)
- Deploying proactive mutex vaccination across endpoints to prevent known ransomware families from executing
- Monitoring DNS for kill switch domain lookups that indicate ransomware attempting to check before encrypting
- During incident response to quickly determine if a ransomware variant can be stopped by activating its kill switch
- Building detection signatures for ransomware mutex creation events using Sysmon or EDR telemetry

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `handle` | `SIFT-178` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-279] powershell per playbook step",
  "why": "Executing cb-implementing-ransomware-kill-switch-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `handle` → `SIFT-178`

```json
{
  "tool_id": "SIFT-178",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-279] handle per playbook step",
  "why": "Executing cb-implementing-ransomware-kill-switch-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-279] file per playbook step",
  "why": "Executing cb-implementing-ransomware-kill-switch-detection \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-279` (`cb-implementing-ransomware-kill-switch-detection`)

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

- Analyzing a ransomware sample to determine if it contains a kill switch mechanism (mutex, domain, registry)
- Deploying proactive mutex vaccination across endpoints to prevent known ransomware families from executing
- Monitoring DNS for kill switch domain lookups that indicate ransomware attempting to check before encrypting
- During incident response to quickly determine if a ransomware variant can be stopped by activating its kill switch
- Building detection signatures for ransomware mutex creation events using Sysmon or EDR telemetry

**Do not use** kill switch vaccination as a primary defense. Not all ransomware families implement kill switches, and those that do may remove them in newer versions. This is a supplementary detection and prevention layer.

## Prerequisites

- Python 3.8+ with `ctypes` (Windows) for mutex creation and enumeration
- Sysmon installed with Event ID 1 (process creation) and Event ID 17/18 (pipe/mutex events) configured
- Access to malware analysis sandbox for identifying kill switch mechanisms in samples
- DNS monitoring capability for detecting kill switch domain resolution attempts
- Familiarity with Windows internals: mutexes (mutants), kernel objects, named pipes
- Reference database of known ransomware mutexes (github.com/albertzsigovits/malware-mutex)

## Workflow

### Step 1: Identify Kill Switch Mechanisms in Ransomware

Analyze samples for common kill switch patterns:

```
Kill Switch Types Found in Ransomware:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. MUTEX-BASED (most common):
   - Ransomware creates a named mutex at startup
   - If mutex already exists → another instance is running → exit
   - Defense: Pre-create the mutex to prevent execution
   - Examples:
     WannaCry:     Global\MsWinZonesCacheCounterMutexA
     Conti:        kasKDJSAFJauisiudUASIIQWUA82
     REvil:        Global\{GUID-based-on-machine}
     Ryuk:         Global\YOURPRODUCT_MUTEX

2. DOMAIN-BASED:
   - Ransomware resolves a hardcoded domain before executing
   - If domain resolves → security sandbox detected → exit
   - Defense: Register/sinkhole the domain to activate kill switch
   - Examples:
     WannaCry v1:  iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
     WannaCry v1:  fferfsodp9ifjaposdfjhgosurijfaewrwergwea.com

3. REGISTRY-BASED:
   - Check for specific registry key/value before executing
   - If key exists → exit (anti-analysis or kill switch)
   - Defense: Create the registry key proactively

4. FILE-BASED:
   - Check for existence of specific file or directory
   - If marker file exists → exit
   - Defense: Create the marker file on all endpoints

5. LANGUAGE-BASED:
   - Check system language/keyboard layout
   - Exit if Russian/CIS country keyboard detected
   - Common in Eastern European ransomware groups
```

### Step 2: Deploy Mutex Vaccination

Pre-create known ransomware mutexes on endpoints to prevent execution:

```python
# Windows mutex vaccination using ctypes
import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

def create_mutex(name):
    """Create a named mutex to vaccinate against ransomware."""
    handle = kernel32.CreateMutexW(None, False, name)
    error = ctypes.get_last_error()
    if handle == 0:
        return False, f"Failed to create mutex: error {error}"
    if error == 183:  # ERROR_ALREADY_EXISTS
        return True, f"Mutex already exists (already vaccinated): {name}"
    return True, f"Mutex created successfully: {name}"

KNOWN_RANSOMWARE_MUTEXES = [
    "Global\\MsWinZonesCacheCounterMutexA",        # WannaCry
    "Global\\kasKDJSAFJauisiudUASIIQWUA82",        # Conti
    "Global\\YOURPRODUCT_MUTEX",                     # Ryuk variant
    "Global\\JhbGjhBsSQjz",                         # Maze
    "Global\\sdjfhksjdhfsd",                         # Generic ransomware
]
```

### Step 3: Monitor for Mutex Creation Events

Use Sysmon to detect when ransomware creates its characteristic mutexes:

```xml
<!-- Sysmon configuration for mutex monitoring -->
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Event ID 1: Process creation with mutex indicators -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">mutex</CommandLine>
      <CommandLine condition="contains">CreateMutex</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

```
Detection via Event Logs:
━━━━━━━━━━━━━━━━━━━━━━━━
Windows Security Log:
  Event ID 4688: Process creation (enable command line logging)

Sysmon:
  Event ID 1:  Process create (includes command line and hashes)
  Event ID 17: Pipe created (named pipes, similar to mutexes)

PowerShell detection:
  Event ID 4104: Script block logging (detect mutex creation in scripts)

Velociraptor artifact:
  Windows.Detection.Mutants - Enumerates all named mutant objects
```

### Step 4: Monitor DNS for Kill Switch Domains

Detect ransomware domain-based kill switch resolution attempts:

```
DNS Monitoring for Kill Switch Domains:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Monitor DNS queries for known kill switch domains
2. High-entropy domain names (>4.0 entropy in domain label) may indicate
   ransomware kill switch domains or DGA-generated C2 domains
3. Queries to newly registered domains from endpoints that typically
   only access well-established domains

Indicators:
  - Domain with no prior resolution history
  - Domain registered in last 24-72 hours
  - High character entropy in domain name
  - Resolution attempt followed by either mass encryption (kill switch failed)
    or process termination (kill switch activated)
```

### Step 5: Enumerate Active Mutexes for Incident Response

During an active incident, scan endpoints for ransomware-associated mutexes:

```powershell
# PowerShell: List all named mutant objects using Sysinternals Handle
# handle.exe -a -p <PID> | findstr "Mutant"

# Velociraptor query for mutex hunting:
# SELECT * FROM glob(globs="\\BaseNamedObjects\\*") WHERE Name =~ "mutex_pattern"

# Python-based enumeration (requires pywin32):
# import win32event
# handle = win32event.OpenMutex(0x00100000, False, "Global\\MutexName")
```

## Verification

- Verify mutex vaccination by attempting to create the same mutex (should get ERROR_ALREADY_EXISTS)
- Test that vaccinated mutexes survive system reboot (they do not; re-apply at startup via scheduled task)
- Confirm DNS monitoring detects test queries for known kill switch domains
- Validate Sysmon event generation for mutex creation by running a test script
- Check that vaccination does not interfere with legitimate applications using similar mutex names
- Test against actual ransomware samples in an isolated sandbox to confirm kill switch activation

## Key Concepts

| Term | Definition |
|------|------------|
| **Mutex (Mutant)** | A Windows kernel synchronization object used to ensure only one instance of a program runs; ransomware uses named mutexes to prevent re-infection |
| **Kill Switch** | A mechanism in ransomware that causes it to terminate without encrypting if a specific condition is met (mutex exists, domain resolves, file present) |
| **Mutex Vaccination** | Proactively creating named mutexes on endpoints that match known ransomware mutex names, preventing the ransomware from executing |
| **Domain Sinkhole** | Registering or redirecting a malicious domain to a controlled server; used to activate domain-based kill switches |
| **DGA (Domain Generation Algorithm)** | Algorithm used by malware to generate pseudo-random domain names for C2 communication, sometimes incorporating kill switch checks |

## Tools & Systems

- **Sysmon**: Microsoft system monitor providing Event ID 17/18 for named pipe and mutex creation monitoring
- **Velociraptor**: Endpoint visibility tool with built-in artifacts for enumerating mutant (mutex) objects on Windows
- **Sysinternals Handle**: Command-line tool for listing open handles including named mutexes per process
- **malware-mutex (GitHub)**: Community-maintained database of mutexes used by known malware families
- **ANY.RUN**: Interactive malware sandbox that reports mutex creation during dynamic analysis
- **PassiveDNS**: DNS monitoring infrastructure for detecting kill switch domain resolution attempts

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
