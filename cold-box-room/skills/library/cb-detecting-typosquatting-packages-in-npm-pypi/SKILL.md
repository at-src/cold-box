---
name: cb-detecting-typosquatting-packages-in-npm-pypi
skill_id: cb-detecting-typosquatting-packages-in-npm-pypi
journal_id: CB-SKL-210
description: Cold-box analyst playbook — Detecting Typosquatting Packages In Npm Pypi.
  Detects typosquatting attacks in npm and PyPI package registries by analyzing package
  name similarity using Levenshtein distance and other string metrics, examining publish
  date heuristics to identify recently created packages mimicking est
domain: cold-box
subdomain: supply-chain-security
tier: adjacent
case_profiles:
- general
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- typosquatting
- npm
- pypi
- supply-chain
- package-security
- Levenshtein
- dependency-confusion
- malicious-packages
cold_box_version: 2
inspired_by: detecting-typosquatting-packages-in-npm-pypi
---

# Detecting Typosquatting Packages In Npm Pypi (cold-box)

> **Journal ID:** `CB-SKL-210` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-210`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-typosquatting-packages-in-npm-pypi")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-typosquatting-packages-in-npm-pypi")` → note **`CB-SKL-210`**
2. `log_skill(case_id, journal_id="CB-SKL-210", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-210` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Auditing project dependencies to identify packages whose names are suspiciously similar to popular libraries
- Proactively scanning package registries for newly published packages that may be typosquats of your organization's packages
- Investigating a suspected supply chain compromise where a developer installed a misspelled package name
- Building automated monitoring that alerts when new packages appear with names close to critical dependencies
- Assessing the risk profile of unfamiliar packages before adding them to a project's dependency tree

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `strings` | `SIFT-044` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-210] strings per playbook step",
  "why": "Executing cb-detecting-typosquatting-packages-in-npm-pypi \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-210` (`cb-detecting-typosquatting-packages-in-npm-pypi`)

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

- Auditing project dependencies to identify packages whose names are suspiciously similar to popular libraries
- Proactively scanning package registries for newly published packages that may be typosquats of your organization's packages
- Investigating a suspected supply chain compromise where a developer installed a misspelled package name
- Building automated monitoring that alerts when new packages appear with names close to critical dependencies
- Assessing the risk profile of unfamiliar packages before adding them to a project's dependency tree

**Do not use** as the sole determination of malicious intent; name similarity alone does not prove a package is malicious. Do not use for bulk automated takedown requests without manual review of flagged packages. Do not use against private registries without authorization.

## Prerequisites

- Python 3.9+ with `requests` and `python-Levenshtein` (or `rapidfuzz`) packages installed
- Network access to `https://pypi.org/pypi/<package>/json` (PyPI JSON API) and `https://registry.npmjs.org/<package>` (npm registry API)
- A list of popular or critical packages to monitor (e.g., top 1000 PyPI packages, organization's dependency list)
- Understanding of common typosquatting patterns: character omission, transposition, insertion, substitution, and hyphen/underscore manipulation

## Workflow

### Step 1: Build the Target Package Watchlist

Establish the set of legitimate packages to monitor for typosquats:

- **Extract project dependencies**: Parse `requirements.txt`, `Pipfile.lock`, `package.json`, or `package-lock.json` to extract all direct and transitive dependency names
- **Include popular packages**: Supplement with high-value targets from the top 1000 PyPI downloads (available from `https://hugovk.github.io/top-pypi-packages/`) or top npm packages by download count
- **Add organization packages**: Include any packages published by your organization that attackers might target with typosquats to intercept internal installations
- **Normalize names**: PyPI treats hyphens, underscores, and periods as equivalent (PEP 503 normalization: `re.sub(r"[-_.]+", "-", name).lower()`). npm package names are case-sensitive but scoped packages use `@scope/name` format. Normalize before comparison.

### Step 2: Generate Candidate Typosquat Names

Produce potential typosquat variants for each target package:

- **Character omission**: Remove each character one at a time (`requests` -> `rquests`, `requets`, `reqests`)
- **Character transposition**: Swap adjacent characters (`requests` -> `erquests`, `rqeuests`, `reques ts`)
- **Character substitution**: Replace characters with keyboard-adjacent keys using a QWERTY distance map (`requests` -> `rrquests`, `requesta`)
- **Character insertion**: Insert common characters at each position (`requests` -> `rrequests`, `reqquests`)
- **Separator manipulation**: For hyphenated names, try removing, doubling, or replacing separators (`my-package` -> `mypackage`, `my--package`, `my_package`)
- **Common prefix/suffix attacks**: Prepend or append common strings (`python-requests`, `requests-python`, `requests2`, `requests-lib`)

### Step 3: Query Registry APIs for Candidate Packages

Check whether generated candidate names actually exist in the registry:

- **PyPI JSON API**: Send `GET https://pypi.org/pypi/<candidate>/json` for each candidate. A `200` response means the package exists; `404` means it does not. Extract from the response: `info.name`, `info.version`, `info.author`, `info.summary`, `info.home_page`, `info.project_urls`, and `releases` (keyed by version with `upload_time_iso_8601` timestamps).
- **npm registry API**: Send `GET https://registry.npmjs.org/<candidate>` with `Accept: application/json`. Extract: `name`, `description`, `dist-tags.latest`, `time.created`, `time.modified`, `maintainers`, and `versions`.
- **Rate limiting**: PyPI has no published rate limits but respect reasonable request rates (1-2 requests/second). npm registry returns `429` when rate limited; implement exponential backoff.
- **Batch optimization**: For large candidate lists, parallelize requests with connection pooling (`requests.Session`) and limit concurrency to avoid triggering abuse protections.

### Step 4: Analyze Package Metadata for Suspicion Signals

Score each existing candidate package against multiple heuristic signals:

- **Levenshtein distance**: Calculate the edit distance between the candidate name and the target. Packages with distance 1-2 from a popular package are high-priority suspects. Historical analysis shows 18 of 40 known typosquats had Levenshtein distance of 2 or less from their targets.
- **Publish date recency**: Compare the candidate's first publish date against the target's. A package created years after its near-namesake is more suspicious. Flag packages created within the last 90 days that are similar to packages published years ago.
- **Download count disparity**: Compare weekly downloads. Legitimate similarly-named packages typically have comparable or explainable download counts. A package with 50 downloads versus its near-namesake with 5 million downloads is suspicious. PyPI download stats are available via BigQuery (`pypistats.org/api/`); npm provides download counts at `https://api.npmjs.org/downloads/point/last-week/<package>`.
- **Author and maintainer analysis**: Check if the candidate package author matches the legitimate package author. Different authors for near-identical names increase suspicion.
- **Description similarity**: Compare package descriptions. Typosquats frequently copy or closely paraphrase the target package description to appear legitimate.
- **Version count**: Legitimate packages typically have many versions over time. A package with only 1-2 versions and a name similar to a popular package is suspicious.
- **Repository URL analysis**: Check if the candidate links to the same repository as the target (likely legitimate fork/mirror) or has no repository URL (suspicious).

### Step 5: Score, Rank, and Report Findings

Combine signals into a composite risk score and generate an actionable report:

- **Weighted scoring**: Assign weights to each signal. Example: Levenshtein distance 1 = 40 points, Levenshtein distance 2 = 25 points, created < 90 days ago = 15 points, download ratio < 0.001 = 15 points, different author = 10 points, single version = 5 points. Total score out of 100.
- **Threshold classification**: Score >= 70: HIGH risk (likely typosquat), 40-69: MEDIUM risk (requires manual review), < 40: LOW risk (likely legitimate)
- **Generate report**: For each flagged package, include the target it mimics, all signal values, the composite score, direct links to both packages on the registry, and a recommendation (block, investigate, or allow)
- **Actionable output**: Produce a blocklist of flagged package names that can be imported into package manager deny-lists, CI/CD policy engines, or artifact repository proxy rules

## Key Concepts

| Term | Definition |
|------|------------|
| **Typosquatting** | Registering a package name that closely resembles a popular package, exploiting common typos to trick developers into installing malicious code |
| **Levenshtein Distance** | The minimum number of single-character edits (insertions, deletions, substitutions) required to transform one string into another; the primary metric for measuring name similarity |
| **Dependency Confusion** | A broader supply chain attack where attackers publish malicious packages to public registries with names matching private internal packages, exploiting package manager resolution order |
| **PEP 503 Normalization** | The Python packaging specification that treats hyphens, underscores, and periods as equivalent in package names, meaning `my-package`, `my_package`, and `my.package` resolve to the same package |
| **QWERTY Distance** | A keyboard-layout-aware distance metric measuring how far apart two keys are on a standard keyboard, used to detect substitutions from adjacent key mistyping |
| **Combosquatting** | A variant of typosquatting where attackers prepend or append common words to a package name (e.g., `requests-security`, `python-requests`) |
| **StarJacking** | An attack where a typosquat package links its repository URL to the legitimate package's GitHub repository to inflate apparent credibility |

## Tools & Systems

- **PyPI JSON API**: REST API at `https://pypi.org/pypi/<package>/json` returning package metadata including name, author, versions, upload timestamps, and project URLs
- **npm Registry API**: REST API at `https://registry.npmjs.org/<package>` returning package metadata including maintainers, version history, creation timestamps, and distribution info
- **python-Levenshtein / rapidfuzz**: Python libraries for fast string distance computation, supporting Levenshtein, Damerau-Levenshtein, Jaro-Winkler, and other similarity metrics
- **pypistats.org API**: Provides download statistics for PyPI packages, enabling download count comparison between suspected typosquats and their targets
- **npm download counts API**: Endpoint at `https://api.npmjs.org/downloads/point/<period>/<package>` providing download statistics for npm packages

## Common Scenarios

### Scenario: Auditing a Python Project for Typosquatted Dependencies

**Context**: A security team discovers that a developer's workstation was compromised after installing a Python package. The incident response team needs to audit all project dependencies for potential typosquats and establish ongoing monitoring.

**Approach**:
1. Parse `requirements.txt` and `Pipfile.lock` to extract all 87 direct and transitive dependencies
2. Generate typosquat candidates for each dependency using character omission, transposition, substitution, and separator manipulation, producing approximately 2,400 candidate names
3. Query the PyPI JSON API for each candidate, finding 34 that actually exist as published packages
4. Score each existing candidate: 3 packages score above 70 (HIGH risk) with Levenshtein distance 1, created within the last 60 days, single version, and fewer than 100 downloads
5. Manual review confirms 2 of the 3 are malicious typosquats containing obfuscated code that exfiltrates environment variables during installation
6. Block the malicious packages in the organization's artifact proxy, report to PyPI for takedown via `security@pypi.org`, and add all 87 dependencies to the ongoing monitoring watchlist
7. Implement the detection agent as a scheduled CI job that runs weekly and alerts on new HIGH-risk findings

**Pitfalls**:
- Not normalizing PyPI package names per PEP 503 before comparison, causing missed matches between hyphenated and underscored variants
- Setting the Levenshtein distance threshold too low (only 1) and missing typosquats at distance 2 that use double substitutions
- Relying solely on name similarity without checking metadata signals, leading to high false positive rates on legitimately similar package names
- Not accounting for npm scoped packages (`@scope/name`) which have different naming rules than unscoped packages
- Querying the registries too aggressively and getting rate-limited or IP-blocked

## Output Format

```
## Typosquatting Detection Report

**Scan Date**: 2026-03-19
**Registry**: PyPI
**Packages Monitored**: 87
**Candidates Generated**: 2,412
**Candidates Found in Registry**: 34
**Flagged as Suspicious**: 5

### HIGH Risk (Score >= 70)

| Suspect Package | Target Package | Levenshtein | Created | Downloads | Score |
|----------------|---------------|-------------|---------|-----------|-------|
| reqeusts       | requests      | 1           | 2026-02-28 | 43     | 92    |
| requsets       | requests      | 1           | 2026-03-01 | 12     | 88    |
| numpyy         | numpy         | 1           | 2026-01-15 | 67     | 78    |

### Recommendation
- BLOCK: reqeusts, requsets, numpyy (add to artifact proxy deny-list)
- REPORT: Submit malware reports to security@pypi.org with package names and evidence
- MONITOR: Continue weekly scans for the full dependency watchlist
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
