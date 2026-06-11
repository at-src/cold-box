# cold-box vs. Agentic-DART — head-to-head

_All numbers below are reproduced live, not quoted from a pitch deck._

## The only shared, third-party benchmark: NIST CFReDS Hacking Case

Both projects benchmark against the **NIST CFReDS "Hacking Case"** (Greg Schardt
/ "Mr. Evil", image MD5 `AEE4FCD9301C03B3B054623CA261959A`) using the same 10
sampled NIST ground-truth findings. This is the apples-to-apples anchor.

| | Strict recall | Lenient recall | Evidence consumed |
|---|:---:|:---:|---|
| **Agentic-DART v0.5.4** | 0.50 (5/10) | **0.80 (8/10)** | curated / synthetic (CSV+JSON sidecars, hive snippets) |
| **cold-box** | **1.00 (10/10)** | **1.00 (10/10)** | **raw split disk image** (`SCHARDT.001-008`), self-ingested |

Reproduce:
- DART: `cd /opt/ref/agentic-dart && python3 scripts/measure_cfreds.py`
- cold-box: `python scripts/measure_cfreds.py` (uses extracted image under `CASE_OUTPUT/nist-hacking`)

### Per-finding

| NIST finding | cold-box | DART v0.5.4 |
|---|---|---|
| F-CFR-001 Registered owner = Greg Schardt | ✓ strict (SOFTWARE hive) | ✓ (v0.5.4) |
| F-CFR-002 Primary account 'Mr. Evil' | ✓ strict (SAM Names) | roadmap |
| F-CFR-003 6+ hacking tools | ✓ strict (9 via prefetch) | ✓ |
| F-CFR-004 Two network cards | ✓ strict (SOFTWARE NetworkCards) | ✓ (v0.5.4) |
| F-CFR-005 'Interception' capture file | ✓ strict (pcap magic) | ~ partial |
| F-CFR-006 Yahoo webmail | ✓ strict (IE index.dat yahoo id) | ✗ gap |
| F-CFR-007 Last logon 'Mr. Evil', 15× | ✓ strict (SAM F-record decode) | ~ partial |
| F-CFR-008 4 exes in recycle bin | ✓ strict (INFO2: 4 exes) | ✗ gap |
| F-CFR-009 Viruses present (AV positive) | ✓ strict (pattern-fallback / R30; `yara` CLI optional on SIFT) | ✗ gap |
| F-CFR-010 Last shutdown 2004-08-27 | ✓ strict (SYSTEM ShutdownTime → `15:46:33Z` = 10:46:33 CDT) | ✓ (v0.5.4) |

## Honest reading

- **cold-box leads on both strict and lenient recall (1.00 vs 0.50 / 0.80)** from the
  **raw image** — a capability DART does not have.
- **F-CFR-009** is covered by bundled pattern rules when the `yara` binary is absent;
  on SIFT, point `yara_scan_evidence` at the system `yara` + `rules/yara/malware_suspicious.yar`.
- Legacy Windows content parsers (recycle bin, IE index.dat, capture files) are **closed on cold-box**;
  DART still documents gaps on several of these.

## Where each wins beyond this case

| Dimension | cold-box | Agentic-DART |
|---|---|---|
| Raw image ingest (E01 / dd / split raw) | ✅ self-ingests, auto-extracts hives/prefetch/MFT | ❌ needs pre-curated evidence |
| Cross-OS validation breadth | ✅ Windows + Linux + network + **Android (DFRWS 2011) + macOS (AD1 carve)** — all scored 1.00 required-recall | Windows-centric + synthetic macOS quarantine / Linux cron fixtures |
| Deterministic + LLM brains, scored | ✅ both, apples-to-apples (`docs/BRAIN-COMPARISON.md`) | live (Claude Code) + deterministic modes |
| Policy benchmark manifest (11 cases) | ✅ `docs/ACCURACY-REPORT.md` — mean required-recall **1.00** | functional scripts on subset |
| Audit chain / read-only boundary | ✅ SHA-256 chained audit, verifier-grounded findings | ✅ SHA-256 chained, architectural read-only |
| Demo UX / live agent polish | pre-demo (MCP server ready; Claude Code wiring TBD) | ✅ install.sh + Claude Code ergonomics |
| Sigma rule matcher | not shipped (not required by any scored case) | `match_sigma_rules` (partial) |
| macOS artifact depth | AD1 manifest + strings (real CyberDefenders carve) | LSQuarantine SQLite parser (synthetic fixtures) |

**Bottom line:** on the shared third-party benchmark and our scored manifest, cold-box
is ahead on recall, raw-evidence ingest, and cross-OS breadth. DART still wins on
demo packaging and a few specialist synthetic parsers (quarantine DB, Sigma harness)
that **no cold-box ground-truth case requires**.
