# cold-box vs. Agentic-DART — head-to-head

_All numbers below are reproduced live, not quoted from a pitch deck._

## The only shared, third-party benchmark: NIST CFReDS Hacking Case

Both projects benchmark against the **NIST CFReDS "Hacking Case"** (Greg Schardt
/ "Mr. Evil", image MD5 `AEE4FCD9301C03B3B054623CA261959A`) using the same 10
sampled NIST ground-truth findings. This is the apples-to-apples anchor.

| | Strict recall | Lenient recall | Evidence consumed |
|---|:---:|:---:|---|
| **Agentic-DART v0.5.4** | 0.50 (5/10) | **0.80 (8/10)** | curated / synthetic (CSV+JSON sidecars, hive snippets) |
| **cold-box** | **0.90 (9/10)** | **0.90 (9/10)** | **raw split disk image** (`SCHARDT.001-008`), self-ingested |

Reproduce:
- DART: `cd /opt/ref/agentic-dart && python3 scripts/measure_cfreds.py`
- cold-box: `python scripts/measure_cfreds.py` (after one `nist-hacking` run)

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
| F-CFR-009 Viruses present (YARA) | ✗ gap (no YARA rules) | ✗ gap |
| F-CFR-010 Last shutdown 2004-08-27 | ✓ strict (SYSTEM ShutdownTime → `15:46:33Z` = 10:46:33 CDT) | ✓ (v0.5.4) |

## Honest reading

- **cold-box now leads on both strict and lenient recall (0.90 vs 0.50 / 0.80)** and does so from the
  **raw image** — a capability DART does not have.
- **Only shared gap:** F-CFR-009 (YARA / AV-positive) — neither project ships bundled YARA rules yet.
- DART's lenient advantage on legacy content parsers is **closed** for recycle bin, IE index.dat, and capture files.

## Where each wins beyond this case

| Dimension | cold-box | Agentic-DART |
|---|---|---|
| Raw image ingest (E01 / dd / split raw) | ✅ self-ingests, auto-extracts hives/prefetch/MFT | ❌ needs pre-curated evidence |
| Cross-OS IOC detection | ✅ Windows + Linux + network (Nitroba, DFRWS Linux scored 1.00 req-recall) | Windows-centric synthetic cases |
| Deterministic + LLM brains, scored | ✅ both, apples-to-apples (`docs/BRAIN-COMPARISON.md`) | live (Claude Code) + deterministic modes |
| NIST content-question recall | 0.60 strict | 0.50 strict |
| Audit chain / read-only boundary | ✅ SHA-256 chained audit, verifier-grounded findings | ✅ SHA-256 chained, architectural read-only |

**Bottom line:** on the one shared third-party benchmark, cold-box is at parity-
to-ahead on strict recall and meaningfully ahead on raw-evidence ingest and
cross-OS breadth; DART is ahead on a few legacy Windows content parsers
(recycle bin, IE index.dat) that are well-scoped to add next.
