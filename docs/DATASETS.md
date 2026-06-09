# Datasets

## Bundled (committed)

| Dataset | Path | Purpose |
|---------|------|---------|
| cold-box-lab | `examples/sample-evidence/` | Original synthetic disk+memory fixtures for CI |
| Verifier fixtures | `examples/sample-verifier/` | JSON inputs for R1–R6 rule tests |
| Ground truth (lab) | `ground-truth/lab.json` | Agent accuracy scoring for lab profile |

## External (not committed)

| Dataset | Location | Notes |
|---------|----------|-------|
| Ali Hadi #1 | `/evidence/ali-hadi-1/` | E01 + memdump — hero case |
| NIST NDLC | `/evidence/nist-ndlc/` | Optional breadth |
| NIST Hacking | `/evidence/nist-hacking/` | Optional breadth |
| DFRWS 2008 | `/evidence/dfrws2008/` | Linux breadth |
| Published answer keys | `/evidence/ground-truth/` | Scoring reference only |

Extracted Ali Hadi artifacts (writable): `${CASE_OUTPUT}/ali-hadi-1/extracted/`  
Memory cache for demos: `${CASE_OUTPUT}/ali-hadi-1/cache/`

See `docs/CASE-ALI-HADI.md` for extraction commands.
