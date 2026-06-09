# Sample evidence (bundled, tiny)

Minimal synthetic case for CI and fast demos. **Not** a substitute for Ali Hadi or NIST images on `/evidence`.

## Layout

```text
examples/sample-evidence/
├── README.md           ← this file
├── disk/
│   └── case-notes.txt  ← placeholder disk-side artifact
└── memory/
    └── case-notes.txt  ← placeholder memory-side artifact
```

Real runs use paths like:

```text
/evidence/ali-hadi-1/
  Case1-Webserver.E01
  memdump/memdump.mem
```

## Commands

```bash
# Repo-local sample (no EVIDENCE_ROOT required)
cold-box-evidence manifest examples/sample-evidence --local

# Production evidence under /evidence
export EVIDENCE_ROOT=/evidence
cold-box-evidence manifest ali-hadi-1
cold-box-evidence integrity-begin ali-hadi-1 --save /cases/ali-hadi-1/baseline.json
cold-box-evidence integrity-check ali-hadi-1 --baseline /cases/ali-hadi-1/baseline.json
```

## Integrity rule

Tools must **read** from `EVIDENCE_ROOT` only and **write** to `CASE_OUTPUT` (`/cases/<case-id>/`). The path guard blocks writes under the evidence root.
