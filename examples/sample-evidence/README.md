# cold-box lab case (bundled, original)

Synthetic **cold-box** scenario for CI, verifier demos, and offline disk-tool runs.
Handcrafted for our R1–R6 rules and MCP tools.

## Scenario: `cold-box-lab-01`

An operator workstation shows signs of a staged loader dropped into Downloads,
prefetch evidence of `COLDLOADER.EXE`, and MFT timestomp on `stage-dropper.exe`
($SI created before $FN — T1070.006). Memory artifacts are exercised via
`examples/sample-verifier/` JSON fixtures (fast, deterministic).

## Layout

```text
examples/sample-evidence/
├── README.md
├── CASE.md
├── disk/
│   ├── $MFT.csv                 ← MFTECmd-style rows incl. timestomp IOC
│   ├── amcache-records.json     ← minimal execution trail (cmd.exe only)
│   └── Windows/Prefetch/
│       ├── COLDLOADER.EXE-B1C2D3E4.pf      ← placeholder (sidecar used)
│       ├── COLDLOADER.EXE-B1C2D3E4.json
│       ├── STAGE-RUNNER.EXE-DEADBEEF.pf    ← ghost binary (no file on disk)
│       └── STAGE-RUNNER.EXE-DEADBEEF.json
├── logs/
│   └── security-events.json     ← stub for future R3 phantom_logon
└── memory/
    └── case-notes.txt
```

## Usage

```bash
export EVIDENCE_ROOT=/opt/postmortem/examples/sample-evidence
export CASE_OUTPUT=/tmp/cold-box-out

cold-box-evidence manifest . --local   # or with EVIDENCE_ROOT set
bash examples/demo-case-run.sh
python scripts/measure_accuracy.py
```

Live memory on `/evidence` (Ali Hadi, NIST) stays separate — never committed.
