# postmortem

Autonomous postmortem investigator for the SANS FIND EVIL! hackathon.

## Requirements

- Python 3.10+
- SIFT Workstation (or compatible forensics toolchain on Linux)

## Install (development)

```bash
cd /opt/postmortem
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Environment

```bash
export EVIDENCE_ROOT=/evidence   # read-only case images
export CASE_OUTPUT=/cases        # writable run output
```

See `examples/sample-evidence/README.md` for bundled demo evidence layout.

## Step 1 — evidence integrity

```bash
# Manifest (SHA-256 all files under a case directory)
postmortem-evidence manifest examples/sample-evidence

# Pre/post integrity check (e.g. before and after an investigation run)
postmortem-evidence integrity-begin examples/sample-evidence
postmortem-evidence integrity-check examples/sample-evidence
```

## License

MIT (to be added before public release)
