# Dataset documentation

Evidence for cold-box-room E2E runs. Download corpora separately — not shipped in git.

---

## Evaluation VM layout

```text
/evidence/
├── nist-ndlc/images/           # NIST CFReDS 2015 Data Leakage
│   ├── cfreds_2015_data_leakage_pc.E01 … E04
│   └── cfreds_2015_data_leakage_rm#1.E01 … rm#3
├── unseen-terry-usb/
│   └── terry-work-usb-2009-12-11.E01
├── ground-truth/
│   └── leakage-answers.pdf
└── dfrws2008/evidence/response_data/
    ├── challenge.mem
    └── suspect.pcap
```

---

## Benchmark: `terry_usb`

| Field | Value |
|-------|-------|
| **Title** | Terry work USB (unseen holdout) |
| **Image** | `terry-work-usb-2009-12-11.E01` |
| **SHA256** | `1600fe2bdfb2bec0b006aa9d1c0ce6d3ad0b6666141a333bf830af7800fb9230` |
| **Measured accuracy** | **100%** — run `terry-fresh-20260615-0345` |
| **Runtime** | ~16 min full hallway |

**Findings:** EWF/E01 · FAT32 · **TERRYS WORK** · **R54402.EXE** keylogger

---

## Benchmark: `ndlc_leakage_pc`

| Field | Value |
|-------|-------|
| **Title** | NIST CFReDS 2015 Data Leakage PC |
| **Source** | [NIST CFReDS](https://www.cfreds.nist.gov/) |
| **Primary image** | `cfreds_2015_data_leakage_pc.E01` (+ E02–E04 auto) |
| **Measured accuracy** | **100% required checks** — run `ndlc-fresh-20260615-0418` |
| **Runtime** | ~18 min full hallway |

**Findings:** **INFORMANT-PC** · **Windows 7** · **NTFS** · data leakage (USB, cloud, Eraser) · MD5 `a49d1254…`

```bash
cold-box-room-hallway \
  --evidence /evidence/nist-ndlc/images/cfreds_2015_data_leakage_pc.E01 \
  --benchmark ndlc_leakage_pc
```

---

## Benchmark: `dfrws2008`

DFRWS 2008 Linux memory + pcap — benchmark defined for multi-artifact cases.

---

## Measured runs

| Run ID | Benchmark | Hallway | Required accuracy | Time |
|--------|-----------|---------|-------------------|------|
| `terry-fresh-20260615-0345` | `terry_usb` | Complete | **100%** | ~16 min |
| `ndlc-fresh-20260615-0418` | `ndlc_leakage_pc` | Complete | **100%** (4/4) | ~18 min |

```bash
python cold-box-room/scripts/score_e2e_accuracy.py --case-id CASE --benchmark ID
```

---

## Download

1. SIFT Workstation or Ubuntu 22.04+ with Sleuth Kit, ewf-tools
2. NIST CFReDS Data Leakage scenario from [cfreds.nist.gov](https://www.cfreds.nist.gov/)
3. Run — see root README §7
