---
name: cb-steganography-detection
skill_id: cb-steganography-detection
journal_id: CB-SKL-109
description: Cold-box analyst playbook — Steganography Detection. Detect and extract
  hidden data embedded in images, audio, and other media files using steganalysis
  tools to uncover covert communication channels.
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- windows_disk
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- forensics
- steganography
- steganalysis
- hidden-data
- covert-channels
- image-analysis
cold_box_version: 2
inspired_by: performing-steganography-detection
---

# Steganography Detection (cold-box)

> **Journal ID:** `CB-SKL-109` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-109`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-steganography-detection")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-steganography-detection")` → note **`CB-SKL-109`**
2. `log_skill(case_id, journal_id="CB-SKL-109", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-109` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When suspecting covert data hiding in images, audio, or video files
- During investigations involving suspected data exfiltration via media files
- For analyzing files in espionage or insider threat investigations
- When standard file analysis reveals anomalies in media file properties
- For detecting communication channels using steganographic techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `exiftool` | `SIFT-055` | yes | yes |
| `binwalk` | `SIFT-037` | no | no |
| `head` | `SIFT-011` | yes | yes |
| `grep` | `SIFT-010` | yes | yes |
| `find` | `SIFT-009` | yes | yes |
| `file` | `SIFT-008` | yes | yes |
| `zip` | `SIFT-036` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `exiftool` → `SIFT-055`

```json
{
  "tool_id": "SIFT-055",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-109] exiftool per playbook step",
  "why": "Executing cb-steganography-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `binwalk` → `SIFT-037`

```json
{
  "tool_id": "SIFT-037",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-109] binwalk per playbook step",
  "why": "Executing cb-steganography-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `head` → `SIFT-011`

```json
{
  "tool_id": "SIFT-011",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-109] head per playbook step",
  "why": "Executing cb-steganography-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-109] grep per playbook step",
  "why": "Executing cb-steganography-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-109] find per playbook step",
  "why": "Executing cb-steganography-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-109] file per playbook step",
  "why": "Executing cb-steganography-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `zip` → `SIFT-036`

```json
{
  "tool_id": "SIFT-036",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-109] zip per playbook step",
  "why": "Executing cb-steganography-detection \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-109` (`cb-steganography-detection`)

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
- When suspecting covert data hiding in images, audio, or video files
- During investigations involving suspected data exfiltration via media files
- For analyzing files in espionage or insider threat investigations
- When standard file analysis reveals anomalies in media file properties
- For detecting communication channels using steganographic techniques

## Prerequisites
- StegDetect, zsteg, stegsolve, binwalk for analysis
- steghide, OpenStego for extraction attempts
- ExifTool for metadata analysis
- Python with Pillow, numpy for custom analysis
- Understanding of common steganographic techniques (LSB, DCT, spread spectrum)
- Sample files for comparison and statistical analysis

## Workflow

### Step 1: Initial File Assessment and Metadata Analysis

```bash
# Install steganography detection tools
sudo apt-get install steghide stegsnow
pip install zsteg
pip install stegoveritas
gem install zsteg  # Ruby-based tool for PNG/BMP

# Examine file metadata for anomalies
exiftool /cases/case-2024-001/media/suspect_image.jpg | tee /cases/case-2024-001/analysis/metadata.txt

# Check for unusual file size (larger than expected for resolution/format)
identify -verbose /cases/case-2024-001/media/suspect_image.jpg | head -30

# Verify file type matches extension
file /cases/case-2024-001/media/suspect_image.jpg
# Confirm JPEG signature vs actual content

# Check for appended data after file footer
python3 << 'PYEOF'
import os

filepath = '/cases/case-2024-001/media/suspect_image.jpg'
filesize = os.path.getsize(filepath)

with open(filepath, 'rb') as f:
    data = f.read()

# JPEG files end with FF D9
jpeg_end = data.rfind(b'\xff\xd9')
if jpeg_end > 0:
    trailing_bytes = filesize - jpeg_end - 2
    if trailing_bytes > 0:
        print(f"WARNING: {trailing_bytes} bytes of data after JPEG end marker!")
        print(f"  File size: {filesize} bytes")
        print(f"  JPEG data: {jpeg_end + 2} bytes")
        print(f"  Hidden data: {trailing_bytes} bytes")
        # Extract trailing data
        with open('/cases/case-2024-001/analysis/trailing_data.bin', 'wb') as out:
            out.write(data[jpeg_end + 2:])
    else:
        print("No trailing data detected after JPEG end marker")

# Check for embedded ZIP/RAR archives
zip_offset = data.find(b'PK\x03\x04')
rar_offset = data.find(b'Rar!\x1a\x07')
if zip_offset > 0:
    print(f"ZIP archive found at offset {zip_offset}")
if rar_offset > 0:
    print(f"RAR archive found at offset {rar_offset}")
PYEOF
```

### Step 2: Run Automated Steganalysis Tools

```bash
# Use binwalk to detect embedded files and data
binwalk /cases/case-2024-001/media/suspect_image.jpg | tee /cases/case-2024-001/analysis/binwalk_scan.txt

# Extract embedded files
binwalk --extract --directory /cases/case-2024-001/analysis/binwalk_extracted/ \
   /cases/case-2024-001/media/suspect_image.jpg

# Use zsteg for PNG and BMP analysis (LSB detection)
zsteg /cases/case-2024-001/media/suspect_image.png | tee /cases/case-2024-001/analysis/zsteg_results.txt

# zsteg with all checks
zsteg -a /cases/case-2024-001/media/suspect_image.png

# Use stegoveritas for comprehensive analysis
stegoveritas /cases/case-2024-001/media/suspect_image.jpg \
   -out /cases/case-2024-001/analysis/stegoveritas/

# Stegoveritas performs:
# - Metadata extraction
# - LSB analysis (multiple bit planes)
# - Color map analysis
# - Trailing data detection
# - Embedded file extraction
# - Image transformation analysis

# Use steghide for JPEG/BMP/WAV/AU extraction attempts
# Try with empty password
steghide extract -sf /cases/case-2024-001/media/suspect_image.jpg -p "" \
   -xf /cases/case-2024-001/analysis/steghide_extract.bin 2>&1

# Try with common passwords
for pwd in password secret hidden stego test 123456 admin; do
    result=$(steghide extract -sf /cases/case-2024-001/media/suspect_image.jpg \
       -p "$pwd" -xf "/cases/case-2024-001/analysis/steghide_$pwd.bin" 2>&1)
    if echo "$result" | grep -q "extracted"; then
        echo "SUCCESS with password: $pwd"
    fi
done
```

### Step 3: Perform LSB (Least Significant Bit) Analysis

```bash
# Custom LSB analysis with Python
python3 << 'PYEOF'
from PIL import Image
import numpy as np

img = Image.open('/cases/case-2024-001/media/suspect_image.png')
pixels = np.array(img)

# Extract LSB from each color channel
for channel, name in enumerate(['Red', 'Green', 'Blue']):
    if channel >= pixels.shape[2]:
        break

    lsb_data = pixels[:, :, channel] & 1

    # Count distribution (should be ~50/50 for natural images)
    zeros = np.sum(lsb_data == 0)
    ones = np.sum(lsb_data == 1)
    total = zeros + ones
    ratio = ones / total

    print(f"{name} channel LSB: 0s={zeros} ({zeros/total*100:.1f}%), 1s={ones} ({ones/total*100:.1f}%)")
    if abs(ratio - 0.5) < 0.01:
        print(f"  NEUTRAL - Close to random (could be stego or natural)")
    elif ratio > 0.55 or ratio < 0.45:
        print(f"  ANOMALY - Significant deviation from expected distribution")

# Extract LSB data as bytes
lsb_bits = (pixels[:, :, 0] & 1).flatten()
lsb_bytes = np.packbits(lsb_bits)

# Check if extracted data has structure
with open('/cases/case-2024-001/analysis/lsb_extracted.bin', 'wb') as f:
    f.write(lsb_bytes.tobytes())

# Check for known file signatures in extracted data
import struct
header = bytes(lsb_bytes[:16])
print(f"\nLSB extracted header (hex): {header.hex()}")
if header[:4] == b'PK\x03\x04':
    print("  DETECTED: ZIP archive in LSB data!")
elif header[:3] == b'GIF':
    print("  DETECTED: GIF image in LSB data!")
elif header[:4] == b'\x89PNG':
    print("  DETECTED: PNG image in LSB data!")
elif header[:2] == b'\xff\xd8':
    print("  DETECTED: JPEG image in LSB data!")

# Generate LSB visualization
lsb_img = Image.fromarray((lsb_data * 255).astype(np.uint8))
lsb_img.save('/cases/case-2024-001/analysis/lsb_visualization.png')
print("\nLSB visualization saved to lsb_visualization.png")
PYEOF
```

### Step 4: Analyze Audio and Video Steganography

```bash
# Spectral analysis of audio files
python3 << 'PYEOF'
import wave
import numpy as np

# Analyze WAV file for audio steganography
with wave.open('/cases/case-2024-001/media/suspect_audio.wav', 'r') as wav:
    frames = wav.readframes(wav.getnframes())
    samples = np.frombuffer(frames, dtype=np.int16)

    # LSB analysis of audio samples
    lsb = samples & 1
    zeros = np.sum(lsb == 0)
    ones = np.sum(lsb == 1)
    total = len(lsb)

    print(f"Audio LSB Analysis:")
    print(f"  Samples: {total}")
    print(f"  LSB 0s: {zeros} ({zeros/total*100:.1f}%)")
    print(f"  LSB 1s: {ones} ({ones/total*100:.1f}%)")

    # Extract LSB data
    lsb_bytes = np.packbits(lsb)
    with open('/cases/case-2024-001/analysis/audio_lsb.bin', 'wb') as f:
        f.write(lsb_bytes.tobytes())

    # Chi-square test for randomness
    from scipy import stats
    chi2, p_value = stats.chisquare([zeros, ones])
    print(f"  Chi-square: {chi2:.4f}, p-value: {p_value:.4f}")
    if p_value < 0.05:
        print(f"  ANOMALY: LSB distribution is not random (potential stego)")
PYEOF

# Use steghide on audio files
steghide info /cases/case-2024-001/media/suspect_audio.wav

# Analyze with sonic-visualiser or audacity for spectral anomalies
# (Check spectrogram for hidden images encoded in frequency domain)
```

### Step 5: Generate Steganalysis Report

```bash
# Compile findings
python3 << 'PYEOF'
import os, json

report = {
    "case": "2024-001",
    "files_analyzed": [],
    "findings": []
}

analysis_dir = '/cases/case-2024-001/analysis/'
for f in os.listdir(analysis_dir):
    if f.endswith('.txt'):
        with open(os.path.join(analysis_dir, f)) as fh:
            content = fh.read()
            if 'DETECTED' in content or 'SUCCESS' in content or 'WARNING' in content:
                report["findings"].append({
                    "source": f,
                    "content": content[:500]
                })

with open('/cases/case-2024-001/analysis/steg_report.json', 'w') as f:
    json.dump(report, f, indent=2)

print("Steganalysis report generated")
print(f"Total findings: {len(report['findings'])}")
PYEOF
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| LSB (Least Significant Bit) | Embedding data in the lowest-order bits of pixel or sample values |
| DCT steganography | Hiding data in JPEG discrete cosine transform coefficients |
| Spread spectrum | Distributing hidden data across the entire carrier signal |
| Steganalysis | The science of detecting the presence of hidden information |
| Chi-square attack | Statistical test detecting non-random LSB distributions |
| Cover medium | The original file used to carry hidden data (image, audio, video) |
| Stego medium | The resulting file after hidden data has been embedded |
| Capacity | Maximum amount of data that can be hidden without visible distortion |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| steghide | Embed/extract data in JPEG, BMP, WAV, AU files |
| zsteg | Detect LSB steganography in PNG and BMP files |
| binwalk | Detect embedded files and data within binary files |
| stegoveritas | Comprehensive steganalysis tool with multiple detection methods |
| StegSolve | Java GUI tool for image bit plane and filter analysis |
| OpenStego | Open-source steganography and watermarking tool |
| ExifTool | Metadata extraction and analysis for media files |
| stegseek | Fast steghide password cracker for JPEG stego extraction |

## Common Scenarios

**Scenario 1: Covert Communication Investigation**
Examine images exchanged between suspects via messaging platforms, run stegoveritas and zsteg on all PNG/BMP files, attempt steghide extraction with known passwords on JPEG files, analyze LSB distributions for statistical anomalies, extract and decode any hidden messages.

**Scenario 2: Data Exfiltration via Image Upload**
Monitor images uploaded to cloud services for unusual file sizes, compare image metadata with expected camera/device profiles, run binwalk to detect embedded archives, analyze JPEG quantization tables for steghide signatures, extract and examine any hidden payloads.

**Scenario 3: Malware Command and Control**
Analyze images downloaded by malware for embedded commands, check for data appended after file end markers, examine DNS query responses for base64-encoded data in TXT records, analyze PNG IDAT chunks for anomalous compressed data sizes.

**Scenario 4: Intellectual Property Theft via Audio Files**
Analyze audio files for embedded documents in LSB, check spectrograms for visual patterns hidden in frequency domain, compare audio file sizes with expected sizes for bitrate and duration, extract and analyze any hidden data payloads.

## Output Format

```
Steganalysis Summary:
  Files Analyzed: 45 (32 images, 8 audio, 5 video)

  Detection Results:
    suspect_image_03.png:
      zsteg: Text detected in R channel LSB
      Content: "Meet at location B, Tuesday 1400"
      Method: LSB embedding in Red channel

    suspect_photo_17.jpg:
      steghide: Data extracted with password "secret123"
      Hidden file: confidential_report.pdf (234 KB)
      Method: DCT coefficient modification

    profile_pic.png:
      binwalk: ZIP archive embedded at offset 45678
      Contents: 3 spreadsheet files with financial data
      Method: Data appended after PNG IEND marker

    recording_05.wav:
      LSB analysis: Non-random distribution (p < 0.001)
      Extracted: 12 KB binary payload (further analysis needed)
      Method: Audio LSB embedding

  Clean Files: 41 (no steganographic indicators)
  Suspicious Files: 4 (data extracted)

  Report: /cases/case-2024-001/analysis/steg_report.json
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
