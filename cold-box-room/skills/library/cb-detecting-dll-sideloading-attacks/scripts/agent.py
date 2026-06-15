#!/usr/bin/env python3
# cold-box skill script — tool calls route through SIFT harness (run_skill_script).
from cold_box_room.skills.skill_runtime import run_cmd, patched_subprocess as subprocess


"""DLL sideloading detection agent using Sysmon Event ID 7 (Image Loaded) analysis.

Detects unsigned DLLs loaded by signed executables from non-standard paths,
a common APT persistence and defense evasion technique (T1574.002).
"""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path

try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None

KNOWN_SIDELOAD_TARGETS = {
    "vmwaretray.exe": ["vmtools.dll"],
    "colorcpl.exe": ["colorui.dll"],
    "searchprotocolhost.exe": ["msfte.dll"],
    "consent.exe": ["comctl32.dll"],
    "dxcap.exe": ["d3d9.dll"],
    "eventvwr.exe": ["mmc.dll"],
    "msdeploy.exe": ["microsoft.web.deployment.dll"],
    "bginfo.exe": ["version.dll"],
    "winword.exe": ["wwlib.dll"],
    "teams.exe": ["version.dll"],
}

STANDARD_DLL_DIRS = {
    r"c:\windows\system32", r"c:\windows\syswow64",
    r"c:\windows\winsxs", r"c:\program files",
    r"c:\program files (x86)",
}


def parse_sysmon_dll_loads(filepath):
    if evtx is None:
        return {"error": "python-evtx not installed: pip install python-evtx"}
    findings = []
    with evtx.Evtx(filepath) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID>7</EventID>" not in xml:
                continue
            image = re.search(r'<Data Name="Image">([^<]+)', xml)
            loaded = re.search(r'<Data Name="ImageLoaded">([^<]+)', xml)
            signed = re.search(r'<Data Name="Signed">([^<]+)', xml)
            sig_status = re.search(r'<Data Name="SignatureStatus">([^<]+)', xml)
            sha256 = re.search(r'<Data Name="Hashes">([^<]+)', xml)
            time_created = re.search(r'SystemTime="([^"]+)"', xml)

            if not image or not loaded:
                continue

            image_path = image.group(1).lower()
            dll_path = loaded.group(1).lower()
            is_signed = signed.group(1) if signed else "unknown"
            image_name = image_path.rsplit("\\", 1)[-1]
            dll_name = dll_path.rsplit("\\", 1)[-1]
            dll_dir = dll_path.rsplit("\\", 1)[0] if "\\" in dll_path else ""

            is_standard_dir = any(dll_dir.startswith(d) for d in STANDARD_DLL_DIRS)
            is_known_target = (image_name in KNOWN_SIDELOAD_TARGETS and
                               dll_name in KNOWN_SIDELOAD_TARGETS[image_name])

            if is_signed == "false" and not is_standard_dir:
                severity = "CRITICAL" if is_known_target else "HIGH"
                findings.append({
                    "timestamp": time_created.group(1) if time_created else "",
                    "host_process": image_path,
                    "loaded_dll": dll_path,
                    "signed": is_signed,
                    "signature_status": sig_status.group(1) if sig_status else "",
                    "hash": sha256.group(1) if sha256 else "",
                    "known_sideload_target": is_known_target,
                    "non_standard_path": True,
                    "severity": severity,
                    "mitre": "T1574.002",
                })
    return findings


def scan_directory_for_sideloading(directory):
    findings = []
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return [{"error": f"Directory not found: {directory}"}]
    exe_files = list(dir_path.glob("*.exe"))
    dll_files = list(dir_path.glob("*.dll"))
    for exe in exe_files:
        exe_name = exe.name.lower()
        if exe_name in KNOWN_SIDELOAD_TARGETS:
            for dll in dll_files:
                if dll.name.lower() in KNOWN_SIDELOAD_TARGETS[exe_name]:
                    findings.append({
                        "exe_path": str(exe),
                        "dll_path": str(dll),
                        "dll_size_bytes": dll.stat().st_size,
                        "known_sideload_pair": True,
                        "severity": "CRITICAL",
                        "mitre": "T1574.002",
                        "description": f"Known sideloading pair: {exe.name} + {dll.name}",
                    })
    return findings


def generate_sigma_rule():
    return {
        "title": "DLL Sideloading - Unsigned DLL in Non-Standard Path",
        "status": "experimental",
        "logsource": {"product": "windows", "category": "image_load"},
        "detection": {
            "selection": {"EventID": 7, "Signed": "false"},
            "filter_standard": {"ImageLoaded|startswith": [
                "C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\",
                "C:\\Program Files\\", "C:\\Program Files (x86)\\"
            ]},
            "condition": "selection and not filter_standard"
        },
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1574.002"],
    }


def main():
    parser = argparse.ArgumentParser(description="DLL Sideloading Detector")
    parser.add_argument("--sysmon-log", help="Sysmon EVTX file with Event ID 7")
    parser.add_argument("--scan-dir", help="Directory to scan for sideloading pairs")
    parser.add_argument("--generate-sigma", action="store_true")
    args = parser.parse_args()

    from cold_box_room.skills.script_helpers import patch_args_from_harness
    patch_args_from_harness(args)

    results = {"timestamp": datetime.utcnow().isoformat() + "Z", "findings": []}

    if args.sysmon_log:
        evtx_findings = parse_sysmon_dll_loads(args.sysmon_log)
        if isinstance(evtx_findings, dict) and "error" in evtx_findings:
            results["error"] = evtx_findings["error"]
        else:
            results["findings"].extend(evtx_findings)

    if args.scan_dir:
        dir_findings = scan_directory_for_sideloading(args.scan_dir)
        results["findings"].extend(dir_findings)

    if args.generate_sigma:
        results["sigma_rule"] = generate_sigma_rule()

    results["total_findings"] = len(results["findings"])
    print(json.dumps(results, indent=2))



# cold-box harness entry
def analyze_image(image_path, case_dir):
    from cold_box_room.skills.script_helpers import run_default_analyze_image

    return run_default_analyze_image(
        image_path,
        case_dir,
        skill_slug='cb-detecting-dll-sideloading-attacks',
        main_fn=main,
    )

if __name__ == "__main__":
    main()
