"""Port tools from cold-box-final manifest into cold_box_room.tools_manifest_v1."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SOURCE_DEFAULT = Path("/opt/cold-box-final/cold_box/tools/tools_manifest.json")

# Curated descriptions where source help text or verify output leaked in.
DESCRIPTION_OVERRIDES: dict[str, str] = {
    "SIFT-021": "Query and inspect SQLite database files from the command line.",
    "SIFT-030": "7-Zip archiver — extract and list 7z and related archive formats.",
    "SIFT-031": "7-Zip standalone binary — extract and list archives.",
    "SIFT-035": "List symbols from object files and binaries.",
    "SIFT-036": "Create and modify ZIP archives.",
    "SIFT-038": "ClamAV antivirus scanner for files and directories.",
    "SIFT-039": "Detect compressed or encrypted regions in files (density analysis).",
    "SIFT-040": "Carve files from disk images and byte streams by header/footer signatures.",
    "SIFT-042": "Carve files from disk images using configurable header/footer rules.",
    "SIFT-046": "Extract and list files from 7z, zip, gzip, bzip2, xz, tar, and related archives.",
    "SIFT-047": "Autopsy digital forensics platform (GUI; often needs manual invocation).",
    "SIFT-033": "Enhanced dd variant for forensic imaging with hashing and progress.",
    "SIFT-034": "Copy and convert raw data blocks (use with care on evidence images).",
    "SIFT-041": "Recover lost files and partitions interactively from disk images.",
    "SIFT-048": "Enhanced dd variant for forensic disk imaging.",
    "SIFT-049": "Extract font metadata from Microsoft Word documents (RegRipper plugin).",
    "SIFT-050": "Parse Windows EVT event logs (legacy Perl parser).",
    # Batch 2 (SIFT-051 … SIFT-100)
    "SIFT-051": "Generate reports from Windows EVT event logs (RegRipper evtrpt.pl).",
    "SIFT-052": "Create forensic disk images in E01/EWF format.",
    "SIFT-053": "Mount E01/EWF evidence images as a raw read-only device.",
    "SIFT-054": "Map EXIF geolocation metadata from images (RegRipper exif2map.pl).",
    "SIFT-055": "Extract file metadata (EXIF, timestamps, author) from many file types.",
    "SIFT-056": "Parse Windows Facebook-related artifacts (RegRipper fb.pl).",
    "SIFT-057": "Parse Firefox browser artifacts (RegRipper ff.pl).",
    "SIFT-058": "Parse Firefox sign-on and session data (RegRipper ff_signons.pl).",
    "SIFT-059": "Convert XML/HTML/text to braille embosser format (accessibility utility).",
    "SIFT-060": "Report file extent layout and fragmentation on a filesystem.",
    "SIFT-061": "Extract files from a mounted filesystem over the network (filesnarf).",
    "SIFT-062": "Update ClamAV virus definition databases.",
    "SIFT-063": "Parse FTK-generated reports (RegRipper ftkparse.pl).",
    "SIFT-064": "Identify processes using specified files or sockets.",
    "SIFT-065": "Parse Google Analytics cookie data (RegRipper gis4cookie.pl).",
    "SIFT-066": "Recursive file hashing with audit and match modes.",
    "SIFT-067": "Parse Internet Explorer index.dat records (RegRipper idx.pl).",
    "SIFT-068": "Parse and decode index.dat structures (RegRipper idxparse.pl).",
    "SIFT-069": "Parse Windows Jump List DestList streams (RegRipper jl.pl).",
    "SIFT-070": "Parse Windows job files (RegRipper jobparse.pl).",
    "SIFT-071": "Pretty-print JSON forensic output (RegRipper json-printer.pl).",
    "SIFT-072": "Parse LastFolderListExplorer MRU artifacts (RegRipper lfle.pl).",
    "SIFT-073": "Set up and manage loopback block devices for mounted images.",
    "SIFT-074": "List open files and the processes that opened them.",
    "SIFT-075": "Mount filesystems from disk images or devices (use with care on evidence).",
    "SIFT-076": "Generic RegRipper parse plugin (parse.pl).",
    "SIFT-077": "Parse NTFS $I30 index slack artifacts (RegRipper parsei30.pl).",
    "SIFT-078": "Parse Internet Explorer artifacts (RegRipper parseie.pl).",
    "SIFT-079": "Parse IE Prefetch-related data (RegRipper pie.pl).",
    "SIFT-080": "Parse IE Preferences records (RegRipper pref.pl).",
    "SIFT-081": "Radare2 reverse-engineering framework (r2 CLI).",
    "SIFT-082": "Radare2 binary analysis utility (rabin2).",
    "SIFT-083": "Radare2 multi-purpose reverse-engineering shell.",
    "SIFT-084": "Parse raw Internet Explorer index structures (RegRipper rawie.pl).",
    "SIFT-085": "Radare2 base converter and expression evaluator (rax2).",
    "SIFT-086": "Parse Windows Recycle Bin metadata (RegRipper recbin.pl).",
    "SIFT-087": "Windows Registry Editor (Wine; Windows-only, often unavailable on Linux).",
    "SIFT-088": "Windows Registry Editor stable build (Wine; Windows-only).",
    "SIFT-089": "Export Windows Registry hive files to JSON (libregf regfexport).",
    "SIFT-090": "Display Windows Registry hive file information (libregf regfinfo).",
    "SIFT-091": "Mount Windows Registry hive as FUSE filesystem (libregf regfmount).",
    "SIFT-092": "Compare two Windows Registry hives with regipy.",
    "SIFT-093": "Dump Windows Registry hive contents with regipy.",
    "SIFT-094": "Parse Registry hive header metadata with regipy.",
    "SIFT-095": "List available regipy Registry analysis plugins.",
    "SIFT-096": "Run regipy plugins against a Registry hive.",
    "SIFT-097": "Process Registry transaction logs with regipy.",
    "SIFT-098": "Registry hive parser with plugin framework (RegRipper rip.pl).",
    "SIFT-099": "Parse Registry slack space (RegRipper regslack.pl).",
    "SIFT-100": "Windows regsvr32 DLL registration utility (Wine; Windows-only).",
    # Batch 3 (SIFT-101 … SIFT-150)
    "SIFT-101": "Windows regsvr32 stable build (Wine; Windows-only).",
    "SIFT-102": "Parse Registry time values (RegRipper regtime.pl).",
    "SIFT-103": "Parse Registry File Contents artifacts (RegRipper rfc.pl).",
    "SIFT-104": "Parse Registry LastOpened MRU data (RegRipper rlo.pl).",
    "SIFT-105": "Configure shadow volume / VSS-related settings (RegRipper shadowconfig).",
    "SIFT-106": "Search SMS/text message patterns (RegRipper sms_grep.pl).",
    "SIFT-107": "Parse SquirrelGripper malware artifacts (RegRipper squirrelgripper.pl).",
    "SIFT-108": "Recover lost partitions and repair boot sectors (TestDisk).",
    "SIFT-109": "Calculate time differences from Registry timestamps (RegRipper timediff32.pl).",
    "SIFT-110": "Unmount mounted filesystems (use with care on evidence mounts).",
    "SIFT-111": "Convert vmail database to HTML (RegRipper vmail-db-2-html.pl).",
    "SIFT-112": "Debug Volume Shadow Copy structures (libvshadow vshadowdebug).",
    "SIFT-113": "List Volume Shadow Copy snapshot information (libvshadow vshadowinfo).",
    "SIFT-114": "Mount Volume Shadow Copy snapshots as raw devices (vshadowmount).",
    "SIFT-115": "Network grep — search PCAP or live traffic for patterns (ngrep).",
    "SIFT-116": "Capture and analyze network packets from interfaces or PCAP files.",
    "SIFT-117": "Wireshark command-line PCAP analyzer (tshark).",
    "SIFT-118": "Wireshark network protocol analyzer (GUI; heavy; use tshark in headless runs).",
    "SIFT-119": "Zeek network security monitor — structured protocol logs from PCAP.",
    "SIFT-120": "Output contents of an AFF forensic disk image (affcat).",
    "SIFT-121": "Compare two AFF image files for differences (affcompare).",
    "SIFT-122": "Convert AFF images between formats (affconvert).",
    "SIFT-123": "Copy AFF image files (affcopy).",
    "SIFT-124": "Encrypt or decrypt AFF image segments (affcrypto).",
    "SIFT-125": "Print disk identifiers embedded in AFF images (affdiskprint).",
    "SIFT-126": "Display metadata about an AFF forensic image (affinfo).",
    "SIFT-127": "Repair and re-index damaged AFF images (affix).",
    "SIFT-128": "Recover data from damaged AFF images (affrecover).",
    "SIFT-129": "Manage AFF image segments (affsegment).",
    "SIFT-130": "Sign AFF image files for integrity (affsign).",
    "SIFT-131": "Report statistics about an AFF image (affstats).",
    "SIFT-132": "Mount AFF images via FUSE (affuse).",
    "SIFT-133": "Verify integrity of AFF image files (affverify).",
    "SIFT-134": "Export AFF metadata to XML (affxml).",
    "SIFT-135": "Convert between disk sector and file system block addresses (blkcalc).",
    "SIFT-136": "Output contents of specific disk blocks (blkcat).",
    "SIFT-137": "Locate block devices by label or UUID (blkid).",
    "SIFT-138": "List unallocated disk blocks / slack space (blkls).",
    "SIFT-139": "Display file system metadata about a disk block (blkstat).",
    "SIFT-140": "Generate TSK bodyfile timeline input (RegRipper bodyfile.pl).",
    "SIFT-141": "Acquire EWF images from a stream source (ewfacquirestream).",
    "SIFT-142": "Debug EWF/E01 image structures (ewfdebug).",
    "SIFT-143": "Export EWF/E01 images to raw or other formats (ewfexport).",
    "SIFT-144": "Display information about EWF/E01 forensic images (ewfinfo).",
    "SIFT-145": "Recover data from damaged EWF/E01 images (ewfrecover).",
    "SIFT-146": "Verify integrity of EWF/E01 image files (ewfverify).",
    "SIFT-147": "Extract a file from a disk image by file name (The Sleuth Kit fcat).",
    "SIFT-148": "List files and directories in a disk image (The Sleuth Kit fls).",
    "SIFT-149": "Display file system statistics and layout (The Sleuth Kit fsstat).",
    "SIFT-150": "Look up file names in TSK hash databases (The Sleuth Kit hfind).",
    # Batch 4 (SIFT-151 … SIFT-200)
    "SIFT-151": "Extract file content from a disk image by inode (The Sleuth Kit icat).",
    "SIFT-152": "Find inode numbers for file names or data units (The Sleuth Kit ifind).",
    "SIFT-153": "Display raw bytes from a disk image at a given offset (The Sleuth Kit img_cat).",
    "SIFT-154": "Display metadata about a disk image (The Sleuth Kit img_stat).",
    "SIFT-155": "Display inode metadata for a file in a disk image (The Sleuth Kit istat).",
    "SIFT-156": "Extract a file from a journal by inode (The Sleuth Kit jcat).",
    "SIFT-157": "List files in a file system journal (The Sleuth Kit jls).",
    "SIFT-158": "Display journal superblock information (The Sleuth Kit jstat).",
    "SIFT-159": "Extract data from a partition by sector range (The Sleuth Kit mmcat).",
    "SIFT-160": "Display partition layout of a disk image (The Sleuth Kit mmls).",
    "SIFT-161": "Display metadata about a partition in a disk image (The Sleuth Kit mmstat).",
    "SIFT-162": "Search a disk image for binary signatures (The Sleuth Kit sigfind).",
    "SIFT-163": "Sort and categorize files in a disk image (The Sleuth Kit sorter).",
    "SIFT-164": "Bulk recover files from a disk image into an output directory (The Sleuth Kit tsk_recover). Harness appends scratch output dir as final arg.",
    "SIFT-165": "Mount disk images via FUSE (xmount; may need case-specific options).",
    "SIFT-166": "Hayabusa Windows event log and Sigma rule scanner (not installed on this host).",
    "SIFT-167": "Build super timelines from plaso/log2timeline (may need case-specific arguments).",
    "SIFT-168": "Generate ASCII timeline from TSK bodyfile (The Sleuth Kit mactime).",
    "SIFT-169": "Display information about a plaso storage file (pinfo).",
    "SIFT-170": "Sort and filter plaso timeline output (psort).",
    "SIFT-171": "Convert TLN timeline files to plaso format (tln_pl).",
    "SIFT-172": "Find AES encryption keys in memory dumps (aeskeyfind).",
    "SIFT-173": "Volatility 3 memory forensics framework (may need case-specific arguments).",
    "SIFT-174": "Report effective permissions on files and registry keys (Sysinternals accesschk).",
    "SIFT-175": "64-bit accesschk — report effective permissions (Sysinternals).",
    "SIFT-176": "List autostart programs and persistence locations (Sysinternals autoruns).",
    "SIFT-177": "64-bit autoruns — list autostart programs (Sysinternals).",
    "SIFT-178": "Display open handles for processes (Sysinternals handle).",
    "SIFT-179": "Windows PowerShell shell and scripting environment.",
    "SIFT-180": "Capture process memory dumps (Sysinternals procdump).",
    "SIFT-181": "64-bit procdump — capture process memory dumps (Sysinternals).",
    "SIFT-182": "List running processes (Sysinternals pslist).",
    "SIFT-183": "Verify file signatures and publisher info (Sysinternals sigcheck).",
    "SIFT-184": "64-bit sigcheck — verify file signatures (Sysinternals).",
    "SIFT-185": "Query and export Windows Event Log channels (wevtutil).",
    "SIFT-186": "Windows Management Instrumentation command-line interface (wmic).",
    "SIFT-187": "Parse Windows Amcache.hve application compatibility cache.",
    "SIFT-188": "Parse Amcache.hve with Eric Zimmerman AmcacheParser.",
    "SIFT-189": "Parse and export NTFS $MFT records (analyzeMFT).",
    "SIFT-190": "Parse Windows AppCompatCache with Eric Zimmerman parser.",
    "SIFT-191": "Parse Bing Bar artifacts (RegRipper bing_bar_parser.pl).",
    "SIFT-192": "Extract strings with better Unicode handling (bstrings).",
    "SIFT-193": "Dump individual MFT entries (RegRipper dump_mft_entry.pl).",
    "SIFT-194": "Dump Windows EVTX event logs to XML (evtx_dump).",
    "SIFT-195": "Dump EVTX chunk slack space (evtx_dump_chunk_slack).",
    "SIFT-196": "Dump Windows EVTX event logs to JSON (evtx_dump_json).",
    "SIFT-197": "List event record numbers in EVTX files (evtx_eid_record_numbers).",
    "SIFT-198": "Extract a single EVTX record by id (evtx_extract_record).",
    "SIFT-199": "Filter EVTX records by XPath-like criteria (evtx_filter_records).",
    "SIFT-200": "Display metadata about an EVTX file (evtx_info).",
    # Batch 5 (SIFT-201 … SIFT-234)
    "SIFT-201": "Pretty-print the binary structure of an EVTX record (evtx_record_structure).",
    "SIFT-202": "Dump the internal structure of a Windows EVTX file (evtx_structure).",
    "SIFT-203": "Extract and dump templates from a binary EVTX file (evtx_templates).",
    "SIFT-204": "Parse Windows Event Log (.evtx) files with Eric Zimmerman EvtxECmd.",
    "SIFT-205": "Export Windows EVTX event logs (libevtx evtxexport).",
    "SIFT-206": "Display metadata about a Windows EVTX file (libevtx evtxinfo).",
    "SIFT-207": "Parse Windows EVTX event logs (RegRipper evtxparse.pl).",
    "SIFT-208": "Extract slack space from individual MFT records (extract_mft_record_slack).",
    "SIFT-209": "Mount NTFS $MFT as a FUSE filesystem for browsing (fuse_mft).",
    "SIFT-210": "Parse Java web browser IDX cache files (idx_parser).",
    "SIFT-211": "Send diagnostic commands to a running JVM (jcmd).",
    "SIFT-212": "Parse Windows Jump List files with Eric Zimmerman JLECmd.",
    "SIFT-213": "Parse Windows LNK shortcut files with Eric Zimmerman LECmd.",
    "SIFT-214": "List and export NTFS $MFT entries (list_mft).",
    "SIFT-215": "Parse Windows LNK shortcut files (RegRipper lnk.pl).",
    "SIFT-216": "Parse NTFS $MFT records (RegRipper mft.pl).",
    "SIFT-217": "Parse $MFT and $UsnJrnl with Eric Zimmerman MFTECmd.",
    "SIFT-218": "Parse NTFS $MFT and $I30 index structures (MFTINDX).",
    "SIFT-219": "GUI viewer for NTFS $MFT records (MFTView; may need display).",
    "SIFT-220": "Query PulseAudio modules, sinks, and sources (pacmd).",
    "SIFT-221": "Parse Windows Prefetch files with Eric Zimmerman PECmd (not installed on this host).",
    "SIFT-222": "Parse Recycle Bin $I metadata files with Eric Zimmerman RBCmd.",
    "SIFT-223": "Parse Windows RecentFileCache.bcf with Eric Zimmerman RecentFileCacheParser.",
    "SIFT-224": "Batch-process Windows Registry hives with Eric Zimmerman RECmd.",
    "SIFT-225": "Parse and analyze Samba log files (samba_log_parser).",
    "SIFT-226": "Parse ShellBags from Registry hives with Eric Zimmerman SBECmd.",
    "SIFT-227": "Parse SQLite databases (browser history, etc.) with Eric Zimmerman SQLECmd.",
    "SIFT-228": "Parse SQLite database structures (RegRipper sqlite-parser.pl).",
    "SIFT-229": "Parse Windows SRUM database with Eric Zimmerman SrumECmd (not installed on this host).",
    "SIFT-230": "Display NTFS $MFT directory tree (tree_mft).",
    "SIFT-231": "Parse NTFS $UsnJrnl change journal (RegRipper usnj.pl).",
    "SIFT-232": "List entries in NTFS $UsnJrnl (usnjls).",
    "SIFT-233": "Parse NTFS USN change journal records (usnparser).",
    "SIFT-234": "Parse Windows Timeline database with Eric Zimmerman WxTCmd.",
}


def _strip_tags(text: str) -> str:
    text = re.sub(r"\[VERIFIED OK\]\s*", "", text)
    text = re.sub(r"\[BAD — DO NOT USE\]\s*", "", text)
    text = re.sub(r"\s*RISK:.*$", "", text, flags=re.IGNORECASE)
    return text.strip()


def _clean_description(tool_id: str, raw: str) -> str:
    if tool_id in DESCRIPTION_OVERRIDES:
        return DESCRIPTION_OVERRIDES[tool_id]
    cleaned = _strip_tags(raw)
    if not cleaned or "invalid option" in cleaned.lower() or "invalid flag" in cleaned.lower():
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned or tool_id)
    if "traceback" in cleaned.lower():
        return DESCRIPTION_OVERRIDES.get(tool_id, "Registry analysis tool (regipy).")
    if "wine32 is missing" in cleaned.lower():
        return DESCRIPTION_OVERRIDES.get(tool_id, "Windows-only tool (Wine required).")
    if cleaned.startswith("Forensic CLI:"):
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned.replace("Forensic CLI:", "RegRipper plugin:").strip())
    # Drop obvious --help noise (version banners kept only if no override)
    if cleaned.startswith("7-Zip (") or cleaned.startswith("Copyright (c)"):
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned)
    if re.match(r"^aff\w+ version ", cleaned) or re.match(r"^ewf\w+ \d{8}", cleaned):
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned)
    if cleaned.startswith("TestDisk ") or cleaned.startswith("tcpdump version"):
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned)
    if cleaned.startswith("Wireshark ") and tool_id == "SIFT-118":
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned)
    if cleaned.startswith("umount "):
        return DESCRIPTION_OVERRIDES.get(tool_id, "Unmount mounted filesystems.")
    if cleaned.startswith("Clam AntiVirus:") or cleaned.startswith("DensityScout"):
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned)
    if cleaned.startswith("Scalpel version"):
        return DESCRIPTION_OVERRIDES.get(tool_id, cleaned)
    if cleaned.startswith("FILENAME is the name of an SQLite"):
        return DESCRIPTION_OVERRIDES["SIFT-021"]
    if cleaned.startswith("List symbols in [file(s)]"):
        return DESCRIPTION_OVERRIDES["SIFT-035"]
    return cleaned


def _map_verification(old: dict[str, Any]) -> dict[str, Any]:
    status = str(old.get("verification_status") or "untested")
    detail = str(old.get("verification_detail") or "").strip()
    runnable = bool(old.get("runnable", False))

    if status == "ok":
        new_status = "ok"
        if not detail:
            detail = "Lab auto-verified on host."
    elif status == "bad":
        new_status = "bad"
    elif status == "unavailable":
        new_status = "unavailable"
        if not detail:
            detail = "Binary not installed on this host."
    else:
        # skip, untested, or unknown — fine to run, just not lab-tested
        new_status = "not_tested"
        if not detail:
            detail = "Not lab auto-tested; runnable if installed on host."
        elif status == "skip" and "manual verify" in detail:
            detail = "Not lab auto-tested; may need case-specific arguments."

    return {"status": new_status, "detail": detail, "runnable": runnable}


def _map_output_style(old_style: str, name: str) -> str:
    if old_style == "inode_stream" or name == "icat":
        return "inode_stream"
    if old_style == "scratch_dir_trailing":
        return "scratch_dir_trailing"
    if old_style in {"stdout", "stderr", "scratch_file", "inode_stream", "scratch_dir_trailing"}:
        return old_style
    return "stdout"


def convert_tool(old: dict[str, Any]) -> dict[str, Any]:
    tool_id = str(old["tool_id"])
    name = str(old["name"])
    out_format = str(old.get("output_format") or "text")
    if out_format not in {"text", "json", "csv", "binary"}:
        out_format = "text"

    flags = old.get("common_flags") or []
    normalized_flags = [
        {
            "flag": str(f.get("flag", "")),
            "description": str(f.get("description", "")),
            **({"required": bool(f["required"])} if "required" in f else {}),
        }
        for f in flags
        if f.get("flag")
    ]

    inp_style = str(old.get("input_style") or "positional")
    if inp_style not in {"positional", "flag", "stdin", "none"}:
        inp_style = "positional"

    record: dict[str, Any] = {
        "tool_id": tool_id,
        "name": name,
        "binary": str(old["binary"]),
        "category": str(old.get("category") or "misc"),
        "description": _clean_description(tool_id, str(old.get("description") or "")),
        "host_platforms": list(old.get("host_platforms") or ["linux"]),
        "artifact_platforms": list(old.get("artifact_platforms") or ["any"]),
        "input": {
            "style": inp_style,
            "flag": str(old.get("input_flag") or ""),
            "common_flags": normalized_flags,
        },
        "output": {
            "format": out_format,
            "style": _map_output_style(str(old.get("output_style") or "stdout"), name),
        },
        "timeout_seconds": int(old.get("timeout_seconds") or 600),
        "interactive": bool(old.get("interactive", False)),
        "verification": _map_verification(old),
    }
    harness = old.get("harness_usage")
    if harness:
        record["input"]["harness_usage"] = str(harness)
    elif record["output"]["style"] == "scratch_dir_trailing":
        record["input"]["harness_usage"] = (
            "Bulk recover: pass image flags only; harness appends scratch output directory as final arg."
        )
    return record


def port_batch(
    *,
    source: Path = SOURCE_DEFAULT,
    start: int = 0,
    limit: int = 50,
) -> list[dict[str, Any]]:
    data = json.loads(source.read_text(encoding="utf-8"))
    tools = data.get("tools") or []
    slice_ = tools[start : start + limit]
    return [convert_tool(t) for t in slice_]


def validate_tool_record(rec: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = (
        "tool_id",
        "name",
        "binary",
        "category",
        "description",
        "host_platforms",
        "artifact_platforms",
        "input",
        "output",
        "timeout_seconds",
        "verification",
    )
    for key in required:
        if key not in rec:
            errors.append(f"missing {key}")
    if not re.match(r"^SIFT-[0-9]{3}$", rec.get("tool_id", "")):
        errors.append("bad tool_id")
    if not rec.get("description"):
        errors.append("empty description")
    if "[VERIFIED OK]" in rec.get("description", ""):
        errors.append("description still has verification tag")
    ver = rec.get("verification") or {}
    if ver.get("status") not in {"ok", "bad", "not_tested", "unavailable"}:
        errors.append(f"bad verification.status {ver.get('status')}")
    return errors
