"""Per-tool verification plans — fixture, args, expected output."""

from __future__ import annotations

from dataclasses import dataclass, field

Fixtures = dict[str, str]  # name -> relpath under fixture dir


@dataclass(frozen=True)
class VerifyPlan:
    mode: str  # fixture | version | skip
    fixture: str = "sample.txt"
    extra_args: list[str] = field(default_factory=list)
    accept_exit: tuple[int, ...] = (0,)
    expect_any: tuple[str, ...] = ()
    expect_all: tuple[str, ...] = ()
    timeout: int = 20
    skip_reason: str = ""
    input_last: bool = False  # grep/awk/sed: args before input path


# Known hashes for fixtures/sample.txt (cold-box-verify-token\nline-two\n)
SAMPLE_TXT_MD5 = "89e7a78e0114e02d573eaf9c2a9886d1"
SAMPLE_TXT_SHA256_PREFIX = "bb85c6c3fd89a237"

TEXT_TOOLS: dict[str, VerifyPlan] = {
    "file": VerifyPlan("fixture", expect_any=("ASCII", "text")),
    "strings": VerifyPlan("fixture", expect_any=("cold-box-verify-token",)),
    "md5sum": VerifyPlan("fixture", expect_any=(SAMPLE_TXT_MD5,)),
    "sha256sum": VerifyPlan("fixture", expect_any=(SAMPLE_TXT_SHA256_PREFIX,)),
    "wc": VerifyPlan("fixture", expect_any=("2", "3")),
    "head": VerifyPlan("fixture", extra_args=["-n", "1"], expect_any=("cold-box-verify-token",)),
    "tail": VerifyPlan("fixture", extra_args=["-n", "1"], expect_any=("line-two",)),
    "grep": VerifyPlan(
        "fixture",
        extra_args=["-F", "cold-box-verify-token"],
        input_last=True,
        expect_any=("cold-box-verify-token",),
    ),
    "awk": VerifyPlan(
        "fixture",
        extra_args=["{print $1}"],
        input_last=True,
        expect_any=("cold-box-verify-token",),
    ),
    "sed": VerifyPlan(
        "fixture",
        extra_args=["-e", "s/token/TOK/"],
        input_last=True,
        expect_any=("TOK",),
    ),
    "cut": VerifyPlan("fixture", extra_args=["-c", "1-5"], expect_any=("cold-",)),
    "sort": VerifyPlan("fixture", expect_any=("cold-box", "line-two")),
    "uniq": VerifyPlan("fixture", expect_any=("cold-box-verify-token",)),
    "xxd": VerifyPlan("fixture", expect_any=("636f6c64", "cold")),
    "hexdump": VerifyPlan("fixture", expect_any=("646c", "6f63", "cold")),
    "cat": VerifyPlan("fixture", expect_any=("cold-box-verify-token",)),
    "objdump": VerifyPlan(
        "fixture",
        fixture="sample.elf",
        extra_args=["-x"],
        input_last=True,
        expect_any=("elf", "file format", "architecture"),
    ),
    "readelf": VerifyPlan("skip", skip_reason="needs ELF fixture"),
    "diff": VerifyPlan("skip", skip_reason="needs two input files"),
    "tar": VerifyPlan("skip", skip_reason="needs tar archive fixture"),
}

BIN_TOOLS: dict[str, VerifyPlan] = {
    "strings": VerifyPlan("fixture", fixture="sample.bin", expect_any=("cold-box-verify-token-binary",)),
    "ssdeep": VerifyPlan("fixture", fixture="sample.bin", accept_exit=(0, 1, 2), expect_any=("",)),
    "trid": VerifyPlan("fixture", fixture="sample.bin", accept_exit=(0, 1), expect_any=("",)),
    "densityscout": VerifyPlan("fixture", fixture="sample.bin", accept_exit=(0, 1), expect_any=("")),
}

DISK_TOOLS: dict[str, VerifyPlan] = {
    "img_stat": VerifyPlan("fixture", fixture="tiny.ext2.dd", expect_any=("IMAGE", "raw")),
    "fsstat": VerifyPlan("fixture", fixture="tiny.ext2.dd", expect_any=("Ext2", "FILE SYSTEM")),
    "fls": VerifyPlan("fixture", fixture="tiny.ext2.dd", extra_args=["-r"], expect_any=("lost+found", "FILE")),
    "mmls": VerifyPlan("skip", skip_reason="needs partitioned image fixture"),
    "icat": VerifyPlan("skip", skip_reason="needs inode from fls run"),
    "istat": VerifyPlan("skip", skip_reason="needs inode number"),
}

ZIP_TOOLS: dict[str, VerifyPlan] = {
    "unzip": VerifyPlan(
        "fixture",
        fixture="sample.zip",
        extra_args=["-l"],
        input_last=True,
        expect_any=("sample.txt", "Archive"),
    ),
    "7z": VerifyPlan(
        "fixture",
        fixture="sample.zip",
        extra_args=["l"],
        input_last=True,
        accept_exit=(0, 1, 2),
        expect_any=("sample.txt", "Zip", "Archive"),
    ),
    "7za": VerifyPlan(
        "fixture",
        fixture="sample.zip",
        extra_args=["l"],
        input_last=True,
        accept_exit=(0, 1, 2),
        expect_any=("sample.txt", "Zip", "Archive"),
    ),
    "7zr": VerifyPlan("skip", skip_reason="7zr not consistently available — use 7z/7za"),
}

PCAP_TOOLS: dict[str, VerifyPlan] = {
    "tshark": VerifyPlan(
        "fixture",
        fixture="sample.pcap",
        extra_args=["-r"],
        input_last=True,
        accept_exit=(0, 1, 2),
        expect_any=("",),
    ),
    "wireshark": VerifyPlan("skip", skip_reason="GUI wireshark — use tshark for headless probes"),
    "tcpdump": VerifyPlan(
        "fixture",
        fixture="sample.pcap",
        extra_args=["-r"],
        input_last=True,
        accept_exit=(0, 1, 2),
        expect_any=("",),
    ),
    "ngrep": VerifyPlan(
        "fixture",
        fixture="sample.pcap",
        extra_args=["-q", "xx"],
        input_last=True,
        accept_exit=(0, 1, 2),
        expect_any=("",),
    ),
}

EVTX_TOOLS: dict[str, VerifyPlan] = {
    "evtx_dump.py": VerifyPlan("fixture", fixture="sample.evtx", accept_exit=(0, 1, 2), expect_any=("",)),
    "evtx_dump_chunk_slack.py": VerifyPlan("fixture", fixture="sample.evtx", accept_exit=(0, 1, 2), expect_any=("",)),
    "evtx_dump_json.py": VerifyPlan("fixture", fixture="sample.evtx", accept_exit=(0, 1, 2), expect_any=("",)),
    "evtx_eid_record_numbers.py": VerifyPlan("fixture", fixture="sample.evtx", accept_exit=(0, 1, 2), expect_any=("",)),
    "evtx_extract_record.py": VerifyPlan("fixture", fixture="sample.evtx", accept_exit=(0, 1, 2), expect_any=("",)),
    "evtx_filter_records.py": VerifyPlan("fixture", fixture="sample.evtx", accept_exit=(0, 1, 2), expect_any=("",)),
    "evtx_info.py": VerifyPlan("fixture", fixture="sample.evtx", accept_exit=(0, 1, 2), expect_any=("",)),
    "evtx_record_structure.py": VerifyPlan("fixture", fixture="sample.evtx", accept_exit=(0, 1, 2), expect_any=("",)),
    "evtx_structure.py": VerifyPlan("fixture", fixture="sample.evtx", accept_exit=(0, 1, 2), expect_any=("",)),
    "evtx_templates.py": VerifyPlan("fixture", fixture="sample.evtx", accept_exit=(0, 1, 2), expect_any=("",)),
}

INTERACTIVE_OR_DESTRUCTIVE = frozenset(
    {
        "dd",
        "dc3dd",
        "dcfldd",
        "ewfacquire",
        "mount",
        "xmount",
        "ewfmount",
        "vshadowmount",
        "autopsy",
        "photorec",
        "testdisk",
        "log2timeline.py",
        "log2timeline",
        "regedit",
        "regedit-stable",
        "regedit_stable",
        "regsvr32",
        "regsvr32-stable",
        "regsvr32_stable",
        "mftview.py",
        "regslack.pl",
        "wine",
        "wine64",
    }
)


def plan_for(binary: str, category: str) -> VerifyPlan:
    key = binary.lower()
    if (key.endswith(".pl") or key.endswith("_pl")) and key not in {"rip.pl", "regripper"}:
        return VerifyPlan(
            "skip",
            skip_reason="RegRipper/helper plugin — run via rip.pl -p or with artifact fixture",
        )
    if key in TEXT_TOOLS:
        return TEXT_TOOLS[key]
    if key in BIN_TOOLS:
        return BIN_TOOLS[key]
    if key in DISK_TOOLS:
        return DISK_TOOLS[key]
    if key in ZIP_TOOLS:
        return ZIP_TOOLS[key]
    if key in PCAP_TOOLS:
        return PCAP_TOOLS[key]
    if key in EVTX_TOOLS:
        return EVTX_TOOLS[key]
    if key in INTERACTIVE_OR_DESTRUCTIVE:
        return VerifyPlan("skip", skip_reason="interactive or destructive — manual verify only")
    if category == "windows_host":
        return VerifyPlan("skip", skip_reason="windows host only")
    if category == "network" and key == "zeek":
        return VerifyPlan("skip", skip_reason="needs live zeek install + pcap fixture")
    if category == "volatility" and key in {"vol", "vol.py", "volatility"}:
        return VerifyPlan("skip", skip_reason="needs memory dump fixture")
    if category in {"zimmerman", "misc", "timeline", "malware", "file_analysis", "sleuthkit", "network"}:
        if binary.lower().endswith(".pl"):
            expect = ("rip", "registry", "usage", "Usage", "plugin", binary[:4].lower())
        else:
            expect = (binary.split(".")[0][:4].lower(), "version", "Usage", "usage", "Options")
        return VerifyPlan(
            "version",
            accept_exit=(0, 1, 2),
            expect_any=expect,
            timeout=8,
        )
    if category in {"common", "analysis"}:
        return VerifyPlan(
            "version",
            accept_exit=(0, 1),
            expect_any=("usage", "Usage", binary[:3].lower()),
            timeout=10,
        )
    return VerifyPlan(
        "version",
        accept_exit=(0, 1, 2),
        expect_any=("version", "Usage", "usage"),
        timeout=12,
    )


def version_argv(binary: str) -> list[list[str]]:
    return [
        ["--version"],
        ["-V"],
        ["-v"],
        ["--help"],
        ["-h"],
    ]
