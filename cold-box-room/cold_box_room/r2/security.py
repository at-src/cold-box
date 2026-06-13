"""Execution sandbox — argument sanitization and output path checks."""

from __future__ import annotations

import re
from pathlib import Path

_DANGEROUS_PATTERNS = (";", "&&", "||", "`", "$(", "${")
_AWK_DANGEROUS_RE = re.compile(
    r"system\s*\(|getline|\".*\||\|.*\"|>\s*\"|>>\s*\"", re.IGNORECASE
)
_PROGRAM_TEXT_TOOLS = {"awk", "gawk", "mawk", "nawk"}
_TSK_OFFSET_TOOLS = frozenset(
    {
        "fls",
        "fsstat",
        "icat",
        "istat",
        "ils",
        "blkls",
        "blkcat",
        "fcat",
        "ffind",
        "ifind",
        "mactime",
        "sigfind",
        "tsk_recover",
        "mmls",
        "mmcat",
    }
)
_NON_OUTPUT_O_TOOLS = frozenset({"grep", "egrep", "fgrep", "zgrep", "rg"})

_POLICY = {
    "dangerous_flags": {
        "-e",
        "--exec",
        "--command",
        "-enc",
        "-encodedcommand",
        "--script",
        "--invoke",
    },
    "tool_allowed_flags": {
        "run_bulk_extractor": {"-e", "-x"},
        "sed": {"-e"},
        "grep": {"-e"},
        "egrep": {"-e"},
        "fgrep": {"-e"},
        "zgrep": {"-e"},
    },
    "tool_blocked_flags": {
        "find": {
            "-exec",
            "-execdir",
            "-delete",
            "-fls",
            "-fprint",
            "-fprint0",
            "-fprintf",
        },
        "sed": {"-i", "--in-place"},
        "tar": {
            "-x",
            "--extract",
            "--get",
            "-c",
            "--create",
            "--delete",
            "--append",
            "--checkpoint-action",
            "--use-compress-program",
            "--to-command",
        },
        "unzip": {"-o", "-n"},
    },
    "denied_binaries": frozenset(
        {
            "mkfs",
            "mkfs.ext4",
            "shutdown",
            "reboot",
            "kill",
            "killall",
            "pkill",
            "curl",
            "wget",
        }
    ),
    "output_flags": frozenset({"--csv", "--csvf", "-o", "--output", "--json", "--jsonl"}),
}


def is_denied(binary_name: str) -> bool:
    return binary_name.lower() in _POLICY["denied_binaries"]


def sanitize_extra_args(extra_args: list[str], tool_name: str = "") -> list[str]:
    if not extra_args:
        return []
    tool_allowed = _POLICY["tool_allowed_flags"].get(tool_name, set())
    tool_blocked = _POLICY["tool_blocked_flags"].get(tool_name, set())
    sanitized: list[str] = []
    for arg in extra_args:
        if not isinstance(arg, str):
            raise ValueError(f"Non-string argument: {type(arg).__name__}")
        flag = arg.lower().split("=")[0]
        if flag in tool_blocked:
            raise ValueError(f"Blocked flag {arg!r} for {tool_name}")
        if flag in _POLICY["dangerous_flags"] and flag not in tool_allowed:
            raise ValueError(f"Blocked dangerous flag {arg!r} for {tool_name}")
        for pattern in _DANGEROUS_PATTERNS:
            if pattern in arg:
                raise ValueError(f"Blocked shell metacharacter in {arg!r}")
        sanitized.append(arg)
    if tool_name in _PROGRAM_TEXT_TOOLS:
        for arg in sanitized:
            if arg.startswith("-"):
                continue
            if _AWK_DANGEROUS_RE.search(arg):
                raise ValueError("Blocked dangerous awk construct")
    return sanitized


def assert_scratch_output(path: Path, scratch_root: Path) -> None:
    resolved = path.expanduser().resolve()
    root = scratch_root.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"Output path {resolved} must stay under scratch {root}"
        ) from exc


def validate_output_args(extra_args: list[str], scratch_root: Path, tool_name: str) -> None:
    output_flags = _POLICY["output_flags"]
    prev_output = False
    for arg in extra_args:
        if "=" in arg and arg.startswith("-"):
            flag, value = arg.split("=", 1)
            if flag in output_flags and value:
                assert_scratch_output(Path(value), scratch_root)
            prev_output = False
            continue
        if arg.startswith("-") and "=" not in arg:
            if tool_name in _TSK_OFFSET_TOOLS and arg == "-o":
                prev_output = False
                continue
            if tool_name in _NON_OUTPUT_O_TOOLS and arg == "-o":
                prev_output = False
                continue
            prev_output = arg in output_flags
            continue
        if prev_output and not arg.startswith("-"):
            assert_scratch_output(Path(arg), scratch_root)
        prev_output = False
