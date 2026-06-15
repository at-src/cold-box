"""Shared harness/catalog probe planning for tools."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from cold_box_room.tools.verify import _matches
from cold_box_room.tools.verify_profiles import VerifyPlan, plan_for, version_argv

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# Disk metadata on tiny ext2 fixture (matches catalog verify).
DISK_FIXTURE_TOOLS = frozenset({"img_stat", "fsstat", "fls"})

# E01-only metadata probes on the Terry sandbox image.
EWF_IMAGE_TOOLS = frozenset(
    {
        "ewfinfo",
        "ewfverify",
        "ewfdebug",
        "ewfacquirestream",
        "mmls",
        "ils",
        "ifind",
        "ffind",
    }
)

HARNESS_SKIP = frozenset(
    {
        "mactime",
        "icat",
        "istat",
        "tsk_recover",
        "mount",
        "ewfmount",
        "ewfexport",
        "ewfacquire",
        "photorec",
        "testdisk",
        "autopsy",
        "dd",
        "dc3dd",
        "dcfldd",
        "xmount",
        "vshadowmount",
        "affuse",
        "MFTView",
    }
)

# Needs AFF/VMEM/other format we do not ship as a tiny fixture.
FORMAT_SKIP = frozenset(
    {
        "affcat",
        "affconvert",
        "affcopy",
        "affcrypto",
        "affinfo",
        "affrecover",
        "affsegment",
        "affsign",
        "affstats",
        "affverify",
        "aeskeyfind",
        "vol3",
        "vol",
        "vol.py",
        "volatility",
    }
)


def plan_probe(tool, *, image_relpath: str) -> tuple[str, str, list[str], VerifyPlan, str]:
    """Return (status, detail, extra_args, plan, input_relpath) before execution."""
    plan = plan_for(tool.name, tool.category)
    if not shutil.which(tool.binary):
        return "unavailable", "binary not on PATH for this host", [], plan, "sample.txt"
    if tool.name in HARNESS_SKIP:
        return "skipped", "interactive/destructive/special-args — manual probe only", [], plan, "sample.txt"
    if tool.name in FORMAT_SKIP:
        return "skipped", "needs dedicated artifact fixture (AFF/memory) — not a harness failure", [], plan, "sample.txt"
    if plan.mode == "skip":
        return "skipped", plan.skip_reason or "skipped by verify plan", [], plan, "sample.txt"

    if tool.name in DISK_FIXTURE_TOOLS:
        fixture = "tiny.ext2.dd"
        if not (FIXTURES_DIR / fixture).is_file():
            return "skipped", f"missing fixture {fixture}", list(plan.extra_args), plan, fixture
        extra = list(plan.extra_args) or (["-r"] if tool.name == "fls" else [])
        return "probe", f"fixture {fixture}", extra, plan, fixture

    if tool.name in EWF_IMAGE_TOOLS or tool.name.lower().startswith("ewf"):
        return "probe", "E01 metadata probe", _ewf_extra(tool.name), plan, image_relpath

    if plan.mode == "fixture":
        fixture = plan.fixture
        if not (FIXTURES_DIR / fixture).is_file():
            return "skipped", f"missing fixture {fixture}", list(plan.extra_args), plan, fixture
        return "probe", f"fixture {fixture}", list(plan.extra_args), plan, fixture

    if plan.mode == "version":
        return "probe", "version/help probe", ["--help"], plan, "sample.txt"

    return "skipped", f"unhandled plan mode {plan.mode}", [], plan, "sample.txt"


def _ewf_extra(name: str) -> list[str]:
    lower = name.lower()
    if lower in {"fls", "fsstat", "ils", "ifind", "ffind", "icat", "istat", "blkls", "blkcat", "blkstat", "blkcalc"}:
        if lower == "fls":
            return ["-r", "-o", "63"]
        if lower == "fsstat":
            return ["-o", "63"]
        return ["-o", "63"]
    if lower == "mmls":
        return []
    return []


def evaluate_probe_result(plan: VerifyPlan, result: dict[str, Any]) -> tuple[bool, str]:
    exit_code = int(result.get("exit_code", 1))
    combined = " ".join(
        filter(
            None,
            [
                str(result.get("stdout_preview") or ""),
                str(result.get("stderr_preview") or ""),
                str(result.get("error") or ""),
            ],
        )
    )
    ok, reason = _matches(plan, exit_code, combined)
    if ok:
        return True, reason
    if exit_code in plan.accept_exit and not plan.expect_any:
        return True, f"exit_code={exit_code}"
    return False, reason


def version_probe_args(tool_name: str) -> list[list[str]]:
    return version_argv(tool_name)
