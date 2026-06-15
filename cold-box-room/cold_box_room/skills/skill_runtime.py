"""Runtime for ported skill scripts — surgical SIFT swap (run_cmd / subprocess → harness)."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

from cold_box_room.r2.errors import ToolExecutionError
from cold_box_room.r2.executor import run_sift_tool
from cold_box_room.r2.output_files import scratch_dir
from cold_box_room.r2.scratch_analysis import resolve_scratch_path, run_scratch_analysis
from cold_box_room.tools.registry import _records_by_id

from cold_box_room.r2.skill_harness import (
    reset_skill_harness_active,
    set_skill_harness_active,
)

_RUNTIME: ContextVar["SkillRuntime | None"] = ContextVar("cold_box_room_skill_runtime", default=None)

SCRATCH_ANALYSIS_BINARIES = frozenset({"grep", "strings", "file", "sqlite3", "head", "tail", "wc", "identify"})

BINARY_ALIASES = {
    "regripper": "rip.pl",
    "vol.py": "vol",
    "log2timeline.py": "log2timeline",
    "psort.py": "psort",
    "evtxecmd": "EvtxECmd",
    "mftecmd": "MFTECmd",
    "pecmd": "PECmd",
    "recmd": "RECmd",
    "amcacheparser": "AmcacheParser",
    "appcompatcacheparser": "AppCompatCacheParser",
    "srch_strings": "strings",
}


class SkillRuntimeError(ToolExecutionError):
    """Skill script tried to run a tool with no SIFT/harness mapping."""


@dataclass
class SkillRuntime:
    case_id: str
    journal_id: str
    skill_id: str
    input_relpath: str
    session_id: str = ""
    evidence_abs_path: Path | None = None
    work_dir: Path | None = None
    audit_ids: list[str] = field(default_factory=list)
    last_tool_result: dict[str, Any] | None = None
    skill_run_id: str = ""

    def scratch_root(self) -> Path:
        return scratch_dir(self.case_id)

    def ensure_work_dir(self) -> Path:
        if self.work_dir is None:
            root = self.scratch_root() / f"skill_{self.skill_id.replace('/', '_')}"
            root.mkdir(parents=True, exist_ok=True)
            self.work_dir = root
        return self.work_dir


def skill_harness_active() -> bool:
    from cold_box_room.r2.skill_harness import skill_harness_active as _active

    return _active()


def get_runtime() -> SkillRuntime:
    runtime = _RUNTIME.get()
    if runtime is None:
        raise SkillRuntimeError(
            "Skill runtime not active — run scripts via run_skill harness tool."
        )
    return runtime


@contextmanager
def activate(runtime: SkillRuntime) -> Iterator[SkillRuntime]:
    runtime_token = _RUNTIME.set(runtime)
    harness_token = set_skill_harness_active(True)
    try:
        yield runtime
    finally:
        reset_skill_harness_active(harness_token)
        _RUNTIME.reset(runtime_token)


@contextmanager
def activate_from_env() -> Iterator[SkillRuntime]:
    """For scripts executed as __main__ with COLD_BOX_* env vars."""
    import os

    case_id = os.environ.get("COLD_BOX_CASE_ID", "")
    journal_id = os.environ.get("COLD_BOX_JOURNAL_ID", "")
    skill_id = os.environ.get("COLD_BOX_SKILL_ID", "")
    input_relpath = os.environ.get("COLD_BOX_INPUT_RELPATH", ".")
    session_id = os.environ.get("COLD_BOX_SESSION_ID", "")
    evidence = os.environ.get("COLD_BOX_EVIDENCE_ABS", "")
    if not case_id or not journal_id:
        raise SkillRuntimeError("Missing COLD_BOX_CASE_ID or COLD_BOX_JOURNAL_ID")

    from cold_box_room.r2.sandbox_input import resolve_sandbox_input_for_skill

    abs_path = Path(evidence) if evidence else resolve_sandbox_input_for_skill(case_id, input_relpath)
    runtime = SkillRuntime(
        case_id=case_id,
        journal_id=journal_id,
        skill_id=skill_id,
        input_relpath=input_relpath,
        session_id=session_id,
        evidence_abs_path=abs_path if abs_path.is_file() else None,
    )
    with activate(runtime):
        yield runtime


def _binary_index() -> dict[str, str]:
    idx: dict[str, str] = {}
    for rec in _records_by_id().values():
        idx[rec.binary.lower()] = rec.tool_id
        idx[rec.name.lower()] = rec.tool_id
    for alias, target in BINARY_ALIASES.items():
        tid = idx.get(target.lower())
        if tid:
            idx[alias.lower()] = tid
    return idx


def resolve_tool_id(binary: str) -> str | None:
    return _binary_index().get(Path(binary).name.lower())


def _is_evidence_arg(arg: str, runtime: SkillRuntime) -> bool:
    if not arg:
        return False
    if arg == runtime.input_relpath:
        return True
    if runtime.evidence_abs_path and arg == str(runtime.evidence_abs_path):
        return True
    try:
        name = Path(arg).name
        if runtime.evidence_abs_path and name == runtime.evidence_abs_path.name:
            return True
        if runtime.input_relpath and name == Path(runtime.input_relpath).name:
            return True
    except OSError:
        pass
    return False


def _scratch_relpath(path: str, runtime: SkillRuntime) -> str | None:
    """Return scratch-relative path only when it points at an existing scratch file."""
    candidate = Path(path)
    for root in (runtime.scratch_root(), runtime.ensure_work_dir()):
        try:
            if candidate.is_absolute():
                rel = str(candidate.resolve().relative_to(root.resolve()))
            else:
                rel = path.lstrip("/")
            target = (root / rel).resolve()
            target.relative_to(root.resolve())
        except ValueError:
            continue
        if target.is_file():
            return rel
    return None


def _read_tool_stdout(result: dict[str, Any]) -> str:
    preview = result.get("stdout_preview") or result.get("preview") or ""
    if preview:
        return preview
    scratch_file = result.get("scratch_file") or ""
    if scratch_file:
        path = Path(scratch_file)
        if path.is_file():
            data = path.read_bytes()
            try:
                return data.decode("utf-8", errors="replace")
            except OSError:
                return ""
    output_files = result.get("output_files") or []
    for item in output_files:
        p = Path(str(item))
        if p.name == "stdout.txt" and p.is_file():
            return p.read_text(encoding="utf-8", errors="replace")
    return ""


def _read_tool_stdout_bytes(result: dict[str, Any]) -> bytes:
    scratch_file = result.get("scratch_file") or ""
    if scratch_file:
        path = Path(scratch_file)
        if path.is_file():
            return path.read_bytes()
    text = _read_tool_stdout(result)
    return text.encode("utf-8", errors="replace")


def _run_harness_tool(
    *,
    tool_id: str | None = None,
    binary: str | None = None,
    input_relpath: str,
    extra_args: list[str],
    purpose: str,
    timeout: int | None = None,
) -> dict[str, Any]:
    runtime = get_runtime()
    tid = tool_id or (resolve_tool_id(binary or "") if binary else None)
    if not tid:
        raise SkillRuntimeError(f"No SIFT catalog entry for binary {binary!r}")

    result = run_sift_tool(
        tool_id=tid,
        case_id=runtime.case_id,
        input_relpath=input_relpath,
        purpose=purpose,
        why=f"Skill script {runtime.skill_id} [{runtime.journal_id}]",
        extra_args=extra_args,
        timeout=timeout,
    )
    aid = result.get("audit_id")
    if aid and aid not in runtime.audit_ids:
        runtime.audit_ids.append(aid)
    runtime.last_tool_result = result
    return result


def _run_harness_scratch(
    *,
    binary: str,
    scratch_relpath: str,
    args: list[str],
    purpose: str,
    timeout: int | None = None,
) -> dict[str, Any]:
    runtime = get_runtime()
    result = run_scratch_analysis(
        case_id=runtime.case_id,
        binary=binary,
        scratch_relpath=scratch_relpath,
        args=args,
        purpose=purpose,
        why=f"Skill script {runtime.skill_id} [{runtime.journal_id}]",
        timeout=timeout,
    )
    aid = result.get("audit_id")
    if aid and aid not in runtime.audit_ids:
        runtime.audit_ids.append(aid)
    runtime.last_tool_result = result
    return result


def _run_mactime_on_bodyfile(
    *,
    bodyfile: Path,
    extra_args: list[str],
    purpose: str,
    timeout: int | None,
) -> dict[str, Any]:
    """Run mactime against a scratch bodyfile (not the disk image)."""
    import time

    from cold_box_room.r2.audit import append_audit, next_audit_id
    from cold_box_room.r2.harness_log import append_harness_tool_log
    from cold_box_room.r2.output_files import describe_output_file, read_text_preview, scratch_dir
    from cold_box_room.r2.security import sanitize_extra_args

    runtime = get_runtime()
    from cold_box_room.r2.mactime_utils import validate_mactime_bodyfile

    validate_mactime_bodyfile(bodyfile)
    resolved = shutil.which("mactime")
    if not resolved:
        raise SkillRuntimeError("mactime not installed on PATH")

    extra = sanitize_extra_args(list(extra_args), tool_name="mactime")
    cmd = [resolved, "-b", str(bodyfile), *extra]
    audit_id = next_audit_id()
    scratch = scratch_dir(runtime.case_id)
    out_root = scratch / f"{audit_id}_SIFT-168_mactime"
    out_root.mkdir(parents=True, exist_ok=True)
    stdout_path = out_root / "stdout.txt"
    start = time.monotonic()
    mactime_timeout = timeout if timeout and timeout > 0 else 600
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(scratch),
            timeout=mactime_timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        append_audit(
            case_id=runtime.case_id,
            audit_id=audit_id,
            tool_id="SIFT-168",
            tool_name="mactime",
            purpose=purpose,
            why=f"Skill script {runtime.skill_id} [{runtime.journal_id}]",
            command=cmd,
            input_relpath=str(bodyfile.relative_to(scratch)),
            input_sha256="",
            exit_code=-1,
            elapsed_ms=elapsed_ms,
            error=f"Timed out after {mactime_timeout}s",
        )
        raise SkillRuntimeError(f"mactime timed out after {mactime_timeout}s") from exc

    elapsed_ms = (time.monotonic() - start) * 1000
    stdout_path.write_text(proc.stdout or "", encoding="utf-8")
    output_files = [str(stdout_path)]
    stderr = (proc.stderr or "").strip()
    if stderr:
        err_path = out_root / "stderr.txt"
        err_path.write_text(stderr, encoding="utf-8")
        output_files.append(str(err_path))
    meta = out_root / "run.meta.txt"
    meta.write_text(f"audit_id={audit_id}\n", encoding="utf-8")
    output_files.append(str(meta))
    preview = read_text_preview(stdout_path)[:2000]
    append_audit(
        case_id=runtime.case_id,
        audit_id=audit_id,
        tool_id="SIFT-168",
        tool_name="mactime",
        purpose=purpose,
        why=f"Skill script {runtime.skill_id} [{runtime.journal_id}]",
        command=cmd,
        input_relpath=str(bodyfile.relative_to(scratch)),
        input_sha256="",
        exit_code=proc.returncode,
        elapsed_ms=elapsed_ms,
        output_files=output_files,
        stdout_preview=preview,
    )
    append_harness_tool_log(
        case_id=runtime.case_id,
        audit_id=audit_id,
        tool_id="SIFT-168",
        tool_name="mactime",
        purpose=purpose,
        why=f"Skill script {runtime.skill_id} [{runtime.journal_id}]",
        command=cmd,
        input_relpath=str(bodyfile.relative_to(scratch)),
        exit_code=proc.returncode,
        stdout_preview=preview,
    )
    result = {
        "ok": proc.returncode == 0,
        "audit_id": audit_id,
        "exit_code": proc.returncode,
        "stdout_preview": preview,
        "preview": describe_output_file(stdout_path, case_id=runtime.case_id).get("preview"),
        "stderr_preview": stderr[:400],
        **describe_output_file(stdout_path, case_id=runtime.case_id),
    }
    aid = result.get("audit_id")
    if aid and aid not in runtime.audit_ids:
        runtime.audit_ids.append(aid)
    runtime.last_tool_result = result
    return result


def parse_and_run(cmd: list[str], *, timeout: int | None = None) -> tuple[str, str, int]:
    """Parse argv and route through SIFT harness. Returns (stdout, stderr, rc)."""
    if not cmd:
        raise SkillRuntimeError("Empty command")
    runtime = get_runtime()
    binary = Path(cmd[0]).name
    args = cmd[1:]

    if binary.lower() == "mactime":
        from cold_box_room.r2.mactime_utils import mactime_bodyfile_from_extra

        bodyfile, remaining = mactime_bodyfile_from_extra(
            args,
            scratch_root=runtime.scratch_root(),
        )
        if bodyfile is not None:
            result = _run_mactime_on_bodyfile(
                bodyfile=bodyfile,
                extra_args=remaining,
                purpose="mactime via skill script",
                timeout=timeout,
            )
            out = _read_tool_stdout(result)
            rc = int(result.get("exit_code") or 0)
            err = (result.get("error") or result.get("stderr_preview") or "").strip()
            return out, err, rc
        for i, arg in enumerate(args):
            if arg == "-b" and i + 1 < len(args) and _is_evidence_arg(args[i + 1], runtime):
                raise SkillRuntimeError(
                    "mactime -b requires a TSK bodyfile from `fls -m`, not the disk image"
                )

    if binary.lower() in SCRATCH_ANALYSIS_BINARIES:
        if not args:
            raise SkillRuntimeError(f"{binary} requires a scratch file argument")
        target = args[-1]
        rel = _scratch_relpath(target, runtime)
        if rel is None:
            raise SkillRuntimeError(f"{binary} input must be under case scratch: {target!r}")
        result = _run_harness_scratch(
            binary=binary.lower(),
            scratch_relpath=rel,
            args=args[:-1],
            purpose=f"{binary} via skill script",
            timeout=timeout,
        )
        out = _read_tool_stdout(result)
        rc = int(result.get("exit_code") or 0)
        err = (result.get("error") or result.get("stderr_preview") or "").strip()
        return out, err, rc

    tool_id = resolve_tool_id(binary)
    if not tool_id:
        raise SkillRuntimeError(
            f"No SIFT mapping for {binary!r} — skill script cannot bypass harness."
        )

    input_relpath = runtime.input_relpath
    extra: list[str] = []

    for arg in args:
        if _is_evidence_arg(arg, runtime):
            continue
        rel = _scratch_relpath(arg, runtime)
        if rel is not None:
            continue
        extra.append(arg)

    result = _run_harness_tool(
        tool_id=tool_id,
        input_relpath=input_relpath,
        extra_args=extra,
        purpose=f"{binary} via skill script",
        timeout=timeout,
    )

    out = _read_tool_stdout(result)
    rc = int(result.get("exit_code") or 0)
    err = (result.get("error") or result.get("stderr_preview") or "").strip()
    return out, err, rc


def run_cmd(cmd: str | list[str], timeout: int = 120) -> tuple[str, str, int]:
    """Drop-in replacement for ACS run_cmd — routes tool calls through SIFT harness."""
    if isinstance(cmd, str):
        argv = shlex.split(cmd)
    else:
        argv = list(cmd)
    return parse_and_run(argv, timeout=timeout)


def run_subprocess(
    cmd: str | list[str],
    *,
    capture_output: bool = False,
    text: bool = False,
    timeout: int | None = 120,
    check: bool = False,
    **_: Any,
) -> SimpleNamespace:
    """Drop-in subprocess.run replacement for skill scripts."""
    if isinstance(cmd, str):
        argv = shlex.split(cmd)
    else:
        argv = list(cmd)
    stdout_s, stderr_s, rc = parse_and_run(argv, timeout=timeout)
    if check and rc != 0:
        raise subprocess.CalledProcessError(rc, cmd, output=stdout_s, stderr=stderr_s)
    runtime = get_runtime()
    binary = Path(argv[0]).name.lower()
    if capture_output and not text and (binary == "icat" or binary in SCRATCH_ANALYSIS_BINARIES):
        last = runtime.last_tool_result or {}
        extracted = last.get("extracted_file") or last.get("scratch_file")
        if extracted and Path(str(extracted)).is_file():
            out = Path(str(extracted)).read_bytes()
        else:
            out = _read_tool_stdout_bytes(last)
        err: str | bytes = stderr_s.encode("utf-8", errors="replace")
    elif text:
        out = stdout_s
        err = stderr_s
    else:
        out = stdout_s.encode("utf-8", errors="replace")
        err = stderr_s.encode("utf-8", errors="replace")
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


class _PatchedSubprocessModule:
    """Minimal subprocess facade for ported skill scripts."""

    run = staticmethod(run_subprocess)
    CalledProcessError = subprocess.CalledProcessError
    DEVNULL = subprocess.DEVNULL
    PIPE = subprocess.PIPE


patched_subprocess = _PatchedSubprocessModule()
