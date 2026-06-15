"""Executor truncation must not deadlock on full stdout pipes."""

import subprocess
import sys
import textwrap

from cold_box_room.r2.executor import _execute
from cold_box_room.r2.output_files import MAX_SCRATCH_FILE_BYTES


def test_execute_kills_spammer_at_scratch_cap(tmp_path):
    script = tmp_path / "spam.py"
    script.write_text(
        textwrap.dedent(
            """
            import sys
            chunk = "x" * 65536
            while True:
                sys.stdout.write(chunk)
                sys.stdout.flush()
            """
        ).strip(),
        encoding="utf-8",
    )
    out = tmp_path / "stdout.txt"
    start = __import__("time").monotonic()
    result = _execute(
        [sys.executable, str(script)],
        timeout=120,
        cwd=tmp_path,
        stdout_file=out,
    )
    elapsed = __import__("time").monotonic() - start
    assert result["truncated"] is True
    assert out.stat().st_size == MAX_SCRATCH_FILE_BYTES
    assert elapsed < 30
    assert result["exit_code"] != 0 or result["truncated"]
