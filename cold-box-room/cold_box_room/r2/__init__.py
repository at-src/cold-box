"""Room 2 — sandboxed evidence workspace."""

from cold_box_room.r2.paths import SandboxError, case_sandbox_dir, get_sandbox_root
from cold_box_room.r2.sandbox import (
    list_sandbox_files,
    load_sandbox_record,
    materialize_sandbox,
    r2_status,
)

__all__ = [
    "SandboxError",
    "case_sandbox_dir",
    "get_sandbox_root",
    "list_sandbox_files",
    "load_sandbox_record",
    "materialize_sandbox",
    "r2_status",
]
