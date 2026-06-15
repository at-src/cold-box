#!/usr/bin/env python3
"""Inject harness analyze_image entry points into skill agent.py scripts."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LIBRARY = REPO / "skills" / "library"
MARKER = "# cold-box harness entry"
PARSE_PATCH = (
    "    from cold_box_room.skills.script_helpers import patch_args_from_harness\n"
    "    patch_args_from_harness(args)\n"
)


def _inject_parse_patch(src: str) -> str:
    if "patch_args_from_harness" in src:
        return src
    pattern = re.compile(r"^(\s*)args\s*=\s*parser\.parse_args\(\)\s*$", re.MULTILINE)
    matches = list(pattern.finditer(src))
    if not matches:
        return src
    # Patch only the last parse_args() in the file (usually main()'s).
    match = matches[-1]
    indent = match.group(1)
    insert = f"{match.group(0)}\n{PARSE_PATCH.rstrip()}\n"
    return src[: match.start()] + insert + src[match.end() :]


def _analyze_block(slug: str, has_main: bool) -> str:
    main_ref = "main_fn=main" if has_main else "main_fn=None"
    return f"""

{MARKER}
def analyze_image(image_path, case_dir):
    from cold_box_room.skills.script_helpers import run_default_analyze_image

    return run_default_analyze_image(
        image_path,
        case_dir,
        skill_slug={slug!r},
        {main_ref},
    )
"""


def fix_script(path: Path) -> str:
    slug = path.parts[-3]
    src = path.read_text(encoding="utf-8")
    if MARKER in src or "def analyze_image" in src:
        return "skip"

    src = src.replace("required=True", "required=False")
    src = _inject_parse_patch(src)
    has_main = "def main(" in src

    main_match = re.search(r"\nif __name__\s*==", src)
    if main_match:
        src = src[: main_match.start()] + _analyze_block(slug, has_main) + src[main_match.start() :]
    else:
        src = src.rstrip() + _analyze_block(slug, has_main) + "\n"

    path.write_text(src, encoding="utf-8")
    return "fixed"


def main() -> int:
    counts = {"fixed": 0, "skip": 0}
    for script in sorted(LIBRARY.glob("*/scripts/agent.py")):
        status = fix_script(script)
        counts[status] = counts.get(status, 0) + 1
    print(counts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
