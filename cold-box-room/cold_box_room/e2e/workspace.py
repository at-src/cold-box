"""E2E workspace helpers — tear down sealed/read-only trees safely."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path


def chmod_writable_tree(root: Path) -> None:
    """Undo R1 seal chmod so shutil.rmtree can remove the tree."""
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        base = Path(dirpath)
        for name in filenames + dirnames:
            path = base / name
            try:
                mode = path.lstat().st_mode
                path.chmod(
                    mode
                    | stat.S_IWUSR
                    | stat.S_IWGRP
                    | stat.S_IWOTH
                    | stat.S_IXUSR
                )
            except OSError:
                pass
        try:
            mode = base.stat().st_mode
            base.chmod(
                mode
                | stat.S_IWUSR
                | stat.S_IWGRP
                | stat.S_IWOTH
                | stat.S_IXUSR
            )
        except OSError:
            pass


def force_remove_tree(root: Path) -> None:
    if not root.exists():
        return
    chmod_writable_tree(root)
    shutil.rmtree(root)
