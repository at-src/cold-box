"""Workspace teardown with sealed R1 trees."""

import stat
from pathlib import Path

from cold_box_room.e2e.workspace import chmod_writable_tree, force_remove_tree


def test_force_remove_sealed_tree(tmp_path):
    root = tmp_path / "sealed"
    case = root / "case"
    case.mkdir(parents=True)
    evidence = case / "disk.E01"
    evidence.write_bytes(b"data")
    for path in (evidence, case, root):
        path.chmod(path.stat().st_mode & ~stat.S_IWUSR)

    force_remove_tree(root)
    assert not root.exists()
