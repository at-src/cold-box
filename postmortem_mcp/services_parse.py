"""Windows service enumeration from a SYSTEM registry hive.

Parses ``ControlSet*\\Services`` ImagePath values for ghost-service triage (R11).
Pure in-Python via ``regipy`` — works on a hive carved from a raw disk image.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from postmortem_mcp.artifact_parse import normalize_service_binary
from regipy.registry import RegistryHive


def _control_sets(hive: RegistryHive) -> list[str]:
    try:
        sel = hive.get_key("\\Select")
        for val in sel.iter_values():
            if val.name == "Current":
                return [f"\\ControlSet{int(val.value):03d}"]
    except Exception:
        pass
    return [f"\\ControlSet{n:03d}" for n in (1, 2, 3)]


def _service_values(node: Any) -> dict[str, Any]:
    try:
        if not getattr(node, "values_count", 0):
            return {}
        return {v.name: v.value for v in node.iter_values()}
    except Exception:
        return {}


def parse_services_hive(hive_path: Path, *, max_records: int = 2000) -> dict[str, Any]:
    """Return Windows services recorded in a SYSTEM hive (name, ImagePath, start type)."""
    hive = RegistryHive(str(hive_path))
    records: list[dict[str, Any]] = []
    seen: set[str] = set()

    for cs in _control_sets(hive):
        key_path = f"{cs}\\Services"
        try:
            services = hive.get_key(key_path)
        except Exception:
            continue
        for svc in services.iter_subkeys():
            name = svc.name or "?"
            if name in seen:
                continue
            vals = _service_values(svc)
            binary = vals.get("ImagePath") or vals.get("Imagepath") or ""
            if not binary:
                continue
            binary_text = str(binary).strip()
            seen.add(name)
            records.append(
                {
                    "name": name,
                    "binary": binary_text,
                    "binary_basename": normalize_service_binary(binary_text),
                    "state": vals.get("Start"),
                    "display_name": vals.get("DisplayName"),
                    "service_type": vals.get("Type"),
                    "control_set": cs.strip("\\"),
                    "source_key": f"{key_path}\\{name}",
                }
            )
            if len(records) >= max_records:
                break
        if records:
            break

    return {
        "source": str(hive_path),
        "parser": "regipy-services",
        "record_count": len(records),
        "returned_count": len(records),
        "records": records,
    }
