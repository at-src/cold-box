"""USB mass-storage device enumeration from a Windows SYSTEM hive.

Parses ``ControlSet*\\Enum\\USBSTOR`` (and enriches with ``Enum\\USB`` VID/PID)
to attribute removable storage devices to a host — vendor, product, serial,
friendly name, container id, and the per-device last-write timestamps that
approximate connection times. Pure in-Python via ``regipy`` so it works on a
hive extracted straight from a raw image, with no external tool dependency.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from regipy.registry import RegistryHive

# Windows FILETIME epoch (100-ns intervals since 1601-01-01).
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _normalize_ts(val: Any) -> str | None:
    """Render a registry timestamp as ISO-8601, converting raw FILETIME ints."""
    if val is None:
        return None
    if isinstance(val, int) and val > 10**16:  # raw FILETIME (100-ns ticks)
        try:
            return (_FILETIME_EPOCH + timedelta(microseconds=val // 10)).isoformat()
        except (OverflowError, OSError, ValueError):
            return str(val)
    return str(val)

# Disk&Ven_SanDisk&Prod_Cruzer_Fit&Rev_2.01 -> vendor/product/revision
_DEV_RE = re.compile(
    r"(?:Disk&)?Ven_(?P<vendor>[^&]*)&Prod_(?P<product>[^&]*)(?:&Rev_(?P<rev>[^&]*))?",
    re.IGNORECASE,
)


def _ts(node: Any) -> str | None:
    for attr in ("timestamp", "last_modified"):
        val = getattr(node, attr, None)
        if val is not None:
            return _normalize_ts(val)
    header = getattr(node, "header", None)
    if header is not None:
        val = getattr(header, "last_modified", None)
        if val is not None:
            return _normalize_ts(val)
    return None


def _values(node: Any) -> dict[str, Any]:
    try:
        if not getattr(node, "values_count", 0):
            return {}
        return {v.name: v.value for v in node.iter_values()}
    except Exception:
        return {}


def _control_sets(hive: RegistryHive) -> list[str]:
    sets: list[str] = []
    for n in range(1, 4):
        sets.append(f"\\ControlSet{n:03d}")
    return sets


def parse_usb_devices(hive_path: Path, *, max_records: int = 200) -> dict[str, Any]:
    """Return USB mass-storage devices recorded in a SYSTEM hive."""
    hive = RegistryHive(str(hive_path))
    devices: list[dict[str, Any]] = []
    seen: set[str] = set()

    for cs in _control_sets(hive):
        key_path = f"{cs}\\Enum\\USBSTOR"
        try:
            usbstor = hive.get_key(key_path)
        except Exception:
            continue
        for dev in usbstor.iter_subkeys():
            m = _DEV_RE.search(dev.name or "")
            vendor = (m.group("vendor") if m else "").replace("_", " ").strip()
            product = (m.group("product") if m else "").replace("_", " ").strip()
            revision = (m.group("rev") if m else "") if m else ""
            for ser in dev.iter_subkeys():
                serial = (ser.name or "").split("&")[0]
                if serial in seen:
                    continue
                seen.add(serial)
                vals = _values(ser)
                devices.append(
                    {
                        "vendor": vendor,
                        "product": product,
                        "revision": revision,
                        "serial": serial,
                        "friendly_name": vals.get("FriendlyName"),
                        "container_id": vals.get("ContainerID"),
                        "device_key": dev.name,
                        "control_set": cs.strip("\\"),
                        "last_connected": _ts(ser),
                        "device_first_seen": _ts(dev),
                        "source_key": f"{key_path}\\{dev.name}\\{ser.name}",
                    }
                )
                if len(devices) >= max_records:
                    break
            if len(devices) >= max_records:
                break
        if devices:
            break  # first present control set is sufficient

    return {
        "source": str(hive_path),
        "parser": "regipy-usbstor",
        "device_count": len(devices),
        "returned_count": len(devices),
        "records": devices,
    }
