"""Read-only generic registry hive value extraction (pure Python).

The artifact-centric registry tools (run keys, services, USB, ShellBags) cover
persistence and execution, but answering content-centric host-attribution
questions ("who registered this box?", "what NICs were installed?", "when was
it last shut down?") requires reading arbitrary hive keys. This module provides
that via the read-only ``python-registry`` parser — the same library DART uses
— so cold-box can extract these values directly from hives it pulls out of a
raw disk image.

Nothing here ever writes to a hive; ``python-registry`` opens hives read-only.
"""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Windows FILETIME epoch (1601-01-01) -> Unix epoch offset.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_iso(raw: Any) -> str | None:
    """Decode an 8-byte little-endian FILETIME (or int) to ISO-8601 UTC."""
    try:
        if isinstance(raw, (bytes, bytearray)) and len(raw) >= 8:
            (intervals,) = struct.unpack("<Q", bytes(raw[:8]))
        elif isinstance(raw, int):
            intervals = raw
        else:
            return None
        if intervals == 0:
            return None
        dt = _FILETIME_EPOCH + timedelta(microseconds=intervals / 10)
        return dt.isoformat()
    except (struct.error, OverflowError, ValueError):
        return None


def _open(hive_path: Path):
    from Registry import Registry  # lazy import; optional dependency

    return Registry.Registry(str(hive_path))


def query_value(hive_path: Path, key_path: str, value_name: str | None = None) -> dict[str, Any]:
    """Return a single value (or all values) under ``key_path`` in a hive."""
    try:
        reg = _open(hive_path)
    except Exception as exc:  # noqa: BLE001 - missing/corrupt hive
        return {"key_path": key_path, "found": False, "error": str(exc), "values": []}
    try:
        key = reg.open(key_path)
    except Exception as exc:  # noqa: BLE001 - python-registry raises broad types
        return {"key_path": key_path, "found": False, "error": str(exc), "values": []}

    values = []
    for val in key.values():
        if value_name is not None and val.name().lower() != value_name.lower():
            continue
        try:
            raw = val.value()
        except Exception:  # noqa: BLE001
            raw = None
        rendered = raw
        if isinstance(raw, (bytes, bytearray)):
            rendered = f"<{len(raw)} bytes>"
        values.append({"name": val.name(), "value": rendered})
    return {"key_path": key_path, "found": bool(values), "values": values}


def sam_accounts(sam_path: Path) -> dict[str, Any]:
    """Enumerate local user accounts from a SAM hive (name, RID, login count, last login).

    Login count and last-login time are decoded from each user's binary ``F``
    record (WORD login count at offset 0x42; FILETIME last-login at offset 0x08).
    """
    accounts: list[dict[str, Any]] = []
    if not sam_path or not sam_path.is_file():
        return {"found": False, "accounts": []}
    try:
        sam = _open(sam_path)
    except Exception as exc:  # noqa: BLE001
        return {"found": False, "error": str(exc), "accounts": []}

    rid_by_name: dict[str, int] = {}
    try:
        names = sam.open("SAM\\Domains\\Account\\Users\\Names")
        for sub in names.subkeys():
            try:
                # The default value's "type" field carries the RID for the name key.
                rid_by_name[sub.name()] = sub.value("(default)").value_type()
            except Exception:  # noqa: BLE001
                rid_by_name[sub.name()] = 0
    except Exception:  # noqa: BLE001
        pass

    try:
        users = sam.open("SAM\\Domains\\Account\\Users")
        for sub in users.subkeys():
            name = sub.name()
            if name == "Names":
                continue
            login_count = None
            last_login = None
            try:
                f_val = sub.value("F").value()
                if isinstance(f_val, (bytes, bytearray)) and len(f_val) >= 0x44:
                    last_login = _filetime_to_iso(f_val[8:16])
                    (login_count,) = struct.unpack("<H", bytes(f_val[0x42:0x44]))
            except Exception:  # noqa: BLE001
                pass
            try:
                rid = int(name, 16)
            except ValueError:
                rid = None
            accounts.append(
                {
                    "rid": rid,
                    "login_count": login_count,
                    "last_login_utc": last_login,
                }
            )
    except Exception as exc:  # noqa: BLE001
        return {"found": bool(rid_by_name), "names": list(rid_by_name), "error": str(exc), "accounts": accounts}

    # Attach friendly names by RID.
    for acct in accounts:
        for nm, rid in rid_by_name.items():
            if rid == acct.get("rid"):
                acct["name"] = nm
                break
    named = [a for a in accounts if a.get("name")]
    primary = None
    real = [a for a in named if a.get("login_count")]
    if real:
        primary = max(real, key=lambda a: a.get("login_count") or 0)
    return {
        "found": bool(named),
        "account_names": list(rid_by_name),
        "accounts": named or accounts,
        "primary_account": primary.get("name") if primary else None,
        "primary_login_count": primary.get("login_count") if primary else None,
    }


def _current_control_set(reg) -> str:
    try:
        sel = reg.open("Select")
        current = next(v.value() for v in sel.values() if v.name() == "Current")
        return f"ControlSet{int(current):03d}"
    except Exception:  # noqa: BLE001
        return "ControlSet001"


def system_profile(
    *,
    software: Path | None = None,
    system: Path | None = None,
    sam: Path | None = None,
) -> dict[str, Any]:
    """Extract a host-attribution / system-state profile from SOFTWARE + SYSTEM (+ SAM) hives.

    Returns a flat dict of well-known forensic facts plus a ``facts`` list of
    (label, value) pairs suitable for surfacing as an observation/finding.
    """
    profile: dict[str, Any] = {}
    facts: list[dict[str, str]] = []

    if software and software.is_file():
        try:
            sw = _open(software)
            cv = sw.open("Microsoft\\Windows NT\\CurrentVersion")
            wanted = {
                "RegisteredOwner": "registered_owner",
                "RegisteredOrganization": "registered_organization",
                "ProductName": "product_name",
                "CSDVersion": "service_pack",
                "InstallDate": "install_date",
            }
            for val in cv.values():
                if val.name() in wanted:
                    raw = val.value()
                    if val.name() == "InstallDate" and isinstance(raw, int):
                        raw = datetime.fromtimestamp(raw, tz=timezone.utc).isoformat()
                    profile[wanted[val.name()]] = raw
            nics: list[str] = []
            try:
                nc = sw.open("Microsoft\\Windows NT\\CurrentVersion\\NetworkCards")
                for sub in nc.subkeys():
                    for val in sub.values():
                        if val.name() == "Description":
                            nics.append(str(val.value()))
            except Exception:  # noqa: BLE001
                pass
            if nics:
                profile["network_cards"] = nics
        except Exception as exc:  # noqa: BLE001
            profile["software_error"] = str(exc)

    if system and system.is_file():
        try:
            sy = _open(system)
            cs = _current_control_set(sy)
            try:
                w = sy.open(f"{cs}\\Control\\Windows")
                for val in w.values():
                    if val.name() == "ShutdownTime":
                        iso = _filetime_to_iso(val.value())
                        if iso:
                            profile["last_shutdown_utc"] = iso
            except Exception:  # noqa: BLE001
                pass
            try:
                cn = sy.open(f"{cs}\\Control\\ComputerName\\ComputerName")
                for val in cn.values():
                    if val.name() == "ComputerName":
                        profile["computer_name"] = str(val.value())
            except Exception:  # noqa: BLE001
                pass
        except Exception as exc:  # noqa: BLE001
            profile["system_error"] = str(exc)

    if sam and sam.is_file():
        sam_info = sam_accounts(sam)
        if sam_info.get("found"):
            profile["local_accounts"] = sam_info.get("account_names")
            profile["primary_account"] = sam_info.get("primary_account")
            profile["primary_login_count"] = sam_info.get("primary_login_count")

    label_map = [
        ("registered_owner", "Registered owner"),
        ("registered_organization", "Registered organization"),
        ("product_name", "OS product"),
        ("install_date", "Install date"),
        ("computer_name", "Computer name"),
        ("network_cards", "Network cards"),
        ("last_shutdown_utc", "Last shutdown (UTC)"),
        ("primary_account", "Primary user account"),
    ]
    for key, label in label_map:
        if key in profile and profile[key]:
            value = profile[key]
            if isinstance(value, list):
                value = "; ".join(str(v) for v in value)
            facts.append({"label": label, "value": str(value)})

    profile["facts"] = facts
    return profile
