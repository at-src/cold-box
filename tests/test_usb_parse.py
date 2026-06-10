"""Hermetic tests for USB device enumeration (mocked regipy hive)."""

from __future__ import annotations

from pathlib import Path

import pytest

from postmortem_mcp import usb_parse


class _Val:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class _Key:
    def __init__(self, name, subkeys=None, values=None, timestamp=None):
        self.name = name
        self._subkeys = subkeys or []
        self._values = values or []
        self.timestamp = timestamp

    @property
    def values_count(self):
        return len(self._values)

    def iter_subkeys(self):
        return iter(self._subkeys)

    def iter_values(self):
        return iter(self._values)


class _FakeHive:
    def __init__(self, _path):
        serial1 = _Key(
            "4C530012450531101593&0",
            values=[
                _Val("FriendlyName", "SanDisk Cruzer Fit USB Device"),
                _Val("ContainerID", "{abc}"),
            ],
            timestamp=130716778800142227,  # raw FILETIME -> 2015
        )
        dev = _Key("Disk&Ven_SanDisk&Prod_Cruzer_Fit&Rev_2.01", subkeys=[serial1], timestamp="2015-03-24T00:00:00")
        self._usbstor = _Key("USBSTOR", subkeys=[dev])

    def get_key(self, path):
        if path.endswith("ControlSet001\\Enum\\USBSTOR"):
            return self._usbstor
        raise KeyError(path)


def test_parse_usb_devices(monkeypatch):
    monkeypatch.setattr(usb_parse, "RegistryHive", _FakeHive)
    out = usb_parse.parse_usb_devices(Path("SYSTEM"))
    assert out["parser"] == "regipy-usbstor"
    assert out["device_count"] == 1
    dev = out["records"][0]
    assert dev["vendor"] == "SanDisk"
    assert dev["product"] == "Cruzer Fit"
    assert dev["serial"] == "4C530012450531101593"
    assert dev["friendly_name"] == "SanDisk Cruzer Fit USB Device"
    assert "USBSTOR" in dev["source_key"]


def test_filetime_normalized():
    iso = usb_parse._normalize_ts(130716778800142227)
    assert iso is not None and iso.startswith("2015-")


def test_plain_timestamp_passthrough():
    assert usb_parse._normalize_ts("2015-03-24T00:00:00") == "2015-03-24T00:00:00"
    assert usb_parse._normalize_ts(None) is None


def test_dev_regex():
    m = usb_parse._DEV_RE.search("Disk&Ven_SanDisk&Prod_Cruzer_Fit&Rev_2.01")
    assert m.group("vendor") == "SanDisk"
    assert m.group("product") == "Cruzer_Fit"
