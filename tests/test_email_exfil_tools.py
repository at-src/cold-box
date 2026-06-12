"""PST parse and MFT user-document discovery."""

from __future__ import annotations

from pathlib import Path

from postmortem_mcp.pst_parse import parse_pst_file
from postmortem_mcp.user_docs import scan_mft_records


def test_parse_pst_finds_external_recipient_and_attachment(tmp_path: Path) -> None:
    blob = (
        "tuckgorge@gmail.com\x00"
        "jean@m57.biz\x00"
        "m57biz.xls\x00"
        "Please send the spreadsheet\x00"
    ).encode("utf-16-le")
    pst = tmp_path / "outlook.pst"
    pst.write_bytes(blob)
    parsed = parse_pst_file(pst)
    assert "tuckgorge@gmail.com" in parsed["external_recipients"]
    assert any("m57biz" in name.lower() for name in parsed["attachment_names"])


def test_scan_mft_records_finds_desktop_xls() -> None:
    records = [
        {
            "ParentPath": ".\\Documents and Settings\\Jean\\Desktop",
            "FileName": "m57biz.xls",
            "FileSize": 291840,
            "IsDirectory": False,
            "LastModified0x10": "2008-07-20T01:28:03.9531250+00:00",
        },
        {
            "ParentPath": ".\\Documents and Settings\\Jean\\Local Settings\\Application Data\\Microsoft\\Outlook",
            "FileName": "outlook.pst",
            "FileSize": 2326528,
            "IsDirectory": False,
        },
    ]
    payload = scan_mft_records(records)
    assert payload["document_count"] == 1
    assert payload["documents"][0]["filename"] == "m57biz.xls"
    assert payload["pst_count"] == 1
