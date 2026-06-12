"""Known-good allowlists for execution/ghost-binary precision gating.

The ghost-binary (R5) and unusual-execution (R16) rules previously fired on
legitimate Windows and Microsoft binaries (e.g. ``onedrive.exe``,
``backgroundtaskhost.exe``) because:

  * the on-disk "file index" the verifier sees is only the *extracted forensic
    artifacts* (prefetch, EVTX, hives, a capped $MFT) — never the full
    filesystem — so almost any executable looks "missing on disk"; and
  * any executable under a ``users\\`` path was treated as "unusual".

These allowlists let the rules treat signed/standard OS and first-party
Microsoft components as benign, so the agent stops declaring benign hosts
"compromised". They are deliberately conservative: an unknown binary in a
user-writable or temp location is still surfaced.
"""

from __future__ import annotations

# Common legitimate Windows OS + first-party Microsoft executables (basenames,
# lowercase). Used by both R5 (prefetch basename only) and R16.
KNOWN_GOOD_BINARIES: frozenset[str] = frozenset(
    {
        # Core OS / session
        "system",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "lsm.exe",
        "svchost.exe",
        "explorer.exe",
        "userinit.exe",
        "dwm.exe",
        "sihost.exe",
        "fontdrvhost.exe",
        "ctfmon.exe",
        "conhost.exe",
        "cmd.exe",
        # VMware guest tools (common on lab VMs — not attacker persistence)
        "vmtoolsd.exe",
        "vm3dservice.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "vgauthservice.exe",
        "audiodg.exe",
        "dllhost.exe",
        "taskhost.exe",
        "taskhostw.exe",
        "backgroundtaskhost.exe",
        "runtimebroker.exe",
        "dashost.exe",
        "appvclient.exe",
        "perfhost.exe",
        "wlidsvc.exe",
        "spoolsv.exe",
        "alg.exe",
        # Shell / UI surfaces
        "shellexperiencehost.exe",
        "startmenuexperiencehost.exe",
        "searchapp.exe",
        "searchui.exe",
        "applicationframehost.exe",
        "systemsettings.exe",
        "lockapp.exe",
        "useroobebroker.exe",
        "wlanext.exe",
        # Search / indexing
        "searchindexer.exe",
        "searchprotocolhost.exe",
        "searchfilterhost.exe",
        # Servicing / update / WMI
        "trustedinstaller.exe",
        "tiworker.exe",
        "wuauclt.exe",
        "usoclient.exe",
        "mousocc.exe",
        "wmiprvse.exe",
        "wmiapsrv.exe",
        "msiexec.exe",
        "msdtc.exe",
        # Defender / security
        "msmpeng.exe",
        "mpcmdrun.exe",
        "nissrv.exe",
        "securityhealthservice.exe",
        "securityhealthsystray.exe",
        "smartscreen.exe",
        "sgrmbroker.exe",
        # First-party Microsoft apps
        "onedrive.exe",
        "onedrivestandaloneupdater.exe",
        "filecoauth.exe",
        "filesyncconfig.exe",
        "teams.exe",
        "ms-teams.exe",
        "update.exe",
        "msedge.exe",
        "msedgewebview2.exe",
        "identity_helper.exe",
        "officeclicktorun.exe",
        "officec2rclient.exe",
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "onenote.exe",
        "msaccess.exe",
        # Visual C++ / .NET redistributables (Windows Installer burn cache)
        "vc_redist.x64.exe",
        "vc_redist.x86.exe",
        "vcredist_x64.exe",
        "vcredist_x86.exe",
        "ndp48-x86-x64-allos-enu.exe",
        "windowsdesktop-runtime.exe",
        "vcsetup.exe",
    }
)

# Path substrings (normalised: lowercase, backslashes -> forward slashes) that
# indicate a standard, trusted install location for a binary.
KNOWN_GOOD_PATH_HINTS: tuple[str, ...] = (
    "windows/system32",
    "windows/syswow64",
    "windows/winsxs",
    "windows/servicing",
    "windows/microsoft.net",
    "windows/systemapps",
    "windows/immersivecontrolpanel",
    "windows/explorer.exe",
    "program files/",
    "program files (x86)/",
    "program files/vmware",
    "program files (x86)/vmware",
    "programdata/microsoft",
    "programdata/package cache",
    "appdata/local/microsoft/onedrive",
    "appdata/local/microsoft/edge",
    "appdata/local/microsoft/teams",
    "appdata/roaming/microsoft/teams",
    "appdata/local/microsoft/onedrivestandalone",
)

# Path substrings that indicate a user-writable / staging location where an
# unknown executable is genuinely worth surfacing.
SUSPICIOUS_LOCATION_HINTS: tuple[str, ...] = (
    "/temp/",
    "/tmp/",
    "/downloads/",
    "appdata/local/temp",
    "appdata/roaming/temp",
    "/$recycle.bin/",
    "/recycler/",
    "/users/public/",
    "/perflogs/",
    "/windows/temp/",
)


def _norm_path(path: str) -> str:
    return path.strip().lower().replace("\\", "/")


def is_known_good_binary(basename: str) -> bool:
    return basename.strip().lower() in KNOWN_GOOD_BINARIES


# AV uninstall / installer prefetch basenames — R5 "ghost" is often partial-tree noise.
_BENIGN_UNINSTALL_EXACT: frozenset[str] = frozenset(
    {
        "setup.exe",
        "install.exe",
        "uninstall.exe",
        "uninst.exe",
        "vcredist_x64.exe",
        "vcredist_x86.exe",
        "vc_redist.x64.exe",
        "vc_redist.x86.exe",
    }
)
_BENIGN_VENDOR_PREFIXES: tuple[str, ...] = (
    "avg",
    "avast",
    "avp",
    "kaspersky",
    "mcafee",
    "norton",
    "symantec",
    "mbam",
    "mbsetup",
    "avgui",
    "avgemc",
)


def is_benign_uninstall_binary(basename: str) -> bool:
    """Prefetch-only ghost signal from removed AV/installers — not a compromise bar."""
    base = basename.strip().lower()
    if base in _BENIGN_UNINSTALL_EXACT:
        return True
    if base.endswith(".exe") and any(base.startswith(prefix) for prefix in _BENIGN_VENDOR_PREFIXES):
        return True
    return False


def is_known_good_path(path: str) -> bool:
    p = _norm_path(path)
    return any(hint in p for hint in KNOWN_GOOD_PATH_HINTS)


def is_suspicious_location(path: str) -> bool:
    p = _norm_path(path)
    return any(hint in p for hint in SUSPICIOUS_LOCATION_HINTS)


def is_user_writable_path(path: str) -> bool:
    """User-writable (non-system) location, excluding trusted app dirs."""
    p = _norm_path(path)
    if is_known_good_path(p):
        return False
    # NB: ProgramData is intentionally excluded — it is a standard installer /
    # app-data location (e.g. Package Cache redistributables), not a per-user
    # write target, and treating it as suspicious produced false positives.
    return (
        "/users/" in p
        or p.startswith("users/")
        or "appdata" in p
        or is_suspicious_location(p)
    )
