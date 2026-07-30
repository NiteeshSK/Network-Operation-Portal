"""
switch_manager.py — Real Netmiko SSH wrapper. No mocks.
Holds the whitelist of permitted commands (read-only safety).

Compatibility note:
    Paramiko 3.x (which Netmiko uses) dropped legacy SSH algorithms by
    default — most importantly `ssh-rsa` (SHA-1) as a host-key algorithm,
    and the SHA-1 Diffie-Hellman KEX variants. Many older Comware /
    H3C / HP switches still only offer those, so out of the box you get:

        paramiko.ssh_exception.IncompatiblePeer:
            Incompatible ssh peer (no acceptable host key)

    The block below re-enables them globally for this process so we can
    talk to legacy switches. This is the only practical fix without
    upgrading the switch firmware.
"""
from typing import Tuple, Optional

# ─── Re-enable legacy SSH algorithms for old Comware/H3C/HP gear ────
# Must happen BEFORE netmiko imports paramiko transports internally.
import logging as _logging
# Expected SSH failures (probing an iLO that only speaks Redfish, unreachable
# gear) make paramiko dump a full traceback at ERROR level. We handle those
# failures ourselves, so keep only real catastrophes in the logs.
_logging.getLogger("paramiko").setLevel(_logging.CRITICAL)
_logging.getLogger("paramiko.transport").setLevel(_logging.CRITICAL)

import paramiko.transport as _pt
from paramiko import RSAKey as _RSAKey

# 1. Server host-key algorithms — add ssh-rsa (SHA-1) back to the
#    list paramiko offers during KEX negotiation.
if "ssh-rsa" not in _pt.Transport._preferred_keys:
    _pt.Transport._preferred_keys = (
        _pt.Transport._preferred_keys + ("ssh-rsa",)
    )

# 2. Host-key parser dispatch — paramiko 3.x also removed ssh-rsa from
#    the dict that maps an algorithm name to its PKey class. Without
#    this, KEX succeeds but parsing the server's key fails with
#    `KeyError: 'ssh-rsa'`. Register it back.
if hasattr(_pt.Transport, "_key_info"):
    if "ssh-rsa" not in _pt.Transport._key_info:
        _pt.Transport._key_info["ssh-rsa"] = _RSAKey

# 3. Key exchange algorithms — add legacy DH-SHA1 variants back.
_LEGACY_KEX = (
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group-exchange-sha1",
)
_pt.Transport._preferred_kex = tuple(
    list(_pt.Transport._preferred_kex)
    + [k for k in _LEGACY_KEX if k not in _pt.Transport._preferred_kex]
)
# ─────────────────────────────────────────────────────────────────────

from netmiko import ConnectHandler  # noqa: E402  (must come after the patch)


# HP Comware / Huawei VRP "display" syntax
ALLOWED_COMMANDS_HP_COMWARE = {
    "version":    "display version",
    "interfaces": "display interface brief",
    "vlans":      "display vlan brief",
    "ip_int":     "display ip interface brief",
    "config":     "display current-configuration",
    "saved":      "display saved-configuration",
    "mac":        "display mac-address",
    "routes":     "display ip routing-table",
    "cpu":        "display cpu-usage",
    "device":     "display device",
    "ssh_status": "display ssh server status",
}

# ArubaOS-CX (AOS-CX) "show" syntax
ALLOWED_COMMANDS_ARUBA_AOSCX = {
    "version":    "show version",
    "interfaces": "show interface brief",
    "vlans":      "show vlan",
    "ip_int":     "show interface vlan",
    "config":     "show running-config interface",
    "saved":      "show running-config",
    "mac":        "show mac-address-table",
    "routes":     "show ip route",
    "cpu":        "show system resource-utilization",
    "device":     "show system",
    "ssh_status": "show ssh server",
    "stats":      "show interface statistics",
}

# ArubaOS-Switch (legacy ProVision, e.g. 2530/2930/5400) "show" syntax
ALLOWED_COMMANDS_ARUBA_PROVISION = {
    "version":    "show version",
    "interfaces": "show interfaces brief",
    "vlans":      "show vlan",
    "ip_int":     "show ip",
    "config":     "show running-config",
    "saved":      "show config",
    "mac":        "show mac-address",
    "routes":     "show ip route",
    "cpu":        "show cpu",
    "device":     "show system information",
    "ssh_status": "show ip ssh",
}

# Map device_type -> command set
COMMAND_SETS = {
    "hp_comware":        ALLOWED_COMMANDS_HP_COMWARE,
    "huawei":            ALLOWED_COMMANDS_HP_COMWARE,
    "huawei_vrp":        ALLOWED_COMMANDS_HP_COMWARE,
    "aruba_os":          ALLOWED_COMMANDS_ARUBA_AOSCX,
    "aruba_osswitch":    ALLOWED_COMMANDS_ARUBA_AOSCX,
    "aruba_aoscx":       ALLOWED_COMMANDS_ARUBA_AOSCX,
    "aruba_procurve":    ALLOWED_COMMANDS_ARUBA_PROVISION,
}

ALLOWED_COMMANDS = ALLOWED_COMMANDS_HP_COMWARE


def get_commands(device_type: str) -> dict:
    """Return the allowed command map for a given switch device_type,
    falling back to HP Comware if the type is unrecognized."""
    return COMMAND_SETS.get(device_type, ALLOWED_COMMANDS_HP_COMWARE)


# Netmiko device_type values these map to (for ConnectHandler).
# Note: netmiko 4.x does NOT include "aruba_aoscx" as a platform.
# ArubaOS-CX uses a Cisco-IOS-like CLI closely enough that "cisco_ios"
# (generic prompt detection) works for "show" commands.
NETMIKO_DEVICE_TYPE = {
    "hp_comware":     "hp_comware",
    "huawei":         "huawei",
    "huawei_vrp":     "huawei_vrpv8",
    "aruba_os":       "aruba_os",
    "aruba_osswitch": "aruba_osswitch",
    "aruba_aoscx":    "cisco_ios",
    "aruba_procurve": "aruba_procurve",
}


def _device_dict(switch, credentials_override: dict | None = None) -> dict:
    """Build the netmiko connection dict for a switch.

    If `credentials_override` is provided ({'username': ..., 'password': ...}),
    those credentials are used instead of the ones stored on the Switch row.
    This is what an authenticated admin session uses. The stored per-switch
    user/pass are only ever used as a fallback (e.g. the background
    scheduler running unattended).
    """
    if credentials_override:
        username = credentials_override["username"]
        password = credentials_override["password"]
    else:
        username = switch.username
        password = switch.password

    return {
        "device_type":   NETMIKO_DEVICE_TYPE.get(switch.device_type, switch.device_type),
        "host":          switch.host,
        "port":          switch.port,
        "username":      username,
        "password":      password,
        "use_keys":      False,
        "allow_agent":   False,
        "conn_timeout":  30,
        "auth_timeout":  30,
        "banner_timeout": 30,
        "disabled_algorithms": {
            "pubkeys": ["rsa-sha2-512", "rsa-sha2-256"],
        },
    }


def _is_auth_error(err: str) -> bool:
    """True when the failure is credential-related rather than network."""
    e = (err or "").lower()
    return ("authentication" in e or "auth failed" in e
            or "permission denied" in e or "bad authentication" in e)


def run_command(
    switch,
    command: str,
    credentials_override: dict | None = None,
    read_timeout: int = 30,
) -> Tuple[Optional[str], Optional[str]]:
    """Open SSH, send one command, close. Returns (output, error).

    CREDENTIAL FALLBACK
    -------------------
    Login only proves the operator's credentials work on *one* in-scope
    switch. A fleet often has per-device credentials, so reusing the session
    credentials everywhere makes calls to other switches fail with
    "Authentication to device failed".

    So we try, in order:
      1. the session credentials (credentials_override), if given
      2. the credentials stored on this switch row (what the background
         scheduler already uses successfully)

    Only if BOTH fail do we return an error, and the message names which
    identities were attempted so the cause is obvious.

    read_timeout is bumped automatically for full-config pulls, which can be
    very large on core switches and otherwise hit the default 30s ceiling.
    """
    lc = command.lower()
    if ("current-configuration" in lc or "running-config" in lc
            or "saved-configuration" in lc):
        read_timeout = max(read_timeout, 120)

    # Build the ordered list of credential sets to try.
    attempts: list[tuple[str, dict | None]] = []
    if credentials_override:
        attempts.append(("session user '%s'" % credentials_override.get("username"),
                         credentials_override))
    if switch.username and (
        not credentials_override
        or switch.username != credentials_override.get("username")
        or switch.password != credentials_override.get("password")
    ):
        attempts.append(("stored switch user '%s'" % switch.username, None))
    if not attempts:
        attempts.append(("stored switch user '%s'" % switch.username, None))

    auth_failures: list[str] = []

    for label, creds in attempts:
        try:
            conn = ConnectHandler(**_device_dict(switch, creds))
        except Exception as e:
            msg = str(e)
            if _is_auth_error(msg) and len(attempts) > 1:
                auth_failures.append(label)
                continue                      # try the next credential set
            if _is_auth_error(msg):
                auth_failures.append(label)
                break
            return None, msg                  # network/timeout — don't retry

        try:
            # Disable the interactive pager so '--More--' never stalls the read.
            try:
                if switch.device_type in ("hp_comware", "huawei", "huawei_vrp"):
                    conn.send_command_timing("screen-length disable")
                elif switch.device_type and switch.device_type.startswith("aruba"):
                    conn.send_command_timing("no page")
            except Exception:
                pass  # non-fatal — Netmiko strips most pager prompts itself
            output = conn.send_command(command, read_timeout=read_timeout)
            return output, None
        except Exception as e:
            return None, str(e)
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass

    tried = " and ".join(auth_failures) if auth_failures else "the configured user"
    return None, (
        f"Authentication to {switch.name} ({switch.host}:{switch.port}) failed "
        f"using {tried}. This switch likely has different credentials from the "
        f"one you logged in with. Fix: open the switch and update its stored "
        f"username/password, or log in with credentials valid on this device."
    )


def test_reachable(
    switch,
    credentials_override: dict | None = None,
) -> Tuple[bool, Optional[str]]:
    cmd = get_commands(switch.device_type)["version"]
    output, err = run_command(switch, cmd, credentials_override)
    return (err is None), err