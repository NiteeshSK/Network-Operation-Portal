"""
winrm_executor.py — Execute switch CLI through the enterprise Windows jump
host, exactly the way MSS AD Studio talks to Active Directory.

WHY THIS EXISTS
---------------
On the enterprise network, configuration changes are made from the managed
remote-desktop host (the same one AD Studio uses): the portal is not allowed
to SSH to production switches directly. AD Studio's proven path is

    pywinrm  ->  WinRM (NTLM)  ->  PowerShell on the jump host

and this module reuses that pattern verbatim (winrm.Session + run_ps +
status_code checks, mirroring services/winrm_create.py). The only difference
is the PowerShell payload: instead of Active Directory cmdlets, we pipe the
switch CLI into an SSH client ON THE JUMP HOST (plink.exe by default — it
accepts a password non-interactively; OpenSSH `ssh` works if key auth is set
up there).

CONFIGURATION (environment, same style as AD Studio's targets)
    LACP_EXEC_MODE       direct | winrm      (default direct — unchanged path)
    WINRM_HOST           jump host IP/name   (required in winrm mode)
    WINRM_PORT           default 5985 (http) / 5986 (https)
    WINRM_USE_SSL        0|1
    WINRM_TRANSPORT      ntlm (default) | kerberos | basic
    WINRM_CERT_VALIDATION  ignore (default) | validate
    WINRM_USERNAME       jump-host account (DOMAIN\\user for NTLM)
    WINRM_PASSWORD       jump-host password
    WINRM_SSH_TOOL       plink (default) | ssh
    WINRM_SSH_EXTRA      extra args appended to the SSH command line

SESSION MODEL
-------------
WinRM's run_ps is one-shot — there is no persistent interactive channel like
netmiko's. So each stage of a deployment (checkpoint / configure / save /
verify / rollback) is sent as ONE self-contained batch: a PowerShell
here-string of CLI lines piped into a single SSH session on the jump host.
lacp_deploy wraps config-mode stages with the vendor's mode-enter command so
every batch stands alone; all commands in this feature are idempotent, so a
re-wrapped `configure terminal` costs nothing.
"""
from __future__ import annotations

import os
import re
from typing import Optional


class WinRMExecError(Exception):
    pass


def exec_mode() -> str:
    return (os.environ.get("LACP_EXEC_MODE") or "direct").strip().lower()


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _endpoint() -> str:
    host = (os.environ.get("WINRM_HOST") or "").strip()
    if not host:
        raise WinRMExecError(
            "LACP_EXEC_MODE=winrm but WINRM_HOST is not set. Configure the "
            "jump host exactly like AD Studio's target (host, username, "
            "password; NTLM over 5985 by default).")
    use_ssl = _bool_env("WINRM_USE_SSL", False)
    port = int(os.environ.get("WINRM_PORT") or (5986 if use_ssl else 5985))
    scheme = "https" if use_ssl else "http"
    return f"{scheme}://{host}:{port}/wsman"


def _session():
    """winrm.Session configured the same way as AD Studio's _session()."""
    import winrm            # pywinrm — imported lazily so direct mode never needs it
    kwargs = {
        "auth": (os.environ.get("WINRM_USERNAME") or "",
                 os.environ.get("WINRM_PASSWORD") or ""),
        "transport": (os.environ.get("WINRM_TRANSPORT") or "ntlm").strip(),
        "operation_timeout_sec": 120,
        "read_timeout_sec": 150,
    }
    if _bool_env("WINRM_USE_SSL", False):
        kwargs["server_cert_validation"] = (
            os.environ.get("WINRM_CERT_VALIDATION") or "ignore").strip()
    if not kwargs["auth"][0] or not kwargs["auth"][1]:
        raise WinRMExecError("WINRM_USERNAME / WINRM_PASSWORD are required.")
    return winrm.Session(_endpoint(), **kwargs)


def _decode(b) -> str:
    if b is None:
        return ""
    if isinstance(b, bytes):
        return b.decode("utf-8", errors="replace")
    return str(b)


def _ps_quote(value: str) -> str:
    """Single-quote escaping for PowerShell (AD Studio's _q)."""
    return str(value or "").replace("'", "''")


def test_connection() -> dict:
    """Prove the jump host answers and PowerShell runs — used by the status
    endpoint so the LACP page can show whether the enterprise path is up."""
    try:
        s = _session()
        r = s.run_ps("$ErrorActionPreference='Stop'; "
                     "Write-Output ('OK ' + $env:COMPUTERNAME)")
        out = _decode(r.std_out).strip()
        return {"ok": r.status_code == 0 and out.startswith("OK"),
                "detail": out or _decode(r.std_err)[:300]}
    except Exception as e:
        return {"ok": False, "detail": str(e)[:300]}


class WinRMSwitchSession:
    """Conn-like object lacp_deploy uses in winrm mode.

    Each run_batch() = one PowerShell invocation on the jump host that opens
    one SSH session to the switch, feeds it the whole command block on stdin,
    and returns the transcript.
    """
    is_winrm = True

    def __init__(self, sw_stub, creds: dict):
        self.host = sw_stub.host
        self.port = getattr(sw_stub, "port", 22) or 22
        self.device_type = sw_stub.device_type
        self.username = (creds or {}).get("username") or sw_stub.username
        self.password = (creds or {}).get("password") or sw_stub.password
        self.name = sw_stub.name
        self._session = _session()          # fail fast if jump host is down

    # netmiko-compat no-op so shared cleanup code works
    def disconnect(self):
        pass

    def _ssh_command(self) -> str:
        tool = (os.environ.get("WINRM_SSH_TOOL") or "plink").strip().lower()
        extra = os.environ.get("WINRM_SSH_EXTRA") or ""
        user, host, port = self.username, self.host, self.port
        if tool == "plink":
            # -batch: never prompt; -pw: password auth (why plink is default)
            return (f"plink.exe -ssh -batch -pw '{_ps_quote(self.password)}' "
                    f"-P {port} {extra} "
                    f"'{_ps_quote(user)}@{_ps_quote(host)}'")
        # OpenSSH: password auth can't be scripted — jump host needs key auth
        return (f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes "
                f"-p {port} {extra} '{_ps_quote(user)}@{_ps_quote(host)}'")

    def run_batch(self, commands: list[str]) -> tuple[str, Optional[str]]:
        """One SSH session on the jump host running the whole block.
        Returns (output, error) — error is set on transport failure or when
        the switch echoed a vendor error marker."""
        body = "\n".join(commands) + "\n"
        ps = "\n".join([
            "$ErrorActionPreference='Stop'",
            "$cmds = @'",
            body.rstrip("\n"),
            "'@",
            f"$cmds | {self._ssh_command()}",
            "if ($LASTEXITCODE -ne 0) { Write-Error ('ssh exited ' + $LASTEXITCODE) }",
        ])
        try:
            r = self._session.run_ps(ps)
        except Exception as e:
            return "", f"WinRM to jump host failed: {e}"

        out = _decode(r.std_out)
        errtxt = _decode(r.std_err).strip()
        if r.status_code != 0:
            return out, (errtxt or f"jump host returned status "
                                   f"{r.status_code}")[:300]

        # same vendor error markers the direct path scans for
        import config_apply as _ca
        m = _ca._ERR.search(out or "")
        if m:
            line = next((l for l in out.splitlines() if _ca._ERR.search(l)),
                        m.group(0))
            return out, line.strip()[:200]
        return out, None
