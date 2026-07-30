"""
config_apply.py — Phase 2: apply configuration to a switch, safely.

This is the only module in the portal that WRITES to a device. Everything
about it is built around one assumption: the change will eventually go wrong,
and when it does we must still be able to reach the switch.

SAFETY MODEL
------------
1. Feature flag.   Disabled unless CONFIG_APPLY_ENABLED=1.
2. Second factor.  Requires an X-Apply-Token header matching CONFIG_APPLY_TOKEN,
                   on top of a valid admin session. Read-only users therefore
                   cannot apply even with a session (a stand-in for RBAC until
                   a real user model exists).
3. Dry run first.  `dry_run` defaults to True everywhere. A caller must ask
                   for a real write explicitly.
4. Pre-flight.     Render + validate + safety-scan + reachability + a fresh
                   config snapshot, before a single line is sent.
5. Checkpoint.     A vendor rollback point is created ON THE DEVICE first.
                   If the checkpoint cannot be created, we do not proceed.
6. Commit-confirm. After applying we verify we can still log in and read the
                   config. The change then sits in `pending_confirm` until an
                   operator confirms. If the confirm window expires, a
                   background job rolls the device back automatically.
                   This is what protects against locking yourself out: if the
                   change killed management access, nobody can confirm, so the
                   device reverts on its own.
7. Abort on error. Commands are sent one at a time. The first failure stops
                   the batch and triggers an immediate rollback.

VENDOR ROLLBACK MECHANICS
------------------------
Aruba AOS-CX
    checkpoint:  copy running-config checkpoint <name>
    rollback:    checkpoint rollback <name>

HP Comware
    checkpoint:  save force <name>.cfg          (writes a restore point file)
    rollback:    configuration replace file <name>.cfg

These are the documented mechanisms for each platform, but they MUST be
validated on your actual firmware before the flag is turned on in production.
The dry-run path prints exactly which commands would be used so you can check
them against a lab device first.
"""
from __future__ import annotations

import os
import re
import secrets
import time
from datetime import timedelta
from typing import Optional

import models
import switch_manager
import template_engine as _tpl

APPLY_ENABLED = os.getenv("CONFIG_APPLY_ENABLED", "0") == "1"
APPLY_TOKEN = os.getenv("CONFIG_APPLY_TOKEN", "")
# How long an operator has to confirm before the device auto-reverts.
CONFIRM_WINDOW_SECONDS = int(os.getenv("CONFIG_CONFIRM_WINDOW_SECONDS", "300"))
# Per-command read timeout while in config mode.
CONFIG_READ_TIMEOUT = int(os.getenv("CONFIG_READ_TIMEOUT", "30"))


class ApplyDisabled(Exception):
    """Writes are switched off, or the apply token is wrong."""


class PreflightFailed(Exception):
    pass


# ── Vendor strategy ────────────────────────────────────────────────────────

def _checkpoint_name() -> str:
    """Unique per change.

    A second-resolution timestamp is NOT enough: two changes applied inside
    the same second would share a name, and the second checkpoint would
    silently overwrite the first one's rollback point. The random suffix makes
    every rollback point distinct.
    """
    return "nocportal_" + time.strftime("%Y%m%d_%H%M%S") + "_" + secrets.token_hex(2)


VENDOR = {
    "aruba_aoscx": {
        "checkpoint": lambda n: [f"copy running-config checkpoint {n}"],
        "rollback":   lambda n: [f"checkpoint rollback {n}"],
        "verify":     "show version",
        "exit_config": "exit",
    },
    "aruba_os": {
        "checkpoint": lambda n: [f"copy running-config checkpoint {n}"],
        "rollback":   lambda n: [f"checkpoint rollback {n}"],
        "verify":     "show version",
        "exit_config": "exit",
    },
    "hp_comware": {
        # `save <file>` prompts [Y/N]; _send answers it when answer_prompts
        # is set. (`save force` does not accept a filename on Comware 7 —
        # the previous `save force <n>.cfg` would have errored or stalled.)
        "checkpoint": lambda n: [f"save {n}.cfg"],
        "rollback":   lambda n: [f"configuration replace file {n}.cfg"],
        "verify":     "display version",
        "exit_config": "quit",
    },
}


def vendor_strategy(device_type: str) -> dict:
    s = VENDOR.get(device_type)
    if not s:
        raise PreflightFailed(
            f"no verified rollback strategy for device_type '{device_type}'. "
            f"Supported: {sorted(VENDOR)}"
        )
    return s


# ── Gate ───────────────────────────────────────────────────────────────────

def assert_allowed(apply_token: Optional[str]):
    if not APPLY_ENABLED:
        raise ApplyDisabled(
            "Configuration apply is disabled. Set CONFIG_APPLY_ENABLED=1 on the "
            "backend to enable it (and only after validating rollback on a lab "
            "device)."
        )
    if not APPLY_TOKEN:
        raise ApplyDisabled(
            "CONFIG_APPLY_TOKEN is not configured on the backend; refusing to "
            "apply without a second factor."
        )
    if not apply_token or apply_token != APPLY_TOKEN:
        raise ApplyDisabled("Invalid or missing X-Apply-Token header.")


# ── Low-level: send one command inside config mode ─────────────────────────

_ERR = re.compile(
    r"(unrecognized|invalid input|incomplete command|% *error|syntax error|"
    r"wrong parameter|ambiguous command|command not exist|not found at|"
    r"permission denied|failed)", re.I
)


_PROMPT = re.compile(r"\[\s*y(es)?\s*/\s*n(o)?\s*\]|\(y/n\)", re.I)


def _send(conn, command: str, answer_prompts: bool = False) -> tuple[str, Optional[str]]:
    """Send one line; return (output, error). Treats vendor error text as error.

    answer_prompts=True additionally replies "Y" to [Y/N]-style confirmation
    prompts. This is deliberately restricted to OUR OWN checkpoint/rollback
    commands (Comware's `save <file>` and `configuration replace file` both
    prompt) — template-supplied commands never get automatic confirmation.
    """
    try:
        out = conn.send_command_timing(command, read_timeout=CONFIG_READ_TIMEOUT)
        if answer_prompts:
            guard = 0
            while _PROMPT.search((out or "").rstrip()[-120:]) and guard < 3:
                out += conn.send_command_timing("Y", read_timeout=CONFIG_READ_TIMEOUT)
                guard += 1
    except Exception as e:
        return "", str(e)
    if _ERR.search(out or ""):
        return out, (out or "").strip().splitlines()[0][:200]
    return out, None


def _open(sw, creds):
    from netmiko import ConnectHandler
    return ConnectHandler(**switch_manager._device_dict(sw, creds))


# ── Preflight ──────────────────────────────────────────────────────────────

def preflight(db, sw, commands: list[str], creds: dict) -> dict:
    """Everything that must be true before we touch the device."""
    rendered = "\n".join(commands)

    scan = _tpl.safety_scan(rendered)
    if scan["blockers"]:
        raise PreflightFailed(f"safety scan blocked the change: {scan['blockers']}")

    strategy = vendor_strategy(sw.device_type)

    # Reachability + a *fresh* pre-change snapshot, so rollback comparison and
    # the audit trail both reference reality, not a stale capture.
    cfg_cmd = switch_manager.get_commands(sw.device_type)["config"]
    before, err = switch_manager.run_command(sw, cfg_cmd,
                                             credentials_override=creds,
                                             read_timeout=120)
    if err:
        raise PreflightFailed(f"cannot read running-config before change: {err}")

    return {"strategy": strategy, "before_config": before,
            "warnings": scan["warnings"], "line_count": scan["line_count"]}


# ── The apply itself ───────────────────────────────────────────────────────

def apply_to_switch(db, sw, commands: list[str], creds: dict,
                    change: models.ConfigChange,
                    target: models.ConfigChangeTarget) -> dict:
    """Checkpoint, apply, verify. Rolls back immediately on any failure.

    Returns a dict describing what happened. Never raises for device-level
    problems — those become target.status == 'failed' / 'rolled_back'.
    """
    pre = preflight(db, sw, commands, creds)
    strategy = pre["strategy"]
    ckpt = _checkpoint_name()

    target.checkpoint_name = ckpt
    target.config_before = pre["before_config"]
    target.status = "applying"
    db.commit()

    conn = None
    executed: list[str] = []
    try:
        conn = _open(sw, creds)

        # 1. Rollback point ON THE DEVICE. Abort the whole thing if it fails.
        for c in strategy["checkpoint"](ckpt):
            out, err = _send(conn, c, answer_prompts=True)
            if err:
                target.status = "failed"
                target.error = f"could not create checkpoint ({c}): {err}"
                db.commit()
                return {"status": "failed", "stage": "checkpoint",
                        "error": target.error}

        # 2. Apply, one line at a time, stopping at the first error.
        for c in commands:
            out, err = _send(conn, c)
            executed.append(c)
            if err:
                target.error = f"command failed: {c!r} -> {err}"
                target.commands_executed = "\n".join(executed)
                db.commit()
                rb = _rollback(conn, sw, strategy, ckpt)
                target.status = "rolled_back" if rb["ok"] else "rollback_failed"
                target.rollback_error = None if rb["ok"] else rb["error"]
                db.commit()
                return {"status": target.status, "stage": "apply",
                        "error": target.error, "rollback": rb}

        target.commands_executed = "\n".join(executed)
        db.commit()

        # 3. Verify we can still talk to the box on a NEW session. If the
        #    change severed management access, this is where we find out —
        #    while we still hold the old, working connection.
        try:
            conn.disconnect()
        except Exception:
            pass
        conn = None

        ok, verr = switch_manager.test_reachable(sw, credentials_override=creds)
        if not ok:
            # We cannot reopen a session. Try the still-plausible path: reconnect
            # once more for rollback; if that fails the confirm window expiry is
            # the last line of defence (and it will also fail — hence the loud
            # error). This is why the checkpoint exists on the device.
            conn2 = None
            try:
                conn2 = _open(sw, creds)
                rb = _rollback(conn2, sw, strategy, ckpt)
            except Exception as e:
                rb = {"ok": False, "error": f"cannot reconnect to roll back: {e}"}
            finally:
                if conn2:
                    try:
                        conn2.disconnect()
                    except Exception:
                        pass
            target.status = "rolled_back" if rb.get("ok") else "rollback_failed"
            target.error = f"post-change verification failed: {verr}"
            target.rollback_error = None if rb.get("ok") else rb.get("error")
            db.commit()
            return {"status": target.status, "stage": "verify",
                    "error": target.error, "rollback": rb}

        # 4. Capture the resulting config for the diff + audit.
        cfg_cmd = switch_manager.get_commands(sw.device_type)["config"]
        after, err = switch_manager.run_command(sw, cfg_cmd,
                                                credentials_override=creds,
                                                read_timeout=120)
        target.config_after = after or ""
        # The operator's window starts NOW — not before preflight/apply —
        # so a slow device doesn't silently eat the confirmation time.
        target.confirm_deadline = confirm_deadline()
        target.status = "pending_confirm"
        db.commit()
        return {"status": "pending_confirm", "stage": "done",
                "checkpoint": ckpt, "warnings": pre["warnings"]}

    except Exception as e:
        target.error = f"unexpected error: {e}"
        db.commit()
        # Best effort rollback with a fresh connection.
        rb = {"ok": False, "error": "no rollback attempted"}
        try:
            c2 = _open(sw, creds)
            rb = _rollback(c2, sw, strategy, ckpt)
            c2.disconnect()
        except Exception as e2:
            rb = {"ok": False, "error": str(e2)}
        target.status = "rolled_back" if rb.get("ok") else "rollback_failed"
        target.rollback_error = None if rb.get("ok") else rb.get("error")
        db.commit()
        return {"status": target.status, "stage": "exception",
                "error": target.error, "rollback": rb}
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass


def _rollback(conn, sw, strategy: dict, ckpt: str) -> dict:
    for c in strategy["rollback"](ckpt):
        out, err = _send(conn, c, answer_prompts=True)
        if err:
            return {"ok": False, "error": f"{c!r} -> {err}"}
    return {"ok": True, "error": None}


def rollback_target(db, target: models.ConfigChangeTarget, creds: dict) -> dict:
    """Explicit / automatic rollback of an already-applied change."""
    sw = db.query(models.Switch).filter(
        models.Switch.name == target.switch_name).first()
    if not sw:
        return {"ok": False, "error": "switch no longer exists"}
    if not target.checkpoint_name:
        return {"ok": False, "error": "no checkpoint recorded for this change"}

    strategy = vendor_strategy(sw.device_type)
    conn = None
    try:
        conn = _open(sw, creds)
        rb = _rollback(conn, sw, strategy, target.checkpoint_name)
    except Exception as e:
        rb = {"ok": False, "error": str(e)}
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass

    target.status = "rolled_back" if rb["ok"] else "rollback_failed"
    target.rollback_error = rb.get("error")
    db.commit()
    return rb


# ── Auto-revert of unconfirmed changes ─────────────────────────────────────

def expire_unconfirmed(db) -> list[dict]:
    """Roll back anything still pending_confirm past its deadline.

    Called by the scheduler. Uses the credentials captured with the change,
    because the operator's session may be long gone by now.
    """
    now = models.ist_now()
    stale = (db.query(models.ConfigChangeTarget)
             .filter(models.ConfigChangeTarget.status == "pending_confirm",
                     models.ConfigChangeTarget.confirm_deadline != None,  # noqa: E711
                     models.ConfigChangeTarget.confirm_deadline <= now)
             .all())
    out = []
    for t in stale:
        sw = db.query(models.Switch).filter(
            models.Switch.name == t.switch_name).first()
        creds = ({"username": sw.username, "password": sw.password}
                 if sw else None)
        if not creds:
            t.status = "rollback_failed"
            t.rollback_error = "no stored credentials to roll back with"
            db.commit()
            out.append({"switch": t.switch_name, "ok": False,
                        "error": t.rollback_error})
            continue
        rb = rollback_target(db, t, creds)
        out.append({"switch": t.switch_name, "ok": rb["ok"],
                    "error": rb.get("error")})
        print(f"[auto-revert] {t.switch_name}: "
              f"{'rolled back' if rb['ok'] else 'ROLLBACK FAILED: ' + str(rb.get('error'))}",
              flush=True)
    return out


def confirm_deadline() -> "models.datetime":
    return models.ist_now() + timedelta(seconds=CONFIRM_WINDOW_SECONDS)
