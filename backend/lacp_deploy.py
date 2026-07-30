"""
lacp_deploy.py — One-click LACP configuration with validation, live progress,
rollback and post-deployment verification.

WORKFLOW (mirrors what a careful engineer does by hand, automated):

    1. PREFLIGHT (read-only)   — one SSH session per switch:
         · every selected interface exists
         · none already belongs to another LAG
         · all run at the same speed (and match the selected speed)
         · none is administratively down
         · the LAG ID is not already in use
    2. DEPLOY (worker thread)  — per switch, stage by stage:
         connecting → creating LAG → adding members → saving → verifying
       Progress is written to the LacpDeployment row after every stage so
       the UI can poll and render it live.
    3. ON FAILURE              — execution stops immediately, everything
       already sent is rolled back (members detached, LAG deleted), the
       reason and the full command log are saved on the record.
    4. VERIFY                  — `show lacp interfaces` + `show lacp
       aggregates` (or the Comware equivalents) are run and parsed into
       LAG / members / operational & synchronization state.

Vendor support matches the write path: Aruba AOS-CX and HP Comware.
All SSH work reuses config_apply's session helpers (_open/_send), i.e. the
same Netmiko framework every other portal feature uses.
"""
from __future__ import annotations

import json
import re
import threading
import time
import traceback

import models
from database import SessionLocal
import config_apply as _ca


SPEED_CHOICES = {          # UI label -> Mb/s (None = don't enforce)
    "auto": None, "1G": 1000, "10G": 10000, "25G": 25000,
    "40G": 40000, "100G": 100000,
}

# Physical-interface shapes we allow as members (keeps VLAN/mgmt/LAG
# interfaces out of the picker and out of the config).
_PHYS_RE = re.compile(
    r"^(?:\d+/\d+/\d+|(?:GigabitEthernet|TenGigE|Ten-GigabitEthernet|"
    r"TwentyFiveGigE|FortyGigE|HundredGigE|XGE|GE|FGE|HGE)\S*)$", re.I)


def is_physical(iface: str) -> bool:
    return bool(_PHYS_RE.match((iface or "").strip()))


# ─────────────────────────────────────────────────────────────────────
# CLI generation
# ─────────────────────────────────────────────────────────────────────

def generate_cli(device_type: str, lag_id: int, mode: str,
                 members: list[str], description: str = "") -> dict:
    """Return the exact commands, sliced by stage so execution progress can
    say WHICH part it is on. `all` is the flat preview list."""
    d = (description or "").strip()

    if device_type == "aruba_aoscx":
        create = ["configure terminal",
                  f"interface lag {lag_id}",
                  f"lacp mode {mode}"]
        if d:
            create.append(f"description {d}")
        create += ["no shutdown", "exit"]
        member_cmds = []
        for m in members:
            member_cmds += [f"interface {m}", f"lag {lag_id}",
                            "no shutdown", "exit"]
        save = ["exit", "write memory"]

    elif device_type == "hp_comware":
        create = ["system-view",
                  f"interface Bridge-Aggregation {lag_id}",
                  # dynamic BEFORE members join: Comware refuses a mode
                  # change on a populated group
                  "link-aggregation mode dynamic"]
        if d:
            create.append(f"description {d}")
        create += ["quit"]
        member_cmds = []
        for m in members:
            member_cmds += [f"interface {m}",
                            f"port link-aggregation group {lag_id}", "quit"]
        save = ["quit", "save force"]

    else:
        raise ValueError(f"LACP automation supports aruba_aoscx and "
                         f"hp_comware; '{device_type}' is not supported")

    return {"create": create, "members": member_cmds, "save": save,
            "all": create + member_cmds + save}


def rollback_cli(device_type: str, lag_id: int, members: list[str]) -> list[str]:
    """Undo everything generate_cli() configures. Safe to run partially —
    detaching a member that never joined is a harmless error we tolerate."""
    if device_type == "aruba_aoscx":
        cmds = ["configure terminal"]
        for m in members:
            cmds += [f"interface {m}", f"no lag {lag_id}", "exit"]
        cmds += [f"no interface lag {lag_id}", "exit", "write memory"]
        return cmds
    if device_type == "hp_comware":
        cmds = ["system-view"]
        for m in members:
            cmds += [f"interface {m}", "undo port link-aggregation group", "quit"]
        cmds += [f"undo interface Bridge-Aggregation {lag_id}", "quit", "save force"]
        return cmds
    return []


# ─────────────────────────────────────────────────────────────────────
# Live-state parsing (tolerant: never crash on unexpected output;
# anything unparseable becomes "unknown" and is reported as such)
# ─────────────────────────────────────────────────────────────────────

def _parse_brief(device_type: str, output: str) -> dict:
    """interface -> {'exists': True, 'admin_down': bool|None,
                     'link_up': bool|None, 'speed_mbps': int|None}"""
    info = {}
    for line in (output or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        iface = parts[0].strip()
        if not is_physical(iface):
            continue
        low = line.lower()

        admin_down = None
        if device_type == "aruba_aoscx":
            # columns include Enabled yes/no; reason 'Administratively down'
            if re.search(r"\bno\b", low) and "down" in low:
                admin_down = True
            elif "administratively" in low:
                admin_down = True
            elif re.search(r"\byes\b", low):
                admin_down = False
        else:  # comware: state column ADM = admin down, Stby, UP, DOWN
            if re.search(r"\badm\b", low):
                admin_down = True
            elif re.search(r"\b(up|down|stby)\b", low):
                admin_down = False

        link_up = True if re.search(r"\bup\b", low) else \
                  (False if "down" in low or re.search(r"\badm\b", low) else None)

        speed = None
        m = re.search(r"\b(\d+(?:\.\d+)?)G\b", line, re.I)          # 10G, 1G(a)
        if not m:
            m = re.search(r"\bG\((\d+(?:\.\d+)?)\)", line)          # rare forms
        if m:
            speed = int(float(m.group(1)) * 1000)
        else:
            m = re.search(r"\b(1000|10000|25000|40000|100000)\b", line)
            if m:
                speed = int(m.group(1))

        info[iface] = {"exists": True, "admin_down": admin_down,
                       "link_up": link_up, "speed_mbps": speed}
    return info


def _parse_lag_membership(device_type: str, output: str) -> tuple[dict, set]:
    """Return (iface -> lag_label, {existing lag ids as int})."""
    membership, lag_ids = {}, set()
    if device_type == "aruba_aoscx":
        # `show lacp interfaces`: rows like  "1/1/1  lag10  ..."
        for line in (output or "").splitlines():
            m = re.match(r"\s*(\S+)\s+(lag\d+)\b", line, re.I)
            if m and is_physical(m.group(1)):
                membership[m.group(1)] = m.group(2).lower()
            for g in re.findall(r"\blag(\d+)\b", line, re.I):
                lag_ids.add(int(g))
    else:
        # `display link-aggregation verbose`: sections headed by
        # "Aggregate Interface: Bridge-Aggregation10", member rows follow
        current = None
        for line in (output or "").splitlines():
            m = re.search(r"Aggregat\w* Interface:\s*"
                          r"(?:Bridge-Aggregation|BAGG)\s*(\d+)", line, re.I)
            if m:
                current = int(m.group(1))
                lag_ids.add(current)
                continue
            if current is not None:
                pm = re.match(r"\s*([A-Za-z\-]+\d+(?:/\d+)+)\b", line)
                if pm and is_physical(pm.group(1)):
                    membership[pm.group(1)] = f"Bridge-Aggregation{current}"
    return membership, lag_ids


# ─────────────────────────────────────────────────────────────────────
# Preflight
# ─────────────────────────────────────────────────────────────────────

_SHOW = {
    "aruba_aoscx": {"brief": "show interface brief",
                    "lacp_if": "show lacp interfaces",
                    "lacp_agg": "show lacp aggregates"},
    "hp_comware":  {"brief": "display interface brief",
                    "lacp_if": "display link-aggregation verbose",
                    "lacp_agg": "display link-aggregation summary"},
}


def preflight_switch(sw, lag_id: int, members: list[str],
                     speed_key: str, creds: dict) -> dict:
    """All five validation rules against LIVE switch state. Read-only.

    Each check is pass / fail / unknown — unknown means the device output
    could not be parsed confidently; it blocks nothing but is surfaced so
    the operator decides.
    """
    checks = []

    def check(name, status, detail):
        checks.append({"name": name, "status": status, "detail": detail})

    if sw.device_type not in _SHOW:
        check("device support", "fail",
              f"{sw.device_type} is not supported for LACP automation")
        return {"switch": sw.name, "ok": False, "checks": checks}

    bad_shape = [m for m in members if not is_physical(m)]
    if bad_shape:
        check("interface names", "fail",
              f"not physical interfaces: {', '.join(bad_shape)}")
        return {"switch": sw.name, "ok": False, "checks": checks}

    cmds = _SHOW[sw.device_type]
    conn = None
    try:
        conn = _open_switch(sw, creds)
        brief_out, e1 = _send_one(conn, cmds["brief"])
        lacp_out,  e2 = _send_one(conn, cmds["lacp_if"])
        agg_out,   e3 = _send_one(conn, cmds["lacp_agg"])
    except Exception as e:
        check("connectivity", "fail", f"SSH failed: {e}")
        return {"switch": sw.name, "ok": False, "checks": checks}
    finally:
        try:
            if conn:
                conn.disconnect()
        except Exception:
            pass

    if e1:
        check("read interface state", "fail", e1)
        return {"switch": sw.name, "ok": False, "checks": checks}

    brief = _parse_brief(sw.device_type, brief_out)
    membership, lag_ids = _parse_lag_membership(
        sw.device_type, (lacp_out or "") + "\n" + (agg_out or ""))

    # 1 — existence
    missing = [m for m in members if m not in brief]
    check("interfaces exist", "fail" if missing else "pass",
          f"not found on switch: {', '.join(missing)}" if missing
          else f"all {len(members)} present")

    ok_members = [m for m in members if m in brief]

    # 2 — not already in another LAG
    taken = {m: membership[m] for m in ok_members if m in membership}
    check("not in another LAG", "fail" if taken else "pass",
          ", ".join(f"{k} → {v}" for k, v in taken.items()) if taken
          else "no existing membership")

    # 3 — identical speed (and matching the selection)
    speeds = {m: brief[m]["speed_mbps"] for m in ok_members}
    known = {v for v in speeds.values() if v is not None}
    unknown = [m for m, v in speeds.items() if v is None]
    want = SPEED_CHOICES.get(speed_key)
    if len(known) > 1:
        check("identical speed", "fail",
              ", ".join(f"{m}={v or '?'}Mb/s" for m, v in speeds.items()))
    elif known and want and next(iter(known)) != want:
        check("identical speed", "fail",
              f"interfaces run {next(iter(known))} Mb/s but "
              f"{speed_key} ({want} Mb/s) was selected")
    elif unknown and (e2 is None or True):
        check("identical speed", "unknown",
              f"speed not readable for: {', '.join(unknown)}")
    else:
        check("identical speed", "pass",
              f"{next(iter(known))} Mb/s" if known else "auto")

    # 4 — administratively up
    admin_down = [m for m in ok_members if brief[m]["admin_down"] is True]
    admin_unknown = [m for m in ok_members if brief[m]["admin_down"] is None]
    if admin_down:
        check("administratively up", "fail",
              f"admin-down: {', '.join(admin_down)}")
    elif admin_unknown:
        check("administratively up", "unknown",
              f"state not readable for: {', '.join(admin_unknown)}")
    else:
        check("administratively up", "pass", "all enabled")

    # 5 — LAG id free
    if e2 and e3:
        check("LAG ID free", "unknown",
              "could not read existing aggregations")
    else:
        check("LAG ID free", "fail" if lag_id in lag_ids else "pass",
              f"LAG {lag_id} already exists" if lag_id in lag_ids
              else f"no existing LAG {lag_id} "
                   f"(in use: {sorted(lag_ids) or 'none'})")

    ok = not any(c["status"] == "fail" for c in checks)
    return {"switch": sw.name, "device_type": sw.device_type,
            "ok": ok, "checks": checks,
            "link_state": {m: brief.get(m, {}).get("link_up") for m in members}}


# ─────────────────────────────────────────────────────────────────────
# Verification (after deploy)
# ─────────────────────────────────────────────────────────────────────

def verify_switch(conn, device_type: str, lag_id: int,
                  expected: list[str]) -> dict:
    cmds = _SHOW[device_type]
    if_out,  e1 = _send_one(conn, cmds["lacp_if"])
    agg_out, e2 = _send_one(conn, cmds["lacp_agg"])
    raw = (f"$ {cmds['lacp_if']}\n{if_out or e1 or ''}\n\n"
           f"$ {cmds['lacp_agg']}\n{agg_out or e2 or ''}")

    members = []
    lag_seen = False
    if device_type == "aruba_aoscx":
        label = f"lag{lag_id}"
        lag_seen = bool(re.search(rf"\b{label}\b", (agg_out or "") +
                                  (if_out or ""), re.I))
        for line in (if_out or "").splitlines():
            m = re.match(rf"\s*(\S+)\s+{label}\b(.*)$", line, re.I)
            if m and is_physical(m.group(1)):
                rest = m.group(2)
                # Real column order: Aggr  Port-id  Port-pri  STATE  System-ID …
                # so the state is the first letters-only token after two
                # numeric columns — NOT at end of line (System-Pri/Aggr-Key
                # follow it). Fall back to older heuristics if the format
                # differs across firmware.
                state = (re.match(r"\s*\d+\s+\d+\s+([A-Za-z]{2,8})\b", rest) or
                         re.search(r"([A-Z]{3,8})\s*$", rest.strip()) or
                         re.search(r"\b(up|down)\b", rest, re.I))
                st = state.group(1) if state else "?"
                synced = bool(re.search(r"C", st)) and bool(re.search(r"D", st))
                members.append({
                    "interface": m.group(1), "state": st,
                    "sync": "in-sync" if synced
                            else ("unknown" if st == "?" else "not synced"),
                })
    else:
        block = ""
        cur = None
        for line in (if_out or "").splitlines():
            hm = re.search(r"Aggregat\w* Interface:\s*"
                           r"(?:Bridge-Aggregation|BAGG)\s*(\d+)", line, re.I)
            if hm:
                cur = int(hm.group(1))
                if cur == lag_id:
                    lag_seen = True
                continue
            if cur == lag_id:
                block += line + "\n"
        for line in block.splitlines():
            pm = re.match(r"\s*([A-Za-z\-]+\d+(?:/\d+)+)\s+(\S+)", line)
            if pm and is_physical(pm.group(1)):
                status = pm.group(2)
                members.append({
                    "interface": pm.group(1), "state": status,
                    "sync": "in-sync" if status.upper().startswith("S")
                            else "not synced",   # S = Selected
                })

    found = {m["interface"] for m in members}
    missing = [m for m in expected if m not in found]
    return {"lag_id": lag_id, "lag_present": lag_seen,
            "members": members, "missing_members": missing,
            "operational": lag_seen and not missing and
                           all(m["sync"] == "in-sync" for m in members)
                           if members else False,
            "raw": raw[-4000:]}


# ─────────────────────────────────────────────────────────────────────
# Deployment worker (background thread; live progress via DB row)
# ─────────────────────────────────────────────────────────────────────

def _record(dep_id: int, mutate):
    """Open a short session, apply `mutate(dep)`, commit. Called per stage so
    the UI polling /api/lacp/deployments/{id} sees progress live."""
    db = SessionLocal()
    try:
        dep = db.query(models.LacpDeployment).filter(
            models.LacpDeployment.id == dep_id).first()
        if dep:
            mutate(dep)
            db.commit()
    finally:
        db.close()


def _push_step(dep_id: int, switch: str, stage: str, status: str,
               detail: str = ""):
    def mut(dep):
        steps = json.loads(dep.steps or "[]")
        steps.append({"switch": switch, "stage": stage, "status": status,
                      "detail": detail[:500],
                      "at": models.ist_now().isoformat()})
        dep.steps = json.dumps(steps)
    _record(dep_id, mut)


def _append_log(dep_id: int, text: str):
    def mut(dep):
        dep.logs = ((dep.logs or "") + text)[-60000:]
    _record(dep_id, mut)



def _send_one(conn, cmd: str) -> tuple[str, str | None]:
    """Single read-only command on either channel type."""
    if getattr(conn, "is_winrm", False):
        return conn.run_batch([cmd])
    return _ca._send(conn, cmd)

def _open_switch(sw_stub, creds):
    """Open the execution channel per LACP_EXEC_MODE.

    direct — netmiko SSH from this container (lab / default)
    winrm  — the enterprise path: WinRM to the Windows jump host, which runs
             PowerShell that SSHes to the switch (AD Studio's mechanism).
    """
    import winrm_executor as _wx
    if _wx.exec_mode() == "winrm":
        return _wx.WinRMSwitchSession(sw_stub, creds)
    return _ca._open(sw_stub, creds)


_MODE_ENTER = {True: "configure terminal", False: "system-view"}
_SELF_CONTAINED = re.compile(
    r"^(configure|system-view|show|display|save|write|copy|checkpoint|"
    r"return|quit|exit)\b", re.I)


def _run_block(conn, dep_id: int, sw_name: str, commands: list[str],
               tolerate_errors: bool = False) -> str | None:
    """Send a command block; return the first error (or None).

    direct mode — one command at a time on the persistent netmiko channel
    (config-mode context carries across blocks, errors attributed per line).

    winrm mode — the whole block goes as ONE batch through the jump host
    (one SSH session per block; WinRM has no persistent channel). Blocks
    that assume they're already in config mode get the vendor's mode-enter
    prepended so each batch is self-contained; every command in this
    feature is idempotent, so the extra `configure terminal` is free.
    """
    if getattr(conn, "is_winrm", False):
        cmds = list(commands)
        if cmds and not _SELF_CONTAINED.match(cmds[0].strip()):
            is_cx = (conn.device_type or "").startswith("aruba")
            cmds = [_MODE_ENTER[is_cx]] + cmds
        out, err = conn.run_batch(cmds)
        _append_log(dep_id, f"\n[{sw_name}] (via jump host) $ "
                            f"{' ; '.join(cmds)}\n{out or ''}"
                            f"{('ERROR: ' + err) if err else ''}\n")
        return None if (err is None or tolerate_errors) else err

    for cmd in commands:
        answer = cmd.startswith(("save", "write",
                                 "configuration replace"))
        out, err = _ca._send(conn, cmd, answer_prompts=answer)
        _append_log(dep_id, f"\n[{sw_name}] $ {cmd}\n{out or ''}"
                            f"{('ERROR: ' + err) if err else ''}\n")
        if err and not tolerate_errors:
            return f"'{cmd}' failed: {err}"
    return None


def run_deployment(dep_id: int, plan: list[dict]):
    """plan = [{switch_row_id, name, device_type, members, cli, creds}] —
    one entry per switch (source first, destination second)."""
    t0 = time.time()
    verification = {}
    failed_reason = None
    executed = []           # [(plan_entry, conn_or_None)] for rollback

    def finish(status: str, error: str = ""):
        def mut(dep):
            dep.status = status
            dep.error = error[:4000]
            dep.finished_at = models.ist_now()
            dep.duration_sec = int(time.time() - t0)
            dep.verification = json.dumps(verification)
        _record(dep_id, mut)

    try:
        for entry in plan:
            name, dt = entry["name"], entry["device_type"]
            cli = entry["cli"]

            _push_step(dep_id, name, "Connecting", "running")
            try:
                conn = _open_switch(entry["sw_stub"], entry["creds"])
            except Exception as e:
                _push_step(dep_id, name, "Connecting", "failed", str(e))
                failed_reason = f"{name}: SSH connection failed: {e}"
                break
            entry["conn"] = conn
            executed.append(entry)
            _push_step(dep_id, name, "Connecting", "done")

            _push_step(dep_id, name, "Creating LAG", "running")
            err = _run_block(conn, dep_id, name, cli["create"])
            if err:
                _push_step(dep_id, name, "Creating LAG", "failed", err)
                failed_reason = f"{name}: {err}"
                break
            entry["created"] = True
            _push_step(dep_id, name, "Creating LAG", "done")

            _push_step(dep_id, name, "Adding members", "running")
            err = _run_block(conn, dep_id, name, cli["members"])
            if err:
                _push_step(dep_id, name, "Adding members", "failed", err)
                failed_reason = f"{name}: {err}"
                break
            _push_step(dep_id, name, "Adding members", "done")

            _push_step(dep_id, name, "Saving configuration", "running")
            err = _run_block(conn, dep_id, name, cli["save"])
            if err:
                _push_step(dep_id, name, "Saving configuration", "failed", err)
                failed_reason = f"{name}: {err}"
                break
            _push_step(dep_id, name, "Saving configuration", "done")

        if failed_reason is None:
            # Give LACP a moment to negotiate before reading state.
            time.sleep(3)
            for entry in executed:
                name = entry["name"]
                _push_step(dep_id, name, "Verifying", "running")
                try:
                    v = verify_switch(entry["conn"], entry["device_type"],
                                      entry["lag_id"], entry["members"])
                    verification[name] = v
                    _push_step(dep_id, name, "Verifying",
                               "done" if v["lag_present"] else "failed",
                               "" if v["lag_present"]
                               else "LAG not visible after deploy")
                except Exception as e:
                    verification[name] = {"error": str(e)}
                    _push_step(dep_id, name, "Verifying", "failed", str(e))
            _push_step(dep_id, "", "Completed", "done")
            finish("completed")
            return

        # ── failure path: stop + roll back everything already touched ──
        # Every switch we CONNECTED to gets rolled back, not just those whose
        # create block fully succeeded: a failure midway through "Creating
        # LAG" can still leave a half-configured aggregate behind. The
        # rollback CLI tolerates errors, so undoing config that never made it
        # onto the device is harmless.
        rb_ok = True
        for entry in reversed(executed):
            name = entry["name"]
            _push_step(dep_id, name, "Rolling back", "running")
            try:
                conn = entry.get("conn") or _open_switch(entry["sw_stub"],
                                                      entry["creds"])
                _run_block(conn, dep_id, name,
                           rollback_cli(entry["device_type"],
                                        entry["lag_id"], entry["members"]),
                           tolerate_errors=True)
                _push_step(dep_id, name, "Rolling back", "done")
            except Exception as e:
                rb_ok = False
                _push_step(dep_id, name, "Rolling back", "failed", str(e))
        finish("rolled_back" if rb_ok else "rollback_failed", failed_reason)

    except Exception as e:
        finish("failed", f"internal error: {e}\n{traceback.format_exc()[:2000]}")
    finally:
        for entry in executed:
            try:
                if entry.get("conn"):
                    entry["conn"].disconnect()
            except Exception:
                pass


def start_deployment(dep_id: int, plan: list[dict]):
    th = threading.Thread(target=run_deployment, args=(dep_id, plan),
                          daemon=True, name=f"lacp-deploy-{dep_id}")
    th.start()
    return th
