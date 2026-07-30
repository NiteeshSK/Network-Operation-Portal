"""
main.py — FastAPI entry point. Supports multiple switches.

Timezone policy:
  - All datetimes are stored in Asia/Kolkata (IST) using
    models.ist_now().
  - When serialized to JSON, they include the +05:30 offset so the
    browser can display the correct local time.

Admin authentication:
  - Sensitive endpoints (anything that opens an SSH session, or that
    exposes config-drift contents) require the caller to include an
    X-Admin-Token header obtained from POST /api/admin/login.
  - The login endpoint stores credentials in RAM only (auth.py); the
    token is the only piece passed to clients. Sessions expire after
    8 hours and after a server restart.
  - The background scheduler is unaffected — it uses the stored
    per-switch credentials and does not require an admin to be logged in.
"""
import os
import re
import logging
from datetime import datetime, timedelta

# Paramiko logs a full stack trace at ERROR level for every failed SSH
# handshake — including the "Error reading SSH protocol banner" that is
# EXPECTED when the server-probe tries SSH against an iLO (which speaks
# Redfish/HTTPS, not SSH). Our code already catches these and falls back to
# Redfish, so the tracebacks are pure noise that buries the real logs. Raise
# paramiko's threshold to CRITICAL so only genuine catastrophes surface; our
# own handled failures are still recorded via last_poll_error / audit.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

from typing import Optional
from zoneinfo import ZoneInfo
from pydantic import BaseModel
from fastapi import FastAPI, Depends, HTTPException, Header, Cookie
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc

from database import engine, get_db, Base, SessionLocal
import models
import schemas
import switch_manager
import diff_engine
import port_stats_parser
import arp_parser
import chatbot
import scheduler as auto_scheduler
import auth


_IST = ZoneInfo("Asia/Kolkata")

def utc_iso(dt: datetime | None) -> str | None:
    """Render a datetime as an ISO-8601 string that ALWAYS carries the
    +05:30 (IST) offset, so browsers display the correct Indian time.

    Every datetime in this system is Asia/Kolkata. However, PostgreSQL's
    TIMESTAMP WITHOUT TIME ZONE column strips the tzinfo on write, so values
    read back are *naive*. If we emitted them without an offset the browser
    would assume UTC and show a time ~5.5 hours off (the cause of the
    "captured 6h ago" bug on fresh data).

    Fix: if the datetime is naive, attach IST; if it already has a tzinfo,
    convert it to IST. Either way the output ends in +05:30."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_IST)       # naive value from Postgres -> it's IST
    else:
        dt = dt.astimezone(_IST)           # tz-aware -> normalize to IST
    return dt.replace(microsecond=0).isoformat()


Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="NOC Portal API",
    version="1.0.0",
    # Disable the auto-mounted docs so we can override their CDN URLs.
    # We re-mount custom /docs and /redoc below that load Swagger UI from
    # cdnjs.cloudflare.com (commonly allow-listed in corporate networks)
    # rather than the FastAPI default cdn.jsdelivr.net.
    docs_url=None,
    redoc_url=None,
)


from fastapi.openapi.docs import (
    get_swagger_ui_html,
    get_redoc_html,
)

@app.get("/docs", include_in_schema=False)
def custom_swagger_ui():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} — Swagger UI",
        swagger_js_url="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-bundle.min.js",
        swagger_css_url="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui.min.css",
        swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
    )


@app.get("/redoc", include_in_schema=False)
def custom_redoc():
    return get_redoc_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} — ReDoc",
        redoc_js_url="https://cdnjs.cloudflare.com/ajax/libs/redoc/2.1.5/redoc.standalone.js",
        redoc_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
        with_google_fonts=False,
    )


@app.on_event("startup")
def _startup():
    auto_scheduler.start_scheduler()


@app.on_event("shutdown")
def _shutdown():
    auto_scheduler.stop_scheduler()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _get_switch(db: Session, name: str) -> models.Switch:
    sw = db.query(models.Switch).filter(models.Switch.name == name).first()
    if not sw:
        raise HTTPException(404, f"Switch '{name}' not found")
    return sw


# ─── Admin auth dependencies ────────────────────────────────────────

NOC_COOKIE_NAME_STATIC = os.environ.get("NOC_COOKIE_NAME", "noc_portal_session")


def require_admin(
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
    portal_cookie: Optional[str] = Cookie(default=None,
                                          alias=NOC_COOKIE_NAME_STATIC),
) -> dict:
    """FastAPI dependency guarding every sensitive endpoint.

    THIS WAS DISABLED. The previous body was:

        # Authentication disabled for testing
        return {"username": "test", "password": "", "scope": ["*"],
                "is_superadmin": True}

    with the real implementation commented out beneath it. That meant all 43
    endpoints declaring Depends(require_admin) — including POST /api/servers,
    the bulk import, config apply and every SSH command endpoint — accepted
    ANY caller with no credential whatsoever. Anyone who could reach the port
    had full control of the fleet. It is restored here.

    Two credentials are accepted:

      1. A valid portal session cookie, from the login page. Carries no
         password, because the portal account is local and unrelated to SSH;
         credentials_for() maps it to None so switch operations use each
         switch's stored credentials, exactly as the capture loops do.

      2. An X-Admin-Token from /api/admin/login, which DOES carry proven SSH
         credentials and overrides the stored ones.
    """
    if portal_cookie:
        session = _NOC_PORTAL_SESSIONS.get(portal_cookie)
        if session and session.get("expires_at_epoch", 0) > _noc_now():
            return {
                "username": session.get("username", "admin"),
                "password": None,
                "scope": session.get("scope", ["*"]),
                "is_superadmin": True,
                "portal_session": True,
            }

    if not x_admin_token:
        raise HTTPException(
            401,
            "Authentication required. Sign in to the portal, or "
            "POST /api/admin/login and send the returned token as the "
            "X-Admin-Token header.",
        )

    session = auth.get_session(x_admin_token)
    if not session:
        raise HTTPException(
            401, "Invalid or expired admin token. Please re-authenticate.")
    return session


def _ensure_scope(session: dict, switch_name: str) -> None:
    """Raise 403 if the admin's scope doesn't cover this switch."""
    if not auth.session_covers_switch(session, switch_name):
        raise HTTPException(
            403,
            f"Admin session does not cover switch '{switch_name}'. "
            f"Its scope is {session['scope']}. "
            "Log in again with a wider scope.",
        )


# ─── Admin auth endpoints ───────────────────────────────────────────

@app.post("/api/admin/login", response_model=schemas.AdminLoginResponse)
def admin_login(payload: schemas.AdminLoginRequest, db: Session = Depends(get_db)):
    """Create a new admin session, but only if the credentials actually
    work against at least one switch in the requested scope.

    Bootstrap exception: if the DB has ZERO switches registered yet, we
    accept ANY credentials and grant a session with scope=["*"]. This
    lets a brand-new operator log in and add the first switch via the
    dashboard. Without this exception, the first login would be
    impossible (no switches to validate against).
    """
    if not payload.username or not payload.password:
        raise HTTPException(400, "Username and password are required.")

    total_switches = db.query(models.Switch).count()

    # ── Bootstrap mode ──────────────────────────────────────────────
    if total_switches == 0:
        try:
            token, session_view = auth.create_session(
                username=payload.username,
                password=payload.password,
                scope=["*"],
                ttl_seconds=payload.ttl_seconds or auth.DEFAULT_TTL_SECONDS,
            )
        except ValueError as e:
            raise HTTPException(400, str(e))
        session_view = dict(session_view)
        session_view["validated_against"] = None
        session_view["bootstrap_mode"] = True
        return {"token": token, "session": session_view}

    # ── Normal mode — validate credentials against an actual switch ──
    if "*" in payload.scope:
        candidates = db.query(models.Switch).order_by(models.Switch.name).all()
    else:
        candidates = (db.query(models.Switch)
                      .filter(models.Switch.name.in_(payload.scope))
                      .order_by(models.Switch.name).all())

    if not candidates:
        raise HTTPException(400,
            "No switches match the requested scope. Add a switch first or "
            "broaden the scope.")

    creds = {"username": payload.username, "password": payload.password}
    last_error = None
    validated_against = None
    for sw in candidates:
        ok, err = switch_manager.test_reachable(sw, credentials_override=creds)
        if ok:
            validated_against = sw.name
            break
        last_error = err or "unknown SSH error"
        low = (err or "").lower()
        if any(s in low for s in ("authentication", "auth failed",
                                  "bad authentication",
                                  "permission denied", "incorrect")):
            break

    if not validated_against:
        raise HTTPException(401,
            f"Login rejected: SSH credentials failed. Last error: {last_error}")

    # Persist the validated credentials onto every in-scope switch. The
    # background scheduler (auto-capture for config snapshots, port stats and
    # ARP) authenticates with these STORED credentials — not the RAM session —
    # so keeping them in sync is what makes unattended auto-capture work after
    # an operator logs in with the real password. Without this, the scheduler
    # keeps using whatever (possibly wrong/empty) password the switch was first
    # added with, and every capture fails with a TCP/auth error.
    #
    # The login above already PROVED these credentials authenticate over SSH
    # (validated_against is set), so we write them to all in-scope switches
    # directly. We deliberately do NOT re-test each switch here: a second probe
    # per switch is slow and, worse, a momentary timeout would silently skip the
    # update and leave stale credentials behind — the exact failure we are
    # fixing. Same-vendor switches in a fleet share one operator credential set,
    # so propagating is safe and is what operators expect.
    try:
        scope_all = "*" in payload.scope
        updated = 0
        for sw in candidates:
            in_scope = scope_all or (sw.name in payload.scope) or (sw.name == validated_against)
            if not in_scope:
                continue
            if sw.username != payload.username or sw.password != payload.password:
                sw.username = payload.username
                sw.password = payload.password
                updated += 1
        if updated:
            db.commit()
            print(f"[login] synced credentials onto {updated} switch(es) "
                  f"so auto-capture can authenticate", flush=True)
    except Exception as _e:
        db.rollback()
        print(f"[login] could not sync stored credentials: {_e}", flush=True)

    try:
        token, session_view = auth.create_session(
            username=payload.username,
            password=payload.password,
            scope=payload.scope,
            ttl_seconds=payload.ttl_seconds or auth.DEFAULT_TTL_SECONDS,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    session_view = dict(session_view)
    session_view["validated_against"] = validated_against
    return {"token": token, "session": session_view}


@app.post("/api/admin/logout")
def admin_logout(
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
):
    """Drop the supplied session. No-op if token is unknown."""
    dropped = auth.delete_session(x_admin_token or "")
    return {"ok": True, "session_existed": dropped}


@app.get("/api/admin/me", response_model=schemas.AdminSessionOut)
def admin_me(session: dict = Depends(require_admin)):
    """Return info about the current session — useful for the UI to
    decide whether to show 'logged in' state."""
    return {
        "username":   session["username"],
        "scope":      session["scope"],
        "created_at": session["created_at"],
        "expires_at": session["expires_at"],
    }


@app.get("/api/admin/sessions", response_model=list[schemas.AdminSessionOut])
def admin_list_sessions():
    """List all active sessions (public view — passwords never leak).
    Helpful for debugging: 'who is currently logged in'."""
    return auth.list_active_sessions()


def _log_command(db: Session, switch, command: str,
                 output: str, success: bool, error: str = ""):
    entry = models.CommandLog(
        switch_id=switch.id,
        switch_name=switch.name,
        command=command,
        output=output or "",
        success=success,
        error=error or "",
        timestamp=models.ist_now(),
    )
    db.add(entry)
    db.commit()


@app.get("/")
def health():
    return {"status": "running", "service": "NOC Portal API"}


@app.get("/api/commands")
def list_commands(device_type: str = "hp_comware"):
    cmds = switch_manager.get_commands(device_type)
    return [{"key": k, "command": v} for k, v in cmds.items()]


# ─── Switch CRUD ──────────────────────────────────────────────────

@app.get("/api/switches", response_model=list[schemas.SwitchOut])
def list_switches(db: Session = Depends(get_db)):
    return db.query(models.Switch).order_by(models.Switch.id).all()


@app.post("/api/switches", response_model=schemas.SwitchOut, status_code=201)
def create_switch(payload: schemas.SwitchCreate, db: Session = Depends(get_db)):
    if db.query(models.Switch).filter(models.Switch.name == payload.name).first():
        raise HTTPException(409, f"Switch '{payload.name}' already exists")
    sw = models.Switch(**payload.model_dump())
    db.add(sw)
    db.commit()
    db.refresh(sw)
    return sw


@app.delete("/api/switches/{name}", status_code=204)
def delete_switch(name: str, db: Session = Depends(get_db)):
    sw = _get_switch(db, name)
    db.delete(sw)
    db.commit()


@app.post("/api/switches/{name}/test")
def test_switch(name: str,
                db: Session = Depends(get_db),
                session: dict = Depends(require_admin)):
    sw = _get_switch(db, name)
    _ensure_scope(session, name)
    ok, err = switch_manager.test_reachable(
        sw, credentials_override=auth.credentials_for(session)
    )
    return {"switch": name, "reachable": ok, "error": err}


@app.post("/api/switches/{name}/run")
def run_display_command(name: str, payload: schemas.CommandRequest,
                        db: Session = Depends(get_db),
                        session: dict = Depends(require_admin)):
    """Run a single command on a switch. Two ways to specify:

      - `command_key`: pick from the curated dropdown via /api/commands
                       (safer, vendor-translated)
      - `command_raw`: pass any string verbatim. Use for ad-hoc
                       troubleshooting. Anything destructive
                       (reboot, delete, erase, format, factory) is
                       still refused unless the explicit override is set.
    """
    sw = _get_switch(db, name)
    _ensure_scope(session, name)

    # Resolve the actual command string from one of the two inputs
    if payload.command_raw:
        command = payload.command_raw.strip()
        if not command:
            raise HTTPException(400, "command_raw is empty")
        # Light safety: block destructive verbs. Operators who really
        # want to do this should SSH directly from a terminal.
        low = command.lower()
        BLOCKED = ("reboot", "reload", "erase", "delete", "format",
                   "factory", "shutdown system", "rmdir")
        for kw in BLOCKED:
            if kw in low:
                raise HTTPException(
                    400,
                    f"Command rejected: contains blocked keyword '{kw}'. "
                    f"Destructive commands must be executed from a regular "
                    f"SSH terminal, not the dashboard."
                )
    elif payload.command_key:
        commands = switch_manager.get_commands(sw.device_type)
        if payload.command_key not in commands:
            raise HTTPException(400, "Unknown command_key. See /api/commands")
        command = commands[payload.command_key]
    else:
        raise HTTPException(400, "Provide either command_key or command_raw")

    output, err = switch_manager.run_command(
        sw, command, credentials_override=auth.credentials_for(session)
    )
    _log_command(db, sw, command, output or "", err is None, err or "")

    return {
        "switch":    sw.name,
        "command":   command,
        "success":   err is None,
        "output":    output or "",
        "error":     err,
        "timestamp": utc_iso(models.ist_now()),
    }


@app.post("/api/switches/{name}/ping")
def ping_from_switch(name: str, payload: schemas.PingRequest,
                     db: Session = Depends(get_db),
                     session: dict = Depends(require_admin)):
    sw = _get_switch(db, name)
    _ensure_scope(session, name)

    if any(c in payload.target for c in " ;|&`$\n\r"):
        raise HTTPException(400, "Invalid characters in target")

    command = f"ping -c 5 {payload.target}"
    output, err = switch_manager.run_command(
        sw, command, credentials_override=auth.credentials_for(session)
    )
    _log_command(db, sw, command, output or "", err is None, err or "")

    return {
        "switch":    sw.name,
        "target":    payload.target,
        "command":   command,
        "success":   err is None,
        "output":    output or "",
        "error":     err,
        "timestamp": utc_iso(models.ist_now()),
    }


# ─── Snapshots + drift ────────────────────────────────────────────

@app.post("/api/switches/{name}/snapshot", response_model=schemas.SnapshotOut)
def take_snapshot(name: str,
                  db: Session = Depends(get_db),
                  session: dict = Depends(require_admin)):
    sw = _get_switch(db, name)
    _ensure_scope(session, name)

    config_cmd = switch_manager.get_commands(sw.device_type)["config"]
    config_text, err = switch_manager.run_command(
        sw, config_cmd, credentials_override=auth.credentials_for(session)
    )
    if err:
        _log_command(db, sw, config_cmd, "", False, err)
        raise HTTPException(502, f"Failed to fetch config: {err}")

    _log_command(db, sw, config_cmd, config_text, True)

    new_hash = diff_engine.hash_config(config_text)
    prev = (
        db.query(models.Snapshot)
        .filter(models.Snapshot.switch_id == sw.id)
        .order_by(desc(models.Snapshot.captured_at))
        .first()
    )

    drift = False
    diff_text = ""
    if prev and prev.config_hash != new_hash:
        drift = True
        diff_text = diff_engine.diff_configs(
            prev.config_text, config_text,
            from_label=f"snapshot_{prev.id}",
            to_label="new_snapshot",
        )

    snap = models.Snapshot(
        switch_id=sw.id,
        switch_name=sw.name,
        config_text=config_text,
        config_hash=new_hash,
        drift_detected=drift,
        diff_from_prev=diff_text,
        captured_at=models.ist_now(),
    )
    db.add(snap)
    db.commit()
    db.refresh(snap)
    return snap


@app.get("/api/switches/{name}/snapshots", response_model=list[schemas.SnapshotOut])
def list_snapshots(name: str,
                   db: Session = Depends(get_db),
                   session: dict = Depends(require_admin)):
    sw = _get_switch(db, name)
    _ensure_scope(session, name)
    return (
        db.query(models.Snapshot)
        .filter(models.Snapshot.switch_id == sw.id)
        .order_by(desc(models.Snapshot.captured_at))
        .all()
    )


@app.get("/api/snapshots/compare")
def compare_snapshots(a: int, b: int,
                      db: Session = Depends(get_db),
                      session: dict = Depends(require_admin)):
    """Return a unified diff between two arbitrary snapshots.
    Snapshot IDs `a` (older) and `b` (newer) are provided as query params.
    Defined BEFORE /api/snapshots/{snap_id} so the literal path 'compare'
    isn't swallowed by the integer path-parameter route."""
    snap_a = db.query(models.Snapshot).filter(models.Snapshot.id == a).first()
    snap_b = db.query(models.Snapshot).filter(models.Snapshot.id == b).first()
    if not snap_a or not snap_b:
        raise HTTPException(404, "Snapshot id not found")
    _ensure_scope(session, snap_a.switch_name)
    if snap_b.switch_name != snap_a.switch_name:
        _ensure_scope(session, snap_b.switch_name)
    diff_text = diff_engine.diff_configs(
        snap_a.config_text or "", snap_b.config_text or "",
        from_label=f"#{snap_a.id} {snap_a.switch_name} @ {snap_a.captured_at.isoformat()}Z",
        to_label  =f"#{snap_b.id} {snap_b.switch_name} @ {snap_b.captured_at.isoformat()}Z",
    )
    return {
        "a": {
            "id": snap_a.id, "switch_name": snap_a.switch_name,
            "captured_at": utc_iso(snap_a.captured_at),
            "config_hash": snap_a.config_hash,
        },
        "b": {
            "id": snap_b.id, "switch_name": snap_b.switch_name,
            "captured_at": utc_iso(snap_b.captured_at),
            "config_hash": snap_b.config_hash,
        },
        "identical": (snap_a.config_hash == snap_b.config_hash),
        "diff": diff_text,
    }


@app.get("/api/snapshots/{snap_id}", response_model=schemas.SnapshotDetail)
def get_snapshot(snap_id: int,
                 db: Session = Depends(get_db),
                 session: dict = Depends(require_admin)):
    snap = db.query(models.Snapshot).filter(models.Snapshot.id == snap_id).first()
    if not snap:
        raise HTTPException(404, "Snapshot not found")
    _ensure_scope(session, snap.switch_name)
    return snap


@app.get("/api/diff", response_model=schemas.DiffResponse)
def diff_two(from_id: int, to_id: int,
             db: Session = Depends(get_db),
             session: dict = Depends(require_admin)):
    a = db.query(models.Snapshot).filter(models.Snapshot.id == from_id).first()
    b = db.query(models.Snapshot).filter(models.Snapshot.id == to_id).first()
    if not a or not b:
        raise HTTPException(404, "One or both snapshots not found")
    _ensure_scope(session, a.switch_name)
    _ensure_scope(session, b.switch_name)

    identical = (a.config_hash == b.config_hash)
    diff_text = "" if identical else diff_engine.diff_configs(
        a.config_text, b.config_text,
        from_label=f"snapshot_{a.id}",
        to_label=f"snapshot_{b.id}",
    )
    return schemas.DiffResponse(
        from_snapshot_id=a.id,
        to_snapshot_id=b.id,
        from_time=a.captured_at,
        to_time=b.captured_at,
        diff=diff_text,
        identical=identical,
    )


# ─── Logs ─────────────────────────────────────────────────────────

@app.get("/api/logs", response_model=list[schemas.CommandLogOut])
def list_logs(limit: int = 50, switch_name: str | None = None,
              db: Session = Depends(get_db)):
    q = db.query(models.CommandLog)
    if switch_name:
        q = q.filter(models.CommandLog.switch_name == switch_name)
    return q.order_by(desc(models.CommandLog.timestamp)).limit(limit).all()


# ─── Port stats (in/out traffic counters) ─────────────────────────

@app.post("/api/switches/{name}/debug-port-stats")
def debug_port_stats(name: str,
                     db: Session = Depends(get_db),
                     session: dict = Depends(require_admin)):
    """Returns the raw output of the interface command + what the parser
    extracted from it. Use this when port stats look wrong — you can
    eyeball whether the issue is on the switch side (raw output has no
    counters) or the parser side (raw output has counters but parser
    didn't extract them).
    """
    sw = _get_switch(db, name)
    _ensure_scope(session, name)
    iface_cmd, parser_fn = port_stats_parser.get_interface_command_and_parser(sw.device_type)
    brief_cmd, brief_fn  = port_stats_parser.get_brief_command_and_parser(sw.device_type)
    creds                = auth.credentials_for(session)

    iface_out, iface_err = switch_manager.run_command(sw, iface_cmd, credentials_override=creds)
    brief_out,  brief_err  = switch_manager.run_command(sw, brief_cmd,  credentials_override=creds)

    parsed = parser_fn(iface_out) if iface_out else []
    brief_map = brief_fn(brief_out) if (brief_out and not brief_err) else {}
    port_stats_parser.merge_brief_into_stats(parsed, brief_map)

    return {
        "device_type":      sw.device_type,
        "iface_command":    iface_cmd,
        "iface_error":      iface_err,
        "iface_output_len": len(iface_out or ""),
        "iface_output_first_2000_chars": (iface_out or "")[:2000],
        "brief_command":    brief_cmd,
        "brief_error":      brief_err,
        "brief_output_len": len(brief_out or ""),
        "brief_output_first_1500_chars": (brief_out or "")[:1500],
        "ports_parsed":     len(parsed),
        "descriptions_extracted": sum(1 for p in parsed if p.get("port_description")),
        "nonzero_total_packets":  sum(1 for p in parsed if p.get("total_packets", 0) > 0),
        "sample_ports":     parsed[:8],
        "brief_map_keys_sample": list(brief_map.keys())[:12],
    }


@app.post("/api/switches/{name}/capture-port-stats")
def capture_port_stats(name: str,
                       db: Session = Depends(get_db),
                       session: dict = Depends(require_admin)):
    """Capture port counters + descriptions. Hardened so any error returns
    a JSON 500 with the failing stage + exception type, AND logs the
    full traceback to the container log. No more bare 'Internal Server Error'."""
    import traceback as _tb
    sw = _get_switch(db, name)
    _ensure_scope(session, name)

    stage = "init"
    try:
        stage = "dispatch"
        iface_cmd, parser_fn = port_stats_parser.get_interface_command_and_parser(sw.device_type)
        brief_cmd, brief_fn  = port_stats_parser.get_brief_command_and_parser(sw.device_type)
        creds                = auth.credentials_for(session)

        # 1. Statistics command (counters)
        stage = "ssh_stats"
        output, err = switch_manager.run_command(sw, iface_cmd, credentials_override=creds)
        _log_command(db, sw, iface_cmd, output or "", err is None, err or "")
        if err:
            raise HTTPException(502, f"Failed to fetch interface details: {err}")

        stage = "parse_stats"
        parsed = parser_fn(output)
        if not parsed:
            raise HTTPException(
                502,
                f"Parser returned no ports for device_type={sw.device_type!r}. "
                f"Command was {iface_cmd!r}. First 200 chars of output: "
                f"{(output or '')[:200]!r}",
            )

        # 2. Brief command (descriptions + mode + vlan). NON-FATAL.
        stage = "ssh_brief"
        brief_map = {}
        try:
            b_out, b_err = switch_manager.run_command(sw, brief_cmd, credentials_override=creds)
            _log_command(db, sw, brief_cmd, b_out or "", b_err is None, b_err or "")
            if not b_err and b_out:
                stage = "parse_brief"
                brief_map = brief_fn(b_out) or {}
        except Exception as brief_exc:
            print(f"[capture-port-stats] brief lookup failed (non-fatal): "
                  f"{type(brief_exc).__name__}: {brief_exc}", flush=True)
            brief_map = {}

        stage = "merge_brief"
        try:
            port_stats_parser.merge_brief_into_stats(parsed, brief_map)
        except Exception as merge_exc:
            print(f"[capture-port-stats] merge failed (non-fatal): "
                  f"{type(merge_exc).__name__}: {merge_exc}", flush=True)

        # 3. Persist — every row in its own try so one bad row doesn't kill them all
        stage = "persist"
        now = models.ist_now()
        skipped = 0
        for p in parsed:
            try:
                row = models.PortStat(
                    switch_id=sw.id,
                    switch_name=sw.name,
                    interface_name=p["interface_name"],
                    link_state=p.get("link_state", ""),
                    in_packets=p.get("in_packets", 0),   in_bytes=p.get("in_bytes", 0),
                    in_errors=p.get("in_errors", 0),     in_broadcasts=p.get("in_broadcasts", 0),
                    out_packets=p.get("out_packets", 0), out_bytes=p.get("out_bytes", 0),
                    out_errors=p.get("out_errors", 0),   out_broadcasts=p.get("out_broadcasts", 0),
                    total_packets=p.get("total_packets",
                                        p.get("in_packets", 0) + p.get("out_packets", 0)),
                    port_description=p.get("port_description", ""),
                    captured_at=now,
                )
                db.add(row)
            except Exception as row_exc:
                skipped += 1
                print(f"[capture-port-stats] skipped row for "
                      f"{p.get('interface_name','?')}: "
                      f"{type(row_exc).__name__}: {row_exc}", flush=True)

        stage = "commit"
        db.commit()

        return {
            "success": True,
            "switch": sw.name,
            "captured_at": utc_iso(now),
            "ports_captured": len(parsed) - skipped,
            "ports_skipped": skipped,
            "descriptions_merged": sum(1 for p in parsed if p.get("port_description")),
        }
    except HTTPException:
        raise
    except Exception as e:
        tb = _tb.format_exc()
        print(f"[capture-port-stats] FAILED stage={stage!r}: "
              f"{type(e).__name__}: {e}\n{tb}", flush=True)
        try: db.rollback()
        except Exception: pass
        raise HTTPException(
            500,
            f"capture-port-stats failed at stage={stage!r}: "
            f"{type(e).__name__}: {e}",
        )


@app.get("/api/port-stats/captures")
def get_port_stats_captures(switch_name: str, db: Session = Depends(get_db)):
    """List distinct capture timestamps for a switch (newest first, up to 100).
    Powers the history dropdown so engineers can view any past snapshot."""
    from sqlalchemy import func as _func
    sw = db.query(models.Switch).filter(models.Switch.name == switch_name).first()
    if not sw:
        raise HTTPException(404, f"Switch '{switch_name}' not found")
    rows = (
        db.query(models.PortStat.captured_at,
                 _func.count(models.PortStat.id).label("port_count"))
        .filter(models.PortStat.switch_id == sw.id)
        .group_by(models.PortStat.captured_at)
        .order_by(desc(models.PortStat.captured_at))
        .limit(100).all()
    )
    return [{"captured_at": utc_iso(r.captured_at), "port_count": r.port_count}
            for r in rows]


@app.get("/api/port-stats")
def get_port_stats(
    switch_name: str | None = None,
    interface_name: str | None = None,
    captured_at: str | None = None,
    limit: int = 500,
    db: Session = Depends(get_db),
):
    if captured_at:
        pass  # handled below after query is built
    q = db.query(models.PortStat)
    if switch_name:
        q = q.filter(models.PortStat.switch_name == switch_name)
    if interface_name:
        q = q.filter(models.PortStat.interface_name == interface_name)
    if captured_at:
        try:
            _ts = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
            q = q.filter(models.PortStat.captured_at.between(
                _ts - timedelta(seconds=10), _ts + timedelta(seconds=10)))
        except (ValueError, AttributeError):
            raise HTTPException(400, "Invalid captured_at — use ISO 8601")
    rows = q.order_by(models.PortStat.captured_at.desc()).limit(limit).all()
    return [
        {
            "id":             r.id,
            "switch_name":    r.switch_name,
            "interface":      r.interface_name,
            "link_state":     r.link_state,
            "in_packets":     r.in_packets,   "in_bytes":     r.in_bytes,
            "in_errors":      r.in_errors,    "in_broadcasts": r.in_broadcasts,
            "out_packets":    r.out_packets,  "out_bytes":    r.out_bytes,
            "out_errors":     r.out_errors,   "out_broadcasts": r.out_broadcasts,
            "total_packets":  r.total_packets,
            "port_description": r.port_description or "",
            "captured_at":    utc_iso(r.captured_at),
        }
        for r in rows
    ]


@app.get("/api/port-stats/latest")
def get_latest_port_stats(switch_name: str, db: Session = Depends(get_db)):
    sw = db.query(models.Switch).filter(models.Switch.name == switch_name).first()
    if not sw:
        raise HTTPException(404, "Switch not found")

    latest_ts = (
        db.query(models.PortStat.captured_at)
        .filter(models.PortStat.switch_id == sw.id)
        .order_by(models.PortStat.captured_at.desc())
        .first()
    )
    if not latest_ts:
        return {"switch": switch_name, "captured_at": None, "ports": []}

    rows = (
        db.query(models.PortStat)
        .filter(models.PortStat.switch_id == sw.id,
                models.PortStat.captured_at == latest_ts[0])
        .order_by(models.PortStat.interface_name)
        .all()
    )

    return {
        "switch": switch_name,
        "captured_at": utc_iso(latest_ts[0]),
        "ports": [
            {
                "interface":  r.interface_name,
                "link_state": r.link_state,
                "in_packets": r.in_packets, "in_bytes": r.in_bytes,
                "out_packets": r.out_packets, "out_bytes": r.out_bytes,
                "in_errors":  r.in_errors,  "out_errors": r.out_errors,
                "total_packets": r.total_packets,
                "port_description": r.port_description or "",
            }
            for r in rows
        ],
    }


# ─── Port-stats deltas (per-interval new traffic) ─────────────────

# Maps the UI interval labels to seconds. Mirrors the auto-capture intervals
# the operator already knows: 1m, 15m, 1h, 12h, 24h.
DELTA_INTERVAL_SECONDS = {
    "1m": 60, "15m": 900, "1h": 3600, "12h": 43200, "24h": 86400,
}


def _resolve_interval_seconds(interval: str) -> int:
    if interval in DELTA_INTERVAL_SECONDS:
        return DELTA_INTERVAL_SECONDS[interval]
    # also accept a raw number of minutes, e.g. "1" or "60"
    try:
        return int(interval) * 60
    except (TypeError, ValueError):
        raise HTTPException(
            400, f"Invalid interval '{interval}' — use one of "
                 f"{', '.join(DELTA_INTERVAL_SECONDS)} or minutes as an integer")


@app.get("/api/port-stats/deltas")
def get_port_stats_deltas(
    switch_name: str,
    interval: str = "1m",        # 1m | 15m | 1h | 12h | 24h  (or minutes int)
    at: str | None = None,       # 'current' capture ISO time; default = latest
    db: Session = Depends(get_db),
):
    """Per-interface NEW traffic over a time window.

    Port counters are cumulative since the switch last booted/cleared, so the
    raw numbers only ever climb. This endpoint subtracts an earlier capture
    from the current one to show how many packets/bytes actually arrived in,
    say, the last minute or last hour.

    For each interface it returns the current absolute counters PLUS deltas:
      delta_in_packets, delta_out_packets, delta_total_packets,
      delta_in_bytes,  delta_out_bytes
    A negative delta means the counter reset (reboot/clear) between the two
    captures; we surface that as reset=true and leave the delta null rather
    than report a misleading huge number.
    """
    secs = _resolve_interval_seconds(interval)

    sw = db.query(models.Switch).filter(models.Switch.name == switch_name).first()
    if not sw:
        raise HTTPException(404, "Switch not found")

    # ── resolve the "current" capture timestamp ──────────────────────────
    if at:
        try:
            _ts = datetime.fromisoformat(at.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, AttributeError):
            raise HTTPException(400, "Invalid 'at' — use ISO 8601")
        cur_row = (db.query(models.PortStat.captured_at)
                   .filter(models.PortStat.switch_id == sw.id,
                           models.PortStat.captured_at.between(
                               _ts - timedelta(seconds=10),
                               _ts + timedelta(seconds=10)))
                   .order_by(desc(models.PortStat.captured_at)).first())
    else:
        cur_row = (db.query(models.PortStat.captured_at)
                   .filter(models.PortStat.switch_id == sw.id)
                   .order_by(desc(models.PortStat.captured_at)).first())

    if not cur_row:
        return {"switch": switch_name, "requested_interval": interval,
                "current_captured_at": None, "baseline_captured_at": None,
                "window_seconds": 0, "partial": False, "ports": []}

    current_ts = cur_row[0]
    target = current_ts - timedelta(seconds=secs)

    # baseline = most recent capture at/before the target boundary …
    base_row = (db.query(models.PortStat.captured_at)
                .filter(models.PortStat.switch_id == sw.id,
                        models.PortStat.captured_at <= target)
                .order_by(desc(models.PortStat.captured_at)).first())
    partial = False
    if not base_row:
        # … not enough history yet — fall back to the earliest capture we have
        base_row = (db.query(models.PortStat.captured_at)
                    .filter(models.PortStat.switch_id == sw.id,
                            models.PortStat.captured_at < current_ts)
                    .order_by(models.PortStat.captured_at.asc()).first())
        partial = True

    baseline_ts = base_row[0] if base_row else None
    window_seconds = int((current_ts - baseline_ts).total_seconds()) if baseline_ts else 0

    # ── pull both captures, keyed by interface ───────────────────────────
    def _rows_at(ts):
        if ts is None:
            return {}
        rows = (db.query(models.PortStat)
                .filter(models.PortStat.switch_id == sw.id,
                        models.PortStat.captured_at == ts).all())
        return {r.interface_name: r for r in rows}

    cur = _rows_at(current_ts)
    base = _rows_at(baseline_ts)

    def _delta(cv, bv):
        if bv is None or cv is None:
            return None
        d = (cv or 0) - (bv or 0)
        return d if d >= 0 else None      # negative ⇒ counter reset

    ports = []
    for iface, c in cur.items():
        b = base.get(iface)
        reset = False
        if b is not None:
            reset = ((c.in_packets or 0) - (b.in_packets or 0) < 0 or
                     (c.out_packets or 0) - (b.out_packets or 0) < 0)
        total = c.total_packets if c.total_packets is not None else \
            (c.in_packets or 0) + (c.out_packets or 0)
        ports.append({
            "interface":        iface,
            "link_state":       c.link_state,
            "port_description":  c.port_description or "",
            # current absolute counters
            "in_packets":  c.in_packets,  "out_packets": c.out_packets,
            "total_packets": total,
            "in_bytes":    c.in_bytes,    "out_bytes":   c.out_bytes,
            "in_errors":   c.in_errors,   "out_errors":  c.out_errors,
            # deltas over the window
            "delta_in_packets":    None if b is None or reset else _delta(c.in_packets,  b.in_packets),
            "delta_out_packets":   None if b is None or reset else _delta(c.out_packets, b.out_packets),
            "delta_total_packets": None if b is None or reset else _delta(total,
                                       (b.total_packets if b.total_packets is not None
                                        else (b.in_packets or 0) + (b.out_packets or 0))),
            "delta_in_bytes":      None if b is None or reset else _delta(c.in_bytes,  b.in_bytes),
            "delta_out_bytes":     None if b is None or reset else _delta(c.out_bytes, b.out_bytes),
            "baseline_missing":    b is None,
            "reset":               reset,
        })

    return {
        "switch":               switch_name,
        "requested_interval":   interval,
        "requested_seconds":    secs,
        "current_captured_at":  utc_iso(current_ts),
        "baseline_captured_at": utc_iso(baseline_ts),
        "window_seconds":       window_seconds,
        "partial":              partial,   # true when history < requested window
        "ports":                ports,
    }


# ─── Auto-capture schedule ────────────────────────────────────────

ALLOWED_INTERVALS = {1, 15, 60, 720, 1440}  # 1m, 15m, 1h, 12h, 24h
ALLOWED_PORT_STATS_INTERVALS_SEC = {15, 30, 60, 120, 300, 600}  # 15s, 30s, 1m, 2m, 5m, 10m


def _serialize_setting(setting, switch_name: str) -> dict:
    if not setting:
        return {
            "switch": switch_name,
            "enabled": False,
            "interval_minutes": 1440,
            "last_captured_at": None, "next_due_at": None,
            "last_snapshot_status": "", "last_snapshot_error": "",
            "port_stats_enabled": False,
            "port_stats_interval_seconds": 30,
            "port_stats_last_captured_at": None,
            "port_stats_next_due_at": None,
            "last_port_stats_status": "", "last_port_stats_error": "",
        }
    return {
        "switch": setting.switch_name,
        "enabled": setting.enabled,
        "interval_minutes": setting.interval_minutes,
        "last_captured_at": utc_iso(setting.last_captured_at),
        "next_due_at":      utc_iso(setting.next_due_at),
        "last_snapshot_status": setting.last_snapshot_status or "",
        "last_snapshot_error":  setting.last_snapshot_error or "",
        "port_stats_enabled": setting.port_stats_enabled,
        "port_stats_interval_seconds": setting.port_stats_interval_seconds,
        "port_stats_last_captured_at": utc_iso(setting.port_stats_last_captured_at),
        "port_stats_next_due_at":      utc_iso(setting.port_stats_next_due_at),
        "last_port_stats_status": setting.last_port_stats_status or "",
        "last_port_stats_error":  setting.last_port_stats_error or "",
    }


@app.get("/api/auto-capture/{name}")
def get_auto_capture(name: str, db: Session = Depends(get_db)):
    sw = _get_switch(db, name)
    setting = db.query(models.AutoCaptureSetting).filter(
        models.AutoCaptureSetting.switch_id == sw.id
    ).first()
    return _serialize_setting(setting, sw.name)


class _SnapCaptureBody(BaseModel):
    interval_minutes: int = 1440
    enabled: bool = True


@app.put("/api/auto-capture/{name}")
def update_auto_capture(
    name: str,
    payload: _SnapCaptureBody,
    db: Session = Depends(get_db),
):
    interval_minutes = payload.interval_minutes
    enabled = payload.enabled
    if interval_minutes not in ALLOWED_INTERVALS:
        raise HTTPException(
            400, f"interval_minutes must be one of {sorted(ALLOWED_INTERVALS)}"
        )

    sw = _get_switch(db, name)
    setting = db.query(models.AutoCaptureSetting).filter(
        models.AutoCaptureSetting.switch_id == sw.id
    ).first()

    now = models.ist_now()
    if not setting:
        setting = models.AutoCaptureSetting(
            switch_id=sw.id,
            switch_name=sw.name,
            interval_minutes=interval_minutes,
            enabled=enabled,
            next_due_at=now if enabled else None,
        )
        db.add(setting)
    else:
        setting.interval_minutes = interval_minutes
        setting.enabled = enabled
        if enabled:
            if setting.next_due_at is None or setting.next_due_at < now:
                setting.next_due_at = now
        else:
            setting.next_due_at = None

    db.commit()
    db.refresh(setting)
    return _serialize_setting(setting, sw.name)


# ─── Port-stats auto-capture (real-time polling) ────────────────────

class _PortStatsCaptureBody(BaseModel):
    interval_seconds: int = 30
    enabled: bool = True


@app.put("/api/auto-capture/{name}/port-stats")
def update_port_stats_auto_capture(
    name: str,
    payload: _PortStatsCaptureBody,
    db: Session = Depends(get_db),
):
    interval_seconds = payload.interval_seconds
    enabled = payload.enabled
    """Turn real-time port-stat polling on or off for a single switch.

    The scheduler's port-stats loop ticks every 15s, so the effective
    granularity is `interval_seconds` rounded up to the next 15s boundary.
    """
    if interval_seconds not in ALLOWED_PORT_STATS_INTERVALS_SEC:
        raise HTTPException(
            400,
            f"interval_seconds must be one of "
            f"{sorted(ALLOWED_PORT_STATS_INTERVALS_SEC)}"
        )

    sw = _get_switch(db, name)
    setting = db.query(models.AutoCaptureSetting).filter(
        models.AutoCaptureSetting.switch_id == sw.id
    ).first()

    now = models.ist_now()
    if not setting:
        setting = models.AutoCaptureSetting(
            switch_id=sw.id,
            switch_name=sw.name,
            port_stats_enabled=enabled,
            port_stats_interval_seconds=interval_seconds,
            port_stats_next_due_at=now if enabled else None,
        )
        db.add(setting)
    else:
        setting.port_stats_enabled = enabled
        setting.port_stats_interval_seconds = interval_seconds
        if enabled:
            if (setting.port_stats_next_due_at is None
                    or setting.port_stats_next_due_at < now):
                setting.port_stats_next_due_at = now
        else:
            setting.port_stats_next_due_at = None

    db.commit()
    db.refresh(setting)
    return _serialize_setting(setting, sw.name)


@app.put("/api/auto-capture/port-stats/enable-all")
def enable_port_stats_for_all(
    interval_seconds: int = 30,
    db: Session = Depends(get_db),
):
    """Bulk-enable real-time port-stat polling on every registered switch.
    Convenience endpoint so you don't have to call the per-switch one
    9+ times. Returns the list of switches affected."""
    if interval_seconds not in ALLOWED_PORT_STATS_INTERVALS_SEC:
        raise HTTPException(
            400,
            f"interval_seconds must be one of "
            f"{sorted(ALLOWED_PORT_STATS_INTERVALS_SEC)}"
        )

    switches = db.query(models.Switch).all()
    now = models.ist_now()
    affected = []

    for sw in switches:
        setting = db.query(models.AutoCaptureSetting).filter(
            models.AutoCaptureSetting.switch_id == sw.id
        ).first()
        if not setting:
            setting = models.AutoCaptureSetting(
                switch_id=sw.id,
                switch_name=sw.name,
                port_stats_enabled=True,
                port_stats_interval_seconds=interval_seconds,
                port_stats_next_due_at=now,
            )
            db.add(setting)
        else:
            setting.port_stats_enabled = True
            setting.port_stats_interval_seconds = interval_seconds
            if (setting.port_stats_next_due_at is None
                    or setting.port_stats_next_due_at < now):
                setting.port_stats_next_due_at = now
        affected.append(sw.name)

    db.commit()
    return {
        "enabled_for": affected,
        "interval_seconds": interval_seconds,
        "count": len(affected),
    }


@app.put("/api/auto-capture/port-stats/disable-all")
def disable_port_stats_for_all(db: Session = Depends(get_db)):
    """Bulk-disable real-time port-stat polling on every switch."""
    settings = db.query(models.AutoCaptureSetting).all()
    for setting in settings:
        setting.port_stats_enabled = False
        setting.port_stats_next_due_at = None
    db.commit()
    return {"disabled_for": [s.switch_name for s in settings],
            "count": len(settings)}


@app.get("/api/auto-capture")
def list_auto_captures(db: Session = Depends(get_db)):
    rows = db.query(models.AutoCaptureSetting).all()
    return [_serialize_setting(r, r.switch_name) for r in rows]

# ─── ARP capture + IP conflict detection ────────────────────────────

@app.post("/api/arp/capture-all")
def capture_arp_all(db: Session = Depends(get_db),
                    session: dict = Depends(require_admin)):
    """Best-effort: capture ARP from every switch the current session
    has scope for. Used by the IP Conflicts view to refresh data with
    one click — caller doesn't have to walk switches individually."""
    all_switches = db.query(models.Switch).order_by(models.Switch.name).all()
    creds = auth.credentials_for(session)
    summary = []
    for sw in all_switches:
        if not auth.session_covers_switch(session, sw.name):
            summary.append({"switch": sw.name, "skipped": "out of scope"})
            continue
        cmd, parser_fn = arp_parser.get_arp_command_and_parser(sw.device_type)
        try:
            output, err = switch_manager.run_command(sw, cmd, credentials_override=creds)
            _log_command(db, sw, cmd, output or "", err is None, err or "")
            if err:
                summary.append({"switch": sw.name, "error": err})
                continue
            rows = parser_fn(output)
            now = models.ist_now()
            for r in rows:
                db.add(models.ArpEntry(
                    switch_id=sw.id, switch_name=sw.name,
                    ip_address=r["ip_address"], mac_address=r["mac_address"],
                    interface=r["interface"], vlan=r["vlan"],
                    arp_type=r["arp_type"], age_seconds=r["age_seconds"],
                    captured_at=now,
                ))
            db.commit()
            summary.append({"switch": sw.name, "entries_captured": len(rows)})
        except Exception as e:
            summary.append({"switch": sw.name, "error": str(e)})
    return {
        "checked_at": utc_iso(models.ist_now()),
        "results": summary,
    }


@app.post("/api/switches/{name}/capture-arp")
def capture_arp(name: str,
                db: Session = Depends(get_db),
                session: dict = Depends(require_admin)):
    """Run the switch's ARP command, parse it, store one row per entry."""
    sw = _get_switch(db, name)
    _ensure_scope(session, name)

    cmd, parser_fn = arp_parser.get_arp_command_and_parser(sw.device_type)
    output, err = switch_manager.run_command(
        sw, cmd, credentials_override=auth.credentials_for(session)
    )
    _log_command(db, sw, cmd, output or "", err is None, err or "")
    if err:
        raise HTTPException(502, f"Failed to fetch ARP table: {err}")

    rows = parser_fn(output)
    now = models.ist_now()
    for r in rows:
        db.add(models.ArpEntry(
            switch_id=sw.id, switch_name=sw.name,
            ip_address=r["ip_address"], mac_address=r["mac_address"],
            interface=r["interface"], vlan=r["vlan"],
            arp_type=r["arp_type"], age_seconds=r["age_seconds"],
            captured_at=now,
        ))
    db.commit()
    return {
        "success": True,
        "switch": sw.name,
        "captured_at": utc_iso(now),
        "entries_captured": len(rows),
    }


@app.get("/api/arp")
def list_arp(switch_name: str | None = None,
             limit: int = 500,
             db: Session = Depends(get_db)):
    """Latest ARP entries — newest first, optionally filtered by switch."""
    q = db.query(models.ArpEntry)
    if switch_name:
        q = q.filter(models.ArpEntry.switch_name == switch_name)
    rows = q.order_by(desc(models.ArpEntry.captured_at)).limit(limit).all()
    return [
        {
            "id":          r.id,
            "switch_name": r.switch_name,
            "ip":          r.ip_address,
            "mac":         r.mac_address,
            "interface":   r.interface,
            "vlan":        r.vlan,
            "type":        r.arp_type,
            "age_seconds": r.age_seconds,
            "captured_at": utc_iso(r.captured_at),
        }
        for r in rows
    ]


@app.get("/api/ip-conflicts")
def ip_conflicts(db: Session = Depends(get_db)):
    """Return IPs that show up with multiple distinct MACs across the
    most recent ARP capture per (switch, ip).  This is the data
    visualization the dashboard's 'IP Conflicts' tab reads.

    IMPORTANT (multi-switch correctness): ARP is captured per switch at
    slightly different times — capture-all commits each switch in turn, the
    scheduler refreshes switches independently, and manual captures happen
    ad-hoc. Taking the "latest per (switch, ip)" across ALL of history then
    mixes rows captured hours apart, which produces false conflicts (e.g. a
    device that legitimately changed MAC during the day, or one switch's
    3-hour-stale row compared against another's fresh one). This grew worse
    as more switches were added. The fix: only consider ARP entries from the
    most recent capture ROUND — a lookback window anchored to the newest
    captured_at in the table — so every switch is compared on contemporaneous
    data. Window is configurable via IP_CONFLICT_WINDOW_MINUTES (default 15).
    """
    window_minutes = int(os.getenv("IP_CONFLICT_WINDOW_MINUTES", "15"))

    # Anchor the window to the newest ARP capture we have, not to wall-clock
    # "now": if the last capture round was 20 min ago we still want to compare
    # that whole round together, rather than returning nothing.
    newest_row = (
        db.query(models.ArpEntry)
        .order_by(desc(models.ArpEntry.captured_at))
        .first()
    )
    cutoff = None
    if newest_row is not None:
        cutoff = newest_row.captured_at - timedelta(minutes=window_minutes)

    # Pull the latest entry per (switch_name, ip_address) using a
    # straightforward Python pass — works on both sqlite and postgres.
    q = db.query(models.ArpEntry)
    if cutoff is not None:
        q = q.filter(models.ArpEntry.captured_at >= cutoff)
    all_rows = (
        q.order_by(
            models.ArpEntry.switch_name,
            models.ArpEntry.ip_address,
            desc(models.ArpEntry.captured_at),
        )
        .all()
    )
    seen = set()
    latest = []
    for r in all_rows:
        k = (r.switch_name, r.ip_address)
        if k in seen:
            continue
        seen.add(k)
        latest.append(r)

    by_ip = {}
    for r in latest:
        by_ip.setdefault(r.ip_address, []).append(r)

    conflicts = []
    for ip, rows in by_ip.items():
        macs = {r.mac_address for r in rows}
        if len(macs) > 1:
            conflicts.append({
                "ip": ip,
                "mac_count": len(macs),
                "entries": [
                    {
                        "switch_name": r.switch_name,
                        "mac":         r.mac_address,
                        "interface":   r.interface,
                        "vlan":        r.vlan,
                        "captured_at": utc_iso(r.captured_at),
                    }
                    for r in rows
                ],
            })
    # Sort by mac_count desc (most-conflicted first), then by IP
    conflicts.sort(key=lambda c: (-c["mac_count"], c["ip"]))

    # Always also return ALL latest ARP entries — when there are zero
    # conflicts the UI uses this list to show what was actually scanned.
    all_entries = [
        {
            "switch_name": r.switch_name,
            "ip":          r.ip_address,
            "mac":         r.mac_address,
            "interface":   r.interface,
            "vlan":        r.vlan,
            "type":        r.arp_type,
            "age_seconds": r.age_seconds,
            "captured_at": utc_iso(r.captured_at),
        }
        for r in sorted(latest, key=lambda x: (x.switch_name, x.ip_address))
    ]

    return {
        "checked_at":       utc_iso(models.ist_now()),
        "switches_scanned": len({r.switch_name for r in latest}),
        "unique_ips":       len(by_ip),
        "total_entries":    len(latest),
        "conflicts":        conflicts,
        "all_entries":      all_entries,
    }


# ─── Chatbot ───────────────────────────────────────────────────────

from pydantic import BaseModel as _BM

class ChatQuery(_BM):
    question: str
    switch:   str | None = None   # optional focus


@app.get("/api/chat/status")
def chat_status():
    return chatbot.health_check()


@app.post("/api/chat/query")
def chat_query(payload: ChatQuery, db: Session = Depends(get_db)):
    if not payload.question or not payload.question.strip():
        raise HTTPException(400, "question is required")
    try:
        result = chatbot.answer(db, payload.question.strip(), payload.switch)
        return result
    except RuntimeError as e:
        raise HTTPException(502, str(e))


# ── RAG (LangChain + ChromaDB) chat path ───────────────────────────────────
# Same request/response shape as /api/chat/query, so the frontend can switch
# to it by changing the URL only. Retrieves from the vector index instead of
# stuffing the whole DB summary into the prompt.

@app.get("/api/chat/rag-status")
def chat_rag_status():
    from rag import rag_health
    return rag_health()


@app.post("/api/chat/rag-query")
def chat_rag_query(payload: ChatQuery):
    if not payload.question or not payload.question.strip():
        raise HTTPException(400, "question is required")
    try:
        from rag import answer_rag
        return answer_rag(payload.question.strip(), payload.switch)
    except Exception as e:
        raise HTTPException(502, f"RAG query failed: {e}")


@app.post("/api/chat/reindex")
def chat_reindex(db: Session = Depends(get_db)):
    """Force a full rebuild of the vector index from current DB state."""
    try:
        from rag import reindex_all
        return reindex_all(db)
    except Exception as e:
        raise HTTPException(502, f"reindex failed: {e}")



# ============================================================================
# NOC_PORTAL_SSH_AUTH_V2
# Portal login/session guard — standalone.
#
# The source of truth is the switch fleet itself: credentials are proved by
# opening an SSH session to a switch in scope. There is no external identity
# provider, no local user table, and no separate portal password.
#
# This replaces NOC_PORTAL_MSS_AUTH_PORT_V1, which delegated to MSS AD Studio
# over MSS_NOC_VALIDATE_URL. That validator and every environment variable it
# read have been removed.
# ============================================================================

import os as _noc_os
import time as _noc_time
import json as _noc_json
import secrets as _noc_secrets
import urllib.request as _noc_urlrequest
import urllib.error as _noc_urlerror
from fastapi import Request as _NocRequest
from fastapi.responses import JSONResponse as _NocJSONResponse
from fastapi.responses import Response as _NocResponse

NOC_COOKIE_NAME = _noc_os.environ.get("NOC_COOKIE_NAME", "noc_portal_session")
NOC_SESSION_TTL_SECONDS = int(_noc_os.environ.get("NOC_SESSION_TTL_SECONDS", "28800"))
# ── Session store and helpers ──────────────────────────────────────────
# Retained from the previous implementation. Only the MSS Studio
# validator that used to sit alongside them has been removed.
_NOC_PORTAL_SESSIONS = {}


def _noc_now():
    return int(_noc_time.time())


def _noc_cleanup_sessions():
    now = _noc_now()
    expired = [
        token
        for token, session in _NOC_PORTAL_SESSIONS.items()
        if int(session.get("expires_at_epoch") or 0) <= now
    ]
    for token in expired:
        _NOC_PORTAL_SESSIONS.pop(token, None)


def _noc_public_session(session):
    return {
        "username": session.get("username"),
        "display_name": session.get("display_name") or session.get("username"),
        "email": session.get("email"),
        "is_superadmin": bool(session.get("is_superadmin")),
        "can_access_noc": True,
        "expires_at_epoch": session.get("expires_at_epoch"),
    }


def _noc_get_session_from_request(request):
    _noc_cleanup_sessions()
    token = request.cookies.get(NOC_COOKIE_NAME)
    if not token:
        return None

    session = _NOC_PORTAL_SESSIONS.get(token)
    if not session:
        return None

    if int(session.get("expires_at_epoch") or 0) <= _noc_now():
        _NOC_PORTAL_SESSIONS.pop(token, None)
        return None

    return session


def _noc_cookie_secure(request):
    forced = _noc_os.environ.get("NOC_COOKIE_SECURE", "").strip().lower()

    if forced in {"1", "true", "yes", "on"}:
        return True

    if forced in {"0", "false", "no", "off"}:
        return False

    return (request.headers.get("x-forwarded-proto") or request.url.scheme or "").lower() == "https"


@app.middleware("http")
async def _noc_portal_cookie_api_guard(request: _NocRequest, call_next):
    path = request.url.path

    if path.startswith("/api/noc/portal/"):
        return await call_next(request)

    if path.startswith("/api/"):
        if not _noc_get_session_from_request(request):
            return _NocJSONResponse(
                {"success": False, "error": "NOC portal login required."},
                status_code=401,
            )

    return await call_next(request)


# ─── NOC_PORTAL_LOCAL_ADMIN_V1 ──────────────────────────────────────────────
# Standalone portal credentials.
#
# The portal previously authenticated by opening an SSH session to a switch,
# which meant you could not log in at all until at least one reachable switch
# existed — awkward on a fresh deployment, and it failed outright whenever the
# fleet was unreachable.
#
# A single local administrator account is used instead. It is defined by
# environment variables so the credential is NOT baked into the source: the
# values below are only the fallback used when nothing is configured.
#
#     NOC_ADMIN_USERNAME   default "admin"
#     NOC_ADMIN_PASSWORD   default "MindSparks!008"
#
# Change it without touching code:
#     NOC_ADMIN_PASSWORD='...' docker compose up -d
#
# The password is compared with secrets.compare_digest, which takes the same
# time whether the first character is wrong or the last, so an attacker cannot
# recover it a character at a time by measuring response times. It is never
# logged and never returned by any endpoint.
#
# SSH credentials remain separate. Logging in here does NOT grant switch
# access on its own — switch operations use each switch's own stored username
# and password, exactly as the unattended capture loops do. /api/admin/login
# is still available when you want to prove SSH credentials and push them onto
# the fleet.
NOC_ADMIN_USERNAME = _noc_os.environ.get("NOC_ADMIN_USERNAME", "admin")
NOC_ADMIN_PASSWORD = _noc_os.environ.get("NOC_ADMIN_PASSWORD", "MindSparks!008")

if NOC_ADMIN_PASSWORD == "MindSparks!008":
    print("[auth] WARNING: the built-in default portal password is in use. "
          "Set NOC_ADMIN_PASSWORD to something unique before this is reachable "
          "outside a trusted network.", flush=True)


def _noc_check_portal_credentials(username: str, password: str) -> bool:
    """Constant-time check of the local administrator credentials."""
    u_ok = _noc_secrets.compare_digest(
        (username or "").strip().lower(), NOC_ADMIN_USERNAME.strip().lower())
    p_ok = _noc_secrets.compare_digest(password or "", NOC_ADMIN_PASSWORD)
    # Both comparisons always run: short-circuiting on the username would leak
    # whether a given username exists.
    return u_ok and p_ok


@app.post("/api/noc/portal/login")
async def _noc_portal_login(request: _NocRequest):
    """Portal login against the local administrator account.

    See NOC_PORTAL_LOCAL_ADMIN_V1 above for how the credential is configured
    and why the comparison is constant-time.
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")

    if not username or not password:
        return _NocJSONResponse(
            {"success": False, "error": "Username and password are required."},
            status_code=400,
        )

    if not _noc_check_portal_credentials(username, password):
        # Deliberately identical message for a bad username and a bad
        # password, so the response does not reveal which was wrong.
        print(f"[auth] failed portal login for '{username}'", flush=True)
        return _NocJSONResponse(
            {"success": False, "error": "Invalid username or password."},
            status_code=401,
        )

    token = _noc_secrets.token_urlsafe(32)
    session = {
        "username": NOC_ADMIN_USERNAME,
        "display_name": NOC_ADMIN_USERNAME,
        "email": None,
        "is_superadmin": True,
        "scope": ["*"],
        "created_at_epoch": _noc_now(),
        "expires_at_epoch": _noc_now() + NOC_SESSION_TTL_SECONDS,
    }
    _NOC_PORTAL_SESSIONS[token] = session
    print(f"[auth] portal login OK for '{NOC_ADMIN_USERNAME}'", flush=True)

    response = _NocJSONResponse({
        "success": True,
        "user": _noc_public_session(session),
    })
    response.set_cookie(
        key=NOC_COOKIE_NAME, value=token, max_age=NOC_SESSION_TTL_SECONDS,
        httponly=True, secure=_noc_cookie_secure(request),
        samesite="lax", path="/",
    )
    return response


@app.post("/api/noc/portal/logout")
async def _noc_portal_logout(request: _NocRequest):
    token = request.cookies.get(NOC_COOKIE_NAME)

    if token:
        _NOC_PORTAL_SESSIONS.pop(token, None)

    response = _NocJSONResponse({"success": True})
    response.delete_cookie(NOC_COOKIE_NAME, path="/")
    return response


@app.get("/api/noc/portal/me")
async def _noc_portal_me(request: _NocRequest):
    session = _noc_get_session_from_request(request)

    if not session:
        return _NocJSONResponse(
            {"success": False, "error": "Not logged in."},
            status_code=401,
        )

    return {"success": True, "user": _noc_public_session(session)}


@app.get("/api/noc/portal/nginx-auth")
async def _noc_portal_nginx_auth(request: _NocRequest):
    session = _noc_get_session_from_request(request)

    if not session:
        return _NocResponse(status_code=401)

    return _NocResponse(status_code=204)




# ═════════════════════════════════════════════════════════════════════
# SERVER MONITORING (additive feature)
# HPE servers polled via iLO 6 Redfish. Mirrors the switch pattern:
# CRUD + test + capture-now + metrics history + alert settings.
# Nothing here modifies any switch endpoint or table.
# ═════════════════════════════════════════════════════════════════════

import ilo_client
import metrics_stream
import metrics_collector

class ServerCreate(BaseModel):
    """Adding a server is deliberately minimal: a name, an address, and one
    set of credentials. The portal probes the address itself — first the iLO
    Redfish API, then SSH — and starts streaming whichever answers. No
    collection mode or second host to configure."""
    name: str
    host: str                    # server address (iLO or host OS — we probe both)
    username: str
    password: str
    location: str = ""
    description: str = ""
    poll_enabled: bool = True


class ServerUpdate(BaseModel):
    poll_enabled: bool | None = None
    poll_interval_seconds: int | None = None
    location: str | None = None
    description: str | None = None


class AlertSettingIn(BaseModel):
    sensor: str
    lower_threshold: int = 0
    lower_dwell_sec: int = 0
    upper_threshold: int = 0
    upper_dwell_sec: int = 0


def _get_server(db: Session, name: str) -> models.Server:
    srv = db.query(models.Server).filter(models.Server.name == name).first()
    if not srv:
        raise HTTPException(404, f"Server '{name}' not found")
    return srv


def _server_out(s: models.Server) -> dict:
    return {
        "id": s.id, "name": s.name,
        "ilo_host": s.ilo_host, "ilo_port": s.ilo_port,
        "location": s.location, "description": s.description,
        "poll_enabled": s.poll_enabled,
        "poll_interval_seconds": s.poll_interval_seconds,
        "collection_mode": s.collection_mode,
        "ssh_host": s.ssh_host,
        "last_source": s.last_source,
        "last_poll_status": s.last_poll_status,
        "last_poll_error": s.last_poll_error,
        "last_polled_at": utc_iso(s.last_polled_at),
        "created_at": utc_iso(s.created_at),
    }


def _capture_server_metrics(db: Session, srv: models.Server) -> dict:
    """Poll one server for REAL metrics and persist one row per sensor.

    Uses metrics_collector, which tries Redfish (iLO hardware counters) then
    SSH (/proc kernel counters). Simulation is opt-in only. If no backend
    yields real data the poll is recorded as an error and NOTHING is stored —
    an honest gap beats fabricated telemetry. Sensors a backend genuinely
    cannot measure come back as None and are skipped, not invented.

    Shared by the manual endpoint and the scheduler loop (one code path).
    """
    try:
        vals, source, note = metrics_collector.collect(srv)
    except metrics_collector.CollectionError as e:
        srv.last_poll_status = "error"
        srv.last_poll_error = str(e)
        srv.last_polled_at = models.ist_now()
        db.commit()
        raise HTTPException(
            502,
            f"Could not collect real metrics from '{srv.name}': {e}. "
            f"Configure iLO (Redfish) or SSH credentials, or set "
            f"SERVER_ALLOW_SIMULATION=1 to permit demo data."
        )

    now = models.ist_now()
    stored = {}
    for sensor, value in vals.items():
        if value is None:
            continue                      # not measurable here — don't fake it
        db.add(models.ServerMetric(
            server_id=srv.id, server_name=srv.name,
            sensor=sensor, value=int(round(float(value) * 100)),
            unit=ilo_client.SENSORS[sensor][1], source=source,
            captured_at=now,
        ))
        stored[sensor] = float(value)

    srv.last_poll_status = "ok" if source != "simulated" else "simulated"
    srv.last_poll_error = note or ""
    srv.last_source = source
    srv.last_polled_at = now
    db.commit()
    return {"source": source, "note": note, "captured_at": utc_iso(now),
            "sensors": stored,
            "unavailable": [k for k, v in vals.items() if v is None]}


@app.get("/api/servers")
def list_servers(db: Session = Depends(get_db)):
    rows = db.query(models.Server).order_by(models.Server.id).all()
    return [_server_out(s) for s in rows]


@app.post("/api/servers", status_code=201)
def create_server(payload: ServerCreate, db: Session = Depends(get_db),
                  session: dict = Depends(require_admin)):
    if db.query(models.Server).filter(models.Server.name == payload.name).first():
        raise HTTPException(409, f"Server '{payload.name}' already exists")

    # One address + one credential pair feeds BOTH backends; the collector
    # probes Redfish first, then SSH, and uses whichever responds.
    srv = models.Server(
        name=payload.name,
        ilo_host=payload.host, ilo_port=443,
        username=payload.username, password=payload.password,
        ssh_host=payload.host, ssh_port=22,
        ssh_username=payload.username, ssh_password=payload.password,
        collection_mode="auto",
        location=payload.location, description=payload.description,
        poll_enabled=payload.poll_enabled,
        poll_interval_seconds=1,          # streamed at ~1 Hz
    )
    srv.next_due_at = models.ist_now()
    db.add(srv)
    db.commit()
    db.refresh(srv)

    # Probe now so the user gets immediate, honest feedback.
    detected, err = _probe_server(srv)
    srv.last_source = detected or ""
    srv.last_poll_status = "ok" if detected else "error"
    srv.last_poll_error = "" if detected else (err or "")
    db.commit()
    db.refresh(srv)

    if detected:
        metrics_stream.manager.ensure(srv)   # start streaming immediately

    out = _server_out(srv)
    out["detected_source"] = detected
    out["detect_error"] = None if detected else err
    return out


def _probe_server(srv) -> tuple[str | None, str | None]:
    """Return (source, error). Tries Redfish then SSH with the one credential
    pair the operator supplied."""
    errs = []
    try:
        import ilo_client
        ilo_client.fetch_metrics(srv.ilo_host, srv.ilo_port,
                                 srv.username, srv.password)
        return "redfish", None
    except Exception as e:
        errs.append(f"iLO Redfish: {e}")
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(hostname=srv.ssh_host, port=srv.ssh_port,
                  username=srv.ssh_username, password=srv.ssh_password,
                  timeout=8, banner_timeout=8, auth_timeout=8,
                  look_for_keys=False, allow_agent=False)
        _i, o, _e = c.exec_command("head -1 /proc/stat", timeout=6)
        ok = o.read().decode().startswith("cpu")
        c.close()
        if ok:
            return "ssh", None
        errs.append("SSH: /proc/stat unreadable")
    except Exception as e:
        errs.append(f"SSH: {e}")
    return None, "; ".join(errs)


@app.delete("/api/servers/{name}", status_code=204)
def delete_server(name: str, db: Session = Depends(get_db),
                  session: dict = Depends(require_admin)):
    srv = _get_server(db, name)
    metrics_stream.manager.drop(name)     # stop its streaming worker
    db.delete(srv)
    db.commit()


@app.patch("/api/servers/{name}")
def update_server(name: str, payload: ServerUpdate,
                  db: Session = Depends(get_db),
                  session: dict = Depends(require_admin)):
    srv = _get_server(db, name)
    for field, val in payload.model_dump(exclude_none=True).items():
        setattr(srv, field, val)
    db.commit()
    db.refresh(srv)
    return _server_out(srv)


@app.post("/api/servers/{name}/test")
def test_server(name: str, db: Session = Depends(get_db),
                session: dict = Depends(require_admin)):
    srv = _get_server(db, name)
    ok, err = ilo_client.test_reachable(srv.ilo_host, srv.ilo_port,
                                        srv.username, srv.password)
    return {"server": name, "reachable": ok, "error": err}


@app.post("/api/servers/{name}/capture")
def capture_server_now(name: str, db: Session = Depends(get_db),
                       session: dict = Depends(require_admin)):
    srv = _get_server(db, name)
    result = _capture_server_metrics(db, srv)
    return {"server": name, **result}


@app.get("/api/servers/{name}/metrics")
def server_metrics(name: str,
                   sensor: str = "cpu_utilization",
                   range_key: str = "10min",
                   db: Session = Depends(get_db)):
    """History for one sensor over an iLO-style range:
    10min / 1hr / 24hr / 1week (matches the four range buttons)."""
    srv = _get_server(db, name)
    if sensor not in ilo_client.SENSORS:
        raise HTTPException(400, f"Unknown sensor '{sensor}'")
    ranges = {"10min": 10, "1hr": 60, "24hr": 60 * 24, "1week": 60 * 24 * 7}
    if range_key not in ranges:
        raise HTTPException(400, f"range_key must be one of {list(ranges)}")
    cutoff = models.ist_now() - timedelta(minutes=ranges[range_key])

    rows = (
        db.query(models.ServerMetric)
        .filter(models.ServerMetric.server_id == srv.id,
                models.ServerMetric.sensor == sensor,
                models.ServerMetric.captured_at >= cutoff)
        .order_by(models.ServerMetric.captured_at)
        .all()
    )
    # Downsample long ranges so the browser never receives >600 points
    step = max(1, len(rows) // 600)
    rows = rows[::step]
    unit = ilo_client.SENSORS[sensor][1]
    return {
        "server": name, "sensor": sensor, "unit": unit,
        "range": range_key,
        "source": srv.last_source,
        "simulated": srv.last_source == "simulated",
        "points": [
            {"t": utc_iso(r.captured_at), "v": r.value / 100.0}
            for r in rows
        ],
        "latest": (rows[-1].value / 100.0) if rows else None,
        "latest_at": utc_iso(rows[-1].captured_at) if rows else None,
    }


@app.get("/api/servers/{name}/sensors")
def server_sensors(name: str, db: Session = Depends(get_db)):
    """Sensor list for the dropdown (key + iLO-style label + unit)."""
    _get_server(db, name)
    return [{"key": k, "label": lbl, "unit": ilo_client.SENSORS[k][1]}
            for k, lbl in ilo_client.SENSOR_LABELS]


@app.get("/api/servers/{name}/alert-settings")
def get_alert_settings(name: str, sensor: str = "cpu_utilization",
                       db: Session = Depends(get_db)):
    srv = _get_server(db, name)
    row = (db.query(models.ServerAlertSetting)
           .filter(models.ServerAlertSetting.server_id == srv.id,
                   models.ServerAlertSetting.sensor == sensor).first())
    if not row:
        return {"server": name, "sensor": sensor,
                "lower_threshold": 0, "lower_dwell_sec": 0,
                "upper_threshold": 0, "upper_dwell_sec": 0}
    return {"server": name, "sensor": row.sensor,
            "lower_threshold": row.lower_threshold,
            "lower_dwell_sec": row.lower_dwell_sec,
            "upper_threshold": row.upper_threshold,
            "upper_dwell_sec": row.upper_dwell_sec}


@app.put("/api/servers/{name}/alert-settings")
def put_alert_settings(name: str, payload: AlertSettingIn,
                       db: Session = Depends(get_db),
                       session: dict = Depends(require_admin)):
    srv = _get_server(db, name)
    if payload.sensor not in ilo_client.SENSORS:
        raise HTTPException(400, f"Unknown sensor '{payload.sensor}'")
    row = (db.query(models.ServerAlertSetting)
           .filter(models.ServerAlertSetting.server_id == srv.id,
                   models.ServerAlertSetting.sensor == payload.sensor).first())
    if not row:
        row = models.ServerAlertSetting(server_id=srv.id, server_name=srv.name,
                                        sensor=payload.sensor)
        db.add(row)
    row.lower_threshold = payload.lower_threshold
    row.lower_dwell_sec = payload.lower_dwell_sec
    row.upper_threshold = payload.upper_threshold
    row.upper_dwell_sec = payload.upper_dwell_sec
    row.updated_at = models.ist_now()
    db.commit()
    return {"success": True, "server": name, "sensor": payload.sensor}


# ─── Live metrics stream (Server-Sent Events) ────────────────────────
# Backed by metrics_stream.manager: worker threads hold persistent
# connections and sample at ~1 Hz, publishing into memory. This endpoint
# drains that in-memory queue, so a browser sees a new point roughly one
# second after it actually happened (no 20 s scheduler lag, no DB polling).

from fastapi.responses import StreamingResponse as _StreamingResponse
import asyncio as _asyncio
import json as _json
import queue as _queue



def _persist_sample(server_id: int, server_name: str, vals: dict, source: str):
    """Throttled history write, called by the worker (not per sample)."""
    db = SessionLocal()
    try:
        now = models.ist_now()
        for sensor, value in vals.items():
            if value is None:
                continue
            db.add(models.ServerMetric(
                server_id=server_id, server_name=server_name,
                sensor=sensor, value=int(round(float(value) * 100)),
                unit=ilo_client.SENSORS[sensor][1], source=source,
                captured_at=now))
        srv = db.query(models.Server).filter(models.Server.id == server_id).first()
        if srv:
            srv.last_source = source
            srv.last_poll_status = "ok" if source != "simulated" else "simulated"
            srv.last_polled_at = now
            srv.last_poll_error = ""
        db.commit()
    finally:
        db.close()


metrics_stream.manager.set_persist(_persist_sample)


@app.on_event("startup")
def _start_metric_streams():
    """Spin up a streaming worker per enabled server."""
    db = SessionLocal()
    try:
        metrics_stream.manager.reconcile(db.query(models.Server).all())
    except Exception as e:
        print(f"[stream] startup failed: {e}", flush=True)
    finally:
        db.close()


@app.on_event("shutdown")
def _stop_metric_streams():
    metrics_stream.manager.stop_all()


@app.get("/api/servers/{name}/stream")
async def stream_server_metrics(name: str, sensor: str = "cpu_utilization"):
    """SSE: pushes each new real sample (~1 Hz) as soon as it is taken."""
    if sensor not in ilo_client.SENSORS:
        raise HTTPException(400, f"Unknown sensor '{sensor}'")

    db = SessionLocal()
    try:
        srv = db.query(models.Server).filter(models.Server.name == name).first()
        if not srv:
            raise HTTPException(404, f"Server '{name}' not found")
        metrics_stream.manager.ensure(srv)      # start on demand
    finally:
        db.close()

    q = metrics_stream.manager.subscribe(name)

    async def gen():
        # Send the most recent sample immediately so the chart isn't blank.
        last = metrics_stream.manager.latest(name)
        if last and "values" in last:
            v = last["values"].get(sensor)
            if v is not None:
                yield _sse(v, last)
        try:
            while True:
                try:
                    payload = await _asyncio.to_thread(q.get, True, 20)
                except _queue.Empty:
                    yield ": heartbeat\n\n"
                    continue
                if "error" in payload:
                    yield f"event: error\ndata: {_json.dumps({'error': payload['error']})}\n\n"
                    continue
                v = (payload.get("values") or {}).get(sensor)
                if v is None:
                    continue        # sensor not measurable here — send nothing
                yield _sse(v, payload)
        finally:
            metrics_stream.manager.unsubscribe(name, q)

    def _sse(value, payload):
        from datetime import datetime as _dt
        ts = _dt.fromtimestamp(payload.get("ts", 0)).isoformat()
        body = {"t": ts, "v": value,
                "unit": ilo_client.SENSORS[sensor][1],
                "source": payload.get("source", "")}
        return f"data: {_json.dumps(body)}\n\n"

    return _StreamingResponse(gen(), media_type="text/event-stream",
                              headers={"Cache-Control": "no-cache",
                                       "X-Accel-Buffering": "no"})


@app.get("/api/servers/{name}/live")
def server_live(name: str):
    """Latest in-memory sample + worker status (instant, no DB hit)."""
    last = metrics_stream.manager.latest(name) or {}
    return {"server": name,
            "status": metrics_stream.manager.status(name),
            "sample": last.get("values"),
            "source": last.get("source", ""),
            "ts": last.get("ts")}


# ═════════════════════════════════════════════════════════════════════
# AI AGENT — tool-calling assistant covering every portal feature.
# The legacy /api/chat/* endpoints are untouched and still work.
# ═════════════════════════════════════════════════════════════════════

import agent as _agent


class AgentQuery(_BM):
    question: str
    switch: str | None = None      # optional focus (the switch being viewed)


@app.post("/api/agent/query")
def agent_query(payload: AgentQuery,
                db: Session = Depends(get_db),
                x_admin_token: str | None = Header(default=None)):
    """Run the tool-calling agent. Returns the answer plus a full trace of
    which tools it called and what they returned."""
    if not payload.question.strip():
        raise HTTPException(400, "question is required")

    # Pass the operator's credentials through ONLY if they have a live
    # session; without it the agent cannot run any switch command.
    creds = None
    if x_admin_token:
        sess = auth.get_session(x_admin_token) if hasattr(auth, "get_session") else None
        if sess:
            try:
                creds = auth.credentials_for(sess)
            except Exception:
                creds = None

    try:
        result = _agent.run_agent(db, payload.question,
                                  focus_switch=payload.switch,
                                  credentials=creds)
    except RuntimeError as e:
        raise HTTPException(502, str(e))
    return result


@app.get("/api/agent/tools")
def agent_tools():
    """Introspection: what the agent can actually do."""
    return [{"name": t["name"], "description": t["description"]}
            for t in _agent.TOOLS]


@app.get("/api/agent/findings")
def agent_findings(db: Session = Depends(get_db)):
    """Proactive scan — problems the agent noticed without being asked.
    Pure rules, no LLM call, so it's instant and safe to poll."""
    return {"findings": _agent.proactive_findings(db),
            "checked_at": utc_iso(models.ist_now())}


# ═════════════════════════════════════════════════════════════════════
# iLO INVENTORY IMPORT + THRESHOLD ALERT STATUS
# ═════════════════════════════════════════════════════════════════════

import inventory as _inv


class ServerImport(_BM):
    """Add servers from the bundled iLO inventory.

    SECURITY: credentials are never stored in the catalog and are never
    defaulted. The operator supplies ONE username/password for the selected
    servers, exactly like unlocking a switch."""
    ilo_ips: list[str]
    username: str
    password: str


@app.get("/api/inventory/servers")
def list_inventory(db: Session = Depends(get_db)):
    """The iLO catalog. Passwords are never included — only a flag saying a
    default exists for that device."""
    return {"servers": _inv.public_inventory(db),
            "count": len(_inv.load_inventory())}


@app.post("/api/servers/import", status_code=201)
def import_servers(payload: ServerImport,
                   db: Session = Depends(get_db),
                   session: dict = Depends(require_admin)):
    if not payload.ilo_ips:
        raise HTTPException(400, "select at least one iLO address")
    if not (payload.username and payload.password):
        raise HTTPException(400, "a username and password are required")

    added, skipped, failed = [], [], []

    for ip in payload.ilo_ips:
        row = _inv.inventory_entry(ip)
        if not row:
            failed.append({"ilo_ip": ip, "error": "not in inventory"})
            continue

        if db.query(models.Server).filter(models.Server.ilo_host == ip).first():
            skipped.append({"ilo_ip": ip, "reason": "already added"})
            continue

        user, pwd = payload.username, payload.password

        name = _inv.suggested_name(row)
        # de-duplicate the display name if needed
        base, n = name, 2
        while db.query(models.Server).filter(models.Server.name == name).first():
            name = f"{base}-{n}"
            n += 1

        srv = models.Server(
            name=name,
            ilo_host=ip, ilo_port=443,
            username=user, password=pwd,
            ssh_host=ip, ssh_port=22,
            ssh_username=user, ssh_password=pwd,
            collection_mode="auto",
            location=f"Rack {row.get('rack')}" if row.get("rack") else "",
            description=_inv.describe_server(row),
            poll_enabled=True, poll_interval_seconds=1,
        )
        srv.next_due_at = models.ist_now()
        db.add(srv)
        db.commit()
        db.refresh(srv)

        detected, err = _probe_server(srv)
        srv.last_source = detected or ""
        srv.last_poll_status = "ok" if detected else "error"
        srv.last_poll_error = "" if detected else (err or "")
        db.commit()
        db.refresh(srv)

        if detected:
            metrics_stream.manager.ensure(srv)

        added.append({"name": name, "ilo_ip": ip,
                      "detected_source": detected,
                      "error": None if detected else err})

    return {"added": added, "skipped": skipped, "failed": failed,
            "added_count": len(added)}


import threshold_analysis as _thr


class ThresholdAnalyzeIn(_BM):
    sensors: list[str] = []          # empty = cpu + memory bus
    window_hours: int = 168          # use all retained history (7 days)


class ThresholdApplyIn(_BM):
    server: str | None = None        # None = every analyzed server
    sensor: str | None = None        # None = every analyzed sensor


@app.post("/api/servers/thresholds/analyze")
def run_threshold_analysis(payload: ThresholdAnalyzeIn,
                           db: Session = Depends(get_db),
                           session: dict = Depends(require_admin)):
    """Deep analysis: derive upper/lower thresholds for every server from its
    own metric history and STORE them in server_threshold_analysis."""
    if payload.window_hours < 1 or payload.window_hours > 24 * 30:
        raise HTTPException(400, "window_hours must be between 1 and 720")
    for s in payload.sensors:
        if s not in ilo_client.SENSORS:
            raise HTTPException(400, f"unknown sensor '{s}'")
    res = _thr.analyze_all(db, payload.sensors or None, payload.window_hours)
    _audit(db, "server.threshold.analyze", actor=_actor(session),
           target="all", target_type="server",
           summary=(f"threshold analysis over {payload.window_hours}h: "
                    f"{res['analyzed']} stored, {res['skipped']} skipped"),
           detail={"sensors": payload.sensors or _thr.DEFAULT_SENSORS})
    res["computed_at"] = utc_iso(res["computed_at"])
    return res


@app.get("/api/servers/thresholds")
def list_threshold_analysis(db: Session = Depends(get_db)):
    """The stored analysis: full distribution + recommendation per row."""
    rows = (db.query(models.ServerThresholdAnalysis)
            .order_by(models.ServerThresholdAnalysis.server_name,
                      models.ServerThresholdAnalysis.sensor).all())
    return {"thresholds": [_thr.row_out(r) for r in rows],
            "count": len(rows)}


@app.post("/api/servers/thresholds/apply")
def apply_threshold_analysis(payload: ThresholdApplyIn,
                             db: Session = Depends(get_db),
                             session: dict = Depends(require_admin)):
    """Copy stored recommendations into the live alert settings the alert
    engine enforces. Scope with server/sensor, or apply everything."""
    res = _thr.apply_to_alert_settings(db, payload.server, payload.sensor)
    if not res["count"]:
        raise HTTPException(404, "no stored analysis matches that scope — "
                                 "run the analysis first")
    _audit(db, "server.threshold.apply", actor=_actor(session),
           target=payload.server or "all", target_type="server",
           summary=f"applied derived thresholds to {res['count']} "
                   f"alert setting(s)",
           detail=res["applied"][:50])
    return res


@app.post("/api/servers/enrich-descriptions")
def enrich_server_descriptions(db: Session = Depends(get_db),
                               session: dict = Depends(require_admin)):
    """Backfill GPU model / owner / team onto servers already imported.

    The GPU catalog arrived after these servers were added, so their
    descriptions still read 'ProLiant DL380 Gen11'. This rewrites them to
    'L40S · Nishith · CNC · ProLiant DL380 Gen11' without re-importing —
    matching on the iLO address, so nothing else is touched.
    """
    updated, skipped = [], []
    for srv in db.query(models.Server).order_by(models.Server.name).all():
        row = _inv.inventory_entry(srv.ilo_host)
        if not row:
            skipped.append({"server": srv.name, "reason": "not in catalog"})
            continue
        new_desc = _inv.describe_server(row)
        if not new_desc or new_desc == (srv.description or ""):
            skipped.append({"server": srv.name, "reason": "already current"})
            continue
        srv.description = new_desc
        updated.append({"server": srv.name, "ilo": srv.ilo_host,
                        "description": new_desc})
    if updated:
        db.commit()
        _audit(db, "server.enrich", actor=_actor(session), target="all",
               target_type="server",
               summary=f"enriched {len(updated)} server description(s) with "
                       f"GPU model/owner/team")
    return {"updated": updated, "skipped": skipped, "count": len(updated)}


@app.get("/api/servers/alerts/{event_id}/metrics")
def server_alert_metrics(event_id: int, db: Session = Depends(get_db)):
    """Every sensor of that server at the instant the alert was raised.

    Survives the 7-day metric pruning, so the evidence behind an old alert
    is still answerable long after the raw history has gone.
    """
    ev = db.query(models.ServerAlertEvent).filter(
        models.ServerAlertEvent.id == event_id).first()
    if not ev:
        raise HTTPException(404, "alert event not found")
    rows = (db.query(models.ServerAlertMetricSnapshot)
            .filter(models.ServerAlertMetricSnapshot.event_id == event_id)
            .order_by(models.ServerAlertMetricSnapshot.sensor).all())
    return {
        "event": _alert_event_out(ev),
        "captured_at": utc_iso(rows[0].captured_at) if rows else None,
        "metrics": [{
            "sensor": r.sensor,
            "label": dict(ilo_client.SENSOR_LABELS).get(r.sensor, r.sensor),
            "value": (r.value or 0) / 100.0,
            "unit": r.unit or "",
            "is_trigger": bool(r.is_trigger),
            "sample_at": utc_iso(r.sample_at),
        } for r in rows],
        "count": len(rows),
    }


# Utilization bands for the fleet column. Without a baseline we use fixed
# bands; once a server has a DERIVED upper threshold (from its own history)
# the bands scale to it — 82% is over-utilized for a quiet VM but perfectly
# normal for a GPU trainer whose analysed ceiling is 96%.
UTIL_BANDS = [(5, "idle"), (30, "low"), (70, "medium")]
UTIL_FRACTIONS = [(0.10, "idle"), (0.45, "low"), (1.0, "medium")]


def _util_category(cpu: float | None, derived_upper: float | None) -> str:
    if cpu is None:
        return "unknown"
    if derived_upper and derived_upper > 0:
        # "over" means over THIS server's own analysed ceiling.
        if cpu >= derived_upper:
            return "over"
        frac = cpu / derived_upper
        for limit, label in UTIL_FRACTIONS:
            if frac < limit:
                return label
        return "medium"
    for limit, label in UTIL_BANDS:
        if cpu < limit:
            return label
    return "over"


@app.get("/api/servers/live-all")
def servers_live_all(db: Session = Depends(get_db)):
    """One call for the whole fleet: live CPU + memory and a utilization
    category per server. Backs the server column so the browser polls a
    single endpoint instead of one per server.

    Reads the in-memory stream samples (~1 s old); a server whose worker
    isn't running or whose credentials are wrong reports live=false with the
    reason, which is what drives the lock indicator in the list.
    """
    import time as _time
    rows = db.query(models.Server).order_by(models.Server.name).all()

    derived = {}
    for t in db.query(models.ServerThresholdAnalysis).filter(
            models.ServerThresholdAnalysis.sensor == "cpu_utilization").all():
        derived[t.server_name] = (t.rec_upper_x100 or 0) / 100.0

    out = []
    for s in rows:
        last = metrics_stream.manager.latest(s.name) or {}
        vals = last.get("values") or {}
        age = (_time.time() - (last.get("ts") or 0)) if last.get("ts") else None
        fresh = age is not None and age < 20

        cpu = vals.get("cpu_utilization") if fresh else None
        mem = vals.get("memory_bus_utilization") if fresh else None

        # fall back to the newest stored sample so a brief stream hiccup
        # doesn't blank the column
        if cpu is None:
            r = (db.query(models.ServerMetric)
                 .filter(models.ServerMetric.server_id == s.id,
                         models.ServerMetric.sensor == "cpu_utilization")
                 .order_by(desc(models.ServerMetric.captured_at)).first())
            if r:
                cpu = (r.value or 0) / 100.0
        if mem is None:
            r = (db.query(models.ServerMetric)
                 .filter(models.ServerMetric.server_id == s.id,
                         models.ServerMetric.sensor == "memory_bus_utilization")
                 .order_by(desc(models.ServerMetric.captured_at)).first())
            if r:
                mem = (r.value or 0) / 100.0

        out.append({
            "server": s.name,
            "cpu": round(cpu, 1) if cpu is not None else None,
            "memory": round(mem, 1) if mem is not None else None,
            "category": _util_category(cpu, derived.get(s.name)),
            "derived_upper": derived.get(s.name),
            "live": bool(fresh),
            "source": last.get("source") or s.last_source or "",
            "status": s.last_poll_status or "",
            "error": s.last_poll_error or "",
            "locked": _is_auth_failure(s.last_poll_error or ""),
        })
    return {"servers": out, "checked_at": utc_iso(models.ist_now())}


def _is_auth_failure(err: str) -> bool:
    """Credential problems get a lock icon and an Unlock button; anything
    else (timeout, no route) is a plain error — retrying with a new password
    would be pointless and misleading."""
    low = (err or "").lower()
    return any(s in low for s in (
        "401", "unauthorized", "authentication", "auth failed",
        "permission denied", "invalid credential", "bad password",
        "login incorrect", "access denied", "forbidden", "403"))


class ServerUnlock(_BM):
    username: str
    password: str


@app.post("/api/servers/{name}/unlock")
def unlock_server(name: str, payload: ServerUnlock,
                  db: Session = Depends(get_db),
                  session: dict = Depends(require_admin)):
    """Try different credentials against a server, exactly like unlocking a
    switch. The credentials are PROVED first (Redfish, then SSH) and only
    stored if something actually answers — so a wrong password can never
    silently replace a working one. On success the streaming worker is
    restarted with the new credentials.
    """
    srv = _get_server(db, name)
    if not payload.username or not payload.password:
        raise HTTPException(400, "username and password are required")

    old = (srv.username, srv.password, srv.ssh_username, srv.ssh_password)
    srv.username, srv.password = payload.username, payload.password
    srv.ssh_username, srv.ssh_password = payload.username, payload.password

    detected, err = _probe_server(srv)
    if not detected:
        # roll back — never persist credentials that don't work
        (srv.username, srv.password,
         srv.ssh_username, srv.ssh_password) = old
        db.commit()
        _audit(db, "server.unlock", actor=_actor(session), target=name,
               target_type="server", success=False,
               summary=f"unlock failed for '{name}': {err}")
        raise HTTPException(401, f"Credentials rejected by '{name}': {err}")

    srv.last_source = detected
    srv.last_poll_status = "ok"
    srv.last_poll_error = ""
    srv.last_polled_at = models.ist_now()
    db.commit()
    db.refresh(srv)

    metrics_stream.manager.drop(name)        # kill the worker using old creds
    metrics_stream.manager.ensure(srv)       # restart with the new ones

    _audit(db, "server.unlock", actor=_actor(session), target=name,
           target_type="server",
           summary=f"unlocked '{name}' via {detected}")
    return {"server": name, "unlocked": True, "source": detected,
            **_server_out(srv)}


@app.get("/api/servers/alert-status")
def servers_alert_status(db: Session = Depends(get_db)):
    """Per-server threshold state so the server list can colour itself:

        state = 'ok'           -> thresholds respected      (green)
                'breach'       -> a threshold is crossed    (red)
                'unknown'      -> configured but no samples yet
                'unconfigured' -> no thresholds set

    Dwell time is enforced: a value must stay beyond the threshold for the
    whole dwell window before it is reported as a breach.
    """
    return {"servers": _inv.evaluate_all(db),
            "checked_at": utc_iso(models.ist_now())}


def _alert_event_out(ev: models.ServerAlertEvent) -> dict:
    return {
        "id": ev.id, "server": ev.server_name, "sensor": ev.sensor,
        "kind": ev.kind, "threshold": ev.threshold, "dwell_sec": ev.dwell_sec,
        "value": (ev.value or 0) / 100.0,
        "worst_value": (ev.worst_value or 0) / 100.0,
        "unit": ev.unit or "",
        "state": ev.state,
        "raised_at": utc_iso(ev.raised_at),
        "cleared_at": utc_iso(ev.cleared_at),
        "acknowledged_by": ev.acknowledged_by or "",
        "acknowledged_at": utc_iso(ev.acknowledged_at),
    }


@app.get("/api/servers/alerts")
def list_server_alerts(include_cleared: bool = True, limit: int = 100,
                       db: Session = Depends(get_db)):
    """The Server Audits feed: active alerts first, then recent history."""
    q = db.query(models.ServerAlertEvent)
    if not include_cleared:
        q = q.filter(models.ServerAlertEvent.state == "active")
    rows = (q.order_by(
                # active before cleared, newest first within each
                models.ServerAlertEvent.state.asc(),
                desc(models.ServerAlertEvent.raised_at))
            .limit(min(limit, 500)).all())
    active = sum(1 for r in rows if r.state == "active")
    return {"alerts": [_alert_event_out(r) for r in rows],
            "active_count": active,
            "checked_at": utc_iso(models.ist_now())}


@app.post("/api/servers/alerts/{event_id}/ack")
def acknowledge_server_alert(event_id: int, db: Session = Depends(get_db),
                             session: dict = Depends(require_admin)):
    ev = db.query(models.ServerAlertEvent).filter(
        models.ServerAlertEvent.id == event_id).first()
    if not ev:
        raise HTTPException(404, "alert event not found")
    if ev.acknowledged_at:
        return _alert_event_out(ev)
    ev.acknowledged_by = _actor(session)
    ev.acknowledged_at = models.ist_now()
    db.commit()
    _audit(db, "server.alert.ack", actor=ev.acknowledged_by,
           target=ev.server_name, target_type="server",
           summary=f"acknowledged {ev.sensor} {ev.kind}-threshold alert "
                   f"(#{ev.id})",
           detail={"event_id": ev.id, "sensor": ev.sensor})
    return _alert_event_out(ev)


# ═════════════════════════════════════════════════════════════════════
# SWITCH INVENTORY IMPORT  +  EDIT (rename / details) FOR BOTH TYPES
# ═════════════════════════════════════════════════════════════════════

class SwitchImport(_BM):
    """Add switches from the bundled catalog. No credentials are stored in
    the catalog — you supply them here, once, for the whole selection."""
    ips: list[str]
    username: str
    password: str


class SwitchEdit(_BM):
    """Rename / re-describe a switch. Credentials are optional: send them
    only if you want to rotate what's stored for the background scheduler."""
    name: str | None = None
    host: str | None = None
    port: int | None = None
    device_type: str | None = None
    location: str | None = None
    username: str | None = None
    password: str | None = None


class ServerEdit(_BM):
    name: str | None = None
    ilo_host: str | None = None
    location: str | None = None
    description: str | None = None
    poll_enabled: bool | None = None
    username: str | None = None
    password: str | None = None


@app.get("/api/inventory/switches")
def list_switch_inventory(db: Session = Depends(get_db)):
    return {"switches": _inv.public_switch_inventory(db),
            "count": len(_inv.load_switch_inventory())}


@app.post("/api/switches/import", status_code=201)
def import_switches(payload: SwitchImport,
                    db: Session = Depends(get_db),
                    session: dict = Depends(require_admin)):
    if not payload.ips:
        raise HTTPException(400, "select at least one switch")
    if not (payload.username and payload.password):
        raise HTTPException(400, "a username and password are required")

    added, skipped, failed = [], [], []
    for ip in payload.ips:
        row = _inv.switch_entry(ip)
        if not row:
            failed.append({"ip": ip, "error": "not in catalog"})
            continue
        if db.query(models.Switch).filter(models.Switch.host == ip).first():
            skipped.append({"ip": ip, "reason": "already added"})
            continue

        name = row.get("name") or f"switch-{ip.replace('.', '-')}"
        base, n = name, 2
        while db.query(models.Switch).filter(models.Switch.name == name).first():
            name = f"{base}-{n}"
            n += 1

        sw = models.Switch(
            name=name, host=ip, port=22,
            device_type=row.get("device_type", "aruba_aoscx"),
            username=payload.username, password=payload.password,
            location=(f"Rack {row['rack']}" if row.get("rack") else "")
                     + (f" · {row['role']}" if row.get("role") else ""),
        )
        db.add(sw)
        db.commit()
        db.refresh(sw)

        ok, err = switch_manager.test_reachable(
            sw, credentials_override={"username": payload.username,
                                      "password": payload.password})
        added.append({"name": name, "ip": ip, "reachable": ok,
                      "error": None if ok else err})

    return {"added": added, "skipped": skipped, "failed": failed,
            "added_count": len(added)}


@app.patch("/api/switches/{name}")
def edit_switch(name: str, payload: SwitchEdit,
                db: Session = Depends(get_db),
                session: dict = Depends(require_admin)):
    sw = _get_switch(db, name)
    _ensure_scope(session, name)
    data = payload.model_dump(exclude_none=True)

    new_name = data.get("name")
    if new_name and new_name != sw.name:
        if db.query(models.Switch).filter(models.Switch.name == new_name).first():
            raise HTTPException(409, f"A switch named '{new_name}' already exists")
        # Denormalised switch_name columns must follow the rename, otherwise
        # snapshots / port stats / ARP / logs would orphan themselves.
        for model in (models.Snapshot, models.PortStat,
                      models.ArpEntry, models.CommandLog,
                      models.AutoCaptureSetting):
            db.query(model).filter(model.switch_id == sw.id).update(
                {"switch_name": new_name}, synchronize_session=False)

    for field, val in data.items():
        setattr(sw, field, val)
    db.commit()
    db.refresh(sw)
    return {"name": sw.name, "host": sw.host, "port": sw.port,
            "device_type": sw.device_type, "location": sw.location}


@app.patch("/api/servers/{name}/edit")
def edit_server(name: str, payload: ServerEdit,
                db: Session = Depends(get_db),
                session: dict = Depends(require_admin)):
    srv = _get_server(db, name)
    data = payload.model_dump(exclude_none=True)

    new_name = data.get("name")
    renamed = bool(new_name and new_name != srv.name)
    if renamed:
        if db.query(models.Server).filter(models.Server.name == new_name).first():
            raise HTTPException(409, f"A server named '{new_name}' already exists")
        for model in (models.ServerMetric, models.ServerAlertSetting):
            db.query(model).filter(model.server_id == srv.id).update(
                {"server_name": new_name}, synchronize_session=False)
        metrics_stream.manager.drop(srv.name)   # old worker keys off the name

    # Credentials feed both collection paths.
    if "username" in data:
        srv.ssh_username = data["username"]
    if "password" in data:
        srv.ssh_password = data["password"]
    if "ilo_host" in data:
        srv.ssh_host = data["ilo_host"]

    for field, val in data.items():
        setattr(srv, field, val)
    db.commit()
    db.refresh(srv)

    if srv.poll_enabled:
        metrics_stream.manager.ensure(srv)      # restart under the new name
    return _server_out(srv)


# ═════════════════════════════════════════════════════════════════════
# AGENT: correct a rejected switch command
# ═════════════════════════════════════════════════════════════════════

import command_advisor as _advisor


class CommandFix(_BM):
    command: str
    error: str = ""
    output: str = ""
    use_model: bool = True


@app.post("/api/switches/{name}/suggest-command")
def suggest_command(name: str, payload: CommandFix,
                    db: Session = Depends(get_db),
                    session: dict = Depends(require_admin)):
    """When a command is rejected by the switch, return runnable corrections.

    Deterministic rules answer instantly and offline; the agent model is then
    asked (best-effort) to pick the best one and explain the mistake. Every
    suggestion is drawn from the vendor's read-only allow-list, so clicking
    one can never run a destructive command.
    """
    sw = _get_switch(db, name)
    _ensure_scope(session, name)

    result = _advisor.suggest(sw.device_type, payload.command,
                              payload.error, payload.output)
    if payload.use_model and result["suggestions"]:
        result = _advisor.refine_with_model(result, sw.name)
    result["switch"] = name
    return result


# ═════════════════════════════════════════════════════════════════════
# LINK INSIGHTS — port-channel ↔ server correlation
# Matches LAG descriptions (server name / iLO last octet) against the
# registered server fleet and joins live sensor data plus an estimated
# CPU attribution for the link's traffic. Read-only: DB queries only.
# ═════════════════════════════════════════════════════════════════════

import link_insights as _links


@app.get("/api/link-insights")
def link_insights_view(switch_name: str = "", db: Session = Depends(get_db)):
    res = _links.insights(db, switch_name or None)
    res["checked_at"] = utc_iso(res["checked_at"])
    return res


@app.get("/api/link-insights/diagnose")
def link_insights_diagnose(switch_name: str = "", db: Session = Depends(get_db)):
    """Why is nothing matching? Reports the four preconditions per switch."""
    res = _links.diagnose(db, switch_name or None)
    res["checked_at"] = utc_iso(res["checked_at"])
    return res


# ═════════════════════════════════════════════════════════════════════
# LACP CONFIGURATION MODULE — one-click LAG deployment
# Preflight validates live switch state; deploy runs in a worker thread
# with live progress, stop-on-failure + rollback, post-verification and
# a persistent deployment history. Gated exactly like the config write
# path (CONFIG_APPLY_ENABLED + X-Apply-Token).
# ═════════════════════════════════════════════════════════════════════

import lacp_deploy as _lacp


class LacpRequest(_BM):
    source_switch: str
    dest_switch: str
    lag_id: int
    lacp_mode: str = "active"            # active | passive (source side)
    speed: str = "auto"                  # auto | 1G | 10G | 25G | 40G | 100G
    description: str = ""
    members: dict = {}                   # {switch_name: [interfaces]}


def _lacp_plan(db, payload: LacpRequest, creds_by_switch: dict) -> list[dict]:
    """Build the per-switch execution plan (source first). Also enforces the
    request-shape rules that don't need a device connection."""
    if payload.source_switch == payload.dest_switch:
        raise HTTPException(400, "source and destination must be different switches")
    if payload.lacp_mode not in ("active", "passive"):
        raise HTTPException(400, "lacp_mode must be 'active' or 'passive'")
    if payload.speed not in _lacp.SPEED_CHOICES:
        raise HTTPException(400, f"speed must be one of {list(_lacp.SPEED_CHOICES)}")
    if not (1 <= payload.lag_id <= 4096):
        raise HTTPException(400, "lag_id must be between 1 and 4096")

    plan = []
    for role, name in (("source", payload.source_switch),
                       ("dest",   payload.dest_switch)):
        sw = _get_switch(db, name)
        members = [m.strip() for m in (payload.members.get(name) or []) if m.strip()]
        if not members:
            raise HTTPException(400, f"select at least one member interface on {name}")
        if len(members) != len(set(members)):
            raise HTTPException(400, f"duplicate member interfaces on {name}")

        # passive+passive never negotiates — the far side is forced active.
        mode = payload.lacp_mode if role == "source" else \
            ("active" if payload.lacp_mode == "passive" else payload.lacp_mode)

        try:
            cli = _lacp.generate_cli(sw.device_type, payload.lag_id, mode,
                                     members, payload.description)
        except ValueError as e:
            raise HTTPException(400, str(e))

        # Plain-data stub: the worker thread runs after this request's DB
        # session is gone, and a committed session expires its ORM rows —
        # touching `sw` there would raise DetachedInstanceError.
        import types as _types
        sw_stub = _types.SimpleNamespace(
            name=sw.name, host=sw.host, port=sw.port,
            device_type=sw.device_type,
            username=sw.username, password=sw.password)

        plan.append({
            "role": role, "name": sw.name, "device_type": sw.device_type,
            "lag_id": payload.lag_id, "mode": mode, "members": members,
            "cli": cli, "sw_stub": sw_stub,
            "creds": creds_by_switch.get(name),
        })
    return plan


@app.post("/api/lacp/preflight")
def lacp_preflight(payload: LacpRequest,
                   db: Session = Depends(get_db),
                   session: dict = Depends(require_admin)):
    """Run all five validation rules against LIVE state on both switches.
    Read-only. Also returns the CLI that Configure LACP would send."""
    for name in (payload.source_switch, payload.dest_switch):
        _ensure_scope(session, name)
    creds = {n: {"username": _get_switch(db, n).username,
                 "password": _get_switch(db, n).password}
             for n in (payload.source_switch, payload.dest_switch)}
    sess_creds = auth.credentials_for(session)
    if sess_creds and sess_creds.get("username"):
        creds = {n: sess_creds for n in creds}

    plan = _lacp_plan(db, payload, creds)
    results = []
    for entry in plan:
        res = _lacp.preflight_switch(entry["sw_stub"], entry["lag_id"],
                                     entry["members"], payload.speed,
                                     entry["creds"])
        res["role"] = entry["role"]
        res["mode"] = entry["mode"]
        res["cli"] = entry["cli"]["all"]
        results.append(res)

    all_ok = all(r["ok"] for r in results)
    _audit(db, "lacp.preflight", actor=_actor(session),
           target=f"{payload.source_switch}+{payload.dest_switch}",
           target_type="switch",
           summary=f"LACP preflight for LAG {payload.lag_id}: "
                   f"{'ok' if all_ok else 'violations found'}",
           detail={"lag_id": payload.lag_id, "ok": all_ok},
           success=all_ok)
    return {"ok": all_ok, "results": results,
            "note": ("destination side is forced to lacp mode active because "
                     "passive+passive never forms a bundle"
                     if payload.lacp_mode == "passive" else "")}


def _lacp_dep_out(dep: models.LacpDeployment) -> dict:
    return {
        "id": dep.id,
        "created_at": utc_iso(dep.created_at),
        "finished_at": utc_iso(dep.finished_at),
        "duration_sec": dep.duration_sec or 0,
        "user": dep.user, "source_switch": dep.source_switch,
        "dest_switch": dep.dest_switch, "lag_id": dep.lag_id,
        "lacp_mode": dep.lacp_mode, "speed": dep.speed,
        "description": dep.description,
        "members": _pjson.loads(dep.members or "{}"),
        "status": dep.status, "error": dep.error or "",
        "steps": _pjson.loads(dep.steps or "[]"),
        "verification": _pjson.loads(dep.verification or "{}"),
    }


@app.post("/api/lacp/deploy", status_code=201)
def lacp_deploy(payload: LacpRequest,
                db: Session = Depends(get_db),
                session: dict = Depends(require_admin),
                x_apply_token: str | None = Header(default=None)):
    """One click: validate → configure both switches → verify. Runs in a
    background worker; poll GET /api/lacp/deployments/{id} for progress."""
    try:
        _apply.assert_allowed(x_apply_token)
    except _apply.ApplyDisabled as e:
        raise HTTPException(403, str(e))

    for name in (payload.source_switch, payload.dest_switch):
        _ensure_scope(session, name)
    creds = {n: {"username": _get_switch(db, n).username,
                 "password": _get_switch(db, n).password}
             for n in (payload.source_switch, payload.dest_switch)}
    sess_creds = auth.credentials_for(session)
    if sess_creds and sess_creds.get("username"):
        creds = {n: sess_creds for n in creds}

    plan = _lacp_plan(db, payload, creds)

    # Preflight is not optional: deploy re-runs it and refuses on violations,
    # so the UI can't skip validation and neither can a raw API call.
    for entry in plan:
        res = _lacp.preflight_switch(entry["sw_stub"], entry["lag_id"],
                                     entry["members"], payload.speed,
                                     entry["creds"])
        if not res["ok"]:
            fails = [c for c in res["checks"] if c["status"] == "fail"]
            raise HTTPException(409, {
                "error": f"preflight failed on {entry['name']}",
                "checks": fails})

    dep = models.LacpDeployment(
        user=_actor(session),
        source_switch=payload.source_switch,
        dest_switch=payload.dest_switch,
        lag_id=payload.lag_id, lacp_mode=payload.lacp_mode,
        speed=payload.speed, description=payload.description,
        members=_pjson.dumps(payload.members),
        status="running",
    )
    db.add(dep)
    db.commit()
    db.refresh(dep)

    _audit(db, "lacp.deploy", actor=dep.user,
           target=f"{payload.source_switch}+{payload.dest_switch}",
           target_type="switch",
           summary=f"LACP deploy started: LAG {payload.lag_id} "
                   f"({payload.lacp_mode})",
           detail={"deployment_id": dep.id,
                   "members": payload.members})

    _lacp.start_deployment(dep.id, plan)
    return _lacp_dep_out(dep)


@app.get("/api/lacp/exec-status")
def lacp_exec_status():
    """How LACP changes reach the switches: 'direct' SSH from the portal, or
    'winrm' — the enterprise path through the Windows jump host (WinRM →
    PowerShell → switch), the same mechanism AD Studio uses for AD changes.
    In winrm mode this also probes the jump host so the UI can show whether
    the path is up before anyone hits Deploy."""
    import winrm_executor as _wx
    mode = _wx.exec_mode()
    out = {"mode": mode,
           "jump_host": os.getenv("WINRM_HOST", "") if mode == "winrm" else None}
    if mode == "winrm":
        out["jump_host_status"] = _wx.test_connection()
    return out


@app.get("/api/lacp/deployments")
def lacp_history(limit: int = 50, db: Session = Depends(get_db)):
    rows = (db.query(models.LacpDeployment)
            .order_by(desc(models.LacpDeployment.created_at))
            .limit(min(limit, 200)).all())
    return [_lacp_dep_out(r) for r in rows]


@app.get("/api/lacp/deployments/{dep_id}")
def lacp_deployment(dep_id: int, db: Session = Depends(get_db)):
    dep = db.query(models.LacpDeployment).filter(
        models.LacpDeployment.id == dep_id).first()
    if not dep:
        raise HTTPException(404, "deployment not found")
    out = _lacp_dep_out(dep)
    out["logs"] = dep.logs or ""
    return out


# ═════════════════════════════════════════════════════════════════════
# PHASE 1 — CONFIG TEMPLATES · PREVIEW · COMPLIANCE · AUDIT
#
# READ-ONLY GUARANTEE: no endpoint below opens an SSH session or writes
# to a device. Templates are rendered and validated in-process; compliance
# reads snapshots already in the database. Applying configuration is a
# later phase, deliberately not implemented here.
# ═════════════════════════════════════════════════════════════════════

import json as _pjson
import template_engine as _tpl
import compliance as _compl
import builtin_templates as _bt


def _actor(session: dict | None) -> str:
    if not session:
        return "unknown"
    return session.get("username") or session.get("user") or "unknown"


def _audit(db, action: str, *, actor: str = "", target: str = "",
           target_type: str = "", summary: str = "", detail=None,
           success: bool = True, source_ip: str = ""):
    ev = models.AuditEvent(
        actor=actor or "unknown", action=action,
        target=target, target_type=target_type,
        summary=summary[:2000],
        detail=_pjson.dumps(detail, default=str)[:8000] if detail else "",
        success=success, source_ip=source_ip,
    )
    db.add(ev)
    db.commit()
    return ev


def _tpl_out(t: models.ConfigTemplate) -> dict:
    try:
        variables = _pjson.loads(t.variables or "[]")
    except Exception:
        variables = []
    return {"id": t.id, "name": t.name, "category": t.category,
            "device_type": t.device_type, "description": t.description,
            "body": t.body, "variables": variables,
            "builtin": t.builtin, "created_by": t.created_by,
            "updated_at": utc_iso(t.updated_at)}


class TemplateIn(_BM):
    name: str
    category: str = "general"
    device_type: str = ""
    description: str = ""
    body: str
    variables: list[dict] = []


class TemplateEdit(_BM):
    name: str | None = None
    category: str | None = None
    device_type: str | None = None
    description: str | None = None
    body: str | None = None
    variables: list[dict] | None = None


class PreviewIn(_BM):
    """Render a template for one or more switches. Nothing is executed."""
    template_id: int
    variables: dict = {}
    switches: list[str] = []          # empty = just render, no targets


class RuleIn(_BM):
    name: str
    kind: str
    pattern: str
    description: str = ""
    threshold: int | None = None
    severity: str = "medium"
    device_type: str = ""
    enabled: bool = True


# ── startup: seed built-ins ───────────────────────────────────────────

@app.on_event("startup")
def _seed_phase1():
    db = SessionLocal()
    try:
        n = _bt.seed_builtin_templates(db, models, _pjson)
        m = _compl.seed_default_rules(db)
        if n or m:
            print(f"[phase1] seeded {n} template(s), {m} compliance rule(s)",
                  flush=True)
    except Exception as e:
        print(f"[phase1] seed skipped: {e}", flush=True)
    finally:
        db.close()


# ── templates ─────────────────────────────────────────────────────────

@app.get("/api/templates")
def list_templates(device_type: str = "", db: Session = Depends(get_db)):
    q = db.query(models.ConfigTemplate)
    if device_type:
        # vendor-neutral templates ("" device_type) always apply
        q = q.filter(models.ConfigTemplate.device_type.in_([device_type, ""]))
    return [_tpl_out(t) for t in q.order_by(models.ConfigTemplate.name).all()]


@app.post("/api/templates", status_code=201)
def create_template(payload: TemplateIn, db: Session = Depends(get_db),
                    session: dict = Depends(require_admin)):
    if db.query(models.ConfigTemplate).filter(
            models.ConfigTemplate.name == payload.name).first():
        raise HTTPException(409, f"Template '{payload.name}' already exists")

    # Reject a template that cannot render or that contains destructive verbs.
    declared = _tpl.declared_variables(payload.body)
    named = {v.get("name") for v in payload.variables}
    missing = [d for d in declared if d not in named]
    if missing:
        raise HTTPException(
            400, f"Template uses variables with no schema entry: {missing}")

    scan = _tpl.safety_scan(payload.body)
    if scan["blockers"]:
        raise HTTPException(400, f"Template rejected: {scan['blockers']}")

    t = models.ConfigTemplate(
        name=payload.name, category=payload.category,
        device_type=payload.device_type, description=payload.description,
        body=payload.body, variables=_pjson.dumps(payload.variables),
        builtin=False, created_by=_actor(session),
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    _audit(db, "template.create", actor=_actor(session), target=t.name,
           target_type="template", summary=f"created template '{t.name}'",
           detail={"device_type": t.device_type, "warnings": scan["warnings"]})
    return _tpl_out(t)


@app.patch("/api/templates/{template_id}")
def update_template(template_id: int, payload: TemplateEdit,
                    db: Session = Depends(get_db),
                    session: dict = Depends(require_admin)):
    t = db.query(models.ConfigTemplate).filter(
        models.ConfigTemplate.id == template_id).first()
    if not t:
        raise HTTPException(404, "template not found")
    if t.builtin:
        raise HTTPException(
            403, "Built-in templates are read-only. Duplicate it to customise.")

    data = payload.model_dump(exclude_none=True)
    if "body" in data:
        scan = _tpl.safety_scan(data["body"])
        if scan["blockers"]:
            raise HTTPException(400, f"Template rejected: {scan['blockers']}")
    if "variables" in data:
        data["variables"] = _pjson.dumps(data["variables"])

    for k, v in data.items():
        setattr(t, k, v)
    t.updated_at = models.ist_now()
    db.commit()
    db.refresh(t)
    _audit(db, "template.update", actor=_actor(session), target=t.name,
           target_type="template", summary=f"updated template '{t.name}'",
           detail={"fields": sorted(data.keys())})
    return _tpl_out(t)


@app.delete("/api/templates/{template_id}", status_code=204)
def delete_template(template_id: int, db: Session = Depends(get_db),
                    session: dict = Depends(require_admin)):
    t = db.query(models.ConfigTemplate).filter(
        models.ConfigTemplate.id == template_id).first()
    if not t:
        raise HTTPException(404, "template not found")
    if t.builtin:
        raise HTTPException(403, "Built-in templates cannot be deleted")
    name = t.name
    db.delete(t)
    db.commit()
    _audit(db, "template.delete", actor=_actor(session), target=name,
           target_type="template", summary=f"deleted template '{name}'")


@app.post("/api/templates/preview")
def preview_template(payload: PreviewIn, db: Session = Depends(get_db),
                     session: dict = Depends(require_admin)):
    """Render the template and show exactly what WOULD run — per switch.

    This never contacts a device. It also diffs the rendered commands against
    the switch's latest snapshot so you can see which lines are already
    present (no-ops) and which would be new.
    """
    t = db.query(models.ConfigTemplate).filter(
        models.ConfigTemplate.id == payload.template_id).first()
    if not t:
        raise HTTPException(404, "template not found")
    try:
        schema = _pjson.loads(t.variables or "[]")
    except Exception:
        schema = []

    targets = payload.switches or []
    per_switch = []

    if not targets:
        base = _tpl.preview(t.body, schema, payload.variables, t.device_type)
        per_switch.append({"switch": None, **base})
    else:
        for name in targets:
            sw = db.query(models.Switch).filter(
                models.Switch.name == name).first()
            if not sw:
                per_switch.append({"switch": name, "ok": False,
                                   "errors": ["switch not found"],
                                   "rendered": None, "blockers": [],
                                   "warnings": []})
                continue

            # A vendor-specific template must not be aimed at the wrong vendor.
            if t.device_type and sw.device_type != t.device_type:
                per_switch.append({
                    "switch": name, "ok": False,
                    "errors": [f"template targets {t.device_type} but "
                               f"{name} is {sw.device_type}"],
                    "rendered": None, "blockers": [], "warnings": []})
                continue

            res = _tpl.preview(t.body, schema, payload.variables, sw.device_type)

            if res["ok"]:
                snap = (db.query(models.Snapshot)
                        .filter(models.Snapshot.switch_id == sw.id)
                        .order_by(desc(models.Snapshot.captured_at)).first())
                if snap:
                    existing = snap.config_text or ""
                    already, new = [], []
                    for line in res["commands"]:
                        stripped = line.strip()
                        # crude but useful: is this exact directive present?
                        if stripped and re.search(
                                r"^\s*" + re.escape(stripped) + r"\s*$",
                                existing, re.M | re.I):
                            already.append(line)
                        else:
                            new.append(line)
                    res["already_present"] = already
                    res["would_change"] = new
                    res["snapshot_at"] = str(snap.captured_at)
                else:
                    res["note"] = "no snapshot yet — cannot diff against running-config"

            per_switch.append({"switch": name, **res})

    all_ok = all(p.get("ok") for p in per_switch)
    _audit(db, "template.preview", actor=_actor(session),
           target=t.name, target_type="template",
           summary=(f"previewed '{t.name}' against "
                    f"{len(targets) or 0} switch(es)"),
           detail={"switches": targets, "ok": all_ok,
                   "variables": list(payload.variables.keys())},
           success=all_ok)

    return {"template": t.name, "device_type": t.device_type,
            "executed": False,          # explicit: Phase 1 never runs anything
            "results": per_switch, "all_ok": all_ok}


# ── compliance ────────────────────────────────────────────────────────

@app.get("/api/compliance/rules")
def list_rules(db: Session = Depends(get_db)):
    rows = db.query(models.ComplianceRule).order_by(models.ComplianceRule.id).all()
    return [{"id": r.id, "name": r.name, "kind": r.kind, "pattern": r.pattern,
             "threshold": r.threshold, "severity": r.severity,
             "device_type": r.device_type, "enabled": r.enabled,
             "builtin": r.builtin, "description": r.description}
            for r in rows]


@app.post("/api/compliance/rules", status_code=201)
def create_rule(payload: RuleIn, db: Session = Depends(get_db),
                session: dict = Depends(require_admin)):
    if payload.kind not in _compl.KINDS:
        raise HTTPException(400, f"kind must be one of {list(_compl.KINDS)}")
    if payload.severity not in _compl.SEVERITIES:
        raise HTTPException(400, f"severity must be one of {list(_compl.SEVERITIES)}")
    try:
        re.compile(payload.pattern)
    except re.error as e:
        raise HTTPException(400, f"invalid regex: {e}")

    r = models.ComplianceRule(**payload.model_dump(), builtin=False)
    db.add(r)
    db.commit()
    db.refresh(r)
    _audit(db, "compliance.rule.create", actor=_actor(session), target=r.name,
           target_type="rule", summary=f"created rule '{r.name}'")
    return {"id": r.id, "name": r.name}


@app.patch("/api/compliance/rules/{rule_id}")
def toggle_rule(rule_id: int, enabled: bool, db: Session = Depends(get_db),
                session: dict = Depends(require_admin)):
    r = db.query(models.ComplianceRule).filter(
        models.ComplianceRule.id == rule_id).first()
    if not r:
        raise HTTPException(404, "rule not found")
    r.enabled = enabled
    db.commit()
    _audit(db, "compliance.rule.update", actor=_actor(session), target=r.name,
           target_type="rule",
           summary=f"{'enabled' if enabled else 'disabled'} rule '{r.name}'")
    return {"id": r.id, "enabled": r.enabled}


@app.delete("/api/compliance/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int, db: Session = Depends(get_db),
                session: dict = Depends(require_admin)):
    r = db.query(models.ComplianceRule).filter(
        models.ComplianceRule.id == rule_id).first()
    if not r:
        raise HTTPException(404, "rule not found")
    if r.builtin:
        raise HTTPException(403, "Built-in rules cannot be deleted — disable it instead")
    name = r.name
    db.delete(r)
    db.commit()
    _audit(db, "compliance.rule.delete", actor=_actor(session), target=name,
           target_type="rule", summary=f"deleted rule '{name}'")


@app.get("/api/compliance/check")
def run_compliance(switches: str = "", db: Session = Depends(get_db)):
    """Evaluate every enabled rule against each switch's LATEST snapshot.
    Reads stored data only — no device is contacted."""
    names = [s.strip() for s in switches.split(",") if s.strip()] or None
    report = _compl.check_all(db, names)
    _audit(db, "compliance.run", target=",".join(names) if names else "all",
           target_type="switch",
           summary=(f"compliance run: {report['summary']}"),
           detail=report["summary"])
    return report


# ── audit log ─────────────────────────────────────────────────────────

@app.get("/api/audit")
def list_audit(limit: int = 100, action: str = "", target: str = "",
               db: Session = Depends(get_db)):
    q = db.query(models.AuditEvent)
    if action:
        q = q.filter(models.AuditEvent.action.like(f"{action}%"))
    if target:
        q = q.filter(models.AuditEvent.target == target)
    rows = q.order_by(desc(models.AuditEvent.timestamp)).limit(min(limit, 500)).all()
    return [{"id": e.id, "actor": e.actor, "action": e.action,
             "target": e.target, "target_type": e.target_type,
             "summary": e.summary, "success": e.success,
             "timestamp": utc_iso(e.timestamp)} for e in rows]


# ═════════════════════════════════════════════════════════════════════
# PHASE 2 — GUARDED CONFIGURATION APPLY
#
# The ONLY write path in the portal. Disabled unless CONFIG_APPLY_ENABLED=1
# AND a valid X-Apply-Token is supplied. dry_run defaults to True.
# Every applied change creates an on-device checkpoint first and is
# auto-rolled-back unless an operator confirms within the window.
# ═════════════════════════════════════════════════════════════════════

import config_apply as _apply


class ApplyIn(_BM):
    template_id: int
    variables: dict = {}
    switches: list[str]
    reason: str = ""
    dry_run: bool = True                 # must be explicitly set False to write
    scheduled_for: str | None = None     # ISO datetime; None = run now
    stop_on_first_failure: bool = True


def _render_for(db, t, sw, variables) -> dict:
    schema = _pjson.loads(t.variables or "[]")
    return _tpl.preview(t.body, schema, variables, sw.device_type)


def _change_out(db, ch: models.ConfigChange) -> dict:
    return {
        "id": ch.id, "template": ch.template_name,
        "status": ch.status, "dry_run": ch.dry_run,
        "requested_by": ch.requested_by, "reason": ch.reason,
        "scheduled_for": utc_iso(ch.scheduled_for),
        "created_at": utc_iso(ch.created_at),
        "started_at": utc_iso(ch.started_at),
        "finished_at": utc_iso(ch.finished_at),
        "targets": [{
            "switch": t.switch_name, "status": t.status,
            "checkpoint": t.checkpoint_name,
            "error": t.error, "rollback_error": t.rollback_error,
            "confirm_deadline": utc_iso(t.confirm_deadline),
            "confirmed_at": utc_iso(t.confirmed_at),
            "confirmed_by": t.confirmed_by,
            "commands_executed": (t.commands_executed or "").splitlines(),
        } for t in ch.targets],
    }


def _run_change(db, ch: models.ConfigChange, creds: dict | None):
    """Execute a change against all its targets. Assumes the gate already passed.

    creds=None means "use each switch's stored credentials" — that's the
    scheduled-run path, where the requesting operator's session is long gone.
    Passing a single creds dict here previously meant a scheduled multi-switch
    change tried the FIRST switch's credentials against every target.
    """
    ch.status = "running"
    ch.started_at = models.ist_now()
    db.commit()

    any_fail = False
    for target in ch.targets:
        sw = db.query(models.Switch).filter(
            models.Switch.name == target.switch_name).first()
        if not sw:
            target.status = "failed"
            target.error = "switch not found"
            db.commit()
            any_fail = True
            continue

        target_creds = creds or {"username": sw.username, "password": sw.password}
        if not target_creds.get("username"):
            target.status = "failed"
            target.error = "no stored credentials for this switch (scheduled run)"
            db.commit()
            any_fail = True
            continue

        commands = [l for l in (ch.rendered or "").splitlines() if l.strip()]

        res = _apply.apply_to_switch(db, sw, commands, target_creds, ch, target)
        target.finished_at = models.ist_now()
        db.commit()

        _audit(db, "config.apply", actor=ch.requested_by,
               target=sw.name, target_type="switch",
               summary=f"applied '{ch.template_name}' -> {res['status']}",
               detail={"change_id": ch.id, **res},
               success=res["status"] == "pending_confirm")

        if res["status"] != "pending_confirm":
            any_fail = True
            # Canary semantics: a failure on one switch stops the rest.
            if len(ch.targets) > 1:
                for rest in ch.targets:
                    if rest.status == "pending":
                        rest.status = "cancelled"
                        rest.error = ("skipped: an earlier switch failed "
                                      "(stop_on_first_failure)")
                db.commit()
                break

    ch.status = "failed" if any_fail else "awaiting_confirmation"
    ch.finished_at = models.ist_now()
    db.commit()


@app.get("/api/config/status")
def apply_status():
    """Is the write path enabled? The UI uses this to hide or gate Apply."""
    return {"apply_enabled": _apply.APPLY_ENABLED,
            "token_configured": bool(_apply.APPLY_TOKEN),
            "confirm_window_seconds": _apply.CONFIRM_WINDOW_SECONDS,
            "supported_device_types": sorted(_apply.VENDOR.keys())}


@app.post("/api/config/apply", status_code=201)
def apply_config(payload: ApplyIn,
                 db: Session = Depends(get_db),
                 session: dict = Depends(require_admin),
                 x_apply_token: str | None = Header(default=None)):
    """Apply a template to switches.

    dry_run=True (the default) renders and validates everything, records the
    intent, and returns exactly what WOULD be sent — without opening a single
    SSH session.
    """
    t = db.query(models.ConfigTemplate).filter(
        models.ConfigTemplate.id == payload.template_id).first()
    if not t:
        raise HTTPException(404, "template not found")
    if not payload.switches:
        raise HTTPException(400, "select at least one switch")

    actor = _actor(session)

    # Render per-switch and refuse the whole batch if any target is invalid.
    rendered_by_switch = {}
    for name in payload.switches:
        sw = _get_switch(db, name)
        _ensure_scope(session, name)
        if t.device_type and sw.device_type != t.device_type:
            raise HTTPException(
                400, f"template targets {t.device_type}; {name} is {sw.device_type}")
        res = _render_for(db, t, sw, payload.variables)
        if not res["ok"]:
            raise HTTPException(
                400, {"switch": name, "errors": res["errors"],
                      "blockers": res["blockers"]})
        rendered_by_switch[name] = res

    sample = rendered_by_switch[payload.switches[0]]

    ch = models.ConfigChange(
        template_id=t.id, template_name=t.name,
        variables=_pjson.dumps(payload.variables),
        rendered=sample["rendered"],
        requested_by=actor, reason=payload.reason,
        dry_run=payload.dry_run,
        status="queued",
    )
    if payload.scheduled_for:
        try:
            ch.scheduled_for = datetime.fromisoformat(
                payload.scheduled_for.replace("Z", ""))
        except ValueError:
            raise HTTPException(400, "scheduled_for must be an ISO datetime")
    db.add(ch)
    db.commit()
    db.refresh(ch)

    for name in payload.switches:
        db.add(models.ConfigChangeTarget(change_id=ch.id, switch_name=name))
    db.commit()
    db.refresh(ch)

    # ── Dry run: stop here. Nothing was sent. ──
    if payload.dry_run:
        ch.status = "dry_run"
        db.commit()
        _audit(db, "config.dry_run", actor=actor, target=t.name,
               target_type="template",
               summary=f"dry run of '{t.name}' on {payload.switches}",
               detail={"change_id": ch.id, "switches": payload.switches})
        out = _change_out(db, ch)
        out["executed"] = False
        out["would_send"] = sample["commands"]
        out["warnings"] = sample["warnings"]
        strat = _apply.VENDOR.get(
            db.query(models.Switch).filter(
                models.Switch.name == payload.switches[0]).first().device_type)
        out["rollback_plan"] = {
            "checkpoint_cmd": strat["checkpoint"]("<name>") if strat else None,
            "rollback_cmd": strat["rollback"]("<name>") if strat else None,
        } if strat else None
        return out

    # ── Real write: enforce the gate ──
    try:
        _apply.assert_allowed(x_apply_token)
    except _apply.ApplyDisabled as e:
        ch.status = "blocked"
        db.commit()
        _audit(db, "config.apply.blocked", actor=actor, target=t.name,
               target_type="template", summary=str(e), success=False)
        raise HTTPException(403, str(e))

    creds = auth.credentials_for(session)

    if ch.scheduled_for and ch.scheduled_for > models.ist_now():
        ch.status = "scheduled"
        # Credentials must survive until the window; reuse the per-switch
        # stored credentials at run time rather than persisting the session's.
        db.commit()
        _audit(db, "config.scheduled", actor=actor, target=t.name,
               target_type="template",
               summary=f"scheduled '{t.name}' for {ch.scheduled_for}",
               detail={"change_id": ch.id, "switches": payload.switches})
        return _change_out(db, ch)

    _run_change(db, ch, creds)
    return _change_out(db, ch)


@app.get("/api/config/changes")
def list_changes(limit: int = 50, db: Session = Depends(get_db)):
    rows = (db.query(models.ConfigChange)
            .order_by(desc(models.ConfigChange.created_at))
            .limit(min(limit, 200)).all())
    return [_change_out(db, c) for c in rows]


@app.post("/api/config/changes/{change_id}/confirm")
def confirm_change(change_id: int, db: Session = Depends(get_db),
                   session: dict = Depends(require_admin),
                   x_apply_token: str | None = Header(default=None)):
    """Keep the change. Until this is called, the device auto-reverts."""
    try:
        _apply.assert_allowed(x_apply_token)
    except _apply.ApplyDisabled as e:
        raise HTTPException(403, str(e))

    ch = db.query(models.ConfigChange).filter(
        models.ConfigChange.id == change_id).first()
    if not ch:
        raise HTTPException(404, "change not found")

    actor = _actor(session)
    now = models.ist_now()
    confirmed, expired = [], []
    for t in ch.targets:
        if t.status != "pending_confirm":
            continue
        if t.confirm_deadline and t.confirm_deadline <= now:
            # Leave it pending_confirm — the auto-revert job owns expired
            # targets. Do NOT abort here: other targets may still be valid.
            expired.append(t.switch_name)
            continue
        t.status = "confirmed"
        t.confirmed_at = now
        t.confirmed_by = actor
        confirmed.append(t.switch_name)

    if not confirmed and not expired:
        raise HTTPException(400, "nothing awaiting confirmation on this change")
    if not confirmed:
        db.rollback()
        raise HTTPException(
            409, f"confirm window expired for: {', '.join(expired)} — "
                 f"auto-rollback will revert them")

    ch.status = "completed" if not expired else "partially_confirmed"
    db.commit()
    _audit(db, "config.confirm", actor=actor, target=ch.template_name,
           target_type="template",
           summary=(f"confirmed change #{ch.id} on {len(confirmed)} switch(es)"
                    + (f"; window expired on {len(expired)}" if expired else "")),
           detail={"change_id": ch.id, "confirmed": confirmed, "expired": expired})
    out = _change_out(db, ch)
    out["confirmed"] = confirmed
    out["expired"] = expired
    return out


@app.post("/api/config/changes/{change_id}/rollback")
def rollback_change(change_id: int, db: Session = Depends(get_db),
                    session: dict = Depends(require_admin),
                    x_apply_token: str | None = Header(default=None)):
    """Roll a change back explicitly, before or after confirmation."""
    try:
        _apply.assert_allowed(x_apply_token)
    except _apply.ApplyDisabled as e:
        raise HTTPException(403, str(e))

    ch = db.query(models.ConfigChange).filter(
        models.ConfigChange.id == change_id).first()
    if not ch:
        raise HTTPException(404, "change not found")

    creds = auth.credentials_for(session)
    results = []
    for t in ch.targets:
        if t.status not in ("pending_confirm", "confirmed"):
            continue
        rb = _apply.rollback_target(db, t, creds)
        results.append({"switch": t.switch_name, **rb})
        _audit(db, "config.rollback", actor=_actor(session),
               target=t.switch_name, target_type="switch",
               summary=f"rollback of change #{ch.id}: "
                       f"{'ok' if rb['ok'] else rb.get('error')}",
               detail={"change_id": ch.id}, success=rb["ok"])

    ch.status = "rolled_back" if all(r["ok"] for r in results) else "failed"
    db.commit()
    return {"change_id": ch.id, "results": results, **_change_out(db, ch)}
# ═════════════════════════════════════════════════════════════════════
# BULK SERVER IMPORT FROM A SPREADSHEET
# Upload a CSV/XLSX of iLO addresses instead of typing them one at a time.
# Parsing never touches the database; the caller previews first, then commits.
# ═════════════════════════════════════════════════════════════════════

import bulk_import as _bulk
from fastapi import UploadFile, File, Form

MAX_UPLOAD_BYTES = 5 * 1024 * 1024        # a list of servers is never large


def _add_one_server(db, ilo_ip: str, username: str, password: str,
                    name: str = "", location: str = "",
                    description: str = "") -> dict:
    """Create one server, probe it, and start streaming if it answers.

    Shared by the spreadsheet import so its behaviour matches the catalogue
    import exactly — same naming rules, same probe, same streaming start.
    Anything the spreadsheet does not specify is filled from the bundled
    catalogue when that address is known.
    """
    if db.query(models.Server).filter(models.Server.ilo_host == ilo_ip).first():
        return {"ilo_ip": ilo_ip, "status": "skipped", "reason": "already added"}

    row = _inv.inventory_entry(ilo_ip) or {}

    final_name = (name or "").strip() or _inv.suggested_name(
        row or {"ilo_ip": ilo_ip, "hostname": "", "serial": ""})
    base, n = final_name, 2
    while db.query(models.Server).filter(models.Server.name == final_name).first():
        final_name = f"{base}-{n}"
        n += 1

    final_location = (location or "").strip() or (
        f"Rack {row.get('rack')}" if row.get("rack") else "")
    final_desc = (description or "").strip() or (
        _inv.describe_server(row) if row else "")

    srv = models.Server(
        name=final_name,
        ilo_host=ilo_ip, ilo_port=443,
        username=username, password=password,
        ssh_host=ilo_ip, ssh_port=22,
        ssh_username=username, ssh_password=password,
        collection_mode="auto",
        location=final_location, description=final_desc,
        poll_enabled=True, poll_interval_seconds=1,
    )
    srv.next_due_at = models.ist_now()
    db.add(srv)
    db.commit()
    db.refresh(srv)

    detected, err = _probe_server(srv)
    srv.last_source = detected or ""
    srv.last_poll_status = "ok" if detected else "error"
    srv.last_poll_error = "" if detected else (err or "")
    db.commit()
    db.refresh(srv)

    if detected:
        metrics_stream.manager.ensure(srv)

    return {"ilo_ip": ilo_ip, "name": final_name,
            "status": "added" if detected else "added_unreachable",
            "detected_source": detected,
            "error": None if detected else err}


@app.post("/api/servers/bulk-upload")
async def bulk_upload_servers(
        file: UploadFile = File(...),
        username: str = Form(""),
        password: str = Form(""),
        dry_run: bool = Form(True),
        db: Session = Depends(get_db),
        session: dict = Depends(require_admin)):
    """Add many servers from a CSV or Excel file.

    Two-phase by design. With dry_run=true (the default) the file is parsed and
    the parsed rows are returned WITHOUT touching the database, so the operator
    can see exactly what was understood — which column was read as the address,
    which rows were skipped and why — before committing. With dry_run=false the
    same rows are created.

    Per-row credentials in the sheet win; otherwise the username and password
    supplied with the upload are used for every row, exactly like the catalogue
    import. Credentials are never written back to any file.
    """
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            413, f"file is larger than {MAX_UPLOAD_BYTES // (1024*1024)} MB — "
                 f"this endpoint expects a list of servers, not a data export")

    try:
        parsed = _bulk.parse_file(file.filename or "", raw)
    except _bulk.BulkParseError as e:
        raise HTTPException(400, str(e))

    rows = parsed["rows"]

    # Flag rows that will need the fallback credentials, and rows already known.
    existing = {s.ilo_host for s in db.query(models.Server.ilo_host).all()}
    preview = []
    for r in rows:
        has_own = bool(r["username"] and r["password"])
        preview.append({
            "ilo_ip": r["ilo_ip"],
            "name": r["name"],
            "location": r["location"],
            "description": r["description"],
            "has_row_credentials": has_own,
            "already_added": r["ilo_ip"] in existing,
            "in_catalog": _inv.inventory_entry(r["ilo_ip"]) is not None,
            "source_row": r["source_row"],
        })

    needs_fallback = [p for p in preview
                      if not p["has_row_credentials"] and not p["already_added"]]

    if dry_run:
        return {
            "dry_run": True,
            "filename": file.filename,
            "parsed": len(rows),
            "new": sum(1 for p in preview if not p["already_added"]),
            "already_added": sum(1 for p in preview if p["already_added"]),
            "needs_credentials": len(needs_fallback),
            "columns_detected": parsed["columns_detected"],
            "had_header": parsed["had_header"],
            "warnings": parsed["warnings"],
            "rows": preview,
        }

    if needs_fallback and not (username and password):
        raise HTTPException(
            400, f"{len(needs_fallback)} row(s) have no username/password of "
                 f"their own — supply credentials with the upload, or add "
                 f"username and password columns to the file")

    added, skipped, failed = [], [], []
    for r in rows:
        user = r["username"] or username
        pwd = r["password"] or password
        try:
            res = _add_one_server(db, r["ilo_ip"], user, pwd,
                                  name=r["name"], location=r["location"],
                                  description=r["description"])
        except Exception as e:                       # one bad row must not
            db.rollback()                            # abort the whole file
            failed.append({"ilo_ip": r["ilo_ip"], "error": str(e)[:200]})
            continue
        if res["status"] == "skipped":
            skipped.append(res)
        else:
            added.append(res)

    _audit(db, "server.bulk_import", actor=_actor(session),
           target=file.filename or "upload", target_type="server",
           summary=f"bulk import from '{file.filename}': {len(added)} added, "
                   f"{len(skipped)} skipped, {len(failed)} failed",
           detail={"added": [a["ilo_ip"] for a in added][:100]})

    return {"dry_run": False, "filename": file.filename,
            "added": added, "skipped": skipped, "failed": failed,
            "added_count": len(added),
            "unreachable_count": sum(1 for a in added
                                     if a["status"] == "added_unreachable"),
            "warnings": parsed["warnings"]}


# ═════════════════════════════════════════════════════════════════════
# FLEET EXPORT — one Excel workbook, one sheet per server
# ═════════════════════════════════════════════════════════════════════

import server_export as _sxp


@app.get("/api/servers/export.xlsx")
def export_servers_xlsx(days: int = 7, bucket_minutes: int = 5,
                        servers: str = "",
                        db: Session = Depends(get_db)):
    """Snapshot every server into a workbook: a fleet overview sheet, then one
    sheet per server carrying its details, derived thresholds, alerts, and
    bucketed metric history for the window.

    History is bucketed (5-minute average and peak by default) because a raw
    dump of a week at ~10-second resolution would be hundreds of thousands of
    rows per server. Peaks are kept alongside averages so spikes stay visible.
    """
    if not 1 <= days <= 31:
        raise HTTPException(400, "days must be between 1 and 31")
    if not 1 <= bucket_minutes <= 1440:
        raise HTTPException(400, "bucket_minutes must be between 1 and 1440")

    names = [s.strip() for s in servers.split(",") if s.strip()] or None
    if not db.query(models.Server).count():
        raise HTTPException(404, "no servers registered yet")

    try:
        data = _sxp.build_workbook(db, days=days,
                                   bucket_seconds=bucket_minutes * 60,
                                   server_names=names)
    except ImportError:
        raise HTTPException(
            500, "Excel export needs the openpyxl package on the backend. "
                 "Rebuild the backend image so requirements.txt is reinstalled.")

    stamp = models.ist_now().strftime("%Y%m%d-%H%M")
    filename = f"noc-servers-{stamp}.xlsx"
    from fastapi.responses import Response as _Resp
    return _Resp(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


import threshold_analysis as _thr


class ThresholdAnalyzeIn(_BM):
    sensors: list[str] = []          # empty = cpu + memory bus
    window_hours: int = 168          # use all retained history (7 days)


class ThresholdApplyIn(_BM):
    server: str | None = None        # None = every analyzed server
    sensor: str | None = None        # None = every analyzed sensor

