"""
inventory.py — Bundled iLO hardware inventory + threshold alert evaluation.

Two jobs:

1. INVENTORY
   Ships the fleet's iLO endpoints (extracted from the Hardware Inventory
   workbook) so servers can be added by picking them from a list instead of
   typing an address every time — exactly like adding a switch, where you
   supply the password once.

   SECURITY: no credentials are stored anywhere in the inventory. The
   operator always types the username/password at import time, exactly as
   when unlocking a switch. Nothing is persisted in the catalog files.

2. ALERTS
   Evaluates each server against its configured Alert Settings (lower/upper
   threshold + dwell time) so the server list can be coloured green when the
   thresholds are respected and red when one is breached.

   Dwell time is honoured properly: a value must stay beyond the threshold
   for the whole dwell window before it counts as a breach. A momentary
   spike does not turn the fleet red.
"""
from __future__ import annotations

import json
import os
from datetime import timedelta
from functools import lru_cache
from typing import Any, Optional

from sqlalchemy import desc

import models

_HERE = os.path.dirname(os.path.abspath(__file__))
_INVENTORY_PATH = os.getenv(
    "ILO_INVENTORY_PATH", os.path.join(_HERE, "inventory_data", "ilo_inventory.json")
)
_SWITCH_INVENTORY_PATH = os.getenv(
    "SWITCH_INVENTORY_PATH", os.path.join(_HERE, "inventory_data", "switch_inventory.json")
)


# ── 1. Inventory ───────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def load_inventory() -> list[dict]:
    try:
        with open(_INVENTORY_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[inventory] failed to load {_INVENTORY_PATH}: {e}", flush=True)
        return []



# ── 1a. GPU ownership catalog ──────────────────────────────────────────────
# The iLO sheet says WHAT the box is (DL380 Gen11); this says what's IN it and
# WHO owns it (L40S · Nishith · CNC). Keyed by iLO IP, merged into every
# catalog row so the model/owner/team travel into the server description.
_GPU_PATH = os.path.join(os.path.dirname(__file__),
                         "inventory_data", "gpu_owners.json")


@lru_cache(maxsize=1)
def load_gpu_catalog() -> list[dict]:
    try:
        with open(_GPU_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[inventory] failed to load {_GPU_PATH}: {e}", flush=True)
        return []


@lru_cache(maxsize=1)
def _gpu_by_ip() -> dict:
    return {r["ilo_ip"]: r for r in load_gpu_catalog()}


def gpu_entry(ilo_ip: str) -> dict:
    return _gpu_by_ip().get(ilo_ip, {})


def gpu_description(ilo_ip: str) -> str:
    """'L40S · Nishith · CNC' — the human-facing summary for a GPU node."""
    g = gpu_entry(ilo_ip)
    if not g:
        return ""
    parts = [g.get("gpu_model"), g.get("owner"), g.get("team")]
    return " · ".join(p for p in parts if p)


def describe_server(row: dict) -> str:
    """Full server description: hardware from the iLO sheet, plus GPU model,
    owner and team when the box is in the GPU catalog."""
    base = " · ".join(x for x in (row.get("model"), row.get("solution")) if x)
    gpu = gpu_description(row.get("ilo_ip", ""))
    return " · ".join(x for x in (gpu, base) if x)


def inventory_entry(ilo_ip: str) -> Optional[dict]:
    for row in load_inventory():
        if row.get("ilo_ip") == ilo_ip:
            return row
    return None


def public_inventory(db) -> list[dict]:
    """Catalog for the UI. Never leaks passwords; flags what's already added.

    Servers the inventory sheet marks as unreachable are excluded entirely —
    offering them for import would only produce guaranteed-failed probes.
    """
    already = {s.ilo_host for s in db.query(models.Server).all()}
    out = []
    for row in load_inventory():
        note = (row.get("note") or "").lower()
        if "unreachable" in note:
            continue
        g = gpu_entry(row["ilo_ip"])
        out.append({
            "ilo_ip": row["ilo_ip"],
            "hostname": row.get("hostname", ""),
            "model": row.get("model", ""),
            "gpu_model": g.get("gpu_model", ""),
            "owner": g.get("owner", ""),
            "team": g.get("team", ""),
            "lm": g.get("lm", ""),
            "serial": row.get("serial", ""),
            "rack": row.get("rack", ""),
            "solution": row.get("solution", ""),
            "note": row.get("note", ""),
            "already_added": row["ilo_ip"] in already,
        })
    return out


def suggested_name(row: dict) -> str:
    """Pick a stable, human name for an imported server.

    GPU nodes get 'l40s-145' rather than 'ilo-10-25-51-145': the model plus
    the octet is what people actually say out loud, and the octet is the same
    number the switch descriptions carry (Links matches on it).
    """
    for key in ("hostname", "serial"):
        v = (row.get(key) or "").strip()
        if v:
            return v
    g = gpu_entry(row.get("ilo_ip", ""))
    if g.get("gpu_model"):
        octet = row["ilo_ip"].split(".")[-1]
        return f"{g['gpu_model'].lower()}-{octet}"
    return f"ilo-{row['ilo_ip'].replace('.', '-')}"


# ── 1b. Switch inventory ───────────────────────────────────────────────────

@lru_cache(maxsize=1)
def load_switch_inventory() -> list[dict]:
    try:
        with open(_SWITCH_INVENTORY_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[inventory] switch catalog: {e}", flush=True)
        return []


def switch_entry(ip: str) -> Optional[dict]:
    for row in load_switch_inventory():
        if row.get("ip") == ip:
            return row
    return None


def public_switch_inventory(db) -> list[dict]:
    """Switch catalog for the UI. Contains no credentials at all."""
    added_hosts = {s.host for s in db.query(models.Switch).all()}
    out = []
    for row in load_switch_inventory():
        out.append({
            "ip": row["ip"],
            "name": row.get("name", ""),
            "role": row.get("role", ""),
            "rack": row.get("rack", ""),
            "model": row.get("model", ""),
            "device_type": row.get("device_type", "aruba_aoscx"),
            "already_added": row["ip"] in added_hosts,
        })
    return out


# ── 2. Alert evaluation ────────────────────────────────────────────────────

def _breach_for_sensor(db, srv, setting) -> Optional[dict]:
    """Return a breach dict if this sensor violates its thresholds for the
    full dwell window, else None.

    A threshold of 0 means "not configured" (matching the iLO UI, where the
    fields default to 0), so it is skipped.
    """
    checks = []
    if setting.upper_threshold and setting.upper_threshold > 0:
        checks.append(("upper", setting.upper_threshold,
                       max(0, setting.upper_dwell_sec or 0)))
    if setting.lower_threshold and setting.lower_threshold > 0:
        checks.append(("lower", setting.lower_threshold,
                       max(0, setting.lower_dwell_sec or 0)))
    if not checks:
        return None

    for kind, threshold, dwell in checks:
        # Look back over the dwell window (minimum: the newest sample).
        window = max(dwell, 1)
        cutoff = models.ist_now() - timedelta(seconds=window)
        rows = (db.query(models.ServerMetric)
                .filter(models.ServerMetric.server_id == srv.id,
                        models.ServerMetric.sensor == setting.sensor,
                        models.ServerMetric.captured_at >= cutoff)
                .order_by(desc(models.ServerMetric.captured_at))
                .all())
        if not rows:
            continue

        vals = [r.value / 100.0 for r in rows]
        if kind == "upper":
            violating = all(v > threshold for v in vals)
        else:
            violating = all(v < threshold for v in vals)

        if not violating:
            continue

        # With a real dwell requirement, the breach must have been continuous
        # for the WHOLE window. We can only claim that if we actually have a
        # sample from at (or before) the start of the window — otherwise the
        # server may only have started reporting a moment ago.
        if dwell > 0:
            oldest = rows[-1].captured_at
            # One sampling interval of slack, so 1 Hz data isn't rejected for
            # landing a few hundred ms inside the boundary.
            slack = timedelta(seconds=float(os.getenv("SERVER_SAMPLE_SECONDS", "1")) * 2)
            if oldest > cutoff + slack:
                continue        # not enough history to prove a sustained breach

        return {"sensor": setting.sensor, "kind": kind,
                "threshold": threshold, "dwell_sec": dwell,
                "value": vals[0], "unit": rows[0].unit,
                "samples": len(vals)}
    return None


def evaluate_server(db, srv) -> dict:
    """Alert state for one server: 'ok' | 'breach' | 'unknown'."""
    settings = (db.query(models.ServerAlertSetting)
                .filter(models.ServerAlertSetting.server_id == srv.id).all())
    configured = [s for s in settings
                  if (s.upper_threshold or 0) > 0 or (s.lower_threshold or 0) > 0]

    if not configured:
        return {"server": srv.name, "state": "unconfigured", "breaches": []}

    # No data at all -> we genuinely don't know.
    has_data = (db.query(models.ServerMetric)
                .filter(models.ServerMetric.server_id == srv.id).first()) is not None
    if not has_data:
        return {"server": srv.name, "state": "unknown", "breaches": []}

    breaches = []
    for st in configured:
        b = _breach_for_sensor(db, srv, st)
        if b:
            breaches.append(b)

    return {"server": srv.name,
            "state": "breach" if breaches else "ok",
            "breaches": breaches,
            "sensors_configured": [s.sensor for s in configured]}


def evaluate_all(db) -> list[dict]:
    return [evaluate_server(db, s)
            for s in db.query(models.Server).order_by(models.Server.name).all()]


def _snapshot_all_metrics(db, srv, event, trigger_sensor: str) -> int:
    """Copy every sensor's latest reading for this server, tied to the event.

    Called once, at raise time. The raw metrics get pruned after 7 days; this
    keeps the full picture behind an alert for as long as the event exists.
    Prefers the live in-memory sample (fresher than the ≤10 s DB write); falls
    back to the newest stored row per sensor.
    """
    import ilo_client as _ilo
    now = models.ist_now()

    live = {}
    try:
        import metrics_stream, time as _time
        last = metrics_stream.manager.latest(srv.name) or {}
        if last.get("values") and (_time.time() - (last.get("ts") or 0)) < 30:
            live = last["values"]
    except Exception:
        pass

    written = 0
    for sensor in _ilo.SENSORS:
        value, sample_at = None, None
        if live.get(sensor) is not None:
            value, sample_at = float(live[sensor]) * 100.0, now
        else:
            row = (db.query(models.ServerMetric)
                   .filter(models.ServerMetric.server_id == srv.id,
                           models.ServerMetric.sensor == sensor)
                   .order_by(desc(models.ServerMetric.captured_at)).first())
            if row:
                value, sample_at = row.value, row.captured_at
        if value is None:
            continue                    # unmeasurable here — don't invent it
        db.add(models.ServerAlertMetricSnapshot(
            event_id=event.id, server_id=srv.id, server_name=srv.name,
            sensor=sensor, value=int(round(value)),
            unit=_ilo.SENSORS[sensor][1],
            is_trigger=(sensor == trigger_sensor),
            sample_at=sample_at, captured_at=now,
        ))
        written += 1
    return written


def record_alert_events(db) -> dict:
    """Turn the instantaneous breach state into a persistent audit trail.

    For every (server, sensor, kind) currently breaching: open an event if
    none is active, otherwise update its worst_value. For every active event
    whose breach has gone away: close it. Called by the scheduler.
    """
    opened, updated, cleared = [], [], []
    now = models.ist_now()

    states = evaluate_all(db)
    breaching = {}                     # (server_name, sensor, kind) -> breach dict
    for st in states:
        for b in st.get("breaches") or []:
            breaching[(st["server"], b["sensor"], b["kind"])] = b

    active = (db.query(models.ServerAlertEvent)
              .filter(models.ServerAlertEvent.state == "active").all())
    active_keys = set()

    for ev in active:
        key = (ev.server_name, ev.sensor, ev.kind)
        active_keys.add(key)
        b = breaching.get(key)
        if b is None:
            ev.state = "cleared"
            ev.cleared_at = now
            cleared.append(key)
        else:
            v100 = int(round(b["value"] * 100))
            worse = (v100 > (ev.worst_value or 0)) if ev.kind == "upper" \
                    else (v100 < (ev.worst_value or 0))
            if worse:
                ev.worst_value = v100
                updated.append(key)

    for key, b in breaching.items():
        if key in active_keys:
            continue
        srv = (db.query(models.Server)
               .filter(models.Server.name == key[0]).first())
        if not srv:
            continue
        v100 = int(round(b["value"] * 100))
        ev = models.ServerAlertEvent(
            server_id=srv.id, server_name=srv.name,
            sensor=b["sensor"], kind=b["kind"],
            threshold=b["threshold"], dwell_sec=b.get("dwell_sec") or 0,
            value=v100, worst_value=v100, unit=b.get("unit") or "",
            state="active", raised_at=now,
        )
        db.add(ev)
        db.flush()                  # need ev.id to key the snapshot rows
        snapped = _snapshot_all_metrics(db, srv, ev, b["sensor"])
        print(f"[alert] raised {srv.name}/{b['sensor']} {b['kind']} "
              f"@{b['value']}{b.get('unit') or ''} — snapshotted "
              f"{snapped} sensor(s)", flush=True)
        opened.append(key)

    if opened or updated or cleared:
        db.commit()
    return {"opened": len(opened), "updated": len(updated),
            "cleared": len(cleared)}
