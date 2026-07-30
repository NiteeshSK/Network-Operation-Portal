"""
link_insights.py — Correlate switch port-channels with the servers behind them.

THE CONVENTION
--------------
When a LAG / Bridge-Aggregation is created (e.g. through the LACP tab), its
description names the connected server and the last octet of that server's
iLO address, e.g.:

    "dl380-rack-b ilo101"      "uplink to gpu-node .167"      "esx7 ilo 85"

This module parses those descriptions, matches them against the registered
server fleet, and joins the two telemetry streams the portal already has:

    switch side : PortStat rows  (cumulative packet counters per capture)
    server side : ServerMetric rows (~1 Hz CPU / memory-bus / jitter samples)

MATCHING RULES (in order of confidence)
    1. name  — the server's name appears in the description (case-insensitive)
    2. ilo   — the iLO last octet appears near an 'ilo' marker ("ilo101",
               "ilo 101", "ilo-101", ".101")
    3. octet — the octet appears as a bare standalone number (weakest; only
               used if nothing better matched, and flagged as low confidence)

CPU ATTRIBUTION ESTIMATE
------------------------
"How much of this server's CPU is this link's traffic costing?" cannot be
measured directly from outside the host, so we ESTIMATE it and say so:

    - Build a history of (packets-per-second, mean CPU%) pairs, one per
      port-stats capture interval over the last hour.
    - Fit ordinary least squares:  cpu = a + b·pps
    - The attribution at the current rate is  b · current_pps  (clamped to
      [0, latest CPU]), reported together with r² and the sample count so the
      operator can judge how much to trust it.

A low r² means CPU moves for reasons other than this link's traffic — the
estimate is then labelled accordingly rather than hidden. No fabricated
numbers: not enough aligned history -> estimate is null with a reason.
"""
from __future__ import annotations

import re
from datetime import timedelta

from sqlalchemy import desc

import models

# Sensors joined into each matched link (key -> short label the UI shows).
SERVER_SENSORS = {
    "cpu_utilization":        "cpu",
    "memory_bus_utilization": "memory",
    "jitter_count":           "jitter",
}

# Interfaces that are aggregates. Physical members are also matched (the
# description convention may live on them instead) but LAGs sort first.
_LAG_RE = re.compile(r"^(bridge-aggregation|bagg|route-aggregation|ragg|lag)\s*\d+",
                     re.I)

_HISTORY_WINDOW_MIN = 60      # pairing window for the regression
_MIN_PAIRS = 5                # fewest aligned intervals we'll fit a line to
_STALE_METRIC_SEC = 300       # server metric older than this = "stale"


def _last_octet(host: str) -> str | None:
    m = re.search(r"(\d{1,3})\s*$", (host or "").strip())
    return m.group(1) if m else None


# Description tags that explicitly precede a server iLO octet. The number
# after any of these is treated as a strong ("label") match — e.g. "VCF 161",
# "ilo 101", "iLO-85". Extend this list as new naming conventions appear.
_OCTET_LABELS = ("vcf", "ilo", "ilom", "bmc", "idrac", "mgmt", "srv", "server")
_LABEL_RE = re.compile(
    r"\b(" + "|".join(_OCTET_LABELS) + r")[\s\-_.:#]*0*(\d{1,3})\b", re.I)


def _tokens(description: str) -> list[str]:
    """Split a description into numeric-or-word tokens, treating _, -, space,
    ., /, and other punctuation all as separators. This is what makes
    'SDA_GPU_143_Nic1' and '51_146_SGH...' yield the standalone number 143 /
    146 — a plain \\b boundary fails here because '_' is a word character."""
    return [t for t in re.split(r"[\s\-_.:#,/|()]+", description or "") if t]


def _labeled_octets(description: str) -> list[str]:
    """Octets that appear immediately after a known label (VCF/iLO/…)."""
    return [m.group(2).lstrip("0") or "0"
            for m in _LABEL_RE.finditer(description or "")]


def _standalone_octets(description: str) -> list[str]:
    """Every pure-number token in the description, normalized (leading zeros
    stripped). 'VCF 161' -> ['161']; '51_146_SGH...' -> ['51','146']."""
    out = []
    for t in _tokens(description):
        if t.isdigit():
            out.append(t.lstrip("0") or "0")
    return out


def _match_server(description: str, servers: list) -> tuple[object, str] | None:
    """Return (server, basis) for the best match, or None.

    basis is 'name' | 'label' | 'octet' so the UI can show confidence:
      name  — the server's name appears verbatim in the description
      label — the iLO octet follows a tag like VCF/iLO ("VCF 161")
      octet — the iLO octet appears as a standalone token ("..._143_...")
    """
    d = (description or "").strip()
    if not d:
        return None
    dl = d.lower()

    # 1. name match — strongest
    for s in servers:
        if s.name and s.name.lower() in dl:
            return s, "name"

    # 2. labeled octet — "VCF 161", "ilo 101", "iLO-85"
    labeled = set(_labeled_octets(d))
    if labeled:
        for s in servers:
            octet = _last_octet(s.ilo_host)
            if octet and (octet.lstrip("0") or "0") in labeled:
                return s, "label"

    # 3. standalone numeric token equal to the octet — "SDA_GPU_143_Nic1",
    #    "51_146_SGH..." (the 146, not the 51, will match a real server).
    standalone = set(_standalone_octets(d))
    if standalone:
        for s in servers:
            octet = _last_octet(s.ilo_host)
            if octet and (octet.lstrip("0") or "0") in standalone:
                return s, "octet"

    return None


def _latest_capture_rows(db, sw) -> list:
    ts = (db.query(models.PortStat.captured_at)
          .filter(models.PortStat.switch_id == sw.id)
          .order_by(desc(models.PortStat.captured_at)).first())
    if not ts:
        return []
    return (db.query(models.PortStat)
            .filter(models.PortStat.switch_id == sw.id,
                    models.PortStat.captured_at == ts[0])
            .order_by(models.PortStat.interface_name).all())


def _iface_history(db, sw, iface: str, since) -> list:
    """(captured_at, total_packets) ascending for one interface."""
    rows = (db.query(models.PortStat)
            .filter(models.PortStat.switch_id == sw.id,
                    models.PortStat.interface_name == iface,
                    models.PortStat.captured_at >= since)
            .order_by(models.PortStat.captured_at.asc()).all())
    out = []
    for r in rows:
        total = r.total_packets if r.total_packets is not None else \
            (r.in_packets or 0) + (r.out_packets or 0)
        out.append((r.captured_at, total))
    return out


def _pps_intervals(history: list) -> list:
    """[(t_start, t_end, pps)] from consecutive cumulative counters.
    Skips counter resets (negative deltas) and degenerate intervals."""
    out = []
    for (t0, p0), (t1, p1) in zip(history, history[1:]):
        dt = (t1 - t0).total_seconds()
        if dt <= 0 or dt > 900:           # gap too large to be one interval
            continue
        dp = (p1 or 0) - (p0 or 0)
        if dp < 0:                         # reset between captures
            continue
        out.append((t0, t1, dp / dt))
    return out


def _server_latest(db, srv) -> dict:
    """Per-sensor value for the card, LIVE first.

    The metrics_stream manager holds a persistent iLO connection sampling at
    ~1 Hz; its in-memory sample is at most a second or two old, so the Links
    card shows genuinely real-time CPU. We also ensure() the worker here, so
    merely opening the Links view starts streaming for every matched server.
    The database is only the fallback (worker still warming up / iLO down).
    """
    now = models.ist_now()
    vals = {}

    live_values, live_source = {}, ""
    try:
        import metrics_stream
        metrics_stream.manager.ensure(srv)          # idempotent
        last = metrics_stream.manager.latest(srv.name) or {}
        import time as _time
        if last.get("values") and (_time.time() - (last.get("ts") or 0)) < 15:
            live_values = last["values"]
            live_source = last.get("source", "live")
    except Exception:
        pass

    import ilo_client as _ilo
    for sensor, short in SERVER_SENSORS.items():
        lv = live_values.get(sensor)
        if lv is not None:
            vals[short] = {"value": round(float(lv), 2),
                           "unit": _ilo.SENSORS[sensor][1],
                           "at": now, "stale": False, "live": True,
                           "source": live_source}
            continue
        row = (db.query(models.ServerMetric)
               .filter(models.ServerMetric.server_id == srv.id,
                       models.ServerMetric.sensor == sensor)
               .order_by(desc(models.ServerMetric.captured_at)).first())
        if not row:
            vals[short] = None
            continue
        age = (now - row.captured_at).total_seconds()
        vals[short] = {
            "value": (row.value or 0) / 100.0,
            "unit": row.unit or "",
            "at": row.captured_at,
            "stale": age > _STALE_METRIC_SEC,
            "live": False,
        }
    return vals


def _mean_metric_between(db, srv, sensor, t0, t1) -> float | None:
    rows = (db.query(models.ServerMetric.value)
            .filter(models.ServerMetric.server_id == srv.id,
                    models.ServerMetric.sensor == sensor,
                    models.ServerMetric.captured_at > t0,
                    models.ServerMetric.captured_at <= t1).all())
    if not rows:
        return None
    return sum(r[0] for r in rows) / len(rows) / 100.0


def _iface_bytes_history(db, sw, iface: str, since) -> list:
    """(captured_at, total_bytes) ascending for one interface."""
    rows = (db.query(models.PortStat)
            .filter(models.PortStat.switch_id == sw.id,
                    models.PortStat.interface_name == iface,
                    models.PortStat.captured_at >= since)
            .order_by(models.PortStat.captured_at.asc()).all())
    return [(r.captured_at, (r.in_bytes or 0) + (r.out_bytes or 0))
            for r in rows]


def _fit_sensor(db, srv, sensor, intervals, current_pps, label) -> dict:
    """Estimate how much of one sensor this link is causing.

    Primary method: OLS regression of the sensor's % against pps over the
    aligned intervals. If the regression is degenerate (negative or ~zero
    slope from noise, r² < 0.05) we fall back to an ACTIVE-VS-IDLE delta:
    mean(sensor) during the busiest half of intervals minus mean(sensor)
    during the quietest half — the plain-language answer to "how much higher
    is CPU when this port is transferring?".

    We also always report the PER-RATE cost (%/10k pps). The estimate *at the
    current rate* is honestly zero when the port is idle right now — the
    per-rate figure is what tells you the transfer cost regardless.
    """
    pairs = []
    for t0, t1, pps in intervals:
        y = _mean_metric_between(db, srv, sensor, t0, t1)
        if y is not None:
            pairs.append((pps, y))

    key = f"estimated_{label}_pct"
    if len(pairs) < _MIN_PAIRS:
        return {key: None, "r2": None, "points": len(pairs), "method": None,
                "cost_per_10kpps": None,
                "note": (f"need ≥{_MIN_PAIRS} aligned traffic/{label} intervals "
                         f"(have {len(pairs)}) — keep port-stats capture and "
                         f"server streaming running")}

    n = len(pairs)
    mx = sum(p for p, _ in pairs) / n
    my = sum(c for _, c in pairs) / n
    sxx = sum((p - mx) ** 2 for p, _ in pairs)
    sxy = sum((p - mx) * (c - my) for p, c in pairs)
    if sxx == 0:
        return {key: None, "r2": None, "points": n, "method": None,
                "cost_per_10kpps": None,
                "note": f"traffic rate constant — cannot separate this link's "
                        f"{label} cost from the baseline"}

    b = sxy / sxx
    a = my - b * mx
    ss_tot = sum((c - my) ** 2 for _, c in pairs)
    ss_res = sum((c - (a + b * p)) ** 2 for p, c in pairs)
    r2 = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
    r2 = max(0.0, r2)

    method = "regression"
    if b <= 0 or r2 < 0.05:
        # regression can't see it — active-vs-idle delta instead
        by_pps = sorted(pairs, key=lambda x: x[0])
        half = n // 2
        idle, busy = by_pps[:half], by_pps[half:]
        idle_pps = sum(p for p, _ in idle) / max(len(idle), 1)
        busy_pps = sum(p for p, _ in busy) / max(len(busy), 1)
        delta = (sum(c for _, c in busy) / max(len(busy), 1)) - \
                (sum(c for _, c in idle) / max(len(idle), 1))
        delta = max(0.0, delta)
        span = busy_pps - idle_pps
        b = (delta / span) if span > 0 else 0.0
        method = "active_vs_idle"

    cost_per_10kpps = round(b * 10000, 3)

    est = None
    if current_pps is not None:
        est = max(0.0, b * current_pps)
        latest = _mean_metric_between(
            db, srv, sensor,
            models.ist_now() - timedelta(seconds=60), models.ist_now())
        if latest is not None and est > latest:
            est = latest                    # can't attribute more than exists

    if method == "regression":
        note = ("this link explains most of the movement" if r2 >= 0.5 else
                "weak correlation — rough indication" if r2 >= 0.2 else
                f"{label} is mostly driven by something else")
    else:
        note = (f"{label} barely reacts to this link's traffic — showing the "
                f"busy-vs-quiet difference instead")
    if est is not None and est < 0.05 and cost_per_10kpps > 0:
        note += " · port is quiet right now; see the per-rate cost"

    return {key: round(est, 2) if est is not None else None,
            "r2": round(r2, 3), "points": n, "method": method,
            "cost_per_10kpps": cost_per_10kpps,
            "slope_pct_per_kpps": round(b * 1000, 4), "note": note}


def _human_bytes(n) -> str:
    if n is None:
        return None
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


def _estimate_attribution(db, sw, srv, iface: str) -> dict:
    """CPU + memory attribution, plus the port's byte-transfer figures."""
    since = models.ist_now() - timedelta(minutes=_HISTORY_WINDOW_MIN)
    hist = _iface_history(db, sw, iface, since)
    intervals = _pps_intervals(hist)
    current_pps = intervals[-1][2] if intervals else None

    # bytes: current rate, last-interval transfer, and hour total
    bhist = _iface_bytes_history(db, sw, iface, since)
    bints = _pps_intervals(bhist)           # same math: (t0, t1, bytes/sec)
    current_bps = bints[-1][2] if bints else None
    bytes_last_interval = None
    last_interval_sec = None
    if bints:
        t0, t1, rate = bints[-1]
        last_interval_sec = int((t1 - t0).total_seconds())
        bytes_last_interval = rate * last_interval_sec
    bytes_window = sum(r * (t1 - t0).total_seconds()
                       for t0, t1, r in bints) if bints else None

    cpu = _fit_sensor(db, srv, "cpu_utilization", intervals, current_pps, "cpu")
    mem = _fit_sensor(db, srv, "memory_bus_utilization", intervals,
                      current_pps, "memory")

    return {
        "current_pps": round(current_pps, 1) if current_pps is not None else None,
        "current_bps": round(current_bps, 1) if current_bps is not None else None,
        "current_rate_human": (_human_bytes(current_bps) + "/s")
                              if current_bps is not None else None,
        "bytes_last_interval": bytes_last_interval,
        "bytes_last_interval_human": _human_bytes(bytes_last_interval),
        "last_interval_sec": last_interval_sec,
        "bytes_window": bytes_window,
        "bytes_window_human": _human_bytes(bytes_window),
        "window_minutes": _HISTORY_WINDOW_MIN,
        # CPU (top level for backward compatibility)
        "estimated_cpu_pct": cpu["estimated_cpu_pct"],
        "r2": cpu["r2"], "points": cpu["points"],
        "cpu_method": cpu["method"],
        "cpu_cost_per_10kpps": cpu["cost_per_10kpps"],
        "slope_pct_per_kpps": cpu.get("slope_pct_per_kpps"),
        "note": cpu["note"],
        # memory
        "estimated_memory_pct": mem["estimated_memory_pct"],
        "memory_r2": mem["r2"], "memory_note": mem["note"],
        "memory_method": mem["method"],
        "memory_cost_per_10kpps": mem["cost_per_10kpps"],
    }


def _snapshot_descriptions(db, sw) -> dict:
    """{interface_name: description} parsed from the latest config snapshot.

    Your real switches carry the server reference in the running-config
    ('description VCF 161'), which is more reliable than the port-stats brief
    (that column truncates). We read both and prefer whichever is non-empty.
    """
    snap = (db.query(models.Snapshot)
            .filter(models.Snapshot.switch_id == sw.id)
            .order_by(desc(models.Snapshot.captured_at)).first())
    if not snap or not snap.config_text:
        return {}
    out, current = {}, None
    for line in snap.config_text.splitlines():
        m = re.match(r"^interface\s+(\S+)", line, re.I)
        if m:
            current = m.group(1)
            continue
        if current:
            dm = re.match(r"^\s+description\s+(.+?)\s*$", line, re.I)
            if dm:
                out[current] = dm.group(1).strip()
            elif line and not line.startswith((" ", "\t")):
                current = None
    return out


def diagnose(db, switch_name: str | None = None) -> dict:
    """Explain why the Links view is (or isn't) matching anything.

    Walks the same data insights() uses and reports, per switch, the four
    preconditions: a config snapshot exists, it has interface descriptions,
    port-stats have been captured, and — the usual culprit — whether any
    description number lines up with a REGISTERED server's iLO last octet.
    """
    servers = db.query(models.Server).order_by(models.Server.name).all()
    server_octets = {}
    for s in servers:
        o = _last_octet(s.ilo_host)
        if o:
            server_octets.setdefault(o.lstrip("0") or "0", []).append(s.name)

    q = db.query(models.Switch).order_by(models.Switch.name)
    if switch_name:
        q = q.filter(models.Switch.name == switch_name)
    switches = q.all()

    per_switch = []
    for sw in switches:
        snap_desc = _snapshot_descriptions(db, sw)
        rows = _latest_capture_rows(db, sw)
        # every description we can see, from snapshot + port-stats
        described = dict(snap_desc)
        for r in rows:
            d = (r.port_description or "").strip()
            if d:
                described.setdefault(r.interface_name, d)

        # of those, which carry a number that COULD be an octet, and does it
        # match a registered server?
        desc_report = []
        for iface, d in sorted(described.items()):
            octets = sorted(set(_labeled_octets(d)) | set(_standalone_octets(d)))
            matched = [srv for o in octets
                       for srv in server_octets.get(o, [])]
            name_hit = next((s.name for s in servers
                             if s.name and s.name.lower() in d.lower()), None)
            desc_report.append({
                "interface": iface, "description": d,
                "octets_in_description": octets,
                "matched_server": name_hit or (matched[0] if matched else None),
            })

        matched_count = sum(1 for x in desc_report if x["matched_server"])
        per_switch.append({
            "switch": sw.name,
            "has_snapshot": bool(snap_desc) or any(
                s.switch_id == sw.id for s in
                db.query(models.Snapshot).filter(
                    models.Snapshot.switch_id == sw.id).limit(1)),
            "descriptions_found": len(described),
            "port_stats_captured": len(rows),
            "matched": matched_count,
            "descriptions": desc_report,
        })

    return {
        "servers_registered": len(servers),
        "server_ilo_octets": {o: names for o, names in
                              sorted(server_octets.items())},
        "switches": per_switch,
        "checked_at": models.ist_now(),
    }


def insights(db, switch_name: str | None = None) -> dict:
    """The Links view payload: every described LAG/port matched to a server,
    with that server's live sensors and the attribution estimate."""
    q = db.query(models.Switch).order_by(models.Switch.name)
    if switch_name:
        q = q.filter(models.Switch.name == switch_name)
    switches = q.all()
    servers = db.query(models.Server).order_by(models.Server.name).all()

    links, unmatched = [], []
    for sw in switches:
        snap_desc = _snapshot_descriptions(db, sw)
        rows = _latest_capture_rows(db, sw)
        seen_ifaces = set()

        def _consider(iface_name, link_state, descr):
            descr = (descr or "").strip()
            if not descr:
                return
            is_lag = bool(_LAG_RE.match(iface_name or ""))
            m = _match_server(descr, servers)
            if not m:
                if is_lag:
                    unmatched.append({
                        "switch": sw.name, "interface": iface_name,
                        "description": descr,
                        "hint": "no registered server matches — the number in "
                                "the description must equal a registered "
                                "server's iLO last octet (e.g. 'VCF 161')",
                    })
                return
            srv, basis = m
            links.append({
                "switch": sw.name,
                "interface": iface_name,
                "is_lag": is_lag,
                "link_state": link_state or "",
                "description": descr,
                "server": srv.name,
                "server_ilo": srv.ilo_host,
                "match_basis": basis,          # name | label | octet
                "server_metrics": {
                    k: (None if v is None else {
                        "value": v["value"], "unit": v["unit"],
                        "stale": v["stale"], "live": v.get("live", False),
                    }) for k, v in _server_latest(db, srv).items()
                },
                "attribution": _estimate_attribution(db, sw, srv, iface_name),
            })

        # 1. ports from the latest capture (have live link_state + traffic),
        #    preferring the snapshot description when the brief one is blank.
        for r in rows:
            seen_ifaces.add(r.interface_name)
            descr = (r.port_description or "").strip() \
                or snap_desc.get(r.interface_name, "")
            _consider(r.interface_name, r.link_state, descr)

        # 2. described interfaces that exist only in the snapshot (no port-stats
        #    row yet) — still worth matching, just without live traffic.
        for iface, descr in snap_desc.items():
            if iface in seen_ifaces:
                continue
            _consider(iface, "", descr)

    # LAGs first (the stated workflow), then by switch/interface.
    links.sort(key=lambda x: (0 if x["is_lag"] else 1,
                              x["switch"], x["interface"]))
    return {"links": links, "unmatched": unmatched,
            "servers_registered": len(servers),
            "checked_at": models.ist_now()}
