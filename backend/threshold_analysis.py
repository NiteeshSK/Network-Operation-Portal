"""
threshold_analysis.py — Derive per-server alert thresholds from real history.

THE PROBLEM WITH ONE-SIZE-FITS-ALL
----------------------------------
"Alert when CPU > 80%" is wrong for almost every server: a GPU training node
legitimately sits at 95% for days, while a quiet management VM at 40% is
already in trouble. The right thresholds come from each server's OWN
baseline.

THE ANALYSIS
------------
For each (server, sensor) we take the last N hours of ServerMetric samples
(the ~1 Hz stream gives tens of thousands of points per day) and compute the
distribution: mean, standard deviation, min/max, and the p05/p50/p95/p99
percentiles (linear interpolation, no numpy needed). The recommendation
combines the two classic baselining approaches so that neither a fat-tailed
distribution (where σ misleads) nor a spiky one (where percentiles misleadingly
hug the spikes) produces a silly number:

    upper = min(unit_max, max(p95, mean + 3σ))
    lower = max(0,        min(p05, mean − 3σ))

Dwell (how long a breach must sustain before alerting) is recommended as
3× the median sampling interval, floored at 30 s — enough to ignore a single
noisy sample without hiding a real event.

Everything is stored in server_threshold_analysis (auditable: the operator
sees the whole distribution, not just the answer). "Apply" copies the
recommendation into ServerAlertSetting, which the existing alert engine and
Server Audits trail already enforce — this module only decides the numbers,
it does not duplicate the alerting machinery.
"""
from __future__ import annotations

from datetime import timedelta

import models
import ilo_client

# sensors that saturate at 100 (percent); others (counts, watts, MHz) don't
_PERCENT_UNITS = {"%"}

DEFAULT_SENSORS = ["cpu_utilization", "memory_bus_utilization"]
# The window matches the retention: analyse everything we still keep (7
# days), so the baseline naturally sharpens as history accumulates rather
# than being frozen at a fixed span.
DEFAULT_WINDOW_HOURS = 168         # = SERVER_METRICS_RETENTION_DAYS (7d)
MIN_SAMPLES = 30
# The gate: a server needs at least this much history before its numbers
# mean anything. 24h covers one full day/night cycle, so a nightly batch or
# an idle overnight period is inside the baseline instead of skewing it.
# Below this the server is reported as "still collecting", never given
# invented thresholds.
MIN_COVERAGE_HOURS = 24


def _percentile(sorted_vals: list[float], q: float) -> float:
    """Linear-interpolated percentile, q in [0,100]."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = (q / 100.0) * (len(sorted_vals) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = pos - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def analyze_server(db, srv, sensor: str,
                   window_hours: int = DEFAULT_WINDOW_HOURS) -> dict:
    """Compute the distribution + recommendation for one server/sensor.
    Returns a dict; does not write anything."""
    since = models.ist_now() - timedelta(hours=window_hours)
    rows = (db.query(models.ServerMetric.value,
                     models.ServerMetric.captured_at)
            .filter(models.ServerMetric.server_id == srv.id,
                    models.ServerMetric.sensor == sensor,
                    models.ServerMetric.captured_at >= since)
            .order_by(models.ServerMetric.captured_at.asc()).all())

    unit = ilo_client.SENSORS.get(sensor, ("", ""))[1]
    base = {"server": srv.name, "sensor": sensor, "unit": unit,
            "window_hours": window_hours, "sample_count": len(rows)}

    if len(rows) < MIN_SAMPLES:
        return {**base, "ok": False, "coverage_hours": 0,
                "note": (f"only {len(rows)} sample(s) in the last "
                         f"{window_hours}h — need ≥{MIN_SAMPLES}; keep the "
                         f"server streaming and retry")}

    # Coverage gate: how much of the requested window does the data span?
    coverage_h = (models.ist_now() - rows[0][1]).total_seconds() / 3600.0
    coverage_h = round(min(coverage_h, float(window_hours)), 1)
    if coverage_h < min(MIN_COVERAGE_HOURS, window_hours):
        need = min(MIN_COVERAGE_HOURS, window_hours)
        return {**base, "ok": False, "coverage_hours": coverage_h,
                "note": (f"still collecting: {coverage_h:.1f}h stored, needs "
                         f"≥{need}h (one full day/night cycle) before its "
                         f"thresholds mean anything")}

    vals = sorted((r[0] or 0) / 100.0 for r in rows)
    n = len(vals)
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / n
    std = var ** 0.5

    p05 = _percentile(vals, 5)
    p50 = _percentile(vals, 50)
    p95 = _percentile(vals, 95)
    p99 = _percentile(vals, 99)

    unit_max = 100.0 if unit in _PERCENT_UNITS else None
    upper = max(p95, mean + 3 * std)
    if unit_max is not None:
        upper = min(unit_max, upper)
    lower = max(0.0, min(p05, mean - 3 * std))

    # dwell: 3× the median sample interval, floored at 30 s
    gaps = sorted(
        (rows[i + 1][1] - rows[i][1]).total_seconds()
        for i in range(len(rows) - 1)
        if (rows[i + 1][1] - rows[i][1]).total_seconds() > 0)
    median_gap = gaps[len(gaps) // 2] if gaps else 10.0
    dwell = max(30, int(round(3 * median_gap)))

    return {**base, "ok": True, "coverage_hours": coverage_h,
            "mean": round(mean, 2), "std": round(std, 2),
            "min": round(vals[0], 2), "max": round(vals[-1], 2),
            "p05": round(p05, 2), "p50": round(p50, 2),
            "p95": round(p95, 2), "p99": round(p99, 2),
            "rec_lower": round(lower, 2), "rec_upper": round(upper, 2),
            "rec_dwell_sec": dwell,
            "method": "p05/p95 ∪ μ±3σ"}


def _upsert(db, srv, res: dict) -> models.ServerThresholdAnalysis:
    row = (db.query(models.ServerThresholdAnalysis)
           .filter(models.ServerThresholdAnalysis.server_id == srv.id,
                   models.ServerThresholdAnalysis.sensor == res["sensor"])
           .first())
    if not row:
        row = models.ServerThresholdAnalysis(server_id=srv.id,
                                             server_name=srv.name,
                                             sensor=res["sensor"])
        db.add(row)
    x = lambda v: int(round(float(v) * 100))
    row.window_hours = res["window_hours"]
    row.coverage_hours = int(round(res.get("coverage_hours") or 0))
    row.sample_count = res["sample_count"]
    row.mean_x100, row.std_x100 = x(res["mean"]), x(res["std"])
    row.min_x100, row.max_x100 = x(res["min"]), x(res["max"])
    row.p05_x100, row.p50_x100 = x(res["p05"]), x(res["p50"])
    row.p95_x100, row.p99_x100 = x(res["p95"]), x(res["p99"])
    row.rec_lower_x100 = x(res["rec_lower"])
    row.rec_upper_x100 = x(res["rec_upper"])
    row.rec_dwell_sec = res["rec_dwell_sec"]
    row.method = res["method"]
    row.computed_at = models.ist_now()
    return row


def analyze_all(db, sensors: list[str] | None = None,
                window_hours: int = DEFAULT_WINDOW_HOURS) -> dict:
    """Analyze every server for the given sensors and PERSIST the results.
    Servers without enough history are reported, not stored."""
    sensors = sensors or DEFAULT_SENSORS
    servers = db.query(models.Server).order_by(models.Server.name).all()
    stored, skipped = [], []
    for srv in servers:
        for sensor in sensors:
            res = analyze_server(db, srv, sensor, window_hours)
            if res["ok"]:
                _upsert(db, srv, res)
                stored.append(res)
            else:
                skipped.append(res)
    db.commit()
    return {"analyzed": len(stored), "skipped": len(skipped),
            "results": stored, "insufficient": skipped,
            "computed_at": models.ist_now()}


def row_out(r: models.ServerThresholdAnalysis) -> dict:
    f = lambda v: (v or 0) / 100.0
    return {"server": r.server_name, "sensor": r.sensor,
            "window_hours": r.window_hours,
            "coverage_hours": r.coverage_hours or 0,
            "sample_count": r.sample_count,
            "mean": f(r.mean_x100), "std": f(r.std_x100),
            "min": f(r.min_x100), "max": f(r.max_x100),
            "p05": f(r.p05_x100), "p50": f(r.p50_x100),
            "p95": f(r.p95_x100), "p99": f(r.p99_x100),
            "rec_lower": f(r.rec_lower_x100), "rec_upper": f(r.rec_upper_x100),
            "rec_dwell_sec": r.rec_dwell_sec, "method": r.method,
            "applied_at": r.applied_at.isoformat() if r.applied_at else None,
            "computed_at": r.computed_at.isoformat() if r.computed_at else None}


def apply_to_alert_settings(db, server_name: str | None = None,
                            sensor: str | None = None) -> dict:
    """Copy stored recommendations into ServerAlertSetting — the table the
    alert engine and Server Audits already watch. Scoped by server and/or
    sensor; None = all."""
    q = db.query(models.ServerThresholdAnalysis)
    if server_name:
        q = q.filter(models.ServerThresholdAnalysis.server_name == server_name)
    if sensor:
        q = q.filter(models.ServerThresholdAnalysis.sensor == sensor)
    rows = q.all()
    applied = []
    now = models.ist_now()
    for r in rows:
        setting = (db.query(models.ServerAlertSetting)
                   .filter(models.ServerAlertSetting.server_id == r.server_id,
                           models.ServerAlertSetting.sensor == r.sensor)
                   .first())
        if not setting:
            setting = models.ServerAlertSetting(
                server_id=r.server_id, server_name=r.server_name,
                sensor=r.sensor)
            db.add(setting)
        setting.upper_threshold = int(round((r.rec_upper_x100 or 0) / 100.0))
        setting.lower_threshold = int(round((r.rec_lower_x100 or 0) / 100.0))
        setting.upper_dwell_sec = r.rec_dwell_sec or 60
        setting.lower_dwell_sec = r.rec_dwell_sec or 60
        setting.updated_at = now
        r.applied_at = now
        applied.append({"server": r.server_name, "sensor": r.sensor,
                        "upper": setting.upper_threshold,
                        "lower": setting.lower_threshold,
                        "dwell_sec": setting.upper_dwell_sec})
    db.commit()
    return {"applied": applied, "count": len(applied)}
