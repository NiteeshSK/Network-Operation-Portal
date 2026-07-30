"""
server_export.py — Snapshot the whole server fleet into one Excel workbook.

SHAPE OF THE OUTPUT
-------------------
    Sheet 1        "Fleet overview"  — every server on one row
    Sheet 2..n+1   one sheet per server, named after the server

Each server sheet carries four sections, top to bottom:

    1. Identity        name, iLO address, description, location, source,
                       poll status, last error, window covered, sample count
    2. Derived         the stored threshold analysis per sensor — mean, sigma,
       thresholds      percentiles, recommended bounds, coverage
    3. Alerts          every alert episode raised inside the window
    4. Metric history  the actual telemetry, bucketed

WHY THE HISTORY IS BUCKETED
---------------------------
Seven days of ~10-second writes is roughly 60,000 samples per sensor, so a
raw dump would be ~420,000 rows per server — slow to generate, slow to open,
and unreadable. Instead each bucket (5 minutes by default) reports the
average and the peak per sensor. That is 2,016 rows per server for a week,
opens instantly, and keeps the peaks that matter for capacity work — an
average alone would hide exactly the spikes an operator is looking for.

The bucket size is a parameter, so a shorter window can be exported at finer
resolution when someone is investigating a specific incident.
"""
from __future__ import annotations

import io
import re
from datetime import timedelta

from sqlalchemy import desc

import models
import ilo_client

# Excel forbids these in sheet names, and caps the name at 31 characters.
_BAD_SHEET_CHARS = re.compile(r"[\[\]:*?/\\]")

HPE_GREEN = "01A982"
DARK = "1D2530"
LIGHT = "F2FBF7"
GREY = "F4F6F5"


def _safe_sheet_name(name: str, used: set) -> str:
    clean = _BAD_SHEET_CHARS.sub("-", str(name or "server")).strip() or "server"
    clean = clean[:31]
    if clean.lower() not in used:
        used.add(clean.lower())
        return clean
    # De-duplicate within the 31-char ceiling: "very-long-name" -> "very-long~2"
    for n in range(2, 1000):
        suffix = f"~{n}"
        candidate = clean[:31 - len(suffix)] + suffix
        if candidate.lower() not in used:
            used.add(candidate.lower())
            return candidate
    used.add(clean.lower())
    return clean


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""


def _bucket_metrics(db, srv, since, until, bucket_seconds: int) -> tuple:
    """Return (sensor_keys, rows) where each row is
    [bucket_start, s1_avg, s1_max, s2_avg, s2_max, ...].

    Streams the query rather than loading a week of samples into memory, and
    aggregates as it goes.
    """
    sensors = list(ilo_client.SENSORS.keys())
    # bucket_start_epoch -> {sensor: [sum, count, max]}
    buckets: dict[int, dict] = {}

    q = (db.query(models.ServerMetric.sensor,
                  models.ServerMetric.value,
                  models.ServerMetric.captured_at)
         .filter(models.ServerMetric.server_id == srv.id,
                 models.ServerMetric.captured_at >= since,
                 models.ServerMetric.captured_at <= until)
         .order_by(models.ServerMetric.captured_at.asc()))

    total = 0
    for sensor, value, captured_at in q.yield_per(5000):
        if captured_at is None or value is None:
            continue
        total += 1
        epoch = int(captured_at.timestamp())
        key = epoch - (epoch % bucket_seconds)
        slot = buckets.setdefault(key, {})
        agg = slot.get(sensor)
        v = value / 100.0
        if agg is None:
            slot[sensor] = [v, 1, v]
        else:
            agg[0] += v
            agg[1] += 1
            if v > agg[2]:
                agg[2] = v

    from datetime import datetime
    rows = []
    for key in sorted(buckets):
        slot = buckets[key]
        row = [datetime.fromtimestamp(key)]
        for s in sensors:
            agg = slot.get(s)
            if agg:
                row.append(round(agg[0] / agg[1], 2))
                row.append(round(agg[2], 2))
            else:
                row.append(None)
                row.append(None)
        rows.append(row)
    return sensors, rows, total


def build_workbook(db, days: int = 7, bucket_seconds: int = 300,
                   server_names: list[str] | None = None) -> bytes:
    """Build the fleet snapshot workbook and return it as bytes."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    until = models.ist_now()
    since = until - timedelta(days=days)

    q = db.query(models.Server).order_by(models.Server.name)
    if server_names:
        q = q.filter(models.Server.name.in_(server_names))
    servers = q.all()

    wb = Workbook()

    title_font = Font(bold=True, size=13, color="FFFFFF")
    title_fill = PatternFill("solid", fgColor=DARK)
    sect_font = Font(bold=True, size=10, color="FFFFFF")
    sect_fill = PatternFill("solid", fgColor=HPE_GREEN)
    head_font = Font(bold=True, size=9)
    head_fill = PatternFill("solid", fgColor=GREY)
    key_font = Font(bold=True, size=9)
    thin = Side(style="thin", color="D8D8D5")
    box = Border(bottom=thin)

    def section(ws, row, text, width):
        ws.cell(row=row, column=1, value=text)
        for c in range(1, width + 1):
            cell = ws.cell(row=row, column=c)
            cell.fill = sect_fill
            cell.font = sect_font
        return row + 1

    def table_header(ws, row, headers):
        for i, h in enumerate(headers, start=1):
            c = ws.cell(row=row, column=i, value=h)
            c.font = head_font
            c.fill = head_fill
            c.border = box
            c.alignment = Alignment(horizontal="left", vertical="center")
        return row + 1

    # ══ Sheet 1 — fleet overview ══════════════════════════════════════════
    ov = wb.active
    ov.title = "Fleet overview"
    ov.cell(row=1, column=1, value="NOC Portal — server fleet snapshot")
    for c in range(1, 12):
        ov.cell(row=1, column=c).fill = title_fill
        ov.cell(row=1, column=c).font = title_font
    ov.row_dimensions[1].height = 22

    ov.cell(row=2, column=1, value="Generated").font = key_font
    ov.cell(row=2, column=2, value=_fmt(until) + " IST")
    ov.cell(row=3, column=1, value="Window").font = key_font
    ov.cell(row=3, column=2, value=f"{_fmt(since)} → {_fmt(until)}  ({days} days)")
    ov.cell(row=4, column=1, value="Resolution").font = key_font
    ov.cell(row=4, column=2,
            value=f"{bucket_seconds // 60} minute buckets (average and peak per sensor)")
    ov.cell(row=5, column=1, value="Servers").font = key_font
    ov.cell(row=5, column=2, value=len(servers))

    r = table_header(ov, 7, ["Server", "iLO address", "Description", "Location",
                             "Source", "Status", "Last polled", "Samples in window",
                             "Active alerts", "CPU upper", "CPU lower"])

    # gather per-server figures as we go, so the overview matches the sheets
    per_server_counts = {}

    for srv in servers:
        samples = (db.query(models.ServerMetric)
                   .filter(models.ServerMetric.server_id == srv.id,
                           models.ServerMetric.captured_at >= since)
                   .count())
        per_server_counts[srv.id] = samples
        active = (db.query(models.ServerAlertEvent)
                  .filter(models.ServerAlertEvent.server_id == srv.id,
                          models.ServerAlertEvent.state == "active").count())
        thr = (db.query(models.ServerThresholdAnalysis)
               .filter(models.ServerThresholdAnalysis.server_id == srv.id,
                       models.ServerThresholdAnalysis.sensor == "cpu_utilization")
               .first())
        ov.cell(row=r, column=1, value=srv.name)
        ov.cell(row=r, column=2, value=srv.ilo_host)
        ov.cell(row=r, column=3, value=srv.description or "")
        ov.cell(row=r, column=4, value=srv.location or "")
        ov.cell(row=r, column=5, value=srv.last_source or "")
        ov.cell(row=r, column=6, value=srv.last_poll_status or "")
        ov.cell(row=r, column=7, value=_fmt(srv.last_polled_at))
        ov.cell(row=r, column=8, value=samples)
        ov.cell(row=r, column=9, value=active)
        ov.cell(row=r, column=10,
                value=round((thr.rec_upper_x100 or 0) / 100.0, 2) if thr else None)
        ov.cell(row=r, column=11,
                value=round((thr.rec_lower_x100 or 0) / 100.0, 2) if thr else None)
        r += 1

    for col, width in zip("ABCDEFGHIJK",
                          [22, 16, 42, 16, 11, 10, 20, 18, 13, 11, 11]):
        ov.column_dimensions[col].width = width
    ov.freeze_panes = "A8"

    # ══ One sheet per server ══════════════════════════════════════════════
    used_names = {"fleet overview"}
    sensor_labels = dict(ilo_client.SENSOR_LABELS)

    for srv in servers:
        ws = wb.create_sheet(_safe_sheet_name(srv.name, used_names))
        sensors, hist, total_samples = _bucket_metrics(
            db, srv, since, until, bucket_seconds)
        width = 1 + 2 * len(sensors)

        ws.cell(row=1, column=1, value=f"{srv.name} — server snapshot")
        for c in range(1, width + 1):
            ws.cell(row=1, column=c).fill = title_fill
            ws.cell(row=1, column=c).font = title_font
        ws.row_dimensions[1].height = 22

        # ── 1. identity ──
        row = section(ws, 3, "SERVER DETAILS", width)
        details = [
            ("Name", srv.name),
            ("iLO address", f"{srv.ilo_host}:{srv.ilo_port}"),
            ("Description", srv.description or ""),
            ("Location", srv.location or ""),
            ("Collection source", srv.last_source or "unknown"),
            ("Poll status", srv.last_poll_status or ""),
            ("Last error", srv.last_poll_error or "none"),
            ("Last polled", _fmt(srv.last_polled_at)),
            ("Added to portal", _fmt(srv.created_at)),
            ("Export window", f"{_fmt(since)} → {_fmt(until)}  ({days} days)"),
            ("Raw samples in window", total_samples),
            ("History resolution", f"{bucket_seconds // 60} minute buckets"),
        ]
        for k, v in details:
            ws.cell(row=row, column=1, value=k).font = key_font
            ws.cell(row=row, column=2, value=v)
            row += 1

        # ── 2. derived thresholds ──
        row += 1
        row = section(ws, row, "DERIVED THRESHOLDS (from this server's own history)", width)
        thr_rows = (db.query(models.ServerThresholdAnalysis)
                    .filter(models.ServerThresholdAnalysis.server_id == srv.id)
                    .order_by(models.ServerThresholdAnalysis.sensor).all())
        if thr_rows:
            row = table_header(ws, row, ["Sensor", "Mean", "Std dev", "p05", "p50",
                                         "p95", "p99", "Lower", "Upper",
                                         "Dwell (s)", "Samples", "Coverage (h)",
                                         "Method", "Computed", "Applied"])
            for t in thr_rows:
                f = lambda v: round((v or 0) / 100.0, 2)
                vals = [sensor_labels.get(t.sensor, t.sensor), f(t.mean_x100),
                        f(t.std_x100), f(t.p05_x100), f(t.p50_x100), f(t.p95_x100),
                        f(t.p99_x100), f(t.rec_lower_x100), f(t.rec_upper_x100),
                        t.rec_dwell_sec, t.sample_count, t.coverage_hours,
                        t.method or "", _fmt(t.computed_at), _fmt(t.applied_at)]
                for i, v in enumerate(vals, start=1):
                    ws.cell(row=row, column=i, value=v)
                row += 1
        else:
            ws.cell(row=row, column=1,
                    value="No analysis stored yet — a server needs at least 24 hours "
                          "of history before its thresholds are derived.")
            row += 1

        # ── 3. alerts in the window ──
        row += 1
        row = section(ws, row, "ALERTS RAISED IN WINDOW", width)
        events = (db.query(models.ServerAlertEvent)
                  .filter(models.ServerAlertEvent.server_id == srv.id,
                          models.ServerAlertEvent.raised_at >= since)
                  .order_by(desc(models.ServerAlertEvent.raised_at)).all())
        if events:
            row = table_header(ws, row, ["Raised", "Cleared", "State", "Sensor",
                                         "Direction", "Threshold", "Value at raise",
                                         "Worst value", "Unit", "Dwell (s)",
                                         "Acknowledged by", "Acknowledged at"])
            for e in events:
                vals = [_fmt(e.raised_at), _fmt(e.cleared_at), e.state,
                        sensor_labels.get(e.sensor, e.sensor),
                        "above" if e.kind == "upper" else "below",
                        e.threshold, round((e.value or 0) / 100.0, 2),
                        round((e.worst_value or 0) / 100.0, 2), e.unit or "",
                        e.dwell_sec, e.acknowledged_by or "",
                        _fmt(e.acknowledged_at)]
                for i, v in enumerate(vals, start=1):
                    ws.cell(row=row, column=i, value=v)
                row += 1
        else:
            ws.cell(row=row, column=1, value="No alerts raised in this window.")
            row += 1

        # ── 4. metric history ──
        row += 1
        row = section(ws, row,
                      f"METRIC HISTORY — {bucket_seconds // 60} minute buckets "
                      f"(avg and peak per sensor)", width)
        headers = ["Timestamp"]
        for s in sensors:
            label = sensor_labels.get(s, s)
            unit = ilo_client.SENSORS[s][1]
            headers.append(f"{label} avg ({unit})")
            headers.append(f"{label} peak ({unit})")
        hist_header_row = row
        row = table_header(ws, row, headers)

        if hist:
            for hrow in hist:
                ws.cell(row=row, column=1, value=hrow[0]).number_format = \
                    "yyyy-mm-dd hh:mm"
                for i, v in enumerate(hrow[1:], start=2):
                    ws.cell(row=row, column=i, value=v)
                row += 1
            ws.freeze_panes = ws.cell(row=hist_header_row + 1, column=2)
        else:
            ws.cell(row=row, column=1,
                    value="No metrics stored in this window — the server may have "
                          "been added recently, or its credentials may be rejected.")
            row += 1

        ws.column_dimensions["A"].width = 22
        ws.column_dimensions["B"].width = 26
        for i in range(3, width + 1):
            ws.column_dimensions[get_column_letter(i)].width = 15

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
