"""
retention.py — One place that decides how long anything is kept.

WHY THIS FILE EXISTS

The old cleanup lived inline in scheduler.py and covered four tables:
port_stats, arp_entries, server_metrics, and only the auto-generated rows in
command_logs. Everything else grew without limit — snapshots (which store the
FULL config text of every switch, every capture), audit_events, config_changes,
lacp_deployments, the alert tables, and every manually-run command log.
On a fleet of any size those are the tables that actually fill the disk.

This module sweeps all of them on a single window, NOC_RETENTION_DAYS,
which defaults to 7.

────────────────────────────────────────────────────────────────────────────
WHAT IS DELETED AND WHAT IS NOT

Two categories of table exist in this schema and they must not be treated
the same way.

  HISTORY — append-only records of things that happened. Rows are
  individually worthless after a week and collectively expensive. These are
  swept: port_stats, arp_entries, command_logs, snapshots, server_metrics,
  server_alert_events, server_threshold_analysis, audit_events,
  config_changes, lacp_deployments.

  CONFIGURATION — the state of the system, entered by an operator. It has
  timestamps, but those record when it was CREATED, not when it happened.
  These are NEVER swept, at any window, because deleting them means the
  portal forgets its own inventory: switches, servers, auto_capture_settings,
  server_alert_settings, config_templates, compliance_rules.

Purging a `switches` row because it was added more than seven days ago would
delete the switch from the portal. That is not retention, that is data loss,
so the split above is enforced structurally: the config tables are simply
never named in this file.

────────────────────────────────────────────────────────────────────────────
FOUR CARVE-OUTS

These are correctness constraints, not preferences. Each one exists because
deleting the row on schedule would make the portal actively wrong rather than
merely forgetful.

  1. The newest snapshot per switch is kept regardless of age.
     Drift detection works by diffing a new capture against the previous
     snapshot. Delete the last one and the next capture has no baseline: it
     reports "no previous config" instead of reporting drift. On a switch
     that is captured rarely, a blind sweep would silently disable drift
     detection for that device.

  2. Alert events still in state='active' are kept regardless of age.
     An active alert is a live, unresolved problem. An alert that has been
     firing for eight days is precisely the one nobody should be deleting.
     Only cleared alerts age out.

  3. config_changes and lacp_deployments still in flight are kept
     regardless of age. A row in status 'queued' or 'running' describes work
     that has not finished. Deleting it orphans the operation and loses the
     rollback point that makes the change reversible.

  4. server_alert_metric_snapshots has its own window.
     models.py documents this table as the forensic record, explicitly
     designed to outlive the raw metrics so that the evidence behind an old
     alert survives after the 1 Hz history is gone. Sweeping it on the same
     seven days collapses that design. It defaults to 7 to honour the
     "nothing older than seven days" requirement, but it is a separate
     variable — NOC_FORENSIC_RETENTION_DAYS — so it can be raised without
     touching anything else.

────────────────────────────────────────────────────────────────────────────
ENVIRONMENT

  NOC_RETENTION_DAYS             default 7    every history table
  NOC_FORENSIC_RETENTION_DAYS    default 7    alert forensic snapshots only
  NOC_RETENTION_BATCH_SIZE       default 20000 rows per DELETE statement

Legacy PORT_STATS_RETENTION_HOURS / PORT_STATS_RETENTION_DAYS are still read
as a fallback so existing deployments do not silently change behaviour on
upgrade, but NOC_RETENTION_DAYS wins when it is set.
"""
import os
from datetime import timedelta

from sqlalchemy import text

from database import engine
import models


# ── Window resolution ───────────────────────────────────────────────────────

def _resolve_retention_days() -> float:
    """Work out the retention window, newest-wins, with legacy fallbacks.

    Order of precedence:
        NOC_RETENTION_DAYS  >  PORT_STATS_RETENTION_HOURS
                            >  PORT_STATS_RETENTION_DAYS
                            >  7
    """
    explicit = os.getenv("NOC_RETENTION_DAYS")
    if explicit is not None:
        try:
            return max(float(explicit), 0.04)      # floor ~1 hour
        except ValueError:
            print(f"[retention] NOC_RETENTION_DAYS={explicit!r} is not a "
                  f"number; falling back to 7 days.", flush=True)
            return 7.0

    legacy_hours = os.getenv("PORT_STATS_RETENTION_HOURS")
    if legacy_hours is not None:
        try:
            return max(float(legacy_hours) / 24.0, 0.04)
        except ValueError:
            pass

    legacy_days = os.getenv("PORT_STATS_RETENTION_DAYS")
    if legacy_days is not None:
        try:
            return max(float(legacy_days), 0.04)
        except ValueError:
            pass

    return 7.0


RETENTION_DAYS = _resolve_retention_days()

try:
    FORENSIC_RETENTION_DAYS = max(
        float(os.getenv("NOC_FORENSIC_RETENTION_DAYS", str(RETENTION_DAYS))),
        RETENTION_DAYS,        # never shorter than the main window
    )
except ValueError:
    FORENSIC_RETENTION_DAYS = RETENTION_DAYS

try:
    BATCH_SIZE = max(int(os.getenv("NOC_RETENTION_BATCH_SIZE", "20000")), 1000)
except ValueError:
    BATCH_SIZE = 20000


# ── Sweep definitions ───────────────────────────────────────────────────────
#
# (table, timestamp column, extra SQL predicate or None)
#
# The predicate is ANDed with the age test and expresses the carve-outs above.
# Anything not in this list is never touched.

_HISTORY_SWEEPS = [
    # Highest-volume first, so the batch budget is spent where it matters.
    ("port_stats",                "captured_at", None),
    ("arp_entries",               "captured_at", None),
    ("server_metrics",            "captured_at", None),

    # All command logs now, not just [AUTO*]. Manually-run commands were the
    # single biggest unbounded table in the old scheme.
    ("command_logs",              "timestamp",   None),

    # Cleared alerts only — carve-out 2.
    ("server_alert_events",       "raised_at",   "state <> 'active'"),

    ("server_threshold_analysis", "computed_at", None),
    ("audit_events",              "timestamp",   None),

    # Finished work only — carve-out 3. Children cascade via FK.
    ("config_changes",            "created_at",
     "status NOT IN ('queued', 'running')"),
    ("lacp_deployments",          "created_at",
     "status <> 'running'"),
]


def _delete_batched(conn, table: str, column: str, cutoff, predicate=None) -> int:
    """DELETE in bounded batches rather than one enormous statement.

    A single unqualified DELETE across a week of 15-second port stats can
    touch millions of rows, which takes a long lock and builds a very large
    transaction. Batching keeps each statement short so the capture loops
    running against the same tables are not blocked behind it.

    Uses a PK subselect because MySQL-style `DELETE ... LIMIT` is not valid
    in PostgreSQL.
    """
    where = f"{column} < :cutoff"
    if predicate:
        where += f" AND ({predicate})"

    sql = text(
        f"DELETE FROM {table} WHERE id IN ("
        f"  SELECT id FROM {table} WHERE {where} "
        f"  ORDER BY id LIMIT :batch"
        f")"
    )

    removed = 0
    while True:
        result = conn.execute(sql, {"cutoff": cutoff, "batch": BATCH_SIZE})
        count = result.rowcount or 0
        removed += count
        if count < BATCH_SIZE:
            return removed


def _delete_stale_snapshots(conn, cutoff) -> int:
    """Delete old snapshots but keep the newest one per switch — carve-out 1.

    The NOT IN subselect pins the most recent snapshot id for every switch,
    so a device that has not been captured in a month still keeps exactly one
    row to diff against.
    """
    sql = text(
        "DELETE FROM snapshots "
        "WHERE captured_at < :cutoff "
        "  AND id NOT IN ("
        "    SELECT DISTINCT ON (switch_id) id "
        "    FROM snapshots "
        "    ORDER BY switch_id, captured_at DESC"
        "  )"
    )
    return conn.execute(sql, {"cutoff": cutoff}).rowcount or 0


def run_retention_cleanup() -> dict:
    """Sweep every history table. Safe to call repeatedly; safe at boot.

    Never raises: retention failing is not a reason to take the portal down,
    so problems are logged and reported in the return value instead.
    """
    now = models.ist_now()
    cutoff = now - timedelta(days=RETENTION_DAYS)
    forensic_cutoff = now - timedelta(days=FORENSIC_RETENTION_DAYS)

    report: dict[str, int] = {}
    errors: list[str] = []

    for table, column, predicate in _HISTORY_SWEEPS:
        try:
            # One transaction per table. A failure on an optional table (say
            # it does not exist yet on a fresh DB) must not roll back the
            # sweeps that already succeeded.
            with engine.begin() as conn:
                report[table] = _delete_batched(
                    conn, table, column, cutoff, predicate
                )
        except Exception as exc:
            errors.append(f"{table}: {exc}")

    try:
        with engine.begin() as conn:
            report["snapshots"] = _delete_stale_snapshots(conn, cutoff)
    except Exception as exc:
        errors.append(f"snapshots: {exc}")

    try:
        with engine.begin() as conn:
            report["server_alert_metric_snapshots"] = _delete_batched(
                conn, "server_alert_metric_snapshots", "sample_at",
                forensic_cutoff,
            )
    except Exception as exc:
        errors.append(f"server_alert_metric_snapshots: {exc}")

    total = sum(report.values())
    if total:
        detail = ", ".join(
            f"{table}={count}" for table, count in report.items() if count
        )
        print(f"[retention] removed {total} row(s) older than "
              f"{RETENTION_DAYS:g}d — {detail}", flush=True)
    else:
        print(f"[retention] nothing older than {RETENTION_DAYS:g}d", flush=True)

    for err in errors:
        print(f"[retention] error: {err}", flush=True)

    return {"cutoff": cutoff.isoformat(), "removed": report, "errors": errors}


def retention_status() -> dict:
    """Current window plus per-table row counts and oldest surviving row.

    Exposed on /api/retention so the policy can be verified from the portal
    rather than by opening a psql session on the server.
    """
    tables = [t for t, _, _ in _HISTORY_SWEEPS] + [
        "snapshots", "server_alert_metric_snapshots",
    ]
    columns = {t: c for t, c, _ in _HISTORY_SWEEPS}
    columns["snapshots"] = "captured_at"
    columns["server_alert_metric_snapshots"] = "sample_at"

    out = []
    for table in tables:
        try:
            with engine.begin() as conn:
                row = conn.execute(text(
                    f"SELECT COUNT(*) AS n, MIN({columns[table]}) AS oldest "
                    f"FROM {table}"
                )).mappings().first()
            out.append({
                "table": table,
                "rows": int(row["n"] or 0),
                "oldest": row["oldest"].isoformat() if row["oldest"] else None,
            })
        except Exception as exc:
            out.append({"table": table, "error": str(exc)})

    return {
        "retention_days": RETENTION_DAYS,
        "forensic_retention_days": FORENSIC_RETENTION_DAYS,
        "batch_size": BATCH_SIZE,
        "tables": out,
        "never_purged": [
            "switches", "servers", "auto_capture_settings",
            "server_alert_settings", "config_templates", "compliance_rules",
        ],
    }
