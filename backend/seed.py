"""
seed.py — Database initialization + idempotent in-place migrations.

Runs on every backend container start. Hardened so missing-column bugs
can't silently leave your DB out of date:

  - Uses Postgres `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` so each
    statement is atomic and idempotent at the DB level, not just at
    the application level. SQLite falls back to try/catch.
  - Every ALTER is in its own transaction so one failure doesn't block
    the others.
  - After all migrations, runs a final verification pass that prints
    the actual columns it sees, so we can spot mismatches in logs.
"""
from sqlalchemy import text, inspect, exc as sa_exc
from database import engine, Base
from models import (   # populate Base.metadata
    Switch, CommandLog, Snapshot, PortStat, AutoCaptureSetting, ArpEntry,
    Server, ServerMetric, ServerAlertSetting,   # server monitoring (additive)
    ServerAlertEvent,                            # alert audit trail
    ServerThresholdAnalysis,                     # derived thresholds
    ServerAlertMetricSnapshot,                   # evidence at alert time
    LacpDeployment,                              # LACP one-click deployments
    ConfigTemplate, ComplianceRule, AuditEvent, # phase 1: templates/compliance/audit
    ConfigChange, ConfigChangeTarget,           # phase 2: guarded apply
)


PORT_STATS_NEW_COLUMNS = [
    ("port_description", "VARCHAR(512) DEFAULT ''"),  # consolidated: "mode · vlan N · description"
    ("total_packets",    "BIGINT       DEFAULT 0"),
]

AUTOCAPTURE_NEW_COLUMNS = [
    ("port_stats_enabled",          "BOOLEAN   DEFAULT FALSE"),
    ("port_stats_interval_seconds", "INTEGER   DEFAULT 30"),
    ("port_stats_last_captured_at", "TIMESTAMP"),
    ("port_stats_next_due_at",      "TIMESTAMP"),
    # Health of the last auto-capture attempt, surfaced in the UI so operators
    # can see WHY capture isn't working (e.g. SSH auth failure) instead of it
    # failing silently.
    ("last_snapshot_status",        "VARCHAR(16) DEFAULT ''"),
    ("last_snapshot_error",         "TEXT        DEFAULT ''"),
    ("last_port_stats_status",      "VARCHAR(16) DEFAULT ''"),
    ("last_port_stats_error",       "TEXT        DEFAULT ''"),
]


# Server-monitoring columns added after the first release of the feature.
SERVERS_NEW_COLUMNS = [
    ("collection_mode", "VARCHAR(16)  DEFAULT 'auto'"),
    ("ssh_host",        "VARCHAR(64)  DEFAULT ''"),
    ("ssh_port",        "INTEGER      DEFAULT 22"),
    ("ssh_username",    "VARCHAR(64)  DEFAULT ''"),
    ("ssh_password",    "VARCHAR(128) DEFAULT ''"),
    ("last_source",     "VARCHAR(16)  DEFAULT ''"),
]

SERVER_METRICS_NEW_COLUMNS = [
    ("source", "VARCHAR(16) DEFAULT ''"),
]

THRESHOLD_ANALYSIS_NEW_COLUMNS = [
    ("coverage_hours", "INTEGER DEFAULT 0"),
]


def _dialect_is_postgres() -> bool:
    return engine.dialect.name in ("postgresql", "postgres")


def _add_column_safely(table: str, column: str, ddl: str) -> str:
    """
    Add a column if missing. Returns one of:
      'added'       — column did not exist and was added now
      'exists'      — already present
      'error: ...'  — failure detail (does NOT raise)
    """
    if _dialect_is_postgres():
        # Postgres path: a single atomic statement, idempotent.
        try:
            with engine.begin() as conn:
                conn.execute(text(
                    f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS "
                    f"{column} {ddl}"
                ))
            # Re-inspect to confirm
            with engine.connect() as conn:
                cols = [c["name"] for c in inspect(conn).get_columns(table)]
            return "added" if column in cols else "error: column not visible after add"
        except sa_exc.SQLAlchemyError as e:
            return f"error: {type(e).__name__}: {e}"
    else:
        # SQLite path: needs check-then-add.
        try:
            with engine.connect() as conn:
                existing = [c["name"] for c in inspect(conn).get_columns(table)]
                if column in existing:
                    return "exists"
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
            return "added"
        except sa_exc.SQLAlchemyError as e:
            msg = str(e).lower()
            if "duplicate" in msg or "already exists" in msg:
                return "exists"
            return f"error: {type(e).__name__}: {e}"


def init():
    print("[seed] dialect =", engine.dialect.name, flush=True)
    print("[seed] Creating tables (if not present)...", flush=True)
    Base.metadata.create_all(bind=engine)

    # Apply column-by-column migrations. Each is independent — if one fails
    # the others still try, and we log all results.
    with engine.connect() as conn:
        existing_tables = set(inspect(conn).get_table_names())

    if "servers" in existing_tables:
        for col, ddl in SERVERS_NEW_COLUMNS:
            r = _add_column_safely("servers", col, ddl)
            print(f"[seed] servers.{col}: {r}", flush=True)

    if "server_metrics" in existing_tables:
        for col, ddl in SERVER_METRICS_NEW_COLUMNS:
            r = _add_column_safely("server_metrics", col, ddl)
            print(f"[seed] server_metrics.{col}: {r}", flush=True)

    if "server_threshold_analysis" in existing_tables:
        for col, ddl in THRESHOLD_ANALYSIS_NEW_COLUMNS:
            r = _add_column_safely("server_threshold_analysis", col, ddl)
            print(f"[seed] server_threshold_analysis.{col}: {r}", flush=True)

    if "port_stats" in existing_tables:
        for col, ddl in PORT_STATS_NEW_COLUMNS:
            result = _add_column_safely("port_stats", col, ddl)
            print(f"[seed] port_stats.{col:20s} -> {result}", flush=True)

    if "auto_capture_settings" in existing_tables:
        for col, ddl in AUTOCAPTURE_NEW_COLUMNS:
            result = _add_column_safely("auto_capture_settings", col, ddl)
            print(f"[seed] auto_capture_settings.{col:30s} -> {result}", flush=True)

    # Drop the deprecated split columns if an older DB still has them.
    # We consolidated mode + vlan + description into the single
    # `port_description` column.
    if "port_stats" in existing_tables and _dialect_is_postgres():
        for legacy in ("port_mode", "port_vlan"):
            try:
                with engine.begin() as conn:
                    conn.execute(text(
                        f"ALTER TABLE port_stats DROP COLUMN IF EXISTS {legacy}"
                    ))
                print(f"[seed] port_stats.{legacy} -> dropped (if existed)", flush=True)
            except Exception as e:
                print(f"[seed] port_stats.{legacy} drop skipped: {e}", flush=True)

    # Final verification pass — print actual schema
    print("[seed] Verification:", flush=True)
    with engine.connect() as conn:
        insp = inspect(conn)
        for tbl in ("port_stats", "auto_capture_settings", "arp_entries"):
            if tbl in insp.get_table_names():
                cols = [c["name"] for c in insp.get_columns(tbl)]
                print(f"[seed]   {tbl}: {len(cols)} cols = {cols}", flush=True)
            else:
                print(f"[seed]   {tbl}: MISSING", flush=True)

    # Hard assertions — if these fail, we WANT the container to refuse to start
    # rather than silently accept inserts that will 500 later.
    with engine.connect() as conn:
        ps_cols = {c["name"] for c in inspect(conn).get_columns("port_stats")}
        required = {"port_description", "total_packets"}
        missing = required - ps_cols
        if missing:
            raise RuntimeError(
                f"[seed] FATAL: port_stats is missing required columns {missing}. "
                f"Cannot start backend until these are added. Run manually:\n"
                + "\n".join(
                    f"  ALTER TABLE port_stats ADD COLUMN IF NOT EXISTS {c} ...;"
                    for c in missing
                )
            )

    print("[seed] Done — all required columns present.", flush=True)


if __name__ == "__main__":
    init()