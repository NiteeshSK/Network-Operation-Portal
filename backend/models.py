"""
models.py — Database schema.
"""
from sqlalchemy import Column, Integer, BigInteger,String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from zoneinfo import ZoneInfo
from database import Base


def ist_now():
    """Current time as a NAIVE datetime holding India Standard Time
    wall-clock (no tzinfo attached).

    Why naive: every DateTime column here is TIMESTAMP WITHOUT TIME ZONE.
    If we stored timezone-AWARE values, PostgreSQL would convert them using
    its session timezone (UTC by default) when writing to a naive column,
    and convert again — sometimes inconsistently — when evaluating WHERE
    clauses like `next_due_at <= now`. That offset (5h30m for IST) made the
    auto-capture "due" check never fire on Postgres, even though it worked on
    SQLite (which does no timezone conversion). Storing and comparing naive
    IST everywhere removes all of that ambiguity: naive-vs-naive comparisons
    are exact regardless of the database session timezone, and the JSON
    serializers tag these naive values as +05:30 for correct display.
    """
    return datetime.now(ZoneInfo("Asia/Kolkata")).replace(tzinfo=None)

class Switch(Base):
    __tablename__ = "switches"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(128), unique=True, nullable=False)
    host        = Column(String(64), nullable=False)
    port        = Column(Integer, default=22)
    device_type = Column(String(32), nullable=False)
    username    = Column(String(64), nullable=False)
    password    = Column(String(128), nullable=False)
    location    = Column(String(128), default="")
    created_at  = Column(DateTime, default=ist_now)  # callable ref, evaluated per row

    logs      = relationship("CommandLog", back_populates="switch", cascade="all, delete-orphan")
    snapshots = relationship("Snapshot",   back_populates="switch", cascade="all, delete-orphan")


class CommandLog(Base):
    __tablename__ = "command_logs"

    id          = Column(Integer, primary_key=True, index=True)
    switch_id   = Column(Integer, ForeignKey("switches.id"), nullable=False)
    switch_name = Column(String(128), nullable=False)
    command     = Column(String(256), nullable=False)
    output      = Column(Text, default="")
    success     = Column(Boolean, default=True)
    error       = Column(Text, default="")
    timestamp   = Column(DateTime, default=ist_now, index=True)  # callable ref

    switch = relationship("Switch", back_populates="logs")


class Snapshot(Base):
    __tablename__ = "snapshots"

    id             = Column(Integer, primary_key=True, index=True)
    switch_id      = Column(Integer, ForeignKey("switches.id"), nullable=False)
    switch_name    = Column(String(128), nullable=False)
    config_text    = Column(Text, nullable=False)
    config_hash    = Column(String(64), nullable=False, index=True)
    drift_detected = Column(Boolean, default=False)
    diff_from_prev = Column(Text, default="")
    captured_at    = Column(DateTime, default=ist_now, index=True)  # callable ref

    switch = relationship("Switch", back_populates="snapshots")
class PortStat(Base):
    __tablename__ = "port_stats"

    id             = Column(Integer, primary_key=True, index=True)
    switch_id      = Column(Integer, ForeignKey("switches.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    switch_name    = Column(String(128), nullable=False)
    interface_name = Column(String(64), nullable=False, index=True)
    link_state     = Column(String(16), default="")        # UP / DOWN / ADM

    in_packets     = Column(BigInteger, default=0)
    in_bytes       = Column(BigInteger, default=0)
    in_errors      = Column(BigInteger, default=0)
    in_broadcasts  = Column(BigInteger, default=0)

    out_packets    = Column(BigInteger, default=0)
    out_bytes      = Column(BigInteger, default=0)
    out_errors     = Column(BigInteger, default=0)
    out_broadcasts = Column(BigInteger, default=0)

    total_packets  = Column(BigInteger, default=0)   # in_packets + out_packets

    # Topology / description metadata — sourced from `display interface brief`
    # (Comware) or `show interface brief` (Aruba) and merged in at capture time.
    # Single consolidated descriptor column. Holds a human-readable
    # string built from `display interface brief` (Comware) or
    # `show interface brief` (Aruba). Format:
    #     "<mode> · vlan <vlan> · <description>"
    # Any missing piece is omitted. Empty string if the brief command
    # didn't return anything for this port.
    port_description = Column(String(512), default="")

    captured_at    = Column(DateTime, default=ist_now, index=True)  # callable ref


class ArpEntry(Base):
    """One row per (switch, IP) seen in an ARP table snapshot.
    Used to detect IP conflicts — same IP appearing with different MACs
    on the same VLAN or across switches."""
    __tablename__ = "arp_entries"

    id          = Column(Integer, primary_key=True, index=True)
    switch_id   = Column(Integer, ForeignKey("switches.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    switch_name = Column(String(128), nullable=False, index=True)

    ip_address  = Column(String(64), nullable=False, index=True)
    mac_address = Column(String(32), nullable=False)
    interface   = Column(String(64), default="")
    vlan        = Column(String(16), default="")
    arp_type    = Column(String(16), default="")   # Dynamic / Static
    age_seconds = Column(Integer, default=0)

    captured_at = Column(DateTime, default=ist_now, index=True)  # callable ref

class AutoCaptureSetting(Base):
    __tablename__ = "auto_capture_settings"

    id                = Column(Integer, primary_key=True, index=True)
    switch_id         = Column(Integer, ForeignKey("switches.id", ondelete="CASCADE"),
                               nullable=False, unique=True)
    switch_name       = Column(String(128), nullable=False)

    # Config-snapshot auto-capture (existing)
    interval_minutes  = Column(Integer, default=1440)   # 24 hours
    enabled           = Column(Boolean, default=False)
    last_captured_at  = Column(DateTime, nullable=True)
    next_due_at       = Column(DateTime, nullable=True)

    # Health of the most recent auto-snapshot attempt, so the UI can show WHY
    # capture isn't working (e.g. bad SSH credentials) instead of failing
    # silently. status is "ok" / "error" / "" (never attempted).
    last_snapshot_status = Column(String(16), default="")
    last_snapshot_error  = Column(Text, default="")

    # Port-stats auto-capture (new) — runs on its own faster cadence
    port_stats_enabled            = Column(Boolean, default=False)
    port_stats_interval_seconds   = Column(Integer, default=30)
    port_stats_last_captured_at   = Column(DateTime, nullable=True)
    port_stats_next_due_at        = Column(DateTime, nullable=True)

    # Same health tracking for the port-stats capture loop.
    last_port_stats_status = Column(String(16), default="")
    last_port_stats_error  = Column(Text, default="")

    created_at        = Column(DateTime, default=ist_now)  # callable ref

# ─────────────────────────────────────────────────────────────────────
# SERVER MONITORING (additive feature — mirrors the Switch pattern).
# Servers are HPE boxes monitored through their iLO 6 Redfish API.
# Nothing below touches or alters the switch tables above.
# ─────────────────────────────────────────────────────────────────────

class Server(Base):
    """One row per monitored server (its iLO endpoint). N servers can be
    added — there is no fixed count."""
    __tablename__ = "servers"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(128), unique=True, nullable=False)
    ilo_host    = Column(String(64), nullable=False)      # iLO IP / hostname
    ilo_port    = Column(Integer, default=443)
    username    = Column(String(64), nullable=False)
    password    = Column(String(128), nullable=False)
    location    = Column(String(128), default="")
    description = Column(String(256), default="")

    # How metrics are collected: "auto" (redfish then ssh), "redfish", "ssh".
    collection_mode = Column(String(16), default="auto")

    # Optional SSH access to the host OS — enables REAL /proc metrics
    # (cpu, memory, frequency, iowait, power) when Redfish isn't available.
    ssh_host     = Column(String(64), default="")
    ssh_port     = Column(Integer, default=22)
    ssh_username = Column(String(64), default="")
    ssh_password = Column(String(128), default="")

    # Which backend produced the most recent successful poll.
    last_source  = Column(String(16), default="")   # redfish | ssh | simulated

    # Capture loop config (per server, like auto_capture_settings for switches)
    poll_enabled          = Column(Boolean, default=True)
    poll_interval_seconds = Column(Integer, default=20)   # iLO graphs use 20s ticks
    next_due_at           = Column(DateTime, nullable=True)

    # Health of the most recent poll so the UI can show WHY it fails
    last_poll_status = Column(String(16), default="")     # "ok" / "error" / ""
    last_poll_error  = Column(Text, default="")
    last_polled_at   = Column(DateTime, nullable=True)

    created_at  = Column(DateTime, default=ist_now)  # callable ref

    metrics = relationship("ServerMetric", back_populates="server",
                           cascade="all, delete-orphan")
    alert_settings = relationship("ServerAlertSetting", back_populates="server",
                                  cascade="all, delete-orphan")


class ServerMetric(Base):
    """One row per (server, sensor, instant). Sensors mirror the iLO 6
    Performance→Monitoring dropdown:
        cpu_utilization            (%)
        memory_bus_utilization     (%)
        io_bus_utilization         (%)
        cpu_interconnect_utilization (%)
        jitter_count               (count)
        average_cpu_frequency      (MHz)
        cpu_power                  (W)
    """
    __tablename__ = "server_metrics"

    id          = Column(Integer, primary_key=True, index=True)
    server_id   = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    server_name = Column(String(128), nullable=False, index=True)

    sensor      = Column(String(48), nullable=False, index=True)
    value       = Column(Integer, default=0)      # store scaled x100 for 2-dp precision
    unit        = Column(String(8), default="%")
    source      = Column(String(16), default="")  # redfish | ssh | simulated

    captured_at = Column(DateTime, default=ist_now, index=True)  # callable ref

    server = relationship("Server", back_populates="metrics")


class ServerAlertSetting(Base):
    """Alert Settings block from the iLO screenshot: per (server, sensor)
    lower/upper thresholds (in %) each with a dwell time (seconds)."""
    __tablename__ = "server_alert_settings"

    id          = Column(Integer, primary_key=True, index=True)
    server_id   = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    server_name = Column(String(128), nullable=False)
    sensor      = Column(String(48), nullable=False)

    lower_threshold  = Column(Integer, default=0)   # in % (or unit of sensor)
    lower_dwell_sec  = Column(Integer, default=0)
    upper_threshold  = Column(Integer, default=0)
    upper_dwell_sec  = Column(Integer, default=0)

    updated_at  = Column(DateTime, default=ist_now)  # callable ref

    server = relationship("Server", back_populates="alert_settings")


class ServerAlertEvent(Base):
    """The alert AUDIT TRAIL: one row per breach episode.

    evaluate_all() gives the instantaneous state; this table remembers it.
    An event is opened ('active') when a sensor first sustains a breach,
    updated with the worst value seen, and closed ('cleared') when the value
    returns inside the threshold. Operators can acknowledge active events —
    acknowledgement is bookkeeping, it never silences detection.
    """
    __tablename__ = "server_alert_events"

    id          = Column(Integer, primary_key=True, index=True)
    server_id   = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    server_name = Column(String(128), nullable=False, index=True)
    sensor      = Column(String(48), nullable=False)
    kind        = Column(String(8), nullable=False)          # 'upper' | 'lower'
    threshold   = Column(Integer, nullable=False)
    dwell_sec   = Column(Integer, default=0)

    value       = Column(Integer, default=0)     # value at raise (x100 like ServerMetric)
    worst_value = Column(Integer, default=0)     # most extreme value while active
    unit        = Column(String(16), default="")

    state       = Column(String(12), default="active", index=True)  # active|cleared
    raised_at   = Column(DateTime, default=ist_now, index=True)
    cleared_at  = Column(DateTime, nullable=True)

    acknowledged_by = Column(String(128), default="")
    acknowledged_at = Column(DateTime, nullable=True)


class ServerAlertMetricSnapshot(Base):
    """Full sensor picture of a server at the instant an alert was raised.

    server_metrics is pruned after 7 days, so the evidence behind an old
    alert would eventually vanish. When an event fires we therefore copy
    EVERY sensor's latest value for that server into this table, keyed to the
    event. One row per (event, sensor); values ×100 like ServerMetric.

    This is the forensic record: months later you can still answer "what was
    memory and power doing when CPU breached on vcf-161?" — even though the
    raw 1 Hz history is long gone. Never pruned by the metric cleanup job.
    """
    __tablename__ = "server_alert_metric_snapshots"

    id          = Column(Integer, primary_key=True, index=True)
    event_id    = Column(Integer, ForeignKey("server_alert_events.id",
                                             ondelete="CASCADE"),
                         nullable=False, index=True)
    server_id   = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    server_name = Column(String(128), nullable=False, index=True)

    sensor      = Column(String(48), nullable=False)
    value       = Column(Integer, default=0)        # ×100
    unit        = Column(String(16), default="")
    is_trigger  = Column(Boolean, default=False)    # the sensor that breached
    sample_at   = Column(DateTime, nullable=True)   # when that value was read
    captured_at = Column(DateTime, default=ist_now, index=True)


class ServerThresholdAnalysis(Base):
    """Statistically derived alert thresholds, one row per (server, sensor).

    Instead of guessing "alert above 80%", the analyzer studies each server's
    own history and derives thresholds from its real behaviour:

        upper = min(max_of_unit, max(p95, mean + 3σ))
        lower = max(0,           min(p05, mean − 3σ))

    The full statistics are stored (not just the recommendation) so the
    analysis is auditable: an operator can see WHY 62% was recommended for
    one GPU node and 91% for another. Values are ×100 like ServerMetric.
    Rows are upserted on every analysis run; applying a recommendation copies
    it into ServerAlertSetting, which the alert engine already enforces.
    """
    __tablename__ = "server_threshold_analysis"

    id          = Column(Integer, primary_key=True, index=True)
    server_id   = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    server_name = Column(String(128), nullable=False, index=True)
    sensor      = Column(String(48), nullable=False)

    window_hours   = Column(Integer, default=48)    # history analyzed
    coverage_hours = Column(Integer, default=0)     # data actually present
    sample_count   = Column(Integer, default=0)

    # distribution (×100)
    mean_x100   = Column(Integer, default=0)
    std_x100    = Column(Integer, default=0)
    min_x100    = Column(Integer, default=0)
    max_x100    = Column(Integer, default=0)
    p05_x100    = Column(Integer, default=0)
    p50_x100    = Column(Integer, default=0)
    p95_x100    = Column(Integer, default=0)
    p99_x100    = Column(Integer, default=0)

    # the recommendation (×100) + how it was derived
    rec_lower_x100 = Column(Integer, default=0)
    rec_upper_x100 = Column(Integer, default=0)
    rec_dwell_sec  = Column(Integer, default=60)
    method         = Column(String(64), default="p05/p95 ∪ μ±3σ")

    applied_at  = Column(DateTime, nullable=True)   # copied into alert settings
    computed_at = Column(DateTime, default=ist_now, index=True)


class LacpDeployment(Base):
    """One row per LACP Configuration run (both switches of the pair).

    `steps` is a JSON list of {switch, stage, status, detail, at} updated
    LIVE while the worker thread runs — the UI polls this row to render
    execution progress. `logs` keeps every command + device reply so a
    failed run can be audited afterwards.
    """
    __tablename__ = "lacp_deployments"

    id            = Column(Integer, primary_key=True, index=True)
    created_at    = Column(DateTime, default=ist_now, index=True)
    finished_at   = Column(DateTime, nullable=True)
    duration_sec  = Column(Integer, default=0)

    user          = Column(String(128), default="")
    source_switch = Column(String(128), default="")
    dest_switch   = Column(String(128), default="")
    lag_id        = Column(Integer, default=0)
    lacp_mode     = Column(String(16), default="active")
    speed         = Column(String(16), default="auto")
    description   = Column(String(256), default="")
    members       = Column(Text, default="{}")     # {switch: [ifaces]}

    status        = Column(String(24), default="running", index=True)
    # running | completed | failed | rolled_back | rollback_failed
    error         = Column(Text, default="")
    steps         = Column(Text, default="[]")     # live progress JSON
    verification  = Column(Text, default="{}")     # parsed post-checks JSON
    logs          = Column(Text, default="")       # full command/output log


# ─────────────────────────────────────────────────────────────────────
# PHASE 1 — CONFIGURATION TEMPLATES, COMPLIANCE, AUDIT
# Read-only by design: nothing here executes against a device. Templates
# are rendered and previewed; compliance reads stored snapshots.
# ─────────────────────────────────────────────────────────────────────

class ConfigTemplate(Base):
    """A reusable configuration snippet, e.g. 'Access Port', 'Server LACP'.

    `body` is written in the restricted template language implemented by
    template_engine (plain {{ var }} plus one level of {% for %}).
    `variables` is a JSON list of {name,type,required,description,choices}.
    """
    __tablename__ = "config_templates"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(128), unique=True, nullable=False)
    category    = Column(String(64), default="general")   # port / vlan / uplink…
    description = Column(Text, default="")

    # Blank device_type means the template is vendor-neutral.
    device_type = Column(String(48), default="")

    body        = Column(Text, nullable=False)
    variables   = Column(Text, default="[]")     # JSON-encoded schema

    builtin     = Column(Boolean, default=False)  # shipped with the portal
    created_by  = Column(String(64), default="")
    created_at  = Column(DateTime, default=ist_now)
    updated_at  = Column(DateTime, default=ist_now)


class ComplianceRule(Base):
    """One declarative standard checked against a stored running-config."""
    __tablename__ = "compliance_rules"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(128), nullable=False)
    description = Column(Text, default="")

    kind        = Column(String(24), nullable=False)   # must_contain / …
    pattern     = Column(Text, nullable=False)         # regex, per-line
    threshold   = Column(Integer, nullable=True)       # for line_count_max
    severity    = Column(String(16), default="medium") # critical/high/medium/low
    device_type = Column(String(48), default="")       # "" = all switches

    enabled     = Column(Boolean, default=True)
    builtin     = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=ist_now)


class AuditEvent(Base):
    """Who did what, when, to which device.

    Phase 1 records authoring and preview activity. When Phase 2 introduces
    writes, the same table records the apply/rollback events, so the audit
    trail is continuous across phases.
    """
    __tablename__ = "audit_events"

    id          = Column(Integer, primary_key=True, index=True)

    actor       = Column(String(64), default="")      # session username
    action      = Column(String(48), nullable=False, index=True)
    # e.g. template.create / template.update / template.delete /
    #      template.preview / compliance.run / compliance.rule.create

    target_type = Column(String(24), default="")      # switch / template / rule
    target      = Column(String(128), default="", index=True)

    summary     = Column(Text, default="")            # one-line human summary
    detail      = Column(Text, default="")            # JSON blob
    success     = Column(Boolean, default=True)

    source_ip   = Column(String(64), default="")
    timestamp   = Column(DateTime, default=ist_now, index=True)


# ─────────────────────────────────────────────────────────────────────
# PHASE 2 — CONFIGURATION CHANGES (the only write path in the portal)
# ─────────────────────────────────────────────────────────────────────

class ConfigChange(Base):
    """One requested change: a template + variables aimed at N switches."""
    __tablename__ = "config_changes"

    id           = Column(Integer, primary_key=True, index=True)
    template_id  = Column(Integer, nullable=True)
    template_name = Column(String(128), default="")

    variables    = Column(Text, default="{}")     # JSON
    rendered     = Column(Text, default="")       # the CLI, as previewed

    requested_by = Column(String(64), default="")
    reason       = Column(Text, default="")       # change ticket / justification

    dry_run      = Column(Boolean, default=True)

    # scheduling: null = run now
    scheduled_for = Column(DateTime, nullable=True, index=True)

    # queued -> running -> completed / failed / rolled_back / cancelled
    status       = Column(String(24), default="queued", index=True)

    created_at   = Column(DateTime, default=ist_now, index=True)
    started_at   = Column(DateTime, nullable=True)
    finished_at  = Column(DateTime, nullable=True)

    targets = relationship("ConfigChangeTarget", back_populates="change",
                           cascade="all, delete-orphan")


class ConfigChangeTarget(Base):
    """Per-switch outcome of a ConfigChange, including its rollback point."""
    __tablename__ = "config_change_targets"

    id          = Column(Integer, primary_key=True, index=True)
    change_id   = Column(Integer, ForeignKey("config_changes.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    switch_name = Column(String(128), nullable=False, index=True)

    # pending -> applying -> pending_confirm -> confirmed
    #                    \-> failed / rolled_back / rollback_failed
    status      = Column(String(24), default="pending", index=True)

    checkpoint_name   = Column(String(64), default="")
    commands_executed = Column(Text, default="")
    config_before     = Column(Text, default="")
    config_after      = Column(Text, default="")

    error          = Column(Text, default="")
    rollback_error = Column(Text, default="")

    confirm_deadline = Column(DateTime, nullable=True, index=True)
    confirmed_at     = Column(DateTime, nullable=True)
    confirmed_by     = Column(String(64), default="")

    started_at  = Column(DateTime, default=ist_now)
    finished_at = Column(DateTime, nullable=True)

    change = relationship("ConfigChange", back_populates="targets")
