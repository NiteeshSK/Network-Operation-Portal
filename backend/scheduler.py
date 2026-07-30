"""
scheduler.py — Background jobs that auto-capture from switches.

Three independent jobs run in the same process as FastAPI:

  1. Config-snapshot loop (every 60s)
       Runs the device's "config" command, hashes it, detects drift,
       stores a Snapshot. Cadence per switch is controlled by
       AutoCaptureSetting.interval_minutes.

  2. Port-stats loop (every 15s)
       Runs the device's interface-stats command, parses it, writes one row
       per port to port_stats. Cadence per switch is controlled by
       AutoCaptureSetting.port_stats_interval_seconds (down to 30s).

  3. Retention cleanup loop (every 1 hour)
       Deletes port_stats and auto-capture command_logs older than
       PORT_STATS_RETENTION_HOURS (env var, default 24 hours) so the DB
       doesn't grow without bound.

All times are Asia/Kolkata (IST).
"""
import os
import threading
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from sqlalchemy import desc, text
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor

from database import SessionLocal, engine
import models
import switch_manager
import diff_engine
import port_stats_parser
import arp_parser


# How many days of port_stats to keep. Override with env var.
# Retention policy lives in retention.py: ONE window for every history table
# (NOC_RETENTION_DAYS, default 7), not just port_stats. Legacy
# PORT_STATS_RETENTION_* are still honoured there as a fallback.
#
# Re-derived here only so anything still reading
# scheduler.PORT_STATS_RETENTION_HOURS sees a value consistent with the real
# policy rather than a stale second opinion.
from retention import RETENTION_DAYS as NOC_RETENTION_DAYS  # noqa: E402

PORT_STATS_RETENTION_HOURS = int(NOC_RETENTION_DAYS * 24)


# ─── Config snapshot loop ───────────────────────────────────────────

def _take_snapshot_for_switch(db, sw: models.Switch) -> dict:
    """Same snapshot logic as the manual endpoint, but headless."""
    config_cmd = switch_manager.get_commands(sw.device_type)["config"]
    config_text, err = switch_manager.run_command(sw, config_cmd)

    log = models.CommandLog(
        switch_id=sw.id,
        switch_name=sw.name,
        command=f"[AUTO] {config_cmd}",
        output=config_text or "",
        success=err is None,
        error=err or "",
        timestamp=models.ist_now(),
    )
    db.add(log)

    if err:
        db.commit()
        return {"ok": False, "error": err}

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
            to_label="auto_snapshot",
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

    # Same tick: refresh ARP for this switch
    try:
        arp_cmd, arp_fn = arp_parser.get_arp_command_and_parser(sw.device_type)
        arp_out, arp_err = switch_manager.run_command(sw, arp_cmd)
        if not arp_err and arp_out:
            arp_rows = arp_fn(arp_out)
            now = models.ist_now()
            for r in arp_rows:
                db.add(models.ArpEntry(
                    switch_id=sw.id, switch_name=sw.name,
                    ip_address=r["ip_address"], mac_address=r["mac_address"],
                    interface=r["interface"], vlan=r["vlan"],
                    arp_type=r["arp_type"], age_seconds=r["age_seconds"],
                    captured_at=now,
                ))
            db.commit()
            print(f"[auto-snapshot] {sw.name} -> {len(arp_rows)} ARP entries", flush=True)
    except Exception as e:
        print(f"[auto-snapshot] {sw.name} ARP refresh failed: {e}", flush=True)

    return {"ok": True, "drift": drift, "snapshot_id": snap.id}


def check_and_run_due_captures():
    """Snapshot loop — runs every 60s."""
    db = SessionLocal()
    try:
        now = models.ist_now()
        due = (
            db.query(models.AutoCaptureSetting)
            .filter(models.AutoCaptureSetting.enabled == True)
            .filter(
                (models.AutoCaptureSetting.next_due_at == None) |
                (models.AutoCaptureSetting.next_due_at <= now)
            )
            .all()
        )

        for setting in due:
            sw = db.query(models.Switch).filter(
                models.Switch.id == setting.switch_id
            ).first()
            if not sw:
                continue

            print(f"[auto-snapshot] running for {sw.name} "
                  f"(interval {setting.interval_minutes}min)",
                  flush=True)

            # Schedule next run from the START time in whole-interval steps,
            # so a slow SSH config pull doesn't push the cadence out.
            prev_due = setting.next_due_at
            step = timedelta(minutes=setting.interval_minutes)
            if prev_due is None:
                next_due = now + step
            else:
                next_due = prev_due + step
                while next_due <= now:
                    next_due += step

            setting.last_captured_at = now
            setting.next_due_at = next_due
            db.commit()

            result = _take_snapshot_for_switch(db, sw)

            # Record health so the UI can show WHY capture is or isn't working.
            if result["ok"]:
                setting.last_snapshot_status = "ok"
                setting.last_snapshot_error = ""
            else:
                setting.last_snapshot_status = "error"
                setting.last_snapshot_error = (result.get("error") or "")[:500]
            db.commit()

            if result["ok"]:
                print(f"[auto-snapshot] {sw.name} -> saved "
                      f"(drift={result.get('drift')})", flush=True)
            else:
                print(f"[auto-snapshot] {sw.name} -> FAILED: {result['error']}",
                      flush=True)
    except Exception as e:
        print(f"[auto-snapshot] scheduler error: {e}", flush=True)
    finally:
        db.close()


# ─── Port-stats loop ────────────────────────────────────────────────

def _capture_port_stats_for_switch(db, sw: models.Switch) -> dict:
    """Same logic as POST /api/switches/{name}/capture-port-stats, but headless."""
    iface_cmd, parser_fn = port_stats_parser.get_interface_command_and_parser(
        sw.device_type
    )
    brief_cmd, brief_fn  = port_stats_parser.get_brief_command_and_parser(sw.device_type)

    output, err = switch_manager.run_command(sw, iface_cmd)
    db.add(models.CommandLog(
        switch_id=sw.id,
        switch_name=sw.name,
        command=f"[AUTO-PORTS] {iface_cmd}",
        output=output or "",
        success=err is None,
        error=err or "",
        timestamp=models.ist_now(),
    ))

    if err:
        db.commit()
        return {"ok": False, "error": err, "ports_captured": 0}

    parsed = parser_fn(output) if output else []
    if not parsed:
        db.commit()
        return {"ok": False,
                "error": "parser returned no ports",
                "ports_captured": 0}

    # Fetch brief for descriptions & mode (best effort, non-fatal)
    brief_map = {}
    try:
        b_out, b_err = switch_manager.run_command(sw, brief_cmd)
        if not b_err and b_out:
            brief_map = brief_fn(b_out)
    except Exception:
        pass
    port_stats_parser.merge_brief_into_stats(parsed, brief_map)

    now = models.ist_now()
    for p in parsed:
        db.add(models.PortStat(
            switch_id=sw.id,
            switch_name=sw.name,
            interface_name=p["interface_name"],
            link_state=p["link_state"],
            in_packets=p["in_packets"],   in_bytes=p["in_bytes"],
            in_errors=p["in_errors"],     in_broadcasts=p["in_broadcasts"],
            out_packets=p["out_packets"], out_bytes=p["out_bytes"],
            out_errors=p["out_errors"],   out_broadcasts=p["out_broadcasts"],
            total_packets=p.get("total_packets",
                                p["in_packets"] + p["out_packets"]),
            port_description=p.get("port_description", ""),
            captured_at=now,
        ))
    db.commit()
    return {"ok": True, "ports_captured": len(parsed)}


def check_and_run_due_port_stats():
    """Port-stats loop — runs every 15s, but each switch only fires when
    its own per-switch interval has elapsed."""
    db = SessionLocal()
    try:
        now = models.ist_now()
        due = (
            db.query(models.AutoCaptureSetting)
            .filter(models.AutoCaptureSetting.port_stats_enabled == True)
            .filter(
                (models.AutoCaptureSetting.port_stats_next_due_at == None) |
                (models.AutoCaptureSetting.port_stats_next_due_at <= now)
            )
            .all()
        )

        for setting in due:
            sw = db.query(models.Switch).filter(
                models.Switch.id == setting.switch_id
            ).first()
            if not sw:
                continue

            interval = max(setting.port_stats_interval_seconds or 30, 15)

            # Compute the NEXT due time from the moment we START (now), not
            # after the SSH capture finishes. A slow capture (30-60s) must NOT
            # be added on top of the interval — otherwise a "1 min" selection
            # would fire every 60s + capture_time (~2 min). We also advance in
            # whole interval steps from the previous due time to prevent drift.
            prev_due = setting.port_stats_next_due_at
            if prev_due is None:
                next_due = now + timedelta(seconds=interval)
            else:
                # Advance past 'now' in interval-sized steps (catch up if behind)
                next_due = prev_due + timedelta(seconds=interval)
                while next_due <= now:
                    next_due += timedelta(seconds=interval)

            # Mark the schedule BEFORE the slow capture so the timestamp and
            # next-due reflect the intended cadence, then run the capture.
            setting.port_stats_last_captured_at = now
            setting.port_stats_next_due_at = next_due
            db.commit()

            result = _capture_port_stats_for_switch(db, sw)

            if result["ok"]:
                setting.last_port_stats_status = "ok"
                setting.last_port_stats_error = ""
            else:
                setting.last_port_stats_status = "error"
                setting.last_port_stats_error = (result.get("error") or "")[:500]
            db.commit()

            if result["ok"]:
                print(f"[auto-ports] {sw.name} -> {result['ports_captured']} ports "
                      f"(interval {interval}s, next {next_due.strftime('%H:%M:%S')})",
                      flush=True)
            else:
                print(f"[auto-ports] {sw.name} -> FAILED: {result['error']}",
                      flush=True)
    except Exception as e:
        print(f"[auto-ports] scheduler error: {e}", flush=True)
    finally:
        db.close()


# ─── Retention cleanup loop ─────────────────────────────────────────

# Retention now sweeps EVERY history table on one window, not just the four
# this function used to cover. See retention.py for the policy, what is never
# swept (the inventory tables), and the four correctness carve-outs.
from retention import run_retention_cleanup, retention_status  # noqa: E402,F401


# ─── Scheduler bootstrap ────────────────────────────────────────────

# Executor sized for the fleet, not for the default.
#
# APScheduler defaults to 10 threads. Every capture job here is a BLOCKING SSH
# session, and a switch that is slow or unreachable holds its thread for the
# full netmiko timeout, so six switches across four capture loops saturate the
# default pool immediately. That is what produces the log spam:
#
#   Execution of job "check_and_run_due_port_stats" skipped:
#       maximum number of running instances reached (1)
#
# coalesce=True collapses a backlog into one run instead of firing every
# missed interval once a thread frees up — without it, a slow patch creates a
# thundering herd of catch-up SSH sessions, which is exactly how memory and
# thread count run away.
_EXECUTOR_THREADS = int(os.getenv("NOC_SCHEDULER_THREADS", "20"))

scheduler = BackgroundScheduler(
    daemon=True,
    timezone="Asia/Kolkata",
    executors={"default": ThreadPoolExecutor(_EXECUTOR_THREADS)},
    job_defaults={"coalesce": True, "misfire_grace_time": 120, "max_instances": 1},
)


def check_and_run_due_arp():
    """Capture ARP from every switch that has any auto-capture enabled.
    Runs every 10 minutes so the IP-Conflicts view stays fresh without
    waiting for the (up to 24-hour) config-snapshot job to fire.
    """
    db = SessionLocal()
    try:
        now = models.ist_now()
        active = (
            db.query(models.AutoCaptureSetting)
            .filter(
                (models.AutoCaptureSetting.enabled == True)  # noqa: E712
                | (models.AutoCaptureSetting.port_stats_enabled == True)  # noqa: E712
            )
            .all()
        )
        for setting in active:
            sw = db.query(models.Switch).filter(
                models.Switch.id == setting.switch_id
            ).first()
            if not sw:
                continue
            try:
                arp_cmd, arp_fn = arp_parser.get_arp_command_and_parser(sw.device_type)
                arp_out, arp_err = switch_manager.run_command(sw, arp_cmd)
                if not arp_err and arp_out:
                    rows = arp_fn(arp_out)
                    for r in rows:
                        db.add(models.ArpEntry(
                            switch_id=sw.id, switch_name=sw.name,
                            ip_address=r["ip_address"], mac_address=r["mac_address"],
                            interface=r["interface"], vlan=r["vlan"],
                            arp_type=r["arp_type"], age_seconds=r["age_seconds"],
                            captured_at=now,
                        ))
                    db.commit()
                    print(f"[auto-arp] {sw.name} -> {len(rows)} entries", flush=True)
                elif arp_err:
                    print(f"[auto-arp] {sw.name} SSH error: {arp_err}", flush=True)
            except Exception as exc:
                db.rollback()
                print(f"[auto-arp] {sw.name} failed: {exc}", flush=True)
    except Exception as e:
        print(f"[auto-arp] scheduler error: {e}", flush=True)
    finally:
        db.close()


# ─── Server metrics poll loop (additive: HPE iLO monitoring) ─────────

def check_and_run_due_servers():
    """Keep the real-time streaming workers in sync with the servers table.

    Metric COLLECTION no longer happens here. metrics_stream runs one
    long-lived worker per server that holds a persistent connection and
    samples at ~1 Hz, publishing to memory (for SSE) and writing throttled
    history to the database. This tick only starts workers for newly-added
    or re-enabled servers and stops workers for removed/disabled ones — so
    the UI is live within ~1 second instead of waiting on a 20 s poll.
    """
    try:
        import metrics_stream
    except Exception as e:
        print(f"[auto-server] streaming unavailable: {e}", flush=True)
        return
    db = SessionLocal()
    try:
        metrics_stream.manager.reconcile(db.query(models.Server).all())
    except Exception as e:
        print(f"[auto-server] reconcile error: {e}", flush=True)
    finally:
        db.close()


def check_config_change_deadlines():
    """Auto-revert any applied change nobody confirmed in time.

    This is the safety net that makes Phase 2 tolerable: if a change severed
    management access, no operator can confirm it, so the device reverts on
    its own via the checkpoint created before the change.
    """
    try:
        import config_apply
    except Exception:
        return
    db = SessionLocal()
    try:
        results = config_apply.expire_unconfirmed(db)
        if results:
            print(f"[auto-revert] processed {len(results)} expired change(s)",
                  flush=True)
    except Exception as e:
        print(f"[auto-revert] error: {e}", flush=True)
    finally:
        db.close()


def run_scheduled_changes():
    """Execute changes whose maintenance window has arrived.

    Uses each switch's STORED credentials, not the requester's session, since
    the operator is unlikely to still be logged in at 02:00.
    """
    try:
        import config_apply
    except Exception:
        return
    if not config_apply.APPLY_ENABLED:
        return
    db = SessionLocal()
    try:
        import main as _main   # for _run_change; imported lazily to avoid cycles
    except Exception:
        db.close()
        return
    try:
        now = models.ist_now()
        due = (db.query(models.ConfigChange)
               .filter(models.ConfigChange.status == "scheduled",
                       models.ConfigChange.scheduled_for != None,   # noqa: E711
                       models.ConfigChange.scheduled_for <= now)
               .all())
        for ch in due:
            if not ch.targets:
                ch.status = "failed"
                db.commit()
                continue
            print(f"[scheduled] running change #{ch.id} ({ch.template_name})",
                  flush=True)
            # creds=None → _run_change resolves each switch's STORED
            # credentials per target (they may differ across the fleet).
            _main._run_change(db, ch, None)
    except Exception as e:
        print(f"[scheduled] error: {e}", flush=True)
    finally:
        db.close()


# ─── Memory maintenance (NOC_MEM_TRIM_V1) ───────────────────────────────────
# Python frees objects back to its own pools and to glibc's per-thread malloc
# ARENAS — not to the operating system. glibc allows up to 8 x CPU-cores
# arenas, each able to retain up to 64 MB of freed-but-unreturned heap. With
# ~93 threads all churning JSON parsing and SQLAlchemy objects, resident
# memory therefore only ever RATCHETS UPWARD, even when there is no object
# leak at all. `docker stats` climbs while gc object counts stay flat.
#
# malloc_trim(0) walks those arenas and hands whatever is genuinely free back
# to the kernel. Paired with an explicit gc.collect() it is the standard
# remedy for this pattern and is safe to run periodically: it only releases
# memory nothing is using.
#
# This does NOT paper over a real leak. If objects are genuinely being
# retained, gc_objects on /api/diagnostics/runtime keeps climbing and the trim
# reclaims nothing — which is exactly how to tell the two apart.
def run_memory_maintenance():
    import gc as _gc
    import ctypes as _ctypes

    def _rss_kb():
        try:
            with open("/proc/self/status") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1])
        except Exception:
            return None

    before = _rss_kb()
    collected = _gc.collect()
    trimmed = False
    try:
        _ctypes.CDLL("libc.so.6").malloc_trim(0)
        trimmed = True
    except Exception:
        pass                        # musl (alpine) has no malloc_trim
    after = _rss_kb()

    if before and after:
        freed = (before - after) / 1024.0
        print(f"[mem] gc collected {collected} obj, "
              f"malloc_trim={'yes' if trimmed else 'n/a'}, "
              f"RSS {before/1024:.0f} -> {after/1024:.0f} MB "
              f"({freed:+.0f} MB)", flush=True)
    return {"collected": collected, "trimmed": trimmed,
            "rss_before_kb": before, "rss_after_kb": after}



# ─── Memory watchdog (NOC_MEM_WATCHDOG_V1) ──────────────────────────────────
# The 10-minute maintenance tick is fine for steady state, but it does nothing
# for a container that is 200 MB from its ceiling with eight minutes still to
# wait. This checks every 60 seconds and reclaims IMMEDIATELY once usage
# crosses a high-water mark, so the process heals itself instead of drifting
# into an OOM kill.
#
# The ceiling is read from the container's own cgroup, so it tracks whatever
# mem_limit is set in compose without needing to be told.

def _cgroup_memory_limit_bytes():
    """Container memory ceiling, cgroup v2 then v1. None if unlimited."""
    for path in ("/sys/fs/cgroup/memory.max",                     # v2
                 "/sys/fs/cgroup/memory/memory.limit_in_bytes"):  # v1
        try:
            with open(path) as fh:
                raw = fh.read().strip()
            if raw == "max":
                return None
            val = int(raw)
            # v1 reports a huge sentinel when unlimited
            if val > (1 << 62):
                return None
            return val
        except Exception:
            continue
    return None


def _current_rss_bytes():
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        return None


_MEM_HIGH_WATER = float(os.getenv("NOC_MEM_HIGH_WATER", "0.70"))
_MEM_CRITICAL = float(os.getenv("NOC_MEM_CRITICAL", "0.85"))


def memory_watchdog():
    """Reclaim as soon as usage crosses the high-water mark."""
    limit = _cgroup_memory_limit_bytes()
    rss = _current_rss_bytes()
    if not limit or not rss:
        return                              # unlimited or unreadable

    ratio = rss / limit
    if ratio < _MEM_HIGH_WATER:
        return                              # nothing to do, the common path

    print(f"[mem-watchdog] {rss/1024**2:.0f} MB of {limit/1024**2:.0f} MB "
          f"({ratio*100:.0f}%) — reclaiming", flush=True)
    result = run_memory_maintenance()

    after = _current_rss_bytes() or rss
    new_ratio = after / limit

    if new_ratio >= _MEM_CRITICAL:
        # Trim could not get us back under. Shed streaming workers: they are
        # the largest discretionary consumer, and losing live graphs for a
        # few servers is far better than losing the whole container.
        try:
            import metrics_stream
            mgr = metrics_stream.manager
            alive = [n for n, w in list(mgr._workers.items()) if w.is_alive()]
            shed = alive[len(alive) // 2:]          # drop half
            for name in shed:
                mgr.drop(name)
            if shed:
                print(f"[mem-watchdog] STILL at {new_ratio*100:.0f}% after "
                      f"reclaim — shed {len(shed)} of {len(alive)} streaming "
                      f"workers to stay under the limit. They restart on the "
                      f"next reconcile if memory allows.", flush=True)
        except Exception as e:
            print(f"[mem-watchdog] worker shedding failed: {e}", flush=True)

    return result


def start_scheduler():
    """Called once when FastAPI boots."""
    if scheduler.running:
        return

    scheduler.add_job(
        check_and_run_due_captures,
        trigger="interval",
        seconds=20,            # 20s tick so a 1-min snapshot interval is accurate
        id="auto_snapshot_loop",
        replace_existing=True,
        max_instances=1,
    )

    scheduler.add_job(
        check_and_run_due_port_stats,
        trigger="interval",
        seconds=10,            # 10s tick for tighter port-stats cadence
        id="auto_port_stats_loop",
        replace_existing=True,
        max_instances=1,
    )

    scheduler.add_job(
        memory_watchdog, "interval",
        seconds=int(os.getenv("NOC_MEM_WATCHDOG_SECONDS", "60")),
        id="memory_watchdog_loop", replace_existing=True,
    )
    scheduler.add_job(
        run_memory_maintenance, "interval",
        minutes=int(os.getenv("NOC_MEM_TRIM_MINUTES", "10")),
        id="memory_maintenance_loop", replace_existing=True,
    )

    scheduler.add_job(
        run_retention_cleanup,
        trigger="interval",
        hours=1,
        id="retention_cleanup_loop",
        replace_existing=True,
        max_instances=1,
    )

    scheduler.add_job(
        check_and_run_due_arp,
        trigger="interval",
        minutes=10,
        id="auto_arp_loop",
        replace_existing=True,
        max_instances=1,
    )

    scheduler.add_job(
        check_and_run_due_servers,
        trigger="interval",
        seconds=15,            # cheap reconcile; real sampling runs at ~1 Hz in metrics_stream
        id="auto_server_metrics_loop",
        replace_existing=True,
        max_instances=1,
    )

    # Phase 2 safety net: revert changes nobody confirmed. Runs often, because
    # a lockout is only fixed once this fires.
    scheduler.add_job(
        check_config_change_deadlines,
        trigger="interval",
        seconds=20,
        id="config_change_auto_revert",
        replace_existing=True,
        max_instances=1,
    )

    # Maintenance-window execution of scheduled changes.
    scheduler.add_job(
        run_scheduled_changes,
        trigger="interval",
        seconds=30,
        id="config_scheduled_changes",
        replace_existing=True,
        max_instances=1,
    )

    # Server alert audit trail: persist breach raise/clear events so the
    # Server Audits section has history, not just an instantaneous state.
    def record_server_alert_events():
        db = SessionLocal()
        try:
            import inventory as _inv
            _inv.record_alert_events(db)
        except Exception as e:
            print(f"[alert-events] error: {e}", flush=True)
        finally:
            db.close()

    scheduler.add_job(
        record_server_alert_events,
        trigger="interval",
        seconds=10,
        id="server_alert_events",
        replace_existing=True,
        max_instances=1,
    )

    # Every 6 hours: re-derive each server's CPU/memory baseline from its own
    # stored history and PUSH the result to the live alert settings, so the
    # Servers page and the alert engine always reflect current behaviour.
    # Auto-apply is on by default; set THRESHOLD_AUTO_APPLY=0 to make the
    # recompute advisory-only (stored, but armed manually from the UI).
    def recompute_threshold_baselines():
        db = SessionLocal()
        try:
            import threshold_analysis as _thr
            res = _thr.analyze_all(db)
            msg = (f"[thresholds] recomputed: {res['analyzed']} stored, "
                   f"{res['skipped']} still collecting")
            if os.getenv("THRESHOLD_AUTO_APPLY", "1") == "1" and res["analyzed"]:
                applied = _thr.apply_to_alert_settings(db)
                msg += f"; auto-applied {applied['count']} to live alerts"
            print(msg, flush=True)
        except Exception as e:
            print(f"[thresholds] analysis error: {e}", flush=True)
        finally:
            db.close()

    scheduler.add_job(
        recompute_threshold_baselines,
        trigger="interval",
        hours=6,
        id="server_threshold_analysis",
        replace_existing=True,
        max_instances=1,
    )

    # ── RAG vector-index sync ───────────────────────────────────────────────
    # Refresh the Chroma index from current DB state on a slow cadence. Import
    # is local + guarded so a missing/broken RAG dependency never stops the
    # core capture loops from running.
    try:
        from rag.sync import sync_vectorstore
        scheduler.add_job(
            sync_vectorstore,
            trigger="interval",
            minutes=int(os.getenv("RAG_SYNC_MINUTES", "5")),
            id="rag_sync_loop",
            replace_existing=True,
            max_instances=1,
        )
        _rag_enabled = True
    except Exception as e:
        print(f"[scheduler] RAG sync disabled: {e}", flush=True)
        _rag_enabled = False

    scheduler.start()

    # Retention is a short series of local DELETEs — fast, and worth doing
    # before the capture loops start writing. It stays on the startup path.
    run_retention_cleanup()

    # ── Everything below runs OFF the startup path ─────────────────────────
    #
    # start_scheduler() is called from a SYNCHRONOUS @app.on_event("startup")
    # handler. Starlette runs sync startup handlers by calling them directly
    # on the event loop, NOT in a threadpool:
    #
    #     if is_async_callable(handler): await handler()
    #     else:                          handler()      # blocking
    #
    # So anything slow here stalls ASGI startup itself: uvicorn prints
    # "Waiting for application startup." and never reaches "Application
    # startup complete", meaning it never binds, never serves, and no
    # healthcheck can pass.
    #
    # Both calls below are exactly that kind of slow:
    #   check_and_run_due_arp()  blocking SSH to EVERY switch in turn; one
    #                            unreachable device costs a full netmiko
    #                            timeout, and a core switch with thousands of
    #                            ARP entries is slow even when it works.
    #   sync_vectorstore()       embeds DB content through the configured
    #                            endpoint; blocks until it answers or times out.
    def _boot_warmup():
        try:
            check_and_run_due_arp()
        except Exception as e:
            print(f"[scheduler] initial ARP sweep failed: {e}", flush=True)
        if _rag_enabled and os.getenv("NOC_RAG_INDEX_ON_BOOT", "0") == "1":
            try:
                from rag.sync import sync_vectorstore
                sync_vectorstore()
            except Exception as e:
                print(f"[scheduler] initial RAG index failed: {e}", flush=True)
        print("[scheduler] boot warm-up complete", flush=True)

    threading.Thread(target=_boot_warmup, name="noc-boot-warmup",
                     daemon=True).start()

    print(f"[scheduler] started — snapshot:60s, port-stats:15s, "
          f"arp:10min, cleanup:1h, rag-sync:{os.getenv('RAG_SYNC_MINUTES', '5')}min "
          f"(keep {NOC_RETENTION_DAYS:g} days of history) — "
          f"warm-up in background, API already live", flush=True)


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)