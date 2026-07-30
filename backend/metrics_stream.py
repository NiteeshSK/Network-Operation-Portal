"""
metrics_stream.py — REAL-TIME server metrics.

Why the old path was slow
-------------------------
`metrics_collector.collect()` was called once per scheduler tick and, for the
SSH backend, it:
   * opened a brand-new SSH connection (TCP + KEX + auth ≈ 0.3-1.5 s),
   * slept 0.4 s in the middle to take two /proc/stat samples,
   * closed the connection.
Add the 20 s poll interval and the UI could be ~20 s behind reality.

What this module does instead
-----------------------------
One long-lived worker thread per server that:
   * holds a PERSISTENT SSH channel (or a persistent HTTPS session for iLO),
   * samples every SAMPLE_SECONDS (default 1.0 s),
   * computes CPU utilisation from the delta against the PREVIOUS sample it
     already holds — so no in-poll sleep is needed at all,
   * publishes each sample to an in-memory ring buffer + subscriber queues,
     which the SSE endpoint drains instantly (no database polling),
   * writes to the database only every DB_WRITE_SECONDS (default 10 s) so
     history is retained without bloating the table at 1 Hz.

Result: the browser sees a new point about one second after it happens.

Honesty rules are unchanged: nothing is fabricated. A sensor the backend
cannot measure is published as None; a worker that cannot reach its server
publishes an error state and stores nothing.
"""
from __future__ import annotations

import os
import queue
import re
import threading
import time
from typing import Any, Callable, Optional

# ═══════════════════════════════════════════════════════════════════════════
# RESOURCE CEILINGS
#
# This module starts ONE dedicated thread per poll_enabled server and keeps a
# per-server ring buffer in RAM. Both scale linearly with the fleet and, until
# now, neither had a cap. On a small fleet that is invisible. After a bulk
# server import it is not: every added server permanently costs a thread, a
# live connection (SSH or Redfish) and a ring buffer, and nothing anywhere
# refuses to start the next one.
#
# Production symptom this addresses: 347-358 threads in the backend container
# with memory climbing 4.6 -> 10.6 GiB. Roughly 82 of those threads are fixed
# overhead (APScheduler pool, uvicorn's anyio pool, main, scheduler), so the
# remaining ~270 were server workers — i.e. thread count was tracking the
# number of monitored servers, one for one.
#
# The defaults below are deliberately more conservative than before:
#
#   SERVER_SAMPLE_SECONDS  1.0 -> 5.0
#       1 Hz per server across a large fleet is what drove sustained >100%
#       CPU and ~1.2 GB of inbound network traffic. Five seconds is still
#       far finer than any alerting threshold needs.
#
#   SERVER_RING_SIZE       900 -> 300
#       The ring is only a short scrollback for the live graphs; history
#       lives in the database. 300 samples at 5 s is 25 minutes of window,
#       LONGER in wall-clock terms than the old 900 at 1 Hz, for a third of
#       the memory.
#
#   SERVER_MAX_WORKERS     new, default 50
#       A hard ceiling on concurrent streaming workers. Past this point the
#       manager refuses to start more and says so, loudly and once per
#       server, instead of quietly consuming the host. Raise it deliberately
#       once you know what the per-worker cost is on your hardware.
# ═══════════════════════════════════════════════════════════════════════════
SAMPLE_SECONDS = float(os.getenv("SERVER_SAMPLE_SECONDS", "10.0"))
DB_WRITE_SECONDS = float(os.getenv("SERVER_DB_WRITE_SECONDS", "60"))
RING_SIZE = int(os.getenv("SERVER_RING_SIZE", "180"))
MAX_WORKERS = int(os.getenv("SERVER_MAX_WORKERS", "25"))
RECONNECT_BACKOFF = (1, 2, 5, 10, 20, 30)

SENSOR_KEYS = [
    "cpu_utilization",
    "memory_bus_utilization",
    "io_bus_utilization",
    "cpu_interconnect_utilization",
    "jitter_count",
    "average_cpu_frequency",
    "cpu_power",
]


# ── One combined read of everything we need from /proc, in a single command.
# Fewer round-trips = lower latency. Markers let us split the reply reliably.
_PROBE = (
    "echo '#STAT'; cat /proc/stat | head -1; "
    "echo '#MEM';  head -5 /proc/meminfo; "
    "echo '#FREQ'; grep -m32 'cpu MHz' /proc/cpuinfo || true; "
    "echo '#LOAD'; cat /proc/loadavg; "
    "echo '#RAPL'; cat /sys/class/powercap/intel-rapl:0/energy_uj 2>/dev/null || echo NA; "
    "echo '#END'"
)


def _split_sections(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#") and s[1:] in ("STAT", "MEM", "FREQ", "LOAD", "RAPL", "END"):
            cur = s[1:]
            out[cur] = []
        elif cur:
            out[cur].append(line)
    return out


class _Sample:
    __slots__ = ("t", "cpu_idle", "cpu_total", "iowait", "energy_uj")

    def __init__(self, t, cpu_idle, cpu_total, iowait, energy_uj):
        self.t = t
        self.cpu_idle = cpu_idle
        self.cpu_total = cpu_total
        self.iowait = iowait
        self.energy_uj = energy_uj


class ServerWorker(threading.Thread):
    """Streams one server's metrics at ~1 Hz over a persistent connection."""

    def __init__(self, server_id: int, name: str, cfg: dict,
                 publish: Callable[[str, dict], None],
                 persist: Callable[[int, str, dict, str], None]):
        super().__init__(daemon=True, name=f"metrics-{name}")
        self.server_id = server_id
        self.name_ = name
        self.cfg = cfg                # host/user/pass/mode
        self._publish = publish
        self._persist = persist
        self._stop = threading.Event()
        self._client = None
        self._prev: Optional[_Sample] = None
        self._last_db = 0.0
        self.source = ""
        self.error = ""

    # -- lifecycle ---------------------------------------------------------
    def stop(self):
        self._stop.set()

    def run(self):
        backoff_i = 0
        while not self._stop.is_set():
            try:
                if self._client is None:
                    self._connect()
                    backoff_i = 0
                t0 = time.time()
                vals = self._sample()
                if vals is not None:
                    self._emit(vals)
                # keep a steady cadence regardless of sample cost
                sleep = SAMPLE_SECONDS - (time.time() - t0)
                if sleep > 0:
                    self._stop.wait(sleep)
            except Exception as e:
                self.error = str(e)
                self.source = ""
                self._close()
                self._publish(self.name_, {"error": self.error})
                wait = RECONNECT_BACKOFF[min(backoff_i, len(RECONNECT_BACKOFF) - 1)]
                backoff_i += 1
                self._stop.wait(wait)
        self._close()

    def _close(self):
        try:
            if self._client is not None:
                self._client.close()
        except Exception:
            pass
        self._client = None
        self._prev = None

    # -- connection --------------------------------------------------------
    def _connect(self):
        mode = self.cfg.get("mode", "auto")
        if mode in ("auto", "redfish") and self.cfg.get("ilo_host"):
            try:
                import ilo_client
                ilo_client.fetch_metrics(self.cfg["ilo_host"], self.cfg["ilo_port"],
                                         self.cfg["username"], self.cfg["password"])
                self.source = "redfish"
                self._client = "redfish"     # sentinel; HTTPS is per-request
                self.error = ""
                return
            except Exception as e:
                if mode == "redfish":
                    raise
                self.error = f"redfish: {e}"

        if mode in ("auto", "ssh"):
            import paramiko
            host = self.cfg.get("ssh_host") or self.cfg.get("ilo_host")
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(hostname=host, port=self.cfg.get("ssh_port", 22),
                      username=self.cfg.get("ssh_username") or self.cfg.get("username"),
                      password=self.cfg.get("ssh_password") or self.cfg.get("password"),
                      timeout=10, banner_timeout=10, auth_timeout=10,
                      look_for_keys=False, allow_agent=False)
            self._client = c
            self.source = "ssh"
            self.error = ""
            return

        raise RuntimeError(self.error or "no usable collection backend")

    # -- sampling ----------------------------------------------------------
    def _sample(self) -> Optional[dict]:
        if self.source == "redfish":
            import ilo_client
            v = ilo_client.fetch_metrics(self.cfg["ilo_host"], self.cfg["ilo_port"],
                                         self.cfg["username"], self.cfg["password"])
            return {k: v.get(k) for k in SENSOR_KEYS}
        return self._sample_ssh()

    def _sample_ssh(self) -> Optional[dict]:
        _in, out, _err = self._client.exec_command(_PROBE, timeout=8)
        text = out.read().decode("utf-8", errors="replace")
        sec = _split_sections(text)
        if "STAT" not in sec or not sec["STAT"]:
            raise RuntimeError("no /proc/stat in probe output")

        f = [int(x) for x in sec["STAT"][0].split()[1:]]
        idle = f[3] + (f[4] if len(f) > 4 else 0)
        total = sum(f[:8]) if len(f) >= 8 else sum(f)
        iowait = f[4] if len(f) > 4 else 0

        energy = None
        if sec.get("RAPL"):
            raw = sec["RAPL"][0].strip()
            if raw.isdigit():
                energy = int(raw)

        now = time.time()
        cur = _Sample(now, idle, total, iowait, energy)
        prev, self._prev = self._prev, cur

        if prev is None:
            return None          # need two samples for a rate; next tick emits

        d_total = cur.cpu_total - prev.cpu_total
        d_idle = cur.cpu_idle - prev.cpu_idle
        cpu = (100.0 * (d_total - d_idle) / d_total) if d_total > 0 else 0.0
        io = (100.0 * (cur.iowait - prev.iowait) / d_total) if d_total > 0 else None

        mem = {}
        for line in sec.get("MEM", []):
            m = re.match(r"^(\w+):\s+(\d+)", line)
            if m:
                mem[m.group(1)] = int(m.group(2))
        mt = mem.get("MemTotal", 0)
        ma = mem.get("MemAvailable", mem.get("MemFree", 0))
        mem_util = (100.0 * (mt - ma) / mt) if mt else None

        mhz = [float(m.group(1)) for m in
               re.finditer(r"([\d.]+)", "\n".join(sec.get("FREQ", [])))]
        avg_mhz = (sum(mhz) / len(mhz)) if mhz else None

        runq = None
        if sec.get("LOAD"):
            parts = sec["LOAD"][0].split()
            if len(parts) >= 4 and "/" in parts[3]:
                try:
                    runq = float(parts[3].split("/")[0])
                except Exception:
                    runq = None

        power = None
        if energy is not None and prev.energy_uj is not None:
            dt = cur.t - prev.t
            de = energy - prev.energy_uj
            if dt > 0 and de >= 0:
                power = de / dt / 1_000_000.0

        return {
            "cpu_utilization":              round(max(0.0, min(100.0, cpu)), 2),
            "memory_bus_utilization":       round(mem_util, 2) if mem_util is not None else None,
            "io_bus_utilization":           round(max(0.0, io), 2) if io is not None else None,
            "cpu_interconnect_utilization": None,   # no Linux equivalent — never faked
            "jitter_count":                 runq,
            "average_cpu_frequency":        round(avg_mhz) if avg_mhz else None,
            "cpu_power":                    round(power, 1) if power is not None else None,
        }

    def _emit(self, vals: dict):
        ts = time.time()
        self._publish(self.name_, {"values": vals, "source": self.source, "ts": ts})
        if ts - self._last_db >= DB_WRITE_SECONDS:
            self._last_db = ts
            try:
                self._persist(self.server_id, self.name_, vals, self.source)
            except Exception as e:
                self.error = f"db write failed: {e}"


class StreamManager:
    """Owns the worker threads, the per-server ring buffers, and SSE queues."""

    def __init__(self):
        self._workers: dict[str, ServerWorker] = {}
        self._rings: dict[str, list] = {}
        self._subs: dict[str, list[queue.Queue]] = {}
        self._capped: set[str] = set()   # names refused by MAX_WORKERS
        self._lock = threading.Lock()
        self._persist_fn: Optional[Callable] = None

    # -- pub/sub ----------------------------------------------------------
    def _publish(self, name: str, payload: dict):
        with self._lock:
            ring = self._rings.setdefault(name, [])
            ring.append(payload)
            if len(ring) > RING_SIZE:
                del ring[: len(ring) - RING_SIZE]
            for q in list(self._subs.get(name, [])):
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    pass

    def subscribe(self, name: str) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=200)
        with self._lock:
            self._subs.setdefault(name, []).append(q)
        return q

    def unsubscribe(self, name: str, q: queue.Queue):
        with self._lock:
            lst = self._subs.get(name, [])
            if q in lst:
                lst.remove(q)

    def latest(self, name: str) -> Optional[dict]:
        with self._lock:
            ring = self._rings.get(name) or []
            return ring[-1] if ring else None

    def status(self, name: str) -> dict:
        w = self._workers.get(name)
        if not w:
            return {"running": False}
        return {"running": w.is_alive(), "source": w.source, "error": w.error}

    # -- worker lifecycle --------------------------------------------------
    def set_persist(self, fn: Callable):
        self._persist_fn = fn

    def ensure(self, server_row):
        """Start a worker for this server if not already running."""
        name = server_row.name
        w = self._workers.get(name)
        if w and w.is_alive():
            return

        # Hard ceiling. Without this the fleet size alone decides how many
        # threads and live connections this process holds.
        live = sum(1 for x in self._workers.values() if x.is_alive())
        if live >= MAX_WORKERS:
            if name not in self._capped:
                self._capped.add(name)
                print(f"[metrics-stream] worker limit reached "
                      f"({live}/{MAX_WORKERS}) — not streaming '{name}'. "
                      f"Raise SERVER_MAX_WORKERS or disable polling on "
                      f"servers you are not actively watching.", flush=True)
            return
        self._capped.discard(name)

        cfg = {
            "mode": server_row.collection_mode or "auto",
            "ilo_host": server_row.ilo_host or "",
            "ilo_port": server_row.ilo_port or 443,
            "username": server_row.username or "",
            "password": server_row.password or "",
            "ssh_host": server_row.ssh_host or server_row.ilo_host or "",
            "ssh_port": server_row.ssh_port or 22,
            "ssh_username": server_row.ssh_username or server_row.username or "",
            "ssh_password": server_row.ssh_password or server_row.password or "",
        }
        w = ServerWorker(server_row.id, name, cfg, self._publish, self._persist_fn)
        self._workers[name] = w
        w.start()

    def drop(self, name: str):
        w = self._workers.pop(name, None)
        if w:
            w.stop()
        with self._lock:
            self._rings.pop(name, None)
            self._subs.pop(name, None)

    def reconcile(self, server_rows):
        """Start workers for new/enabled servers, stop removed/disabled ones."""
        wanted = {s.name for s in server_rows if s.poll_enabled}
        for s in server_rows:
            if s.poll_enabled:
                self.ensure(s)
        for name in list(self._workers):
            if name not in wanted:
                self.drop(name)

    def stop_all(self):
        for name in list(self._workers):
            self.drop(name)


manager = StreamManager()


def stream_stats() -> dict:
    """Live worker/ring accounting — surfaced on /api/diagnostics/runtime."""
    m = manager
    with m._lock:
        rings = {k: len(v) for k, v in m._rings.items()}
        subs = {k: len(v) for k, v in m._subs.items()}
    workers = {k: w.is_alive() for k, w in m._workers.items()}
    return {
        "workers_total": len(workers),
        "workers_alive": sum(1 for a in workers.values() if a),
        "max_workers": MAX_WORKERS,
        "capped_out": sorted(m._capped),
        "sample_seconds": SAMPLE_SECONDS,
        "ring_size": RING_SIZE,
        "ring_entries_total": sum(rings.values()),
        "subscriber_queues_total": sum(subs.values()),
    }
