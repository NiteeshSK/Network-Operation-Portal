"""
metrics_collector.py — REAL server metrics, with an explicit source chain.

Collection backends are tried in priority order and the winner is recorded on
the row, so the UI can always tell you exactly where a number came from:

  1. "redfish"  — HPE iLO Redfish (Oem.Hpe.SystemUsage). True hardware
                  counters: CPU/mem-bus/IO-bus/interconnect util, jitter,
                  average CPU frequency, CPU power.
  2. "ssh"      — Read the Linux kernel directly over SSH:
                    /proc/stat        -> real CPU utilisation (delta of two samples)
                    /proc/meminfo     -> real memory utilisation
                    /proc/cpuinfo     -> real average core MHz
                    /proc/loadavg     -> run-queue pressure
                    /sys/.../intel-rapl or ipmitool -> real package power (if present)
                  This is genuine live data from the machine, not an estimate.
  3. "simulated" — DISABLED BY DEFAULT. Only used when the operator explicitly
                  sets SERVER_ALLOW_SIMULATION=1. Never silently substituted.

If every enabled backend fails the poll is recorded as an ERROR (status
"error") and NO metric rows are written — a gap in the graph is honest;
fabricated data is not.

Sensors that a backend genuinely cannot measure are returned as None and are
simply not stored, rather than being faked with a plausible number.
"""
from __future__ import annotations

import math
import os
import random
import re
import time

import ilo_client

# Sensor keys, canonical order (mirrors the iLO dropdown)
SENSOR_KEYS = [
    "cpu_utilization",
    "memory_bus_utilization",
    "io_bus_utilization",
    "cpu_interconnect_utilization",
    "jitter_count",
    "average_cpu_frequency",
    "cpu_power",
]

ALLOW_SIMULATION = os.getenv("SERVER_ALLOW_SIMULATION", "0") == "1"
SSH_TIMEOUT = int(os.getenv("SERVER_SSH_TIMEOUT", "10"))


class CollectionError(Exception):
    """No backend could produce real metrics for this server."""


# ── Backend 1: Redfish (HPE iLO) ───────────────────────────────────────────

def _collect_redfish(srv) -> dict:
    vals = ilo_client.fetch_metrics(
        srv.ilo_host, srv.ilo_port, srv.username, srv.password
    )
    return {k: vals.get(k) for k in SENSOR_KEYS}


# ── Backend 2: SSH into the Linux host and read /proc (REAL data) ──────────

_CPU_SAMPLE_GAP = 0.4   # seconds between the two /proc/stat samples


def _ssh_exec(client, cmd: str) -> str:
    _in, out, _err = client.exec_command(cmd, timeout=SSH_TIMEOUT)
    return out.read().decode("utf-8", errors="replace")


def _parse_proc_stat_cpu(text: str):
    """Return (idle_all, total) from the aggregate 'cpu ' line of /proc/stat."""
    for line in text.splitlines():
        if line.startswith("cpu "):
            f = [int(x) for x in line.split()[1:]]
            # user nice system idle iowait irq softirq steal guest guest_nice
            idle = f[3] + (f[4] if len(f) > 4 else 0)          # idle + iowait
            total = sum(f[:8]) if len(f) >= 8 else sum(f)
            return idle, total
    raise CollectionError("no 'cpu ' line in /proc/stat")


def _collect_ssh(srv) -> dict:
    """Genuine kernel counters over SSH. Requires ssh_* fields on the server."""
    import paramiko

    host = srv.ssh_host or srv.ilo_host
    user = srv.ssh_username
    pwd = srv.ssh_password
    if not (host and user and pwd):
        raise CollectionError("no SSH credentials configured for this server")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, port=srv.ssh_port or 22,
                       username=user, password=pwd,
                       timeout=SSH_TIMEOUT, banner_timeout=SSH_TIMEOUT,
                       auth_timeout=SSH_TIMEOUT, look_for_keys=False,
                       allow_agent=False)

        # --- CPU utilisation: two samples of /proc/stat, delta-based ---------
        s1 = _ssh_exec(client, "cat /proc/stat")
        idle1, tot1 = _parse_proc_stat_cpu(s1)
        time.sleep(_CPU_SAMPLE_GAP)
        s2 = _ssh_exec(client, "cat /proc/stat")
        idle2, tot2 = _parse_proc_stat_cpu(s2)

        d_total = tot2 - tot1
        d_idle = idle2 - idle1
        cpu_util = (100.0 * (d_total - d_idle) / d_total) if d_total > 0 else 0.0

        # --- Memory utilisation from /proc/meminfo ---------------------------
        mem_txt = _ssh_exec(client, "cat /proc/meminfo")
        mem = {}
        for line in mem_txt.splitlines():
            m = re.match(r"^(\w+):\s+(\d+)", line)
            if m:
                mem[m.group(1)] = int(m.group(2))   # kB
        mem_total = mem.get("MemTotal", 0)
        mem_avail = mem.get("MemAvailable", mem.get("MemFree", 0))
        mem_util = (100.0 * (mem_total - mem_avail) / mem_total) if mem_total else None

        # --- Average core frequency from /proc/cpuinfo ------------------------
        cpuinfo = _ssh_exec(client, "cat /proc/cpuinfo")
        mhz = [float(m.group(1)) for m in re.finditer(r"cpu MHz\s+:\s+([\d.]+)", cpuinfo)]
        avg_mhz = (sum(mhz) / len(mhz)) if mhz else None

        # --- I/O pressure: iowait share of the same delta --------------------
        # (real, derived from the counters we already sampled)
        io_util = None
        try:
            f1 = [int(x) for x in s1.splitlines()[0].split()[1:]]
            f2 = [int(x) for x in s2.splitlines()[0].split()[1:]]
            if len(f1) > 4 and len(f2) > 4 and d_total > 0:
                io_util = 100.0 * (f2[4] - f1[4]) / d_total   # iowait delta
        except Exception:
            io_util = None

        # --- Run-queue pressure as the "jitter"/contention proxy -------------
        loadavg = _ssh_exec(client, "cat /proc/loadavg").split()
        runq = None
        if len(loadavg) >= 4 and "/" in loadavg[3]:
            try:
                runq = float(loadavg[3].split("/")[0])   # currently-running tasks
            except Exception:
                runq = None

        # --- Package power: Intel RAPL, else ipmitool, else unavailable ------
        power = None
        rapl = _ssh_exec(
            client,
            "cat /sys/class/powercap/intel-rapl:0/energy_uj 2>/dev/null || true"
        ).strip()
        if rapl.isdigit():
            e1 = int(rapl)
            time.sleep(0.3)
            rapl2 = _ssh_exec(
                client,
                "cat /sys/class/powercap/intel-rapl:0/energy_uj 2>/dev/null || true"
            ).strip()
            if rapl2.isdigit():
                e2 = int(rapl2)
                if e2 >= e1:
                    power = (e2 - e1) / 0.3 / 1_000_000.0   # µJ -> W
        if power is None:
            ipmi = _ssh_exec(
                client,
                "ipmitool sensor get 'Pwr Consumption' 2>/dev/null "
                "| grep -i 'Sensor Reading' || true"
            )
            m = re.search(r"([\d.]+)", ipmi)
            if m:
                power = float(m.group(1))

        # CPU interconnect utilisation is an HPE hardware counter with no Linux
        # equivalent — report it as unavailable rather than inventing a value.
        return {
            "cpu_utilization":              round(cpu_util, 2),
            "memory_bus_utilization":       round(mem_util, 2) if mem_util is not None else None,
            "io_bus_utilization":           round(io_util, 2) if io_util is not None else None,
            "cpu_interconnect_utilization": None,
            "jitter_count":                 runq,
            "average_cpu_frequency":        round(avg_mhz) if avg_mhz else None,
            "cpu_power":                    round(power, 1) if power is not None else None,
        }
    except CollectionError:
        raise
    except Exception as e:
        raise CollectionError(f"SSH metrics failed: {e}") from e
    finally:
        try:
            client.close()
        except Exception:
            pass


# ── Backend 3: simulation (opt-in only) ────────────────────────────────────

def _collect_simulated(srv) -> dict:
    seed = sum(ord(c) for c in srv.name)
    t = time.time() / 60.0
    rng = random.Random(int(time.time() // 20) ^ seed)

    def wave(b, a, p, j):
        return max(0.0, b + a * math.sin((t / p) * 2 * math.pi + seed) + rng.uniform(-j, j))

    return {
        "cpu_utilization":              round(min(100, wave(18, 12, 7, 3)), 2),
        "memory_bus_utilization":       round(min(100, wave(9, 5, 11, 2)), 2),
        "io_bus_utilization":           round(min(100, wave(6, 4, 9, 2)), 2),
        "cpu_interconnect_utilization": round(min(100, wave(4, 3, 13, 1.5)), 2),
        "jitter_count":                 round(max(0, wave(2, 2, 5, 1))),
        "average_cpu_frequency":        round(wave(2400, 300, 8, 60)),
        "cpu_power":                    round(wave(180, 60, 10, 12), 1),
    }


# ── Public entry point ─────────────────────────────────────────────────────

def collect(srv) -> tuple[dict, str, str]:
    """Return (values, source, note).

    values : {sensor_key: float|None}   None == genuinely not measurable here
    source : "redfish" | "ssh" | "simulated"
    note   : human-readable explanation of why fallbacks happened ("" if clean)

    Raises CollectionError if no backend produced real data and simulation
    is not explicitly enabled.
    """
    mode = (getattr(srv, "collection_mode", "") or "auto").lower()
    attempts: list[str] = []
    if mode in ("auto", "redfish"):
        attempts.append("redfish")
    if mode in ("auto", "ssh"):
        attempts.append("ssh")

    notes = []
    for backend in attempts:
        try:
            if backend == "redfish":
                return _collect_redfish(srv), "redfish", "; ".join(notes)
            if backend == "ssh":
                return _collect_ssh(srv), "ssh", "; ".join(notes)
        except Exception as e:
            notes.append(f"{backend}: {e}")

    if ALLOW_SIMULATION:
        notes.append("falling back to SIMULATED data "
                     "(SERVER_ALLOW_SIMULATION=1)")
        return _collect_simulated(srv), "simulated", "; ".join(notes)

    raise CollectionError(
        "; ".join(notes) or "no collection backend configured"
    )
