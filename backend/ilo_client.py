"""
ilo_client.py — HPE iLO 6 Redfish client for server performance sensors.

The iLO 6 "Performance → Monitoring" page reads its seven sensors from the
Redfish system resource, specifically Oem.Hpe.SystemUsage on
GET /redfish/v1/Systems/1/ :

    AvgCPU0Freq   -> average_cpu_frequency        (MHz)
    CPU0Power     -> cpu_power                    (W)
    CPUICUtil     -> cpu_interconnect_utilization (%)
    CPUUtil       -> cpu_utilization              (%)
    IOBusUtil     -> io_bus_utilization           (%)
    JitterCount   -> jitter_count                 (count)
    MemoryBusUtil -> memory_bus_utilization       (%)

This module uses ONLY the Python standard library (urllib + ssl + json),
so it adds no new dependency to requirements.txt.

If the iLO is unreachable (lab/demo without real hardware), fetch_metrics()
raises IloError; the caller may instead use simulate_metrics(), which
produces smooth plausible values and is CLEARLY flagged as simulated in the
API response so nobody mistakes demo data for live telemetry.
"""
from __future__ import annotations

import base64
import json
import math
import random
import ssl
import time
import urllib.request
import urllib.error

# Sensor key -> (Redfish SystemUsage field, unit)
SENSORS = {
    "cpu_utilization":              ("CPUUtil",       "%"),
    "memory_bus_utilization":       ("MemoryBusUtil", "%"),
    "io_bus_utilization":           ("IOBusUtil",     "%"),
    "cpu_interconnect_utilization": ("CPUICUtil",     "%"),
    "jitter_count":                 ("JitterCount",   "cnt"),
    "average_cpu_frequency":        ("AvgCPU0Freq",   "MHz"),
    "cpu_power":                    ("CPU0Power",     "W"),
}

# Human labels used by the frontend dropdown (iLO wording, same order)
SENSOR_LABELS = [
    ("cpu_utilization",              "CPU Utilization"),
    ("memory_bus_utilization",       "Memory Bus Utilization"),
    ("io_bus_utilization",           "I/O Bus Utilization"),
    ("cpu_interconnect_utilization", "CPU Interconnect Utilization"),
    ("jitter_count",                 "Jitter count"),
    ("average_cpu_frequency",        "Average CPU Frequency"),
    ("cpu_power",                    "CPU Power"),
]


class IloError(Exception):
    """Raised when the iLO Redfish endpoint can't be reached / parsed."""


def _request(url: str, username: str, password: str, timeout: int = 8) -> dict:
    """GET a Redfish URL with HTTP Basic auth, ignoring the self-signed cert
    (iLO ships with one by default)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url)
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        raise IloError(f"iLO HTTP {e.code}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise IloError(f"iLO unreachable: {e.reason}") from e
    except Exception as e:  # timeout, bad JSON, TLS failure …
        raise IloError(f"iLO error: {e}") from e


def fetch_metrics(host: str, port: int, username: str, password: str) -> dict:
    """Return {sensor_key: float} for all seven sensors from a live iLO.

    Raises IloError on any connectivity/parse problem so the caller can
    decide whether to fall back to simulation.
    """
    base = f"https://{host}:{port}".rstrip("/")
    data = _request(f"{base}/redfish/v1/Systems/1/", username, password)

    usage = (data.get("Oem", {}) or {}).get("Hpe", {}).get("SystemUsage")
    if not isinstance(usage, dict):
        raise IloError("Redfish response has no Oem.Hpe.SystemUsage block "
                       "(is this an HPE iLO 5/6 system resource?)")

    out = {}
    for key, (field, _unit) in SENSORS.items():
        v = usage.get(field)
        if v is None:
            v = 0
        try:
            out[key] = float(v)
        except (TypeError, ValueError):
            out[key] = 0.0
    return out


def test_reachable(host: str, port: int, username: str, password: str):
    """(ok, error) tuple — mirrors switch_manager.test_reachable()."""
    try:
        base = f"https://{host}:{port}".rstrip("/")
        _request(f"{base}/redfish/v1/", username, password, timeout=6)
        return True, None
    except IloError as e:
        return False, str(e)


# ── Simulated fallback (demo without real iLO hardware) ─────────────────────
# Smooth, per-server-deterministic waveforms so graphs look like real
# telemetry. The API response marks these rows simulated=True.

def simulate_metrics(server_name: str) -> dict:
    seed = sum(ord(c) for c in server_name)
    t = time.time() / 60.0  # minutes
    rng = random.Random(int(time.time() // 20) ^ seed)  # stable per 20s tick

    def wave(base_v, amp, period_min, jitter):
        return max(0.0, base_v
                   + amp * math.sin((t / period_min) * 2 * math.pi + seed)
                   + rng.uniform(-jitter, jitter))

    return {
        "cpu_utilization":              round(min(100, wave(18, 12, 7, 3)), 2),
        "memory_bus_utilization":       round(min(100, wave(9,   5, 11, 2)), 2),
        "io_bus_utilization":           round(min(100, wave(6,   4, 9, 2)), 2),
        "cpu_interconnect_utilization": round(min(100, wave(4,   3, 13, 1.5)), 2),
        "jitter_count":                 round(max(0, wave(2, 2, 5, 1)), 0),
        "average_cpu_frequency":        round(wave(2400, 300, 8, 60), 0),
        "cpu_power":                    round(wave(180, 60, 10, 12), 1),
    }
