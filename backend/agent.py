"""
agent.py — A tool-calling AI agent for the NOC Portal.

Unlike the previous assistant (which stuffed a fixed context blob into a
prompt and answered once), this is a real agent loop:

    user question
        -> model decides WHICH tools to call, with arguments
        -> we execute the tools against the live database / devices
        -> results are fed back
        -> model may call more tools (multi-step reasoning)
        -> final grounded answer, with a full trace of what it did

The model runs on the on-prem Ollama node via its OpenAI-compatible
/v1/chat/completions endpoint, which supports the `tools` parameter
(qwen3:32b advertises the "tools" capability).

Design rules
------------
* Every tool is READ-ONLY except `run_switch_command`, which is additionally
  constrained by the same destructive-verb blocklist the REST API uses.
* Tools return compact JSON so the context stays small.
* The loop is bounded (MAX_STEPS) so a confused model can't spin forever.
* If the model emits no tool calls it just answers — that path is equivalent
  to the old chatbot, so nothing regresses.
* qwen3 emits <think>…</think> reasoning; we strip it from the user-visible
  answer but keep it in the trace for debugging.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from datetime import timedelta
from typing import Any, Callable, Optional

from sqlalchemy import desc

import models

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://10.25.167.101:11434").rstrip("/")
AGENT_MODEL = os.getenv("AGENT_MODEL", os.getenv("OLLAMA_MODEL", "qwen3:32b"))
AGENT_TIMEOUT = int(os.getenv("AGENT_TIMEOUT", "180"))
MAX_STEPS = int(os.getenv("AGENT_MAX_STEPS", "6"))

# Reused from the REST layer: never let the agent run a destructive command.
DESTRUCTIVE = re.compile(
    r"\b(reboot|reload|erase|delete|format|factory|write|save|shutdown|"
    r"clear|reset|install|upgrade|boot)\b", re.I
)

SYSTEM_PROMPT = """You are the NOC Portal Agent, an expert network operations assistant.

You manage a fleet of enterprise switches (HP Comware, Aruba AOS-CX) and HPE
servers. You have TOOLS that read the portal's live database and devices.

Rules:
- ALWAYS call a tool to get facts. Never guess switch names, IPs, MACs,
  counters, or metrics from memory.
- Call several tools if needed to answer fully. Think about which data you
  actually need before calling.
- When you have enough information, answer concisely and concretely: name the
  exact switch, interface, IP, or sensor involved, and cite the numbers.
- If a tool returns no data, say so plainly rather than inventing an answer.
- For anything destructive, refuse and explain — you are read-only.
- Prefer short, operator-friendly answers. Use a short bulleted list when
  reporting several findings.
"""


# ══════════════════════════════════════════════════════════════════════
# TOOL IMPLEMENTATIONS — each takes (db, **kwargs) and returns JSON-able data
# ══════════════════════════════════════════════════════════════════════

def _t_list_switches(db, **_):
    rows = db.query(models.Switch).order_by(models.Switch.name).all()
    return [{"name": s.name, "host": s.host, "device_type": s.device_type,
             "location": s.location} for s in rows]


def _t_list_servers(db, **_):
    rows = db.query(models.Server).order_by(models.Server.name).all()
    return [{"name": s.name, "ilo_host": s.ilo_host, "ssh_host": s.ssh_host,
             "collection_mode": s.collection_mode,
             "last_source": s.last_source,
             "last_poll_status": s.last_poll_status,
             "last_poll_error": (s.last_poll_error or "")[:200],
             "poll_interval_seconds": s.poll_interval_seconds}
            for s in rows]


def _t_get_drift(db, switch_name: Optional[str] = None, limit: int = 5, **_):
    q = db.query(models.Snapshot).filter(models.Snapshot.drift_detected == True)  # noqa: E712
    if switch_name:
        q = q.filter(models.Snapshot.switch_name == switch_name)
    rows = q.order_by(desc(models.Snapshot.captured_at)).limit(min(limit, 20)).all()
    return [{"switch": r.switch_name,
             "captured_at": str(r.captured_at),
             "config_hash": r.config_hash[:12],
             "diff_preview": (r.diff_from_prev or "")[:800]}
            for r in rows]


def _t_snapshot_summary(db, switch_name: Optional[str] = None, **_):
    q = db.query(models.Snapshot)
    if switch_name:
        q = q.filter(models.Snapshot.switch_name == switch_name)
    total = q.count()
    drifted = q.filter(models.Snapshot.drift_detected == True).count()  # noqa: E712
    latest = q.order_by(desc(models.Snapshot.captured_at)).first()
    return {"total_snapshots": total, "drift_events": drifted,
            "latest_capture": str(latest.captured_at) if latest else None,
            "latest_switch": latest.switch_name if latest else None}


def _t_get_ip_conflicts(db, **_):
    window = int(os.getenv("IP_CONFLICT_WINDOW_MINUTES", "15"))
    newest = db.query(models.ArpEntry).order_by(desc(models.ArpEntry.captured_at)).first()
    if not newest:
        return {"conflicts": [], "note": "no ARP data captured yet"}
    cutoff = newest.captured_at - timedelta(minutes=window)
    rows = (db.query(models.ArpEntry)
            .filter(models.ArpEntry.captured_at >= cutoff)
            .order_by(models.ArpEntry.switch_name, models.ArpEntry.ip_address,
                      desc(models.ArpEntry.captured_at)).all())
    seen, latest = set(), []
    for r in rows:
        k = (r.switch_name, r.ip_address)
        if k in seen:
            continue
        seen.add(k)
        latest.append(r)
    by_ip: dict[str, list] = {}
    for r in latest:
        by_ip.setdefault(r.ip_address, []).append(r)
    conflicts = [
        {"ip": ip, "mac_count": len({x.mac_address for x in rs}),
         "entries": [{"switch": x.switch_name, "mac": x.mac_address,
                      "interface": x.interface, "vlan": x.vlan} for x in rs]}
        for ip, rs in by_ip.items() if len({x.mac_address for x in rs}) > 1
    ]
    return {"conflicts": conflicts, "unique_ips": len(by_ip),
            "switches_scanned": len({r.switch_name for r in latest})}


def _t_get_arp(db, switch_name: Optional[str] = None, ip: Optional[str] = None,
               limit: int = 25, **_):
    q = db.query(models.ArpEntry)
    if switch_name:
        q = q.filter(models.ArpEntry.switch_name == switch_name)
    if ip:
        q = q.filter(models.ArpEntry.ip_address == ip)
    rows = q.order_by(desc(models.ArpEntry.captured_at)).limit(min(limit, 100)).all()
    return [{"switch": r.switch_name, "ip": r.ip_address, "mac": r.mac_address,
             "interface": r.interface, "vlan": r.vlan,
             "captured_at": str(r.captured_at)} for r in rows]


def _t_get_port_stats(db, switch_name: str, only_problems: bool = False,
                      limit: int = 20, **_):
    sub = (db.query(models.PortStat.interface_name,
                    models.PortStat.captured_at)
           .filter(models.PortStat.switch_name == switch_name)
           .order_by(desc(models.PortStat.captured_at)).first())
    if not sub:
        return {"error": f"no port stats for '{switch_name}'"}
    newest_ts = sub[1]
    rows = (db.query(models.PortStat)
            .filter(models.PortStat.switch_name == switch_name,
                    models.PortStat.captured_at >= newest_ts - timedelta(seconds=30))
            .all())
    out = []
    for r in rows:
        rec = {"interface": r.interface_name, "link": r.link_state,
               "in_errors": r.in_errors, "out_errors": r.out_errors,
               "in_packets": r.in_packets, "out_packets": r.out_packets,
               "description": r.port_description}
        if only_problems and r.link_state == "UP" and not (r.in_errors or r.out_errors):
            continue
        out.append(rec)
    return {"switch": switch_name, "captured_at": str(newest_ts),
            "ports": out[:min(limit, 100)], "total_ports": len(rows)}


def _t_get_server_metrics(db, server_name: str, sensor: str = "cpu_utilization",
                          minutes: int = 10, **_):
    srv = db.query(models.Server).filter(models.Server.name == server_name).first()
    if not srv:
        return {"error": f"no such server '{server_name}'"}
    cutoff = models.ist_now() - timedelta(minutes=min(minutes, 10080))
    rows = (db.query(models.ServerMetric)
            .filter(models.ServerMetric.server_id == srv.id,
                    models.ServerMetric.sensor == sensor,
                    models.ServerMetric.captured_at >= cutoff)
            .order_by(models.ServerMetric.captured_at).all())
    if not rows:
        return {"server": server_name, "sensor": sensor, "points": 0,
                "note": f"no samples in last {minutes} min "
                        f"(poll status: {srv.last_poll_status or 'never'}; "
                        f"{(srv.last_poll_error or '')[:120]})"}
    vals = [r.value / 100.0 for r in rows]
    return {"server": server_name, "sensor": sensor,
            "source": rows[-1].source, "unit": rows[-1].unit,
            "points": len(vals), "latest": vals[-1],
            "min": min(vals), "max": max(vals),
            "avg": round(sum(vals) / len(vals), 2),
            "window_minutes": minutes}


def _t_get_alert_settings(db, server_name: str, sensor: str = "cpu_utilization", **_):
    srv = db.query(models.Server).filter(models.Server.name == server_name).first()
    if not srv:
        return {"error": f"no such server '{server_name}'"}
    row = (db.query(models.ServerAlertSetting)
           .filter(models.ServerAlertSetting.server_id == srv.id,
                   models.ServerAlertSetting.sensor == sensor).first())
    if not row:
        return {"server": server_name, "sensor": sensor, "configured": False}
    return {"server": server_name, "sensor": sensor, "configured": True,
            "lower_threshold": row.lower_threshold,
            "lower_dwell_sec": row.lower_dwell_sec,
            "upper_threshold": row.upper_threshold,
            "upper_dwell_sec": row.upper_dwell_sec}


def _t_recent_commands(db, switch_name: Optional[str] = None, limit: int = 10, **_):
    q = db.query(models.CommandLog)
    if switch_name:
        q = q.filter(models.CommandLog.switch_name == switch_name)
    rows = q.order_by(desc(models.CommandLog.timestamp)).limit(min(limit, 30)).all()
    return [{"switch": r.switch_name, "command": r.command,
             "success": r.success, "error": (r.error or "")[:200],
             "at": str(r.timestamp)} for r in rows]


def _t_run_switch_command(db, switch_name: str, command: str, **kw):
    """Guarded read-only execution. Requires an admin session token to be
    passed through from the caller; otherwise refuses."""
    creds = kw.get("_credentials")
    if not creds:
        return {"error": "no admin session — the agent cannot run commands "
                         "without an authenticated operator session"}
    if DESTRUCTIVE.search(command or ""):
        return {"refused": True,
                "reason": f"'{command}' contains a destructive verb; the "
                          f"agent is strictly read-only"}
    sw = db.query(models.Switch).filter(models.Switch.name == switch_name).first()
    if not sw:
        return {"error": f"no such switch '{switch_name}'"}
    import switch_manager
    out, err = switch_manager.run_command(sw, command, credentials_override=creds)
    if err:
        return {"switch": switch_name, "command": command, "error": err}
    return {"switch": switch_name, "command": command,
            "output": (out or "")[:4000]}


def _t_search_knowledge(db, query: str, k: int = 4, **_):
    """RAG search over the portal's vector index, if the RAG layer is enabled."""
    try:
        from rag.chain import search_documents
        return {"results": search_documents(query, k=k)}
    except Exception:
        try:
            from rag.vectorstore import get_vectorstore
            vs = get_vectorstore()
            docs = vs.similarity_search(query, k=k)
            return {"results": [{"source": d.metadata.get("source", ""),
                                 "text": d.page_content[:600]} for d in docs]}
        except Exception as e:
            return {"error": f"RAG layer unavailable: {e}"}


# ── Tool registry: JSON schema (for the model) + python impl ───────────────

TOOLS: list[dict[str, Any]] = [
    {"name": "list_switches",
     "description": "List every managed switch: name, host, vendor/device type, location.",
     "params": {"type": "object", "properties": {}},
     "fn": _t_list_switches},

    {"name": "list_servers",
     "description": "List every monitored server, how its metrics are collected "
                    "(redfish/ssh), and whether the last poll succeeded.",
     "params": {"type": "object", "properties": {}},
     "fn": _t_list_servers},

    {"name": "get_config_drift",
     "description": "Recent configuration-drift events with the actual diff text. "
                    "Use this to answer 'what changed' questions.",
     "params": {"type": "object", "properties": {
         "switch_name": {"type": "string", "description": "optional: filter to one switch"},
         "limit": {"type": "integer", "description": "max events (default 5)"}}},
     "fn": _t_get_drift},

    {"name": "get_snapshot_summary",
     "description": "Counts of config snapshots and drift events, and the latest capture time.",
     "params": {"type": "object", "properties": {
         "switch_name": {"type": "string"}}},
     "fn": _t_snapshot_summary},

    {"name": "get_ip_conflicts",
     "description": "Fleet-wide duplicate-IP detection: any IP resolving to more "
                    "than one MAC across the latest ARP capture round.",
     "params": {"type": "object", "properties": {}},
     "fn": _t_get_ip_conflicts},

    {"name": "get_arp_table",
     "description": "Raw ARP entries; filter by switch and/or a specific IP.",
     "params": {"type": "object", "properties": {
         "switch_name": {"type": "string"},
         "ip": {"type": "string"},
         "limit": {"type": "integer"}}},
     "fn": _t_get_arp},

    {"name": "get_port_stats",
     "description": "Latest per-interface counters for a switch: link state, "
                    "packets, and error counters. Set only_problems=true to see "
                    "just down links and ports with errors.",
     "params": {"type": "object", "properties": {
         "switch_name": {"type": "string"},
         "only_problems": {"type": "boolean"},
         "limit": {"type": "integer"}},
         "required": ["switch_name"]},
     "fn": _t_get_port_stats},

    {"name": "get_server_metrics",
     "description": "Statistics for one server sensor over a time window: latest, "
                    "min, max, avg, and which backend produced the data. Sensors: "
                    "cpu_utilization, memory_bus_utilization, io_bus_utilization, "
                    "cpu_interconnect_utilization, jitter_count, "
                    "average_cpu_frequency, cpu_power.",
     "params": {"type": "object", "properties": {
         "server_name": {"type": "string"},
         "sensor": {"type": "string"},
         "minutes": {"type": "integer", "description": "look-back window, default 10"}},
         "required": ["server_name"]},
     "fn": _t_get_server_metrics},

    {"name": "get_alert_settings",
     "description": "Configured lower/upper thresholds and dwell times for a "
                    "server sensor.",
     "params": {"type": "object", "properties": {
         "server_name": {"type": "string"}, "sensor": {"type": "string"}},
         "required": ["server_name"]},
     "fn": _t_get_alert_settings},

    {"name": "get_recent_commands",
     "description": "Audit trail: recently executed CLI commands and whether they succeeded.",
     "params": {"type": "object", "properties": {
         "switch_name": {"type": "string"}, "limit": {"type": "integer"}}},
     "fn": _t_recent_commands},

    {"name": "run_switch_command",
     "description": "Run a READ-ONLY show/display command on a switch over SSH and "
                    "return its output. Destructive verbs are refused. Use only "
                    "when stored data cannot answer the question.",
     "params": {"type": "object", "properties": {
         "switch_name": {"type": "string"},
         "command": {"type": "string", "description": "e.g. 'display version'"}},
         "required": ["switch_name", "command"]},
     "fn": _t_run_switch_command},

    {"name": "search_knowledge",
     "description": "Semantic search over the portal's indexed operational "
                    "knowledge (snapshots, conflicts, anomalies) via RAG.",
     "params": {"type": "object", "properties": {
         "query": {"type": "string"}, "k": {"type": "integer"}},
         "required": ["query"]},
     "fn": _t_search_knowledge},
]

_BY_NAME: dict[str, Callable] = {t["name"]: t["fn"] for t in TOOLS}


def _openai_tools_schema() -> list[dict]:
    return [{"type": "function",
             "function": {"name": t["name"],
                          "description": t["description"],
                          "parameters": t["params"]}}
            for t in TOOLS]


# ══════════════════════════════════════════════════════════════════════
# Model transport (OpenAI-compatible endpoint on Ollama)
# ══════════════════════════════════════════════════════════════════════

def _chat(messages: list[dict], use_tools: bool = True) -> dict:
    payload = {
        "model": AGENT_MODEL,
        "messages": messages,
        "temperature": 0.1,
        "stream": False,
    }
    if use_tools:
        payload["tools"] = _openai_tools_schema()
        payload["tool_choice"] = "auto"

    req = urllib.request.Request(
        f"{OLLAMA_URL}/v1/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer ollama"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=AGENT_TIMEOUT) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        raise RuntimeError(f"Agent model HTTP {e.code}: {body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Cannot reach the model at {OLLAMA_URL}: {e.reason}")


_THINK = re.compile(r"<think>.*?</think>", re.S)


def strip_think(text: str) -> str:
    return _THINK.sub("", text or "").strip()


# ══════════════════════════════════════════════════════════════════════
# The agent loop
# ══════════════════════════════════════════════════════════════════════

def run_agent(db, question: str, focus_switch: Optional[str] = None,
              credentials: Optional[dict] = None) -> dict:
    """Execute the tool-calling loop and return answer + trace."""
    user = question
    if focus_switch:
        user = f"[Operator is currently viewing switch '{focus_switch}']\n{question}"

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]
    trace: list[dict] = []

    for step in range(MAX_STEPS):
        data = _chat(messages)
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        tool_calls = msg.get("tool_calls") or []

        if not tool_calls:
            answer = strip_think(msg.get("content") or "")
            return {"answer": answer or "(no answer produced)",
                    "trace": trace, "steps": step + 1,
                    "model": AGENT_MODEL,
                    "tools_used": [t["tool"] for t in trace]}

        # Record the assistant's tool-call turn verbatim
        messages.append({"role": "assistant",
                         "content": msg.get("content") or "",
                         "tool_calls": tool_calls})

        for call in tool_calls:
            fn = (call.get("function") or {})
            name = fn.get("name", "")
            raw_args = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            except Exception:
                args = {}

            impl = _BY_NAME.get(name)
            if impl is None:
                result: Any = {"error": f"unknown tool '{name}'"}
            else:
                try:
                    if name == "run_switch_command":
                        args["_credentials"] = credentials
                    result = impl(db, **args)
                except TypeError as e:
                    result = {"error": f"bad arguments for {name}: {e}"}
                except Exception as e:
                    result = {"error": f"{name} failed: {e}"}

            trace.append({"step": step + 1, "tool": name,
                          "args": {k: v for k, v in args.items()
                                   if not k.startswith("_")},
                          "result_preview": json.dumps(result, default=str)[:400]})

            messages.append({
                "role": "tool",
                "tool_call_id": call.get("id", name),
                "name": name,
                "content": json.dumps(result, default=str)[:6000],
            })

    # Ran out of steps — ask for a final answer with no further tools.
    messages.append({"role": "user",
                     "content": "Stop calling tools. Answer now using what you have."})
    data = _chat(messages, use_tools=False)
    msg = (data.get("choices") or [{}])[0].get("message") or {}
    return {"answer": strip_think(msg.get("content") or "") or "(no answer)",
            "trace": trace, "steps": MAX_STEPS, "model": AGENT_MODEL,
            "truncated": True, "tools_used": [t["tool"] for t in trace]}


# ══════════════════════════════════════════════════════════════════════
# Proactive analysis (inspired by Byte's stuck-detector): surface problems
# without being asked.
# ══════════════════════════════════════════════════════════════════════

def proactive_findings(db) -> list[dict]:
    """Cheap rule-based scan of the whole portal. No LLM call — instant."""
    out: list[dict] = []

    conf = _t_get_ip_conflicts(db)
    for c in conf.get("conflicts", []):
        out.append({"severity": "high", "type": "ip_conflict",
                    "title": f"IP {c['ip']} has {c['mac_count']} MACs",
                    "detail": ", ".join(f"{e['switch']}→{e['mac']}"
                                        for e in c["entries"])})

    drift = _t_get_drift(db, limit=3)
    for d in drift:
        out.append({"severity": "medium", "type": "config_drift",
                    "title": f"Config drift on {d['switch']}",
                    "detail": f"at {d['captured_at']}"})

    for s in db.query(models.Server).all():
        if s.last_poll_status == "error":
            out.append({"severity": "medium", "type": "server_poll_failed",
                        "title": f"No real metrics from {s.name}",
                        "detail": (s.last_poll_error or "")[:180]})
        elif s.last_poll_status == "simulated":
            out.append({"severity": "low", "type": "server_simulated",
                        "title": f"{s.name} is serving SIMULATED data",
                        "detail": "Configure iLO or SSH credentials for real metrics."})

    # Interfaces with error counters on their newest sample
    for sw in db.query(models.Switch).all():
        ps = _t_get_port_stats(db, switch_name=sw.name, only_problems=True, limit=5)
        if isinstance(ps, dict):
            for p in ps.get("ports", []):
                if p.get("in_errors") or p.get("out_errors"):
                    out.append({"severity": "medium", "type": "port_errors",
                                "title": f"{sw.name} {p['interface']} has errors",
                                "detail": f"in={p['in_errors']} out={p['out_errors']}"})
    return out
