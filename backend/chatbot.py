"""
chatbot.py — Resilient Ollama proxy + lightweight RAG over DB state.

Improvements over v1:
  - Auto-detects which models are installed on the Ollama server.
    If the configured OLLAMA_MODEL isn't there, falls back to the first
    qwen-family model installed, otherwise the first installed model.
  - Surfaces detailed connection / HTTP errors back to the client
    (so the UI can show "model not found" instead of "failed to fetch").
  - Truncates oversized context blocks so a single huge diff never
    blows up num_ctx.
"""
import os
import json
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session
from sqlalchemy import desc

import models


OLLAMA_URL     = os.getenv("OLLAMA_URL",     "http://10.25.41.185:11434")
OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL",   "qwen2.5:7b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))
CONTEXT_BUDGET = int(os.getenv("CHATBOT_CONTEXT_CHARS", "8000"))


SYSTEM_PROMPT = (
    "You are a network operations analyst embedded in a NOC portal. You answer "
    "questions about switch configurations, configuration drift, suspected IP "
    "conflicts, and port-traffic patterns.\n\n"
    "FORMATTING RULES — follow these exactly:\n"
    "- Write in plain, clear prose. Use short paragraphs.\n"
    "- Do NOT use bold (**), italics, or nested bullet hierarchies.\n"
    "- Use at most ONE simple level of bullets ('- '), and only when listing "
    "several parallel items. Otherwise write sentences.\n"
    "- Do NOT wrap every value in markdown. Interface names, IPs and numbers "
    "can appear inline in normal text.\n"
    "- Keep it skimmable: lead with the direct answer in one or two sentences, "
    "then add supporting detail only if useful.\n"
    "- Format large packet/byte counts readably (e.g. 4.38 trillion, 610 million).\n\n"
    "CONTENT RULES:\n"
    "- Be concrete: name the switch and the affected interface or IP when citing "
    "a finding.\n"
    "- All timestamps in the context are India Standard Time (IST, +05:30). They "
    "are current and correct — never call a timestamp a 'future date' or a data "
    "error; just report it in IST if relevant.\n"
    "- If the context lacks the information needed, say so plainly in one sentence "
    "and state what the operator should capture next.\n"
    "- Do not invent data that is not in the context."
)


# ════════════════════════════════════════════════════════════════════
# Ollama low-level helpers
# ════════════════════════════════════════════════════════════════════

def _ollama_get(path: str, timeout: int = 10):
    req = urllib.request.Request(OLLAMA_URL.rstrip("/") + path)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _ollama_post(path: str, payload: dict, timeout: int):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_URL.rstrip("/") + path,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def list_installed_models() -> list[str]:
    """Return tag names installed on the Ollama server."""
    try:
        obj = _ollama_get("/api/tags", timeout=8)
        return [m.get("name") for m in obj.get("models", []) if m.get("name")]
    except Exception:
        return []


def pick_model(preferred: str) -> tuple[str, str | None]:
    """Return (model_to_use, warning_if_any).
    Falls back to the first qwen-family model, then any installed model."""
    installed = list_installed_models()
    if not installed:
        return preferred, "Could not list installed models"
    if preferred in installed:
        return preferred, None
    qwens = [m for m in installed if m.lower().startswith("qwen")]
    if qwens:
        return qwens[0], f"Configured model '{preferred}' not installed; using '{qwens[0]}'."
    return installed[0], f"Configured model '{preferred}' not installed; using '{installed[0]}'."


# ════════════════════════════════════════════════════════════════════
# Context builders — pull structured state from the DB
# ════════════════════════════════════════════════════════════════════

def _switches_summary(db: Session) -> str:
    out = []
    for sw in db.query(models.Switch).order_by(models.Switch.name).all():
        out.append(f"- {sw.name} ({sw.device_type}) host={sw.host} loc={sw.location or '-'}")
    return "\n".join(out) if out else "(no switches registered)"


def _latest_snapshot_summary(db: Session, switch_name: Optional[str]) -> str:
    q = db.query(models.Snapshot).order_by(desc(models.Snapshot.captured_at))
    if switch_name:
        q = q.filter(models.Snapshot.switch_name == switch_name)
        snaps = q.limit(3).all()
    else:
        snaps = q.limit(10).all()
    if not snaps:
        return "(no snapshots captured)"
    out = []
    for s in snaps:
        marker = "DRIFT" if s.drift_detected else "stable"
        out.append(
            f"- snapshot #{s.id} on {s.switch_name} at {s.captured_at.isoformat()}Z "
            f"hash={s.config_hash[:8]} [{marker}]"
        )
        if s.drift_detected and s.diff_from_prev:
            diff_lines = s.diff_from_prev.splitlines()[:20]
            out.append("    diff (first 20 lines):")
            for ln in diff_lines:
                out.append(f"      {ln}")
    return "\n".join(out)


def _ip_conflict_summary(db: Session) -> str:
    sub = (db.query(models.ArpEntry)
           .order_by(models.ArpEntry.switch_name,
                     models.ArpEntry.ip_address,
                     desc(models.ArpEntry.captured_at))
           .all())
    seen, latest = set(), []
    for r in sub:
        k = (r.switch_name, r.ip_address)
        if k in seen:
            continue
        seen.add(k)
        latest.append(r)
    by_ip = {}
    for r in latest:
        by_ip.setdefault(r.ip_address, []).append(r)
    conflicts = [(ip, rows) for ip, rows in by_ip.items()
                 if len({r.mac_address for r in rows}) > 1]
    if not conflicts:
        return f"(no IP conflicts detected across {len(by_ip)} unique IPs)"
    out = ["DETECTED CONFLICTS:"]
    for ip, rows in conflicts[:15]:
        out.append(f"- IP {ip} appears on {len(rows)} switches with different MACs:")
        for r in rows:
            out.append(f"    {r.switch_name}: mac={r.mac_address} iface={r.interface} vlan={r.vlan}")
    return "\n".join(out)


def _port_summary(db: Session, switch_name: Optional[str]) -> str:
    if not switch_name:
        return "(no focused switch)"
    last = (db.query(models.PortStat.captured_at)
            .filter(models.PortStat.switch_name == switch_name)
            .order_by(desc(models.PortStat.captured_at))
            .first())
    if not last:
        return f"(no port stats for {switch_name})"
    rows = (db.query(models.PortStat)
            .filter(models.PortStat.switch_name == switch_name,
                    models.PortStat.captured_at == last[0])
            .order_by(models.PortStat.interface_name).all())
    if not rows:
        return f"(no port stats for {switch_name})"
    top = sorted(rows, key=lambda r: r.total_packets or 0, reverse=True)[:25]
    out = [f"latest capture {last[0].isoformat()}Z ({len(rows)} ports):"]
    for r in top:
        desc_s = (r.port_description or "-")[:60]
        out.append(
            f"- {r.interface_name:30s} desc={desc_s:60s} "
            f"in={r.in_packets} out={r.out_packets} tot={r.total_packets}"
        )
    return "\n".join(out)


def build_context(db: Session, focus_switch: Optional[str]) -> tuple[str, list[str]]:
    blocks, included = [], []

    blocks.append("=== SWITCH REGISTRY ===")
    blocks.append(_switches_summary(db)); included.append("switch_registry")

    blocks.append("\n=== RECENT CONFIG SNAPSHOTS / DRIFT ===")
    blocks.append(_latest_snapshot_summary(db, focus_switch)); included.append("config_snapshots")

    blocks.append("\n=== IP CONFLICT SCAN ===")
    blocks.append(_ip_conflict_summary(db)); included.append("ip_conflicts")

    if focus_switch:
        blocks.append(f"\n=== PORT-LEVEL STATE FOR {focus_switch} ===")
        blocks.append(_port_summary(db, focus_switch)); included.append("port_state")

    full = "\n".join(blocks)
    if len(full) > CONTEXT_BUDGET:
        full = full[:CONTEXT_BUDGET] + "\n…(context truncated)"
    return full, included


# ════════════════════════════════════════════════════════════════════
# Ollama client
# ════════════════════════════════════════════════════════════════════

def call_ollama(question: str, context: str) -> tuple[str, str, str | None]:
    """Returns (answer, model_used, warning_if_any)."""
    model, warning = pick_model(OLLAMA_MODEL)
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "system", "content": "CURRENT NETWORK STATE:\n" + context},
            {"role": "user",   "content": question},
        ],
        "options": {"temperature": 0.2, "num_ctx": 4096},
    }
    try:
        obj = _ollama_post("/api/chat", payload, OLLAMA_TIMEOUT)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"Ollama returned HTTP {e.code}: {body}")
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Cannot reach Ollama at {OLLAMA_URL}: {e.reason}. "
            f"Is the backend container able to route to {OLLAMA_URL}?")
    except (ValueError, KeyError) as e:
        raise RuntimeError(f"Bad response from Ollama: {e}")
    msg = obj.get("message", {}).get("content", "")
    return (msg.strip() or "(empty response from model)"), model, warning

    
def health_check() -> dict:
    """Used by /api/chat/status — shows URL, models available, picked model."""
    try:
        installed = list_installed_models()
        chosen, warning = pick_model(OLLAMA_MODEL)
        return {
            "ok": bool(installed),
            "url": OLLAMA_URL,
            "configured_model": OLLAMA_MODEL,
            "chosen_model": chosen,
            "warning": warning,
            "models_available": installed,
        }
    except Exception as e:
        return {
            "ok": False,
            "url": OLLAMA_URL,
            "configured_model": OLLAMA_MODEL,
            "error": str(e),
        }


def answer(db: Session, question: str, focus_switch: Optional[str] = None) -> dict:
    context, included = build_context(db, focus_switch)
    msg, model, warning = call_ollama(question, context)
    return {
        "answer":             msg,
        "model":              model,
        "warning":            warning,
        "context_sections":   included,
        "focus_switch":       focus_switch,
        "context_chars":      len(context),
        "asked_at":           models.ist_now().isoformat() + "Z",
    }