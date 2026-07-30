"""
rag/ingestor.py — Turn live PostgreSQL state into LangChain Documents.

Each Document carries a deterministic `id` in its metadata so the vector store
can UPSERT on every sync instead of piling up duplicates. IDs are derived from
the natural key of the row (e.g. snapshot id, switch+ip+mac) — re-ingesting the
same fact overwrites the same vector.

We index the things an operator actually asks the assistant about:
  - drift snapshots (the unified diff is the high-value text)
  - IP conflicts (computed fleet-wide, same logic as chatbot.py)
  - per-switch port anomalies (ports currently showing errors)
  - a switch-registry card per device (so "where is comware?" resolves)
"""
from __future__ import annotations

from typing import Iterable
from sqlalchemy.orm import Session
from sqlalchemy import desc

from langchain_core.documents import Document

import models
from . import config


# ── helpers ────────────────────────────────────────────────────────────────

def _doc(text: str, doc_id: str, **metadata) -> Document:
    metadata = {"id": doc_id, **metadata}
    return Document(page_content=text.strip(), metadata=metadata)


# ── switch registry ────────────────────────────────────────────────────────

def ingest_switches(db: Session) -> list[Document]:
    docs = []
    for sw in db.query(models.Switch).order_by(models.Switch.name).all():
        text = (
            f"Switch registry entry.\n"
            f"Name: {sw.name}\n"
            f"Vendor/type: {sw.device_type}\n"
            f"Host: {sw.host}:{sw.port}\n"
            f"Location: {sw.location or 'unspecified'}"
        )
        docs.append(_doc(text, f"switch:{sw.id}",
                         source="switches", switch=sw.name, type="registry"))
    return docs


# ── drift snapshots ────────────────────────────────────────────────────────

def ingest_snapshots(db: Session) -> list[Document]:
    snaps = (db.query(models.Snapshot)
             .filter(models.Snapshot.drift_detected.is_(True))
             .order_by(desc(models.Snapshot.captured_at))
             .limit(config.MAX_SNAPSHOTS)
             .all())
    docs = []
    for s in snaps:
        diff = (s.diff_from_prev or "").strip() or "(drift flagged but no stored diff)"
        text = (
            f"Configuration drift detected.\n"
            f"Switch: {s.switch_name}\n"
            f"Captured at (IST): {s.captured_at.isoformat()}\n"
            f"Config hash: {s.config_hash[:12]}\n"
            f"Unified diff (added '+' / removed '-'):\n{diff}"
        )
        docs.append(_doc(text, f"snapshot:{s.id}",
                         source="snapshots", switch=s.switch_name,
                         type="drift", captured_at=s.captured_at.isoformat()))
    return docs


# ── IP conflicts (mirrors chatbot.py logic, fleet-wide) ────────────────────

def ingest_conflicts(db: Session) -> list[Document]:
    rows = (db.query(models.ArpEntry)
            .order_by(models.ArpEntry.switch_name,
                      models.ArpEntry.ip_address,
                      desc(models.ArpEntry.captured_at))
            .all())
    # keep most-recent entry per (switch, ip)
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

    docs = []
    for ip, entries in by_ip.items():
        macs = {e.mac_address for e in entries}
        if len(macs) <= 1:
            continue  # not a conflict
        lines = "\n".join(
            f"  {e.switch_name}: mac={e.mac_address} iface={e.interface} vlan={e.vlan}"
            for e in entries
        )
        text = (
            f"IP conflict detected (HIGH severity).\n"
            f"IP address {ip} resolves to {len(macs)} distinct MACs across the fleet:\n"
            f"{lines}"
        )
        docs.append(_doc(text, f"conflict:{ip}",
                         source="arp_entries", ip=ip, type="conflict"))
    return docs


# ── port anomalies (current error counters) ────────────────────────────────

def ingest_port_anomalies(db: Session) -> list[Document]:
    # For each switch, take its latest capture timestamp, then surface ports
    # with non-zero error counters in that capture.
    docs = []
    switch_names = [s.name for s in db.query(models.Switch).all()]
    for name in switch_names:
        last = (db.query(models.PortStat.captured_at)
                .filter(models.PortStat.switch_name == name)
                .order_by(desc(models.PortStat.captured_at))
                .first())
        if not last:
            continue
        rows = (db.query(models.PortStat)
                .filter(models.PortStat.switch_name == name,
                        models.PortStat.captured_at == last[0])
                .all())
        bad = [r for r in rows if (r.in_errors or 0) + (r.out_errors or 0) > 0]
        if not bad:
            continue
        lines = "\n".join(
            f"  {r.interface_name}: in_err={r.in_errors} out_err={r.out_errors} "
            f"state={r.link_state} desc={(r.port_description or '-')[:60]}"
            for r in sorted(bad,
                            key=lambda r: (r.in_errors or 0) + (r.out_errors or 0),
                            reverse=True)
        )
        text = (
            f"Port error anomalies on {name}.\n"
            f"Latest capture (IST): {last[0].isoformat()}\n"
            f"Interfaces currently reporting errors:\n{lines}"
        )
        docs.append(_doc(text, f"portanomaly:{name}",
                         source="port_stats", switch=name, type="port_anomaly",
                         captured_at=last[0].isoformat()))
    return docs


# ── aggregate ──────────────────────────────────────────────────────────────

def ingest_all(db: Session) -> list[Document]:
    docs: list[Document] = []
    docs += ingest_switches(db)
    docs += ingest_snapshots(db)
    docs += ingest_conflicts(db)
    docs += ingest_port_anomalies(db)
    return docs
