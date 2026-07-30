"""
compliance.py — Phase 1: verify a switch's running-config against standards.

Operates ONLY on configuration snapshots already stored in the database, so a
compliance run costs nothing on the device and cannot change anything. If a
switch has never been snapshotted, it is reported as "no data" rather than
being quietly treated as compliant.

A rule is a small, declarative object:

    kind            meaning
    ------------    ---------------------------------------------------------
    must_contain    the pattern MUST appear in the running-config
    must_not_contain the pattern MUST NOT appear
    line_count_max  at most N lines may match the pattern

`pattern` is a regular expression matched per-line (MULTILINE), which keeps
rules readable ("^ntp server 10\\.", "^snmp-agent community") without needing
a parser for two different vendor syntaxes.

Rules may be scoped to a device_type; an empty scope means "all switches".
"""
from __future__ import annotations

import re
from typing import Optional

from sqlalchemy import desc

import models

SEVERITIES = ("critical", "high", "medium", "low")

KINDS = ("must_contain", "must_not_contain", "line_count_max")


def _latest_snapshot(db, switch) -> Optional[models.Snapshot]:
    return (db.query(models.Snapshot)
            .filter(models.Snapshot.switch_id == switch.id)
            .order_by(desc(models.Snapshot.captured_at))
            .first())


def _matches(pattern: str, config: str) -> list[str]:
    try:
        rx = re.compile(pattern, re.M | re.I)
    except re.error as e:
        raise ValueError(f"invalid regex {pattern!r}: {e}") from e
    return [m.group(0).strip() for m in rx.finditer(config)]


def evaluate_rule(rule, config_text: str) -> dict:
    """Return {status, matches, detail} for one rule against one config."""
    try:
        hits = _matches(rule.pattern, config_text or "")
    except ValueError as e:
        return {"status": "error", "matches": [], "detail": str(e)}

    if rule.kind == "must_contain":
        ok = len(hits) > 0
        detail = (f"found {len(hits)} matching line(s)" if ok
                  else "required configuration is missing")
    elif rule.kind == "must_not_contain":
        ok = len(hits) == 0
        detail = ("not present" if ok
                  else f"forbidden configuration present ({len(hits)} line(s))")
    elif rule.kind == "line_count_max":
        limit = rule.threshold if rule.threshold is not None else 0
        ok = len(hits) <= limit
        detail = f"{len(hits)} matching line(s), limit {limit}"
    else:
        return {"status": "error", "matches": [],
                "detail": f"unknown rule kind '{rule.kind}'"}

    return {"status": "pass" if ok else "fail",
            "matches": hits[:10], "detail": detail}


def _rule_applies(rule, switch) -> bool:
    scope = (rule.device_type or "").strip()
    return (not scope) or scope == switch.device_type


def check_switch(db, switch, rules) -> dict:
    snap = _latest_snapshot(db, switch)
    applicable = [r for r in rules if r.enabled and _rule_applies(r, switch)]

    if snap is None:
        return {"switch": switch.name, "device_type": switch.device_type,
                "status": "no_data", "checked_at": None,
                "rules_evaluated": 0, "results": [],
                "note": "no configuration snapshot captured yet"}

    results = []
    for r in applicable:
        res = evaluate_rule(r, snap.config_text)
        results.append({
            "rule_id": r.id, "name": r.name, "kind": r.kind,
            "severity": r.severity, "pattern": r.pattern,
            "description": r.description,
            **res,
        })

    failed = [x for x in results if x["status"] == "fail"]
    errored = [x for x in results if x["status"] == "error"]
    if errored:
        status = "error"
    elif failed:
        worst = min((SEVERITIES.index(f["severity"]) for f in failed),
                    default=len(SEVERITIES) - 1)
        status = "fail" if SEVERITIES[worst] in ("critical", "high") else "warn"
    else:
        status = "pass"

    return {"switch": switch.name, "device_type": switch.device_type,
            "status": status,
            "checked_at": str(snap.captured_at),
            "snapshot_hash": snap.config_hash[:12],
            "rules_evaluated": len(results),
            "failed": len(failed),
            "results": results}


def check_all(db, switch_names: Optional[list[str]] = None) -> dict:
    rules = db.query(models.ComplianceRule).order_by(models.ComplianceRule.id).all()
    q = db.query(models.Switch)
    if switch_names:
        q = q.filter(models.Switch.name.in_(switch_names))
    switches = q.order_by(models.Switch.name).all()

    reports = [check_switch(db, sw, rules) for sw in switches]
    summary = {s: sum(1 for r in reports if r["status"] == s)
               for s in ("pass", "warn", "fail", "error", "no_data")}
    return {"reports": reports, "summary": summary,
            "rules_total": len(rules),
            "switches_checked": len(reports)}


# ── Built-in starter rules (seeded once; fully editable afterwards) ────────

DEFAULT_RULES = [
    {"name": "SSH server enabled", "kind": "must_contain",
     "pattern": r"^\s*(ssh server enable|ssh server vrf)", "severity": "critical",
     "device_type": "hp_comware",
     "description": "Management access must remain available over SSH."},

    {"name": "Telnet disabled", "kind": "must_not_contain",
     "pattern": r"^\s*telnet server enable", "severity": "high",
     "device_type": "hp_comware",
     "description": "Telnet is cleartext and must not be enabled."},

    {"name": "No default SNMP community", "kind": "must_not_contain",
     # Comware:  snmp-agent community read public
     # Aruba:    snmp-server community public
     # The access mode (read/write/ro/rw) may sit between, so allow it.
     "pattern": r"^\s*snmp(-agent|-server)?\s+community\s+"
                r"(read|write|ro|rw)?\s*(public|private)\b",
     "severity": "critical",
     "device_type": "",
     "description": "Default SNMP communities are publicly known."},

    {"name": "NTP configured", "kind": "must_contain",
     "pattern": r"^\s*(ntp-service unicast-server|ntp server)\s+\S+", "severity": "medium",
     "device_type": "",
     "description": "Accurate clocks are required for correlating logs."},

    {"name": "Logging host configured", "kind": "must_contain",
     "pattern": r"^\s*(info-center loghost|logging)\s+\S+", "severity": "medium",
     "device_type": "",
     "description": "Devices must ship logs to a central collector."},

    {"name": "No unencrypted passwords", "kind": "must_not_contain",
     "pattern": r"password\s+simple\s+\S+", "severity": "critical",
     "device_type": "hp_comware",
     "description": "Passwords must be stored hashed, never in cleartext."},
]


def seed_default_rules(db) -> int:
    """Insert starter rules if the table is empty. Returns rows added."""
    if db.query(models.ComplianceRule).first():
        return 0
    for r in DEFAULT_RULES:
        db.add(models.ComplianceRule(enabled=True, builtin=True, **r))
    db.commit()
    return len(DEFAULT_RULES)
