"""
template_engine.py — Phase 1: render + validate configuration templates.

DESIGN NOTE — why not Jinja2
----------------------------
Jinja is powerful but its expression language reaches into Python objects
(attribute access, filters, arbitrary calls if the environment is careless).
A configuration template is a *security-sensitive artefact* that produces
commands aimed at production switches, so the renderer here is deliberately
tiny and has no code-execution surface at all:

    {{ variable }}                 -> substitution, that's it
    {% for x in list_var %} ... {% endfor %}   -> one level of iteration
    {# comment #}                  -> stripped

No filters, no attribute access, no calls, no conditionals with expressions.
Anything not in that grammar is a template error, not a silent surprise.

NOTHING IN THIS MODULE TOUCHES A DEVICE. Rendering and validation are pure
functions over text. Phase 1 never executes what it produces.
"""
from __future__ import annotations

import re
from typing import Any

# Commands that must never appear in a rendered template, even in Phase 1
# where we don't execute. Catching them at authoring time is the point.
DESTRUCTIVE = re.compile(
    r"^\s*(reboot|reload|erase|delete|format|factory[- ]?(default|reset)|"
    r"boot\s+system|shutdown\s+system|clear\s+startup|"
    r"restore\s+factory)\b",
    re.I | re.M,
)

# Commands that would sever our own management path. A template containing
# these is almost always an accident and would lock the fleet out.
LOCKOUT = re.compile(
    r"^\s*(no\s+ssh\s+server|undo\s+ssh\s+server|"
    r"no\s+ip\s+ssh|"
    r"shutdown\s*$|"          # bare 'shutdown' only — 'no/undo shutdown' ENABLES a port
    r"interface\s+(mgmt|management)\b|"
    r"no\s+interface\s+(mgmt|management)\b|"
    r"undo\s+interface\s+(M-GigabitEthernet|MGE)\b)",
    re.I | re.M,
)

_VAR = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
_FOR = re.compile(
    r"\{%\s*for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([A-Za-z_][A-Za-z0-9_]*)\s*%\}"
    r"(.*?)"
    r"\{%\s*endfor\s*%\}",
    re.S,
)
_COMMENT = re.compile(r"\{#.*?#\}", re.S)
_ANY_TAG = re.compile(r"\{%.*?%\}", re.S)


class TemplateError(Exception):
    pass


def _stringify(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def declared_variables(body: str) -> list[str]:
    """Every {{ name }} and every loop source, in order of first appearance."""
    seen: list[str] = []

    def add(n: str):
        if n not in seen:
            seen.append(n)

    for m in _FOR.finditer(body):
        add(m.group(2))                       # the list variable
    loop_vars = {m.group(1) for m in _FOR.finditer(body)}
    for m in _VAR.finditer(body):
        if m.group(1) not in loop_vars:
            add(m.group(1))
    return seen


def render(body: str, variables: dict[str, Any]) -> str:
    """Render a template body. Raises TemplateError on unknown variables or
    unsupported syntax."""
    text = _COMMENT.sub("", body)

    # 1. Expand loops first (single level; nesting is intentionally unsupported).
    def expand(m: re.Match) -> str:
        item_name, list_name, inner = m.group(1), m.group(2), m.group(3)
        if list_name not in variables:
            raise TemplateError(f"unknown list variable '{list_name}'")
        seq = variables[list_name]
        if isinstance(seq, str):
            seq = [s.strip() for s in seq.split(",") if s.strip()]
        if not isinstance(seq, (list, tuple)):
            raise TemplateError(f"'{list_name}' must be a list")
        out = []
        for item in seq:
            scoped = dict(variables)
            scoped[item_name] = item
            out.append(_substitute(inner, scoped))
        return "".join(out)

    text = _FOR.sub(expand, text)

    # 2. Any remaining {% ... %} is unsupported syntax — fail loudly.
    leftover = _ANY_TAG.search(text)
    if leftover:
        raise TemplateError(
            f"unsupported template tag: {leftover.group(0)[:40]!r}. "
            "Only {% for x in list %}…{% endfor %} is allowed."
        )

    text = _substitute(text, variables)

    # 3. Nothing that looks like a placeholder may survive. A bare identifier
    #    would already have been substituted or raised; anything left is an
    #    expression we deliberately do not support (attribute access, filters,
    #    calls). Emitting it verbatim into switch CLI would be a silent bug.
    stray = re.search(r"\{\{.*?\}\}", text, re.S)
    if stray:
        raise TemplateError(
            f"unsupported expression {stray.group(0)[:40]!r}. Only plain "
            "{{ variable }} names are allowed — no attributes, filters or calls."
        )
    return text


def _substitute(text: str, variables: dict[str, Any]) -> str:
    def sub(m: re.Match) -> str:
        name = m.group(1)
        if name not in variables:
            raise TemplateError(f"unknown variable '{name}'")
        return _stringify(variables[name])
    return _VAR.sub(sub, text)


# ── Validation ─────────────────────────────────────────────────────────────

def _looks_like_interface(v: str) -> bool:
    return bool(re.match(
        r"^(GigabitEthernet|Ten-GigabitEthernet|TenGigE|XGE|FGE|"
        r"HundredGigE|Twenty-FiveGigE|Bridge-Aggregation|"
        r"Route-Aggregation|lag|vlan|1/\d|\d+/\d+)",
        str(v), re.I))


def validate_variables(schema: list[dict], provided: dict) -> list[str]:
    """schema entries: {name, type, required, description, choices?}"""
    errors: list[str] = []
    for spec in schema:
        name = spec["name"]
        req = spec.get("required", True)
        if name not in provided or provided[name] in ("", None):
            if req:
                errors.append(f"'{name}' is required")
            continue
        val = provided[name]
        t = spec.get("type", "string")
        if t == "int":
            try:
                int(val)
            except (TypeError, ValueError):
                errors.append(f"'{name}' must be a whole number (got {val!r})")
        elif t == "vlan":
            try:
                iv = int(val)
                if not (1 <= iv <= 4094):
                    errors.append(f"'{name}': VLAN must be 1–4094 (got {iv})")
            except (TypeError, ValueError):
                errors.append(f"'{name}': VLAN must be numeric")
        elif t == "interface":
            if not _looks_like_interface(val):
                errors.append(f"'{name}': {val!r} does not look like an interface")
        elif t == "list":
            items = ([s.strip() for s in val.split(",")] if isinstance(val, str)
                     else list(val))
            if not items or not any(items):
                errors.append(f"'{name}' must contain at least one item")
        if spec.get("choices") and str(val) not in [str(c) for c in spec["choices"]]:
            errors.append(f"'{name}' must be one of {spec['choices']}")
    unknown = set(provided) - {s["name"] for s in schema}
    for u in sorted(unknown):
        errors.append(f"'{u}' is not a variable of this template")
    return errors


def safety_scan(rendered: str) -> dict:
    """Static safety review of the generated CLI. Returns blockers + warnings."""
    blockers: list[str] = []
    warnings: list[str] = []

    for m in DESTRUCTIVE.finditer(rendered):
        blockers.append(f"destructive command: {m.group(0).strip()!r}")
    for m in LOCKOUT.finditer(rendered):
        warnings.append(
            f"may sever management access: {m.group(0).strip()!r}")

    lines = [l for l in rendered.splitlines() if l.strip()]
    if not lines:
        blockers.append("template renders to nothing")
    if len(lines) > 300:
        warnings.append(f"{len(lines)} lines — unusually large change")

    # A config template that never enters config mode is suspicious.
    if not re.search(r"^\s*(configure|system-view|conf t)\b", rendered, re.I | re.M):
        warnings.append("template never enters configuration mode")

    return {"blockers": blockers, "warnings": warnings, "line_count": len(lines)}


def preview(body: str, schema: list[dict], variables: dict,
            device_type: str = "") -> dict:
    """Full Phase-1 preview: validate, render, safety-scan. Never executes."""
    errors = validate_variables(schema, variables)
    if errors:
        return {"ok": False, "errors": errors, "rendered": None,
                "blockers": [], "warnings": []}
    try:
        rendered = render(body, variables)
    except TemplateError as e:
        return {"ok": False, "errors": [str(e)], "rendered": None,
                "blockers": [], "warnings": []}

    scan = safety_scan(rendered)
    return {
        "ok": not scan["blockers"],
        "errors": [],
        "rendered": rendered,
        "commands": [l.rstrip() for l in rendered.splitlines() if l.strip()],
        "blockers": scan["blockers"],
        "warnings": scan["warnings"],
        "line_count": scan["line_count"],
        "device_type": device_type,
    }
