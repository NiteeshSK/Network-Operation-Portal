"""
command_advisor.py — When an operator runs a command that the switch rejects,
work out what they *meant* and offer runnable corrections.

Two layers, in order:

  1. DETERMINISTIC (always runs, instant, offline)
     Every vendor command set is keyed by the same intent ("version",
     "interfaces", "vlans", …). So if a command matches an entry in ANY
     vendor's table, we know the intent and can emit the correct command for
     *this* switch's device_type. That single rule fixes the most common
     mistake by far — using `show ...` on a Comware box or `display ...` on
     an Aruba box.

     We also do fuzzy matching against the correct table, so typos and
     partial commands ("dis int br") still resolve.

  2. LLM REFINEMENT (optional, best-effort)
     If the agent model is reachable it is asked to pick/rank candidates and
     explain the fix in one line. If it is unreachable or slow, we simply
     return the deterministic suggestions — the feature never breaks because
     the model is down.

Everything returned is a *read-only* command drawn from the vendor's allow-list,
so clicking a suggestion can never run something destructive.
"""
from __future__ import annotations

import difflib
import re
from typing import Optional

import switch_manager

# Human labels for each intent key, shown next to the suggestion.
INTENT_LABELS = {
    "version":    "Show software/hardware version",
    "interfaces": "List interfaces and link state",
    "vlans":      "List VLANs",
    "ip_int":     "Show IP interfaces",
    "config":     "Show running configuration",
    "saved":      "Show saved configuration",
    "mac":        "Show MAC address table",
    "routes":     "Show IP routing table",
    "cpu":        "Show CPU utilisation",
    "device":     "Show device / system info",
    "ssh_status": "Show SSH server status",
    "stats":      "Show interface statistics",
}

# Error text that means "the switch did not understand the command"
_SYNTAX_ERROR = re.compile(
    r"(unrecognized|unknown command|invalid input|incomplete command|"
    r"% *error|syntax error|not found at|ambiguous command|"
    r"wrong parameter|command not exist)", re.I
)


def looks_like_bad_command(error_text: str, output_text: str = "") -> bool:
    """True when the failure is a syntax problem rather than SSH/auth/network."""
    blob = f"{error_text or ''}\n{output_text or ''}"
    return bool(_SYNTAX_ERROR.search(blob))


def _normalise(cmd: str) -> str:
    return re.sub(r"\s+", " ", (cmd or "").strip().lower())


def _intent_from_any_vendor(cmd: str) -> Optional[str]:
    """If the command is valid for SOME vendor, return the intent it expresses."""
    n = _normalise(cmd)
    for table in switch_manager.COMMAND_SETS.values():
        for intent, correct in table.items():
            if _normalise(correct) == n:
                return intent
    return None


def _fuzzy_intents(cmd: str, table: dict, limit: int = 3) -> list[str]:
    """Rank intents whose correct command most resembles what was typed."""
    n = _normalise(cmd)
    if not n:
        return []
    scored = []
    for intent, correct in table.items():
        c = _normalise(correct)
        ratio = difflib.SequenceMatcher(None, n, c).ratio()
        # Token overlap rewards "dis int br" -> "display interface brief"
        tw = set(n.split())
        cw = set(c.split())
        overlap = len(tw & cw) / max(1, len(tw))
        prefix = sum(1 for a, b in zip(n.split(), c.split())
                     if b.startswith(a) and len(a) >= 2) / max(1, len(n.split()))
        scored.append((0.5 * ratio + 0.3 * overlap + 0.2 * prefix, intent))
    scored.sort(reverse=True)
    return [i for score, i in scored[:limit] if score > 0.34]


def suggest(device_type: str, failed_command: str,
            error_text: str = "", output_text: str = "") -> dict:
    """Return runnable corrections for `failed_command` on this device_type."""
    table = switch_manager.get_commands(device_type)
    suggestions: list[dict] = []
    seen: set[str] = set()

    def add(intent: str, reason: str, confidence: str):
        correct = table.get(intent)
        if not correct or correct in seen:
            return
        if _normalise(correct) == _normalise(failed_command):
            return                       # don't suggest exactly what failed
        seen.add(correct)
        suggestions.append({
            "command": correct,
            "intent": intent,
            "label": INTENT_LABELS.get(intent, intent),
            "reason": reason,
            "confidence": confidence,
        })

    # 1. Same intent, wrong dialect — the classic mistake.
    intent = _intent_from_any_vendor(failed_command)
    if intent:
        add(intent, f"'{failed_command}' is the other vendor's syntax for this. "
                    f"On {device_type} the equivalent is below.", "high")

    # 2. Fuzzy match against this vendor's own table (typos, abbreviations).
    for i in _fuzzy_intents(failed_command, table):
        add(i, "Closest matching supported command on this switch.", "medium")

    # 3. Nothing matched — offer the safe, most common reads.
    if not suggestions:
        for i in ("interfaces", "version", "vlans", "config"):
            add(i, "Common read-only command on this switch.", "low")

    return {
        "device_type": device_type,
        "failed_command": failed_command,
        "is_syntax_error": looks_like_bad_command(error_text, output_text),
        "suggestions": suggestions[:5],
    }


def _validate_reply(parsed, allowed: list[str]) -> Optional[str]:
    """Return an error string if the model's JSON violates the contract.

    This is the output contract (same idea as the SLM assistant's Pydantic
    schema): {"best": <one of the allowed commands>, "explanation": <str>}.
    The critical rule is that `best` MUST be drawn from the allow-list — the
    model ranks commands, it never invents them.
    """
    if not isinstance(parsed, dict):
        return "output must be a JSON object"
    best = parsed.get("best")
    if not isinstance(best, str) or best not in allowed:
        return (f"'best' must be exactly one of the allowed commands: "
                f"{allowed}")
    expl = parsed.get("explanation")
    if expl is not None and not isinstance(expl, str):
        return "'explanation' must be a string"
    if isinstance(expl, str) and len(expl) > 300:
        return "'explanation' must be under 300 characters"
    return None


def refine_with_model(base: dict, switch_name: str, max_retries: int = 3) -> dict:
    """Best-effort LLM ranking with a self-correcting retry loop.

    The model is asked for a JSON object matching a strict contract; if the
    reply is malformed or violates it (e.g. invents a command not on the
    allow-list), the SPECIFIC validation error is fed back and it gets
    another attempt — up to max_retries. If everything fails, the
    deterministic suggestions stand unchanged. The feature can therefore
    never break because the model is down, slow, or misbehaving.
    """
    try:
        import json as _json
        import agent as _agent

        cmds = [s["command"] for s in base["suggestions"]]
        base_prompt = (
            f"A network operator ran this on switch '{switch_name}' "
            f"(device type {base['device_type']}):\n"
            f"  {base['failed_command']}\n"
            f"It failed. These read-only commands are supported on that "
            f"switch: {cmds}\n\n"
            "Reply with ONLY a JSON object of this exact shape:\n"
            '{"best": "<one command copied verbatim from the list>", '
            '"explanation": "<one short sentence explaining the mistake>"}\n'
            "No prose, no markdown fences."
        )

        prompt = base_prompt
        for attempt in range(1, max_retries + 1):
            data = _agent._chat(
                [{"role": "system", "content": "You reply with JSON only."},
                 {"role": "user", "content": prompt}],
                use_tools=False,
            )
            content = _agent.strip_think(
                (data.get("choices") or [{}])[0]
                .get("message", {}).get("content") or "")
            m = re.search(r"\{.*\}", content, re.S)
            err = "no JSON object found in the reply"
            parsed = None
            if m:
                try:
                    parsed = _json.loads(m.group(0))
                    err = _validate_reply(parsed, cmds)
                except Exception as e:
                    err = f"invalid JSON: {e}"

            if parsed is not None and err is None:
                best = parsed["best"]
                expl = (parsed.get("explanation") or "").strip()
                base["suggestions"].sort(
                    key=lambda s: 0 if s["command"] == best else 1)
                base["suggestions"][0]["confidence"] = "high"
                if expl:
                    base["explanation"] = expl
                base["model_attempts"] = attempt
                return base

            # Feed the exact error back so the model can self-correct
            # (identical pattern to the SLM assistant's structured retry).
            prompt = (
                f"{base_prompt}\n\n"
                f"Your previous answer was invalid:\n{content}\n\n"
                f"The error was:\n{err}\n\n"
                f"Return corrected JSON only."
            )
    except Exception:
        pass          # model down / slow — deterministic answer stands
    return base
