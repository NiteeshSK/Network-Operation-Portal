"""
diff_engine.py — Detect and describe configuration changes.
"""
import hashlib
import difflib


def hash_config(config_text: str) -> str:
    return hashlib.sha256(config_text.encode("utf-8")).hexdigest()


def diff_configs(old: str, new: str,
                 from_label: str = "previous",
                 to_label: str = "current") -> str:
    diff = difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile=from_label,
        tofile=to_label,
        lineterm="",
        n=3,
    )
    return "".join(diff)
