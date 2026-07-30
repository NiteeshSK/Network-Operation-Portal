"""
auth.py — In-memory admin session store.

The admin enters SSH credentials (username + password) once and chooses
which switches those credentials apply to (a scope). The server creates
a session, returns a random token, and from then on the token unlocks
all SSH operations on switches inside the scope — using the admin's
credentials, not the per-switch stored ones.

Credentials are stored in RAM only. They are wiped on server restart.
Nothing is written to disk or to the database.
"""
import secrets
import threading
import time
from typing import Optional


# 8 hours — typical for an admin work session.
DEFAULT_TTL_SECONDS = int(8 * 60 * 60)

# Sentinel used in the scope list to mean "all switches".
SCOPE_ALL = "*"

# token -> dict(username, password, scope, created_at, expires_at)
_SESSIONS: dict[str, dict] = {}
_LOCK = threading.Lock()


def create_session(
    username: str,
    password: str,
    scope: list[str],
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> tuple[str, dict]:
    """Create a new admin session.

    scope: list of switch names this credential covers. Use ["*"] for all.

    Returns (token, session_dict). The session_dict EXCLUDES the password.
    """
    if not username or not password:
        raise ValueError("username and password are required")
    if not scope:
        raise ValueError("scope must be a non-empty list (use ['*'] for all)")

    token = secrets.token_urlsafe(32)
    now = time.time()
    with _LOCK:
        _SESSIONS[token] = {
            "username":   username,
            "password":   password,   # plaintext, in RAM only
            "scope":      list(scope),
            "created_at": now,
            "expires_at": now + ttl_seconds,
        }
    return token, _public_view(_SESSIONS[token])


def get_session(token: Optional[str]) -> Optional[dict]:
    """Return the full session dict (including password) if the token is
    valid and not expired. Returns None otherwise."""
    if not token:
        return None
    with _LOCK:
        s = _SESSIONS.get(token)
        if not s:
            return None
        if time.time() > s["expires_at"]:
            _SESSIONS.pop(token, None)
            return None
        return s


def delete_session(token: str) -> bool:
    """Forcefully drop a session. Returns True if it existed."""
    if not token:
        return False
    with _LOCK:
        return _SESSIONS.pop(token, None) is not None


def session_covers_switch(session: Optional[dict], switch_name: str) -> bool:
    """Does this session's scope include the given switch?"""
    if not session:
        return False
    scope = session.get("scope", [])
    if SCOPE_ALL in scope:
        return True
    return switch_name in scope


def list_active_sessions() -> list[dict]:
    """Return the public view of every active session.
    Excludes passwords. Drops expired sessions on the way out."""
    now = time.time()
    out = []
    with _LOCK:
        expired = [t for t, s in _SESSIONS.items() if now > s["expires_at"]]
        for t in expired:
            _SESSIONS.pop(t, None)
        for s in _SESSIONS.values():
            out.append(_public_view(s))
    return out


def credentials_for(session: dict) -> dict:
    """Return the SSH credentials dict for use as a `credentials_override`
    parameter in switch_manager.run_command()."""
    return {
        "username": session["username"],
        "password": session["password"],
    }


def _public_view(session: dict) -> dict:
    """Return a session dict safe to send to a client (no password)."""
    return {
        "username":   session["username"],
        "scope":      list(session["scope"]),
        "created_at": session["created_at"],
        "expires_at": session["expires_at"],
    }