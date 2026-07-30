"""
schemas.py — Pydantic request/response models.

All datetime fields are stored as IST (Asia/Kolkata) in the DB.
They are serialised with the +05:30 offset so browsers display the
correct local time without client-side conversion.
"""
from pydantic import BaseModel, ConfigDict, field_serializer
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Optional

_IST = ZoneInfo("Asia/Kolkata")


def _to_utc_iso(dt: datetime | None) -> str | None:
    """Return an ISO-8601 string that ALWAYS carries the +05:30 (IST) offset.

    Postgres TIMESTAMP WITHOUT TIME ZONE strips tzinfo, so values read back
    are naive. Without an explicit offset the browser assumes UTC and shows
    times ~5.5h off. We attach IST to naive values and normalize tz-aware
    ones, so the output always ends in +05:30."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_IST)
    else:
        dt = dt.astimezone(_IST)
    return dt.replace(microsecond=0).isoformat()


class _TZAwareBase(BaseModel):
    """Base class that serializes every datetime field with a 'Z' suffix."""
    @field_serializer("*", when_used="json", check_fields=False)
    def _serialize_dt(self, v):
        if isinstance(v, datetime):
            return _to_utc_iso(v)
        return v


class SwitchCreate(BaseModel):
    name: str
    host: str
    port: int = 22
    device_type: str = "hp_comware"
    username: str
    password: str
    location: str = ""


class SwitchOut(_TZAwareBase):
    id: int
    name: str
    host: str
    port: int
    device_type: str
    location: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class CommandRequest(BaseModel):
    """Either pick from the curated dropdown via `command_key`, OR type
    any command directly via `command_raw`. Exactly one must be set."""
    command_key: str | None = None
    command_raw: str | None = None


class PingRequest(BaseModel):
    target: str


class CommandLogOut(_TZAwareBase):
    id: int
    switch_name: str
    command: str
    output: str
    success: bool
    error: str
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)


class SnapshotOut(_TZAwareBase):
    id: int
    switch_name: str
    config_hash: str
    drift_detected: bool
    captured_at: datetime
    model_config = ConfigDict(from_attributes=True)


class SnapshotDetail(SnapshotOut):
    config_text: str
    diff_from_prev: str


class DiffResponse(_TZAwareBase):
    from_snapshot_id: int
    to_snapshot_id: int
    from_time: datetime
    to_time: datetime
    diff: str
    identical: bool


# ─── Admin auth ─────────────────────────────────────────────────────

class AdminLoginRequest(BaseModel):
    """Body for POST /api/admin/login.

    scope: list of switch names this credential should apply to.
           Use ["*"] for "all switches" — or list specific switch names.
    """
    username: str
    password: str
    scope: list[str] = ["*"]
    ttl_seconds: Optional[int] = None   # override default 8-hour expiry


class AdminSessionOut(BaseModel):
    """Returned by login / `/api/admin/me`. Never includes the password."""
    username: str
    scope: list[str]
    created_at: float
    expires_at: float
    validated_against: str | None = None
    bootstrap_mode: bool = False    # True when login was granted with no switches in DB


class AdminLoginResponse(BaseModel):
    token: str
    session: AdminSessionOut