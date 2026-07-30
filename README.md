# NOC Portal

Browser-based Network Operations Centre dashboard for managing an HP Comware +
Aruba AOS-CX switch fleet. Live port statistics, configuration-drift detection,
IP-conflict / ARP visibility, an on-prem AI assistant, and a guarded SSH command
runner — all behind one SSH-validated login.

Stack: **FastAPI + SQLAlchemy + Netmiko** (backend) · **React 18 + Babel**
(frontend, no build step) · **PostgreSQL 16** · **Ollama** (local LLM) ·
**Docker Compose** (3 containers). All timestamps are Asia/Kolkata (IST, +05:30).

---

## What changed in this version — the "Failed to fetch" fix

**Symptom:** saving a snapshot schedule / starting auto-capture failed with
`Snapshot save failed: Failed to fetch`, and the dashboard could not reach the
backend.

**Root cause:** the frontend called the backend on a *separate* origin —
`http://<host>:18000` — hardcoded in `app.jsx`. A cross-origin call like that
fails with the browser's generic "Failed to fetch" whenever:
- the page is served over **HTTPS** but the API URL is **HTTP** (mixed-content
  block), or
- anything (proxy, firewall, port remap) makes `<host>:18000` unreachable from
  the browser even though the page on `:5173` loads fine.

The backend code was always correct — the request never reached it.

**Fix:** the frontend now calls the **same origin** it was loaded from, using a
relative `/api/...` path, and **Nginx reverse-proxies `/api` to the backend**
over the internal Docker network.

- `frontend/nginx.conf` — added `location /api/ { proxy_pass http://backend:8000; }`
  with long timeouts (config pulls can be slow) plus `/docs`, `/redoc`,
  `/openapi.json` passthrough.
- `frontend/app.jsx` — `const API = ""` (same origin). Override with
  `window.NOC_API_BASE` if you ever need a different backend host.
- `frontend/admin.html` — same `const API = ""` change.

Result: **no cross-origin request, no CORS preflight, no mixed-content** — one
single origin (`:5173`) for both the UI and the API. This permanently removes
the "Failed to fetch" class of errors.

The auto-capture save endpoints were verified end-to-end (HTTP 200, IST
timestamps, settings persisted) with an in-process test client.

---

## Quick start

```bash
docker compose up --build -d      # build images + start postgres, backend, nginx
docker compose logs -f backend    # watch startup
```

Healthy startup ends with:

```
[scheduler] started — snapshot:20s, port-stats:10s, arp:10min, cleanup:1h ...
INFO:     Application startup complete.
```

Then open the dashboard:

```
http://<this-host>:5173/
```

> Use the machine's real IP/hostname if you're on another computer
> (e.g. `http://10.25.128.167:5173/`). Because the UI and API now share one
> origin, whatever host:port loads the page also serves the API — nothing else
> to configure.

API docs (proxied through the same origin):

```
http://<this-host>:5173/docs
```

### First login enables auto-capture

Log in with the **real SSH credentials** for your switches. On success the
portal:
1. validates the credentials by SSHing into a switch in scope, and
2. **stores those working credentials on the switch record** so the background
   scheduler can authenticate too.

This is required for unattended auto-capture (snapshots / port-stats / ARP) to
actually run. After logging in, open a switch → **Auto-capture** tab → enable
config snapshots and/or real-time port polling and pick an interval.

---

## Ports

| Service   | Host port | Container | Notes                                   |
|-----------|-----------|-----------|-----------------------------------------|
| frontend  | **5173**  | 80        | Nginx — serves the UI **and** proxies `/api` |
| backend   | 18000     | 8000      | FastAPI — still exposed for direct/debug use |
| postgres  | 15432     | 5432      | `psql -h localhost -p 15432 -U noc_user noc_portal` |

The browser only needs **5173** now. Port 18000 stays mapped for direct API
access / debugging but the UI no longer depends on it.

---

## Useful commands

```bash
# Follow backend logs (scheduler activity, capture results, errors)
docker compose logs -f backend

# Confirm data is being written
docker exec noc-postgres psql -U noc_user noc_portal -c \
  "SELECT switch_name, COUNT(*), MAX(captured_at) FROM port_stats GROUP BY switch_name;"

# Check auto-capture schedules
docker exec noc-postgres psql -U noc_user noc_portal -c \
  "SELECT switch_name, enabled, interval_minutes, port_stats_enabled, \
          port_stats_interval_seconds, next_due_at, port_stats_next_due_at \
   FROM auto_capture_settings;"

# Stop (data kept) / wipe everything
docker compose down
docker compose down -v
```

---

## Project layout

```
noc-portal/
├── docker-compose.yml          # 3 services on one private bridge network
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt        # paramiko 2.12 + cryptography <46 pinned for legacy gear
│   ├── .env                    # DATABASE_URL, OLLAMA_*, retention
│   ├── database.py             # SQLAlchemy engine + get_db()
│   ├── models.py               # 6 ORM tables; ist_now() = IST timestamps
│   ├── schemas.py              # Pydantic models; serialise datetimes as +05:30
│   ├── auth.py                 # in-RAM SSH-validated sessions, 8h TTL
│   ├── switch_manager.py       # Netmiko + legacy ssh-rsa patch; per-vendor commands
│   ├── diff_engine.py          # SHA-256 hash + unified diff
│   ├── port_stats_parser.py    # Comware / AOS-CX / ProVision counter parsers
│   ├── arp_parser.py           # Comware / Aruba ARP parsers
│   ├── scheduler.py            # 4 APScheduler jobs: snapshot / port-stats / ARP / cleanup
│   ├── chatbot.py              # Ollama RAG context builder
│   ├── seed.py                 # idempotent table create + column migrations (runs on boot)
│   └── main.py                 # FastAPI app + 32 API endpoints
└── frontend/
    ├── Dockerfile
    ├── nginx.conf              # serves UI + proxies /api  ← the fix
    ├── index.html              # loads React + Babel from CDN
    ├── app.jsx                 # entire React UI (one file, ~1900 lines)
    ├── admin.html              # optional standalone admin page
    └── styles.css
```

Legacy `migrate*.py` scripts are superseded by `seed.py` (kept for reference).

---

## Auto-capture fix (config-snapshot / drift)

**Symptom:** config-snapshot auto-capture didn't produce snapshots at any interval.

**Diagnosis:** by live-triggering the scheduler I confirmed the scheduler itself
fires correctly — it finds the due switch and attempts the capture. The capture
then **fails at the SSH step** because the scheduler authenticates with the
credentials *stored on the switch row*, and those were stale/wrong. Every failed
attempt was being logged to `command_logs` but nothing surfaced in the UI, so it
looked like "nothing happens."

**Fixes:**
1. **Reliable credential sync on login** (`main.py`) — when you log in with the
   real SSH password, those credentials are now written to **all in-scope
   switches** without a fragile per-switch re-test that previously skipped
   switches on any timeout. This is what the scheduler authenticates with.
2. **Visible failure reason** (`models.py`, `scheduler.py`, `main.py`,
   `app.jsx`, `seed.py`) — each auto-capture attempt now records its status and
   error on the setting row. The **Auto-capture tab shows a red banner with the
   exact reason** (e.g. SSH auth failure, switch unreachable) when capture
   fails, and a green confirmation when it succeeds. New columns are added
   automatically by `seed.py` on boot.

**What to do after deploying:** open a switch → **Auto-capture** tab → enable
config snapshots. If it fails, the banner tells you why. The usual fix is to
**log out and back in with the correct switch password** — that syncs the
credentials the scheduler uses. Watch `docker compose logs -f backend` for
`[auto-snapshot] <switch> -> saved` to confirm success.

---

## Troubleshooting: `Unexpected token '<', "<html>..." is not valid JSON`

This means an `/api` request received an **HTML page** instead of JSON. The cause
is that the **`/api` reverse proxy in `nginx.conf` is not active** — the running
nginx container is still using the old config, so `/api/...` falls through to the
SPA fallback and returns `index.html` (which starts with `<html>`).

**Fix — rebuild the frontend container so the new `nginx.conf` loads:**

```bash
docker compose up -d --build frontend
# then hard-refresh the browser:  Ctrl+Shift+R
```

If you changed any backend file too, rebuild everything:

```bash
docker compose up -d --build
```

The frontend now detects this situation and shows a clear message
("The API returned an HTML page instead of data — the /api proxy isn't active…")
instead of the cryptic JSON parse error, so you know exactly what to do.

**Quick check that the proxy is live:**

```bash
curl -i http://<host>:5173/api/switches
# Expect: Content-Type: application/json  (NOT text/html)
```

---

## THE auto-capture fix — naive/aware datetime mismatch (Postgres only)

**Root cause (found and fixed):** every `DateTime` column is
`TIMESTAMP WITHOUT TIME ZONE`, but the code was storing and comparing
**timezone-aware** values (`datetime.now(ZoneInfo("Asia/Kolkata"))` →
`11:00+05:30`). When PostgreSQL writes an aware value into a naive column it
converts it to the session timezone (UTC) and drops the offset; the same happens
to the value in `WHERE next_due_at <= now`. Mixing those conversions across the
column DEFAULTs, the Python-side interval arithmetic, and the due-check made the
`next_due_at <= now` comparison inconsistent — so **no snapshot was ever "due"**
and auto-capture never fired for any interval (1 m / 15 m / 1 h / 12 h / 24 h).

This is why it appeared totally broken on the real PostgreSQL deployment but
"passed" earlier SQLite tests — SQLite stores datetimes as plain strings and does
no timezone conversion, so the IST values matched there.

**Fix:** `ist_now()` now returns a **naive** datetime holding IST wall-clock
time, and every `datetime.now(ZoneInfo("Asia/Kolkata"))` across `models.py`,
`scheduler.py`, `main.py` and `chatbot.py` routes through it. With naive IST
everywhere, comparisons are exact regardless of the database session timezone,
and the JSON serializers still tag these naive values as `+05:30` so the UI shows
correct Indian time. Verified end-to-end: all five intervals enable correctly,
the scheduler identifies due switches, runs, and advances `next_due_at`.

**After deploying:** open a switch → Auto-capture → enable config snapshots and
pick any interval. Watch `docker compose logs -f backend` for
`[auto-snapshot] <switch> -> saved`. (If you instead see a TCP/auth error in the
red banner, that's the switch credentials — log out and back in with the correct
SSH password.)
