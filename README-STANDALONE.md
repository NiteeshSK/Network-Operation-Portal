# NOC Portal — standalone

No dependency on MSS AD Studio. No SSO, no shared session, no validator call.

## Log in

    username: admin
    password: MindSparks!008

Set from the environment, not baked into the image:

```bash
NOC_ADMIN_PASSWORD='something-else' docker compose up -d
```

`NOC_ADMIN_USERNAME` / `NOC_ADMIN_PASSWORD`, defaults `admin` /
`MindSparks!008`. The backend prints a warning on every start while the
default password is still in use.

The comparison uses `secrets.compare_digest`, so it takes the same time
whether the first character is wrong or the last — the password cannot be
recovered a character at a time by timing responses. A wrong username and a
wrong password return the identical message, so the response does not reveal
which was wrong. The password is never logged.

**Portal login is not SSH.** It gates the UI and API. Switch operations use
each switch's own stored credentials, exactly as the unattended capture loops
do. `POST /api/admin/login` still exists for proving real SSH credentials and
pushing them onto the fleet — useful after a password rotation.

## A hole that was open in the build you sent

`require_admin` had been stubbed out:

```python
# Authentication disabled for testing
return {"username": "test", "password": "", "scope": ["*"],
        "is_superadmin": True}
```

with the real implementation commented out beneath it. All 43 endpoints
declaring `Depends(require_admin)` — `POST /api/servers`, bulk import, config
apply, every SSH command endpoint — accepted any caller with no credential.
Anyone who could reach port 18000 had full control of the fleet.

Restored. Verified: `POST /api/servers` with no credential now returns **401**.

## Features carried over from the Studio build

| feature | endpoint |
|---|---|
| Bulk iLO server import from spreadsheet | `POST /api/servers/bulk-upload` |
| Fleet export to Excel | `GET /api/servers/export.xlsx?days=7` |

Both verified registered and responding (`export.xlsx` returned a 7,277-byte
workbook in test).

Also carried over: 7-day retention across all 11 history tables with hourly
sweep and VACUUM, the streaming-worker ceiling, `MALLOC_ARENA_MAX` plus the
memory watchdog, non-blocking startup, single-pass pip build, log rotation,
and `mem_limit`/`pids_limit` containment.

## Verified

| check | result |
|---|---|
| `POST /api/servers` no credential | **401** |
| `admin` / wrong password | **401** |
| wrong username / correct password | **401** |
| `admin` / `MindSparks!008` | **200** |
| add a server once signed in | **201** |
| `/api/servers/bulk-upload` | registered |
| `/api/servers/export.xlsx` | 200, 7,277 bytes |
| Studio references in backend | none |

## Run

```bash
export DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1
docker compose up -d --build
```

Portal on `http://<host>:5173`, API on `:18000`.
