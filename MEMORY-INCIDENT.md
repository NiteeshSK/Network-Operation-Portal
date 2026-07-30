# Memory incident — what is contained here, and what is not

## What the screenshots show

`mss-noc-backend` climbing 4.63 → 6.86 → 9.66 → 9.76 → 10.57 GiB on a
15.62 GiB host, holding **347–358 threads**, at 113–175% CPU. Everything else
on the box is flat: `mss-user-app` 273 MiB, `mss-noc-postgres` 191 MiB. This is
unbounded growth in one process, not general pressure.

## What is fixed in this build

**The container can no longer take the VM down.** `docker-compose.yml` now sets
`mem_limit: 3g`, `memswap_limit: 3g` and `pids_limit: 256` on the backend.

This matters more than it looks. With no limit, Docker lets a container consume
the whole host, so when memory runs out the kernel OOM killer fires against the
**host** — which is why the VM became unreachable instead of just the portal
failing. With a cgroup limit, the kernel kills only this container and
`restart: unless-stopped` brings it straight back. The portal blips; your SSH
session, Studio and the VM survive.

`pids_limit: 256` is a second tripwire. A healthy backend sits well under 50
threads, so hitting 256 means something is leaking threads and the container
should die rather than climb to 350.

**Contributing factors also addressed:**

- Scheduler pool set to 20 threads with `coalesce=True` and
  `misfire_grace_time=120`. Without coalescing, a slow patch causes every
  missed interval to fire once threads free up — a thundering herd of catch-up
  SSH sessions, each holding buffers. That amplifies any leak badly.
  (An earlier revision of mine raised this to 40, which would have made the
  pile-up worse, not better. 20 is deliberate.)
- Boot-time ARP sweep and RAG index moved off the ASGI startup path.
- Retention now sweeps all 11 history tables at 7 days instead of 4.

## What is NOT fixed — read this

**The leak has not been root-caused.** Containment stops the crash; it does not
stop the growth. Expect the container to still climb and now get OOM-killed
every few hours until the cause is found.

I could not diagnose it properly because `mss-ad-studio-final.zip` arrived
**empty** — 178 bytes, a single directory entry, no files. I could not see the
code that was actually running.

What I ruled out by reading this codebase:

- SSH sessions in `switch_manager.run_command` — closed in a `finally` block.
- Metric ring buffers in `metrics_stream.py` — bounded by `RING_SIZE`.
- Subscriber queues — bounded at `maxsize=200` with `put_nowait`.
- Worker lifecycle — `ensure()` checks `is_alive()`, `reconcile()` drops
  removed servers.

What I did **not** rule out, in rough order of suspicion:

1. **`_subs` list growth.** `subscribe()` appends a queue; if a client
   disconnects without the matching unsubscribe running (dropped SSE stream, an
   exception inside the generator), the queue stays in the list forever holding
   up to 200 payloads. Many reconnects would accumulate.
2. **SQLAlchemy sessions not closed** in a capture path. A session holds every
   ORM object it loaded. `GCC-CORE-01` returns ~1786 ARP rows and is captured
   every 60s — one leaked session per cycle is GB-scale within hours.
3. **ChromaDB / ONNX runtime.** Large resident footprint and its own thread
   pools; a plausible source of both the memory and the thread count.
4. **Paramiko transport threads** left behind by connections that error in a
   way that skips `disconnect()`.

## To find it — three commands

```bash
# 1. Where are the threads?
docker exec mss-noc-backend python -c "
import threading,collections
c=collections.Counter(t.name.split('-')[0] for t in threading.enumerate())
print('total',threading.active_count()); print(c.most_common(15))"

# 2. What is holding the memory?
docker exec mss-noc-backend pip install pympler -q 2>/dev/null
docker exec mss-noc-backend python -c "
import gc,collections
c=collections.Counter(type(o).__name__ for o in gc.get_objects())
print(c.most_common(20))"

# 3. Does it still climb with RAG off?
NOC_INSTALL_RAG=0 docker compose build backend && docker compose up -d
```

Command 1 is the highest value: a thread-name histogram at 350 threads will
name the leak almost immediately. Send me that output and the real zip and I
can go after the cause rather than the symptom.
