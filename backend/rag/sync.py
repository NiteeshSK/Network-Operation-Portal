"""
rag/sync.py — Keep the vector index in step with PostgreSQL.

Called by APScheduler (see scheduler.py). Opens its own DB session exactly
like the other background jobs do, re-ingests current state, and upserts into
Chroma. Because ids are deterministic, this is idempotent: running it every
few minutes simply refreshes vectors for rows that changed.
"""
from __future__ import annotations

import traceback

from database import SessionLocal
from . import vectorstore


def sync_vectorstore() -> dict:
    db = SessionLocal()
    try:
        result = vectorstore.reindex_all(db)
        print(f"[rag-sync] indexed parents={result['indexed_parents']} "
              f"chunks={result.get('chunks')} by_source={result['by_source']}",
              flush=True)
        return result
    except Exception as e:
        print(f"[rag-sync] FAILED: {e}\n{traceback.format_exc()}", flush=True)
        return {"error": str(e)}
    finally:
        db.close()
