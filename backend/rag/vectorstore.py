"""
rag/vectorstore.py — ChromaDB persistence + embeddings + tiktoken chunking.

Uses the four requested libraries:
  - langchain / langchain-chroma  : Chroma vector store wrapper + Document model
  - langchain-openai              : OpenAIEmbeddings (pointed at Ollama /v1 by default)
  - chromadb                      : persistent on-disk store
  - tiktoken                      : token-aware chunk splitting (cl100k_base)

The collection is rebuilt incrementally: each Document has a deterministic id,
so we delete-then-add by id on every sync. That keeps the index a faithful
mirror of current DB state without unbounded growth.
"""
from __future__ import annotations

import threading
from typing import Optional

from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

from . import config
from . import ingestor

# Chroma + the embedding HTTP client aren't guaranteed thread-safe under the
# scheduler firing concurrently with a user query; serialise writes.
_LOCK = threading.Lock()
_STORE: Optional[Chroma] = None


def _embeddings() -> OpenAIEmbeddings:
    # base_url + api_key route this at Ollama's OpenAI-compatible endpoint by
    # default (see rag/config.py). Swap env vars to hit real OpenAI cloud.
    return OpenAIEmbeddings(
        model=config.EMBED_MODEL,
        base_url=config.OPENAI_BASE_URL,
        api_key=config.OPENAI_API_KEY,
        check_embedding_ctx_length=False,  # required for non-OpenAI servers
    )


def get_store() -> Chroma:
    """Singleton persistent Chroma collection."""
    global _STORE
    if _STORE is None:
        _STORE = Chroma(
            collection_name=config.CHROMA_COLLECTION,
            embedding_function=_embeddings(),
            persist_directory=config.CHROMA_DIR,
        )
    return _STORE


def _splitter() -> RecursiveCharacterTextSplitter:
    # tiktoken-backed: chunk sizes are measured in TOKENS, not characters,
    # so we never silently overflow the embedding model's context.
    return RecursiveCharacterTextSplitter.from_tiktoken_encoder(
        encoding_name=config.TIKTOKEN_ENC,
        chunk_size=config.CHUNK_TOKENS,
        chunk_overlap=config.CHUNK_OVERLAP,
    )


def _split(docs: list[Document]) -> tuple[list[str], list[Document]]:
    """Split docs into chunks, producing parallel id + Document lists.

    A parent doc with id 'snapshot:42' that splits into 3 chunks yields ids
    'snapshot:42#0', 'snapshot:42#1', 'snapshot:42#2'. On the next sync we
    delete every id beginning with the parent id before re-adding, so chunk
    counts can shrink without leaving orphans.
    """
    splitter = _splitter()
    ids, chunks = [], []
    for parent in docs:
        parent_id = parent.metadata["id"]
        pieces = splitter.split_documents([parent])
        for i, piece in enumerate(pieces):
            cid = f"{parent_id}#{i}"
            piece.metadata = {**parent.metadata, "id": cid, "parent_id": parent_id}
            ids.append(cid)
            chunks.append(piece)
    return ids, chunks


def upsert_documents(docs: list[Document]) -> dict:
    """Delete-by-parent then add — keeps the collection in sync with the DB."""
    store = get_store()
    ids, chunks = _split(docs)
    parent_ids = sorted({d.metadata["parent_id"] for d in chunks})

    with _LOCK:
        # remove any existing chunks for these parents (handles shrink/replace)
        if parent_ids:
            try:
                store.delete(where={"parent_id": {"$in": parent_ids}})
            except Exception:
                # first run / empty collection — nothing to delete
                pass
        if chunks:
            store.add_documents(documents=chunks, ids=ids)

    return {"parents": len(parent_ids), "chunks": len(chunks)}


def reindex_all(db) -> dict:
    """Full rebuild from current DB state. Safe to call anytime."""
    docs = ingestor.ingest_all(db)
    result = upsert_documents(docs)
    by_source: dict[str, int] = {}
    for d in docs:
        by_source[d.metadata["source"]] = by_source.get(d.metadata["source"], 0) + 1
    return {"indexed_parents": len(docs), "by_source": by_source, **result}


def collection_count() -> int:
    try:
        return get_store()._collection.count()
    except Exception:
        return -1
