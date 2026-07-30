# RAG Layer — LangChain + ChromaDB + tiktoken + OpenAI client

This adds a retrieval-augmented chat path on top of the existing SQL-summary
chatbot. It uses LangChain, ChromaDB, the OpenAI client, and tiktoken — but by
default the OpenAI client is pointed at your **Ollama** server's
OpenAI-compatible `/v1` endpoint, so **no data leaves the network**.

## What was added

```
backend/rag/
  config.py        every knob, env-driven
  ingestor.py      PostgreSQL rows -> LangChain Documents (deterministic IDs)
  vectorstore.py   ChromaDB + OpenAIEmbeddings + tiktoken-based chunking
  sync.py          scheduler job: re-index from the DB (idempotent upsert)
  chain.py         LCEL retriever -> prompt -> ChatOpenAI -> sourced answer
```

Wiring:
- `scheduler.py` registers `rag_sync_loop` (default every 5 min) + an initial
  index at boot. Guarded so a RAG failure never stops the capture loops.
- `main.py` adds three endpoints (existing `/api/chat/query` is untouched):
  - `POST /api/chat/rag-query`  — same shape as `/api/chat/query`, RAG-backed
  - `GET  /api/chat/rag-status` — mode, models, vector count
  - `POST /api/chat/reindex`    — force a full rebuild
- `docker-compose.yml` adds a `chroma_data` volume so the index persists.
- `Dockerfile` pre-caches the tiktoken vocab at build time (locked-down network).

## One-time setup on the Ollama host

```bash
ollama pull nomic-embed-text     # embedding model used by OpenAIEmbeddings
ollama pull qwen2.5:7b           # answering model (or keep your existing tag)
```

## How it stays on-prem

`rag/config.py` defaults the OpenAI client to `OLLAMA_URL/v1`. The `openai`
package and `langchain-openai` wrappers speak the OpenAI protocol, but every
request goes to Ollama. The `RAG_OPENAI_API_KEY=ollama` value is a placeholder
the client requires; Ollama ignores it.

## To use real OpenAI cloud instead (data WILL leave the network)

Set in `.env` / compose:
```
RAG_OPENAI_BASE_URL=https://api.openai.com/v1
RAG_OPENAI_API_KEY=sk-...
RAG_EMBED_MODEL=text-embedding-3-small
RAG_CHAT_MODEL=gpt-4o-mini
```

## Frontend switch

The RAG endpoint returns the same JSON shape as the current one, plus a
`sources` array. To try it, point the chat call at `/api/chat/rag-query`
instead of `/api/chat/query` — no other frontend change needed.

## Why RAG here instead of stuffing the whole DB summary

The original `chatbot.py` packs a fixed DB summary into the prompt every time.
That works but doesn't scale as snapshots/ARP grow, and it can't rank what's
relevant to the question. The vector path retrieves only the most relevant
chunks (drift diffs, conflicts, port anomalies) for each question, leaving more
of the context window for reasoning. Both paths remain available.
