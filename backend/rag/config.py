"""
rag/config.py — One place for every RAG knob, all env-driven.

DEFAULT MODE = on-prem. The `openai` client and `langchain-openai` wrappers
are pointed at your Ollama server's OpenAI-compatible endpoint (/v1), so the
LangChain + Chroma + OpenAI + tiktoken pipeline runs without anything leaving
the network. To use real OpenAI cloud instead, set:

    RAG_OPENAI_BASE_URL=https://api.openai.com/v1
    RAG_OPENAI_API_KEY=sk-...                    # a real key
    RAG_EMBED_MODEL=text-embedding-3-small
    RAG_CHAT_MODEL=gpt-4o-mini

…and be aware that config/ARP/diff text then leaves your network.
"""
import os

# ── Where the OpenAI-compatible API lives ──────────────────────────────────
# Ollama exposes an OpenAI-compatible server at http://<host>:11434/v1
_OLLAMA_URL = os.getenv("OLLAMA_URL", "http://10.25.41.185:11434").rstrip("/")

OPENAI_BASE_URL = os.getenv("RAG_OPENAI_BASE_URL", _OLLAMA_URL + "/v1")
# Ollama ignores the key, but the openai client requires a non-empty string.
OPENAI_API_KEY  = os.getenv("RAG_OPENAI_API_KEY", "ollama")

# ── Models ─────────────────────────────────────────────────────────────────
# Embedding model must be pulled on the Ollama host:  ollama pull nomic-embed-text
EMBED_MODEL = os.getenv("RAG_EMBED_MODEL", "nomic-embed-text")
# Answering model — reuse what the rest of the portal already runs.
CHAT_MODEL  = os.getenv("RAG_CHAT_MODEL",  os.getenv("OLLAMA_MODEL", "qwen2.5:7b"))

# ── Chroma persistence ─────────────────────────────────────────────────────
CHROMA_DIR        = os.getenv("RAG_CHROMA_DIR", "/data/chroma")
CHROMA_COLLECTION = os.getenv("RAG_CHROMA_COLLECTION", "noc_portal")

# ── Chunking (token-aware, via tiktoken) ───────────────────────────────────
CHUNK_TOKENS   = int(os.getenv("RAG_CHUNK_TOKENS", "400"))
CHUNK_OVERLAP  = int(os.getenv("RAG_CHUNK_OVERLAP", "60"))
TIKTOKEN_ENC   = os.getenv("RAG_TIKTOKEN_ENCODING", "cl100k_base")

# ── Retrieval ──────────────────────────────────────────────────────────────
RETRIEVE_K     = int(os.getenv("RAG_RETRIEVE_K", "6"))
CHAT_TEMP      = float(os.getenv("RAG_TEMPERATURE", "0.2"))

# ── Ingestion limits (keep the index lean & fresh) ─────────────────────────
MAX_SNAPSHOTS  = int(os.getenv("RAG_MAX_SNAPSHOTS", "200"))   # most recent drifted snapshots
ARP_WINDOW_MIN = int(os.getenv("RAG_ARP_WINDOW_MIN", "120"))  # ARP recency window
