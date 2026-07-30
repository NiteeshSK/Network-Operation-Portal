"""
rag/ — LangChain + ChromaDB retrieval-augmented layer for the NOC portal.

Public surface:
    from rag.chain import answer_rag          # main entry used by /api/chat
    from rag.sync  import sync_vectorstore     # called by the scheduler
    from rag.vectorstore import reindex_all    # full rebuild (manual endpoint)
"""
from .chain import answer_rag, rag_health
from .sync import sync_vectorstore
from .vectorstore import reindex_all

__all__ = ["answer_rag", "rag_health", "sync_vectorstore", "reindex_all"]
