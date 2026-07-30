"""
rag/chain.py — The retrieval-augmented answer path.

Pipeline (LCEL):
    question
      -> Chroma similarity retriever (k chunks)
      -> format retrieved context (with source tags)
      -> ChatPromptTemplate (NOC analyst system prompt)
      -> ChatOpenAI  (pointed at Ollama /v1 by default)
      -> string answer  + the source docs used

Exposes answer_rag(question, switch) returning the same dict shape the existing
/api/chat/query endpoint already returns, so the frontend needs no changes.
"""
from __future__ import annotations

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnableParallel, RunnablePassthrough

import models
from . import config
from .vectorstore import get_store


SYSTEM_PROMPT = (
    "You are a network operations analyst embedded in a NOC portal. You answer "
    "questions about switch configurations, configuration drift, suspected IP "
    "conflicts, and port-traffic patterns, using ONLY the retrieved context "
    "below.\n\n"
    "FORMATTING RULES — follow exactly:\n"
    "- Plain, clear prose in short paragraphs.\n"
    "- No bold, italics, or nested bullets. At most one simple level of '- ' "
    "bullets, only for several parallel items.\n"
    "- Lead with the direct answer in one or two sentences, then supporting "
    "detail.\n\n"
    "CONTENT RULES:\n"
    "- Be concrete: name the switch and the affected interface or IP.\n"
    "- All timestamps are India Standard Time (IST, +05:30); they are current "
    "and correct — never call one a future date or an error.\n"
    "- If the retrieved context lacks the answer, say so in one sentence and "
    "state what the operator should capture next. Do not invent data."
)

_PROMPT = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    ("human", "Retrieved context:\n{context}\n\nQuestion: {question}"),
])


def _llm() -> ChatOpenAI:
    return ChatOpenAI(
        model=config.CHAT_MODEL,
        base_url=config.OPENAI_BASE_URL,
        api_key=config.OPENAI_API_KEY,
        temperature=config.CHAT_TEMP,
    )


def _format_docs(docs) -> str:
    blocks = []
    for d in docs:
        src = d.metadata.get("source", "?")
        sw = d.metadata.get("switch") or d.metadata.get("ip") or ""
        tag = f"[{src}{(' · ' + sw) if sw else ''}]"
        blocks.append(f"{tag}\n{d.page_content}")
    return "\n\n---\n\n".join(blocks) if blocks else "(no relevant context retrieved)"


def _retriever(switch: str | None):
    search_kwargs = {"k": config.RETRIEVE_K}
    # When the user is focused on a switch, bias retrieval to it (plus fleet-wide
    # conflict docs, which have no switch metadata, still surface via similarity).
    if switch:
        search_kwargs["filter"] = {"switch": switch}
    return get_store().as_retriever(search_kwargs=search_kwargs)


def answer_rag(question: str, switch: str | None = None) -> dict:
    retriever = _retriever(switch)

    chain = (
        RunnableParallel(
            context=retriever | _format_docs,
            question=RunnablePassthrough(),
        )
        | _PROMPT
        | _llm()
        | StrOutputParser()
    )

    # Grab the docs separately so we can report sources back to the UI.
    source_docs = retriever.invoke(question)
    msg = chain.invoke(question)

    return {
        "answer": msg.strip() or "(empty response from model)",
        "model": config.CHAT_MODEL,
        "warning": None,
        "context_sections": sorted({d.metadata.get("source") for d in source_docs}),
        "sources": [
            {
                "source": d.metadata.get("source"),
                "switch": d.metadata.get("switch"),
                "ip": d.metadata.get("ip"),
                "captured_at": d.metadata.get("captured_at"),
            }
            for d in source_docs
        ],
        "focus_switch": switch,
        "retrieved_chunks": len(source_docs),
        "asked_at": models.ist_now().isoformat() + "Z",
    }


def rag_health() -> dict:
    from .vectorstore import collection_count
    return {
        "ok": True,
        "mode": "openai-compatible",
        "base_url": config.OPENAI_BASE_URL,
        "embed_model": config.EMBED_MODEL,
        "chat_model": config.CHAT_MODEL,
        "chroma_dir": config.CHROMA_DIR,
        "collection": config.CHROMA_COLLECTION,
        "vector_count": collection_count(),
    }
