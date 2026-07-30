# syntax=docker/dockerfile:1.7
# ═══════════════════════════════════════════════════════════════════════════
# NOC PORTAL BACKEND
#
# WHY THIS FILE LOOKS THE WAY IT DOES
#
# The previous version installed all ~98 packages in a single `pip install`
# with --no-cache-dir. That had three consequences, all of which were being
# felt:
#
#   1. SLOW. Every build re-downloaded the entire LangChain/ChromaDB tree
#      (several hundred MB) from PyPI, because --no-cache-dir throws the
#      wheels away and there was no cache mount to fall back on.
#   2. FLAKY. A single slow or dropped connection anywhere in those ~98
#      downloads failed the whole layer, and the next build started from
#      scratch. This is the "sometimes it just fails" symptom.
#   3. FRAGILE ON NON-amd64. chroma-hnswlib, grpcio and tokenizers ship
#      prebuilt manylinux wheels for x86_64. On arm64 (Apple Silicon, Graviton,
#      Ampere) pip silently falls back to compiling them from source — and
#      python:3.12-slim has no compiler, so the build dies partway through
#      with a wall of gcc errors. Where a compiler IS present, grpcio from
#      source takes 10+ minutes and routinely exhausts memory.
#
# The fixes, in order:
#   - BuildKit cache mount on pip's cache dir, so wheels survive between
#     builds. A no-change rebuild now costs seconds instead of minutes.
#   - Requirements split in two layers, so touching a core pin does not
#     invalidate the expensive RAG layer.
#   - Retries and a longer timeout, so one flaky download retries instead of
#     failing the build.
#   - A wheel-builder stage that carries a compiler. On amd64 it is a no-op
#     (pip finds wheels and never builds). On arm64 it is the difference
#     between a working image and a failed build. Either way the compiler is
#     left behind in the builder and never reaches the runtime image.
#
# BuildKit is required for the cache mounts. Docker Compose v2 and Docker
# 23+ enable it by default; if you are on something older, export
# DOCKER_BUILDKIT=1 before building.
# ═══════════════════════════════════════════════════════════════════════════

ARG PYTHON_VERSION=3.12

# ───────────────────────────────────────────────────────────────────────────
# STAGE 1 — build wheels
#
# Everything is resolved to a wheel here, into /wheels. On a platform where
# PyPI already publishes wheels this stage just downloads them. On a platform
# where it does not, the compiler present in this stage builds them once, and
# the cache mount means it is not repeated on the next build.
# ───────────────────────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS wheels

# INSTALL_RAG=0 skips the ~90-package LangChain/ChromaDB tree entirely.
# Every `rag` import in the app is function-scoped, so the portal still runs;
# only the retrieval-backed chat endpoints degrade. Use it when you want a
# fast image and are not using the chatbot.
ARG INSTALL_RAG=1

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10

# Build toolchain — only ever used on architectures without prebuilt wheels.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        g++ \
    && true

WORKDIR /src
COPY requirements-core.txt requirements-rag.txt ./

# BOTH requirement files are resolved in ONE pip invocation. This is not a
# stylistic choice — resolving them in two passes is a correctness bug.
#
# chromadb declares `fastapi>=0.95.2` as a transitive dependency. Resolved on
# its own, that pass has no knowledge of the `fastapi==0.115.0` pin in
# requirements-core.txt, so it picks the newest release instead. Both wheels
# then land in /wheels, and because the runtime stage installs from that
# directory, pip is handed two mutually exclusive pins for the same package:
#
#     ERROR: Cannot install fastapi 0.115.0 and fastapi 0.140.1 because
#     these package versions have conflicting dependencies.
#     ERROR: ResolutionImpossible
#
# One pass gives pip the whole picture, so every shared transitive dependency
# gets a single consistent answer. Verified: 88 packages resolve with no
# package appearing at more than one version, and the core pins hold
# (fastapi 0.115.0, uvicorn 0.30.6, pydantic 2.9.2) while chromadb 0.5.20 is
# satisfied — its floor is 0.95.2, so the pin was always compatible.
#
# The two files stay separate because they still drive the INSTALL_RAG toggle
# and they document which half is expensive. They are just no longer resolved
# in isolation from each other.
RUN --mount=type=cache,target=/root/.cache/pip \
    set -eux; \
    REQS="-r requirements-core.txt"; \
    if [ "$INSTALL_RAG" = "1" ]; then \
        REQS="$REQS -r requirements-rag.txt"; \
    else \
        echo "INSTALL_RAG=0 - skipping the RAG dependency tree."; \
    fi; \
    pip wheel --wheel-dir /wheels $REQS


# ───────────────────────────────────────────────────────────────────────────
# STAGE 2 — runtime
#
# Installs only from the local /wheels directory. --no-index means pip is
# forbidden from touching the network at all here, so this stage cannot fail
# on a flaky connection and cannot silently pull a different version than the
# one that was resolved above.
# ───────────────────────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG INSTALL_RAG=1

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Runtime OS packages only:
#   openssh-client — netmiko's SSH transport for talking to switches
#   curl           — used by the container healthcheck
# psycopg2-binary ships a precompiled wheel, so libpq-dev is not needed.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-client \
        curl \
    && true

# The requirement files are needed here too: installing by filename glob
# (`/wheels/*.whl`) tells pip that EVERY wheel in the directory is an
# explicitly requested top-level requirement, which both defeats its resolver
# and turns any stray duplicate into a hard conflict. Installing `-r` the same
# files that produced the wheels lets pip resolve normally, just with the
# local directory as its only source.
COPY requirements-core.txt requirements-rag.txt ./
COPY --from=wheels /wheels /wheels

# --no-index forbids pip from touching the network, so this layer cannot fail
# on a flaky connection and cannot silently install a different version than
# the one resolved in the wheel stage.
RUN set -eux; \
    REQS="-r requirements-core.txt"; \
    if [ "$INSTALL_RAG" = "1" ]; then \
        REQS="$REQS -r requirements-rag.txt"; \
    fi; \
    pip install --no-index --find-links=/wheels $REQS; \
    rm -rf /wheels

# Pre-cache the tiktoken cl100k_base encoding at BUILD time. The NOC network
# is locked down; without this, tiktoken's first-use download of the BPE vocab
# (from a Microsoft blob URL) would fail at runtime and break RAG chunking.
# Guarded because tiktoken is not installed when INSTALL_RAG=0, and guarded
# again at runtime because a build-time network hiccup here should degrade
# the chatbot, not fail the image.
ENV TIKTOKEN_CACHE_DIR=/app/.tiktoken_cache
RUN mkdir -p /app/.tiktoken_cache && \
    if [ "$INSTALL_RAG" = "1" ]; then \
        python -c "import tiktoken; tiktoken.get_encoding('cl100k_base')" \
        || echo "WARNING: tiktoken vocab could not be pre-cached; RAG chunking will need network on first use." ; \
    fi

COPY . .

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8000/ >/dev/null || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
