# syntax=docker/dockerfile:1

# --- Builder stage ---------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# System dependencies needed to build wheels (kept minimal; grows only if a
# future dependency genuinely needs a compiler).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip \
    && pip wheel --no-cache-dir --wheel-dir /wheels .

# --- Runtime stage -----------------------------------------------------------
FROM python:3.12-slim AS runtime

# Run as a non-root user (defense in depth — this process handles peer
# network traffic and local filesystem access).
RUN useradd --create-home --shell /usr/sbin/nologin securesync
WORKDIR /home/securesync

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

USER securesync

# Sync data directory and SQLite metadata store live under this volume.
VOLUME ["/home/securesync/data"]

# Peer discovery (UDP) + transfer engine (TCP/TLS) — see docs/networking.md
# and docs/configuration.md for how these are made configurable.
EXPOSE 21027/udp 22000/tcp

ENTRYPOINT ["securesync"]
CMD ["--help"]
