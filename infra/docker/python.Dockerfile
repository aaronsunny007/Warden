# Warden Python services: the detection cascade service, the control plane, the Kafka audit
# consumer and the learning loop. One image, service chosen with `command:` (`warden detector
# serve`, `warden control serve`, `warden audit consume`, `warden loop run`, ...).
#
# Kept lean: the heavy optional extras (sentence-transformers/torch for a neural embedder,
# agentdojo for the benchmark, torch again for L2 training) are NOT installed here — the
# default embedder is the offline hashing one and the default victim is the simulated agent.
# The ONNX serving path (onnxruntime + tokenizers) and the Kafka consumer ARE included.
#
#   docker build -f infra/docker/python.Dockerfile -t warden/python:dev .

# Base image is overridable (private mirror, or a base with a corporate proxy CA baked in).
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE} AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PIP_DISABLE_PIP_VERSION_CHECK=1
# uv comes from PyPI (pinned) rather than a second registry, so the build needs only Docker Hub + PyPI.
RUN pip install --no-cache-dir 'uv==0.9.9'
WORKDIR /app

# Resolve dependencies first (cached unless the manifest changes).
COPY python/pyproject.toml python/README.md ./
# Base + Kafka consumer + the ONNX serving path + the MCP client (drives the compose demo).
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --system --no-cache '.[kafka]' onnxruntime tokenizers 'mcp>=2.0'

COPY python/src ./src
COPY python/alembic.ini ./alembic.ini
COPY python/migrations ./migrations
RUN --mount=type=cache,target=/root/.cache/uv uv pip install --system --no-cache --no-deps -e .

FROM ${PYTHON_IMAGE} AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin warden
WORKDIR /app
# System site-packages and the installed console script come from the build stage.
COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin/warden /usr/local/bin/warden
COPY --from=build --chown=warden:warden /app /app
# Repo data (corpora, scenarios, lab world) and policies are read at runtime.
COPY --chown=warden:warden data /app/data
COPY --chown=warden:warden policies /app/policies
ENV WARDEN_REPO_ROOT=/app
USER warden
EXPOSE 8000 8008
ENTRYPOINT ["warden"]
CMD ["detector", "serve", "--host", "0.0.0.0", "--port", "8000"]
