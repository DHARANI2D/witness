# WITNESS admission-gate service -- see service/app.py for the endpoints
# and README.md's "Deploying the HTTP service" for configuration.
#
# Build:  docker build -t witness-gate .
# Run:    docker run -p 8080:8080 -e WITNESS_SERVICE_API_KEY=<a-real-secret> witness-gate
#
# Multi-stage: the builder stage installs into a throwaway prefix so
# the final image ships only the installed packages and source, not
# pip's own build cache or metadata -- keeps the deployed image smaller.
# fastapi/uvicorn's dependencies all publish manylinux wheels for this
# base image's platform, so no C toolchain is needed to install them.

FROM python:3.11-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY witness_core/ witness_core/
COPY adapters/ adapters/
COPY scenarios/ scenarios/
COPY service/ service/
COPY demo.py ./

RUN pip install --no-cache-dir --prefix=/install ".[service]"

FROM python:3.11-slim

# Run as a non-root user -- a compromised process inside the container
# should not have root inside it either, standard defense-in-depth for
# anything that terminates untrusted-shaped HTTP input (even though
# this service's whole job is refusing to trust that input further).
RUN useradd --create-home --uid 10001 witness
WORKDIR /app

COPY --from=builder /install /usr/local
COPY --from=builder /build /app

USER witness

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)" || exit 1

# WITNESS_SERVICE_API_KEY and WITNESS_ATTESTATION_KEY are read from the
# environment at process startup (see service/app.py's module
# docstring) -- pass them with `docker run -e` or your orchestrator's
# secret injection, never bake them into the image.
CMD ["uvicorn", "service.app:app", "--host", "0.0.0.0", "--port", "8080"]
