# syntax=docker/dockerfile:1
#
# Multi-stage build — keeps the final image small by discarding build tooling.
#
# Stage 1: build a virtualenv with only production dependencies
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build-time tools, then wipe them in the next stage
RUN pip install --no-cache-dir --upgrade pip

COPY pyproject.toml README.md ./
COPY depfence/ ./depfence/

# Install production deps only (no [dev] or [ml] extras) into /opt/venv
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir .

# Stage 2: lean runtime image
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="depfence" \
      org.opencontainers.image.description="AI-aware dependency security scanner — CVE, behavioral, supply chain, EPSS, CISA KEV, and MCP scanning" \
      org.opencontainers.image.source="https://github.com/ericrihm/depfence" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="depfence contributors"

# Don't run as root inside the container
RUN useradd --create-home --shell /bin/sh depfence
USER depfence
WORKDIR /scan

# Copy the pre-built venv from the builder stage
COPY --from=builder /opt/venv /opt/venv

# Make the venv binaries available on PATH
ENV PATH="/opt/venv/bin:$PATH"

ENTRYPOINT ["depfence"]
CMD ["--help"]
