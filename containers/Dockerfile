# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# This digest is the immutable multi-platform index for
# python:3.12.11-slim-bookworm. Renovation must update the digest and run the
# container contract workflow before merging.
ARG PYTHON_BASE=python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

FROM ${PYTHON_BASE} AS wheel
WORKDIR /src
COPY pyproject.toml README.md ./
COPY depfence/ ./depfence/
# The [evilfont] extra (fontTools/pypdf/jsonschema) is required: the static
# worker runs depfence-sealed-git-analyze -> scan_artifact_bytes, which cannot
# do semantic font or PDF inspection without it.
RUN python -m pip wheel --disable-pip-version-check --no-cache-dir \
      --wheel-dir /wheelhouse ".[evilfont]"

FROM ${PYTHON_BASE} AS runtime
ARG DEPFENCE_VERSION=dev
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="DepFence isolated analysis worker" \
      org.opencontainers.image.description="Purpose-scoped workers for sealed intake and visual-text analysis" \
      org.opencontainers.image.source="https://github.com/ericrihm/depfence" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${DEPFENCE_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      dev.depfence.worker.uid="65532" \
      dev.depfence.worker.protocol="1"
ENV PATH="/opt/depfence/bin:/usr/local/bin:/usr/bin:/bin" \
    HOME="/tmp/depfence-home" \
    LANG="C.UTF-8" \
    LC_ALL="C.UTF-8" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONHASHSEED="0" \
    PYTHONUNBUFFERED="1"
COPY --from=wheel /wheelhouse /wheelhouse
RUN python -m venv /opt/depfence \
    && /opt/depfence/bin/pip install --disable-pip-version-check --no-cache-dir \
       --no-index --find-links /wheelhouse "depfence[evilfont]" \
    && rm -rf /wheelhouse /root/.cache
COPY --chmod=0555 containers/bin/depfence-worker-entrypoint /usr/local/bin/depfence-worker-entrypoint
WORKDIR /work
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/depfence-worker-entrypoint"]
CMD ["--self-test"]

FROM runtime AS intake
USER 0:0
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
       ca-certificates=20250419~deb12u1 \
       git=1:2.39.5-0+deb12u3 \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
ENV DEPFENCE_WORKER_ROLE="intake"
LABEL dev.depfence.worker.role="intake" \
      dev.depfence.worker.commands="depfence-sealed-git-resolve,depfence-sealed-git-acquire,depfence-sealed-git-inventory"
USER 65532:65532

FROM runtime AS static
USER 0:0
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
       ca-certificates=20250419~deb12u1 \
       git=1:2.39.5-0+deb12u3 \
       opentype-sanitizer=8.2.1+dfsg-2 \
       woff2=1.0.2-2 \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
ENV DEPFENCE_WORKER_ROLE="static"
LABEL dev.depfence.worker.role="static" \
      dev.depfence.worker.commands="depfence-sealed-git-inventory,depfence-sealed-git-analyze"
USER 65532:65532

FROM runtime AS render
USER 0:0
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
       ca-certificates=20250419~deb12u1 \
       chromium=151.0.7922.137-1~deb12u1 \
       fonts-dejavu-core=2.37-6 \
       libreoffice-writer=4:7.4.7-1+deb12u14 \
       poppler-utils=22.12.0-2+deb12u3 \
       tesseract-ocr=5.3.0-2 \
       tesseract-ocr-eng=1:4.1.0-2 \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
    && find /usr/share/fonts -type f -exec chmod a-w {} +
ENV DEPFENCE_WORKER_ROLE="render"
LABEL dev.depfence.worker.role="render" \
      dev.depfence.worker.commands="depfence-artifact-analyzer"
USER 65532:65532
