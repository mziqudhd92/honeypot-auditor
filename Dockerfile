# Base image is digest-pinned (multi-arch index); bump deliberately and rebuild.
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

LABEL org.opencontainers.image.title="honeypot-auditor" \
      org.opencontainers.image.description="Multi-protocol CLI that fingerprints whether an authorized target behaves like a low-interaction honeypot" \
      org.opencontainers.image.source="https://github.com/mziqudhd92/honeypot-auditor" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[full]" \
    && useradd --create-home --shell /usr/sbin/nologin auditor \
    && chown -R auditor:auditor /app

# Reports default to the CWD; /app is writable by the runtime user.
USER auditor

ENTRYPOINT ["honeypot-auditor"]
CMD ["--help"]
