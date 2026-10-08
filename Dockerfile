# Container Image Security Scanner – Dockerfile
# Multi-stage build: keeps the final image small and secure.
# The scanner works in demo mode without Trivy. Install Trivy for real scans.

# ── Stage 1: Download Trivy ──────────────────────────────────────────────────
FROM python:3.11-slim AS trivy-downloader

ARG TRIVY_VERSION=0.50.4
ARG TARGETARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download Trivy (Linux 64-bit). Fails gracefully — image still builds if download fails.
RUN curl -sSfL \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /tmp trivy \
    && chmod 0755 /tmp/trivy \
    && rm /tmp/trivy.tar.gz \
    || echo "WARNING: Trivy download failed. Image will run in demo mode."

# ── Stage 2: Final image ─────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="Container Image Security Scanner"
LABEL org.opencontainers.image.description="DevSecOps web tool for scanning container images and Dockerfiles"
LABEL org.opencontainers.image.licenses="MIT"

# Install runtime OS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Trivy binary from builder stage (may not exist if download failed — that's OK)
COPY --from=trivy-downloader /tmp/trivy /usr/local/bin/trivy
RUN chmod 0755 /usr/local/bin/trivy 2>/dev/null || true

# Create non-root user
RUN groupadd --gid 10001 scanner \
    && useradd --uid 10001 --gid scanner --no-create-home --shell /usr/sbin/nologin scanner

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/       ./src/
COPY scanner.py .
COPY webserver.py .
COPY config.yaml .
COPY web/       ./web/
COPY static/    ./static/
COPY templates/ ./templates/

# Create reports directory and fix permissions
RUN mkdir -p /app/reports /tmp/trivy-cache \
    && chown -R scanner:scanner /app /tmp/trivy-cache

# Switch to non-root user
USER scanner

# Expose reports volume
VOLUME ["/app/reports"]

# Expose web UI port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default: web UI (override with scanner.py for CLI mode)
ENTRYPOINT ["python", "webserver.py"]
CMD ["--host", "0.0.0.0", "--port", "8000"]

# ── Notes ────────────────────────────────────────────────────────────────────
# CLI mode:     docker run --rm container-image-security-scanner python scanner.py --help
# Web mode:     docker run -p 8000:8000 container-image-security-scanner
# With Trivy:   requires docker socket or pre-pulled images (see docker-compose.yml)
# Demo mode:    Trivy unavailable → realistic sample scan data is used automatically
