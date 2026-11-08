# ============================================================================
# BaitBox — M5 Detonation Worker Dockerfile
# ============================================================================
# Based on the official Microsoft Playwright Python image.
# Hardened to run strictly as a non-root user (UID 10001) with zero secrets,
# read-only root filesystem compatibility, and tmpfs scratch directories.
# ============================================================================
FROM mcr.microsoft.com/playwright/python:v1.48.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp/pwuser

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY worker.py /app/worker.py

# Create dedicated unprivileged user (UID 10001)
RUN groupadd -g 10001 chamber && \
    useradd -u 10001 -g 10001 -d /tmp/pwuser -s /usr/sbin/nologin chamber && \
    chown -R 10001:10001 /app

USER 10001:10001

ENTRYPOINT ["python3", "/app/worker.py"]
