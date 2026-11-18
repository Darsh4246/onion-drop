# OnionDrop - Hardened, Minimal Dockerfile
# Python 3.12+ base
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install security updates and curl for container health check
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Create a dedicated non-root user and group
RUN groupadd -g 10001 oniondrop && \
    useradd -u 10001 -g oniondrop -m -s /bin/sh oniondrop

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and scripts
COPY app/ ./app/
COPY scripts/ ./scripts/

# Create persistent storage directories with non-root ownership
RUN mkdir -p /app/data/uploads /app/data/db && \
    chown -R oniondrop:oniondrop /app

# Switch to non-root user
USER oniondrop

# Expose internal port
EXPOSE 8000

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/health || exit 1

# Start Uvicorn ASGI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
