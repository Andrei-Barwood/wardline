FROM python:3.12-slim

# No new privileges for security
# But wait, cap_drop and security_opt are usually set in docker-compose.yml or docker run.
# We do the basics in Dockerfile.

# Create non-root user
RUN groupadd -g 10001 wardline && \
    useradd -u 10001 -g 10001 -m -s /bin/bash wardline

WORKDIR /app

# Install dependencies (only required for runtime, no build tools unless necessary)
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# Change ownership
RUN chown -R wardline:wardline /app

USER 10001:10001

# No debug shell, explicit entrypoint
ENTRYPOINT ["python", "-m", "wardline"]

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health').getcode() == 200 else 1)"
