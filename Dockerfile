FROM python:3.12-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    procps \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY pyproject.toml README.md ./
COPY opsbot/ opsbot/
RUN pip install --no-cache-dir -e .

# Copy playbooks
COPY playbooks/ playbooks/

# Create log directory
RUN mkdir -p /var/log/opsbot

ENV OPSBOT_LOG_LEVEL=INFO
ENV OPSBOT_REMEDIATION_DRY_RUN=false

EXPOSE 8501

CMD ["python", "-m", "opsbot.app"]
