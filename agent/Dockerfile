FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer cache friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Only bake in validator-controlled infrastructure files
# agent.py is intentionally NOT copied — it comes from /miner_agent at runtime
COPY runner.py     /app/runner.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# /miner_agent  → miner's cloned repo (mounted read-only at runtime)
# /challenge    → challenge .sol files (mounted read-only at runtime)

ENTRYPOINT ["/app/entrypoint.sh"]