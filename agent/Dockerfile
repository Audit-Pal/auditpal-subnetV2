FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install all pipeline dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN solc-select install 0.8.20 && solc-select use 0.8.20

# Bake in validator-controlled pipeline — miner never sees or modifies these
COPY runner.py          /app/runner.py
COPY stage1.py   /app/stage1.py
COPY stage2.py /app/stage2.py
COPY stage3.py      /app/stage3.py
COPY stage4.py    /app/stage4.py
COPY entrypoint.sh      /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# /miner_agent  → miner's cloned repo (mounted read-only at runtime)
# /challenge    → challenge .sol files (mounted read-only at runtime)

ENTRYPOINT ["/app/entrypoint.sh"]