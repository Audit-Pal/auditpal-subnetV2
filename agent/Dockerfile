FROM python:3.11-slim

# System deps: git for cloning, build tools for slither's native deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry inside the image (no venv — we're in Docker already)
ENV POETRY_VERSION=2.1.1
ENV POETRY_HOME=/opt/poetry
ENV PATH="$POETRY_HOME/bin:$PATH"
ENV POETRY_VIRTUALENVS_CREATE=false  

RUN curl -sSL https://install.python-poetry.org | python3 -

# Pre-install the agent's dependencies from the lockfile
# (this layer is cached — only rebuilds when pyproject.toml changes)
WORKDIR /deps
COPY agent/pyproject.toml agent/poetry.lock* ./
RUN poetry install --only main --no-root

# Create required dirs
RUN mkdir -p /challenge /output /agent

COPY agent/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]