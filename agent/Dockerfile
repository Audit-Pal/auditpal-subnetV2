FROM python:3.12-slim

WORKDIR /agent

# Install system dependencies (git is critical for cloning repos)
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy agent files
COPY . .

# Make scripts executable
RUN chmod +x entrypoint.sh

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt



# Set entrypoint
ENTRYPOINT ["/agent/entrypoint.sh"]