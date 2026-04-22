#!/bin/bash
set -euo pipefail

echo "[entrypoint] PWD=$(pwd)" >&2
echo "[entrypoint] Checking /agent..." >&2


echo "[entrypoint] Files in /agent:" >&2
ls -la /agent/ >&2
echo "[entrypoint] Files in /miner_agent:" >&2
ls -la /miner_agent/ >&2 2>/dev/null || echo "[entrypoint] /miner_agent not found" >&2

# Always use the validator's agent
AGENT_PATH="/agent"

echo "[entrypoint] Using agent from: $AGENT_PATH" >&2
export AGENT_PATH

echo "[entrypoint] Using validator's runner.py" >&2
exec python /agent/runner.py