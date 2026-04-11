#!/bin/bash
set -euo pipefail

echo "[entrypoint] PWD=$(pwd)" >&2
echo "[entrypoint] Checking /agent..." >&2

# List files in /agent and /miner_agent for debugging
echo "[entrypoint] Files in /agent:" >&2
ls -la /agent/ >&2
echo "[entrypoint] Files in /miner_agent:" >&2
ls -la /miner_agent/ 2>/dev/null || echo "[entrypoint] /miner_agent not found" >&2

# Check for agent.py in both locations
if [ -f "/agent/agent.py" ]; then
  AGENT_PATH="/agent"
elif [ -f "/miner_agent/agent.py" ]; then
  AGENT_PATH="/miner_agent"
else
  echo '{"status":"error","error":"agent.py not found in /agent or /miner_agent"}'
  exit 1
fi

echo "[entrypoint] Using agent from: $AGENT_PATH" >&2

# Check if miner has their own runner script
if [ -f "$AGENT_PATH/agent_runner.py" ]; then
  echo "[entrypoint] Using miner's agent_runner.py" >&2
  exec python "$AGENT_PATH/agent_runner.py"
elif [ -f "/agent/runner.py" ]; then
  echo "[entrypoint] Using default runner.py" >&2
  exec python /agent/runner.py
else
  echo "[entrypoint] No runner found, trying to run agent.py directly" >&2
  exec python "$AGENT_PATH/agent.py"
fi