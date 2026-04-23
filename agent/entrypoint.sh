#!/bin/bash
set -euo pipefail

echo "[entrypoint] ══════════════════════════════════════════" >&2
echo "[entrypoint] AuditPal sandbox starting" >&2
echo "[entrypoint] PWD=$(pwd)" >&2
echo "[entrypoint] ══════════════════════════════════════════" >&2

echo "[entrypoint] /app contents (validator infrastructure):" >&2
ls -la /app/ >&2

echo "[entrypoint] /miner_agent contents (miner code):" >&2
ls -la /miner_agent/ 2>&1 >&2 || echo "[entrypoint] ✗ /miner_agent not mounted or empty" >&2

echo "[entrypoint] /challenge contents (codebase):" >&2
ls -la /challenge/ 2>&1 >&2 || echo "[entrypoint] ✗ /challenge not mounted or empty" >&2

# Sanity check — miner must have supplied agent.py
if [ ! -f "/miner_agent/agent.py" ]; then
    echo "[entrypoint] ✗ FATAL: /miner_agent/agent.py not found" >&2
    echo "[entrypoint]   Miner repo must contain agent.py at its root" >&2
    # Emit a valid empty report so the validator doesn't hang on no stdout
    echo '{"challenge_id":"'"${CHALLENGE_ID:-unknown}"'","project_id":"'"${PROJECT_ID:-unknown}"'","findings":[],"_runner_error":"agent.py not found in miner repo"}'
    exit 1
fi

echo "[entrypoint] ✓ /miner_agent/agent.py found" >&2

# AGENT_PATH tells runner.py where to find the miner's agent directory
export AGENT_PATH="/miner_agent"

echo "[entrypoint] Launching runner.py..." >&2
exec python /app/runner.py