#!/bin/bash
set -euo pipefail

echo "[entrypoint] PWD=$(pwd)" >&2
echo "[entrypoint] Checking /agent..." >&2

if [ ! -f "/agent/agent.py" ]; then
  echo '{"status":"error","error":"agent.py not found in /agent"}'
  exit 1
fi

echo "[entrypoint] Launching runner..." >&2
exec python /app/runner.py