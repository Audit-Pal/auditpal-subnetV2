#!/bin/bash
set -e

if [ ! -f /agent/agent.py ]; then
    echo '{"challenge_id":"","project_id":"","findings":[]}' > /output/report.json
    echo "[entrypoint] ERROR: agent.py not found at /agent/agent.py"
    exit 1
fi

if [ -f /agent/requirements.txt ]; then
    pip install --no-cache-dir -q -r /agent/requirements.txt
fi

cd /agent
python agent.py