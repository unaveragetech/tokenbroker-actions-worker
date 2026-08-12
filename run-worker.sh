#!/bin/bash
set -e

cat > worker-config.json <<EOF
{
  "name": "${TB_NAME:-actions-worker}",
  "gateway": "${TB_GATEWAY}",
  "token": "${TB_NODE_TOKEN}",
  "private_jobs": false,
  "cloud_enabled": false,
  "storage_gb": 8,
  "evict_after_job": true,
  "max_pool_idle_hours": 2
}
EOF

ollama serve > /tmp/ollama.log 2>&1 &
sleep 3

# Run until the runner's job window ends (timeout-minutes) - the schedule
# starts the next window. Models are pulled on demand and evicted after each
# job, so the ephemeral runner disk stays clean.
python worker.py --config worker-config.json --headless
