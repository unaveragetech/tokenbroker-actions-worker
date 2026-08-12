#!/bin/bash
set -e

write_cfg() {
  local name="$1" token="$2" file="$3"
  cat > "$file" <<EOF
{
  "name": "${name}",
  "gateway": "${TB_GATEWAY}",
  "token": "${token}",
  "private_jobs": false,
  "cloud_enabled": false,
  "storage_gb": 8,
  "evict_after_job": false,
  "max_pool_idle_hours": 2
}
EOF
}

write_cfg "actions-worker-1" "${TB_NODE_TOKEN}" worker-config.json
write_cfg "actions-worker-2" "${TB_NODE_TOKEN_2}" worker-config-2.json
write_cfg "actions-worker-3" "${TB_NODE_TOKEN_3}" worker-config-3.json

# One Ollama server shared by all three workers on this runner.
ollama serve > /tmp/ollama.log 2>&1 &
sleep 3

# Multi-instance mode (-multi) skips the single-instance pid check; each
# worker is a separate node token but they all hit the same local Ollama.
python worker.py --config worker-config.json  --headless --multi > /tmp/worker1.log 2>&1 &
python worker.py --config worker-config-2.json --headless --multi > /tmp/worker2.log 2>&1 &
python worker.py --config worker-config-3.json --headless --multi > /tmp/worker3.log 2>&1 &

# Run until the job window (timeout-minutes) ends; the schedule starts the
# next window. evict_after_job is off so models stay cached across runs.
wait
