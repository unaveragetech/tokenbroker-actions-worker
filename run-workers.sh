#!/bin/bash
# Runs three TokenBroker worker nodes on this Actions runner, sharing one
# Ollama server. Everything the workers print goes to the step log (prefixed
# [w1]/[w2]/[w3]) so a failed run is diagnosable from the Actions UI.
set -u

: "${TB_GATEWAY:?TB_GATEWAY secret is not set}"
MODELS_DIR="${OLLAMA_MODELS:-$HOME/.ollama/models}"
RUN_FOR="${WORKER_RUN_MINUTES:-350}"   # stop cleanly before the job timeout so the model cache is saved
export OLLAMA_MODELS="$MODELS_DIR" OLLAMA_URL="http://127.0.0.1:11434" OLLAMA_HOST="127.0.0.1:11434"
export PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8
mkdir -p "$MODELS_DIR"

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

# --- Ollama: one server we own, storing models where actions/cache looks. ---
# The installer may have started its own systemd service (which stores models
# under /usr/share/ollama, outside the cache); stop it so ours is the only one.
sudo systemctl stop ollama 2>/dev/null || true
pkill -x ollama 2>/dev/null || true
sleep 1
ollama serve > /tmp/ollama.log 2>&1 &
for i in $(seq 1 60); do
  curl -fs "$OLLAMA_URL/api/version" >/dev/null 2>&1 && break
  sleep 1
done
if ! curl -fs "$OLLAMA_URL/api/version" >/dev/null 2>&1; then
  echo "::error::Ollama did not come up within 60s"
  tail -n 40 /tmp/ollama.log
  exit 1
fi
echo "Ollama $(curl -fs "$OLLAMA_URL/api/version") ready, models in $MODELS_DIR"
df -h / | tail -1

# --- Workers ---
declare -a LOGS=()
declare -a PIDS=()
start_worker() {
  local idx="$1" token="$2" cfg="worker-config-$1.json"
  if [ -z "$token" ]; then
    echo "::warning::node token $idx is empty (secret not set) - skipping worker $idx"
    return
  fi
  write_cfg "actions-worker-$idx" "$token" "$cfg"
  local log="/tmp/worker$idx.log"
  : > "$log"
  LOGS+=("$log")
  # -multi: skip the single-instance check; the three workers are separate
  # nodes (separate tokens) that share the one local Ollama.
  ( timeout "${RUN_FOR}m" python -u -X faulthandler worker.py --config "$cfg" --headless --multi 2>&1 \
      | tee "$log" | sed -u "s/^/[w$idx] /" ) &
  PIDS+=($!)
}
start_worker 1 "${TB_NODE_TOKEN:-}"
start_worker 2 "${TB_NODE_TOKEN_2:-}"
start_worker 3 "${TB_NODE_TOKEN_3:-}"

if [ ${#LOGS[@]} -eq 0 ]; then
  echo "::error::No node tokens configured - set TB_NODE_TOKEN (and _2, _3) repository secrets"
  exit 1
fi

# --- Fail fast if the gateway rejects every node (e.g. revoked tokens). ---
# Without this the workers loop on "heartbeat failed" until the job times out
# and the run still looks green.
sleep 90
online=0
for log in "${LOGS[@]}"; do
  if grep -q "heartbeat ok" "$log"; then online=$((online + 1)); fi
done
if [ "$online" -eq 0 ]; then
  echo "::error::No worker heartbeat was accepted by $TB_GATEWAY within 90s. Tokens revoked/invalid, or gateway unreachable. Recent worker output:"
  for log in "${LOGS[@]}"; do echo "--- $log"; tail -n 8 "$log"; done
  pkill -f "worker.py" 2>/dev/null || true
  exit 1
fi
echo "$online of ${#LOGS[@]} workers online; running for up to ${RUN_FOR} minutes"

# Run until the time budget ends; the schedule starts the next window.
# evict_after_job is off so models stay cached across runs. (Wait on the
# worker pids only - a bare `wait` would also wait on the Ollama server.)
wait "${PIDS[@]}"
echo "Worker window finished."
