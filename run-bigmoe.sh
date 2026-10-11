#!/bin/bash
# One TokenBroker worker node that serves bmoe-qwen3-30b-a3b on an Actions
# runner: BigMoeOnEdge streams the MoE experts from the runner's SSD, so a
# 14 GB model runs on a 16 GB / 4 vCPU box. The model is NOT fetched from
# Hugging Face: it lives in this repo's release (split into <2 GiB parts).
set -u

: "${TB_GATEWAY:?TB_GATEWAY secret is not set}"
: "${TB_NODE_TOKEN_BMOE:?TB_NODE_TOKEN_BMOE secret is not set}"
REPO="${GITHUB_REPOSITORY:-unaveragetech/tokenbroker-actions-worker}"
TAG="${MODEL_RELEASE_TAG:-model-qwen3-30b-a3b-q3_k_m}"
MODEL_NAME="bmoe-qwen3-30b-a3b"
GGUF="Qwen_Qwen3-30B-A3B-Q3_K_M.gguf"
RUN_FOR="${WORKER_RUN_MINUTES:-345}"
export PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8

# --- Engine: pinned binary shipped in the repo (BigMoeOnEdge v0.28.0, Apache-2.0) ---
chmod +x bin/bmoe-cli
if [ "$(sha256sum bin/bmoe-cli | cut -d' ' -f1)" != "$(cat bin/bmoe-cli.sha256)" ]; then
  echo "::error::bin/bmoe-cli does not match its pinned sha256"; exit 1
fi

# --- Disk: the runner's /mnt scratch disk is the big one ---
for d in /mnt "$RUNNER_TEMP" /tmp; do
  [ -d "$d" ] || continue
  free_gb=$(df -BG --output=avail "$d" | tail -1 | tr -dc '0-9')
  if [ "${free_gb:-0}" -ge 30 ]; then MODEL_DIR="$d/bigmoe"; break; fi
done
: "${MODEL_DIR:?no disk with >=30 GB free}"
sudo mkdir -p "$MODEL_DIR" && sudo chown "$(id -u):$(id -g)" "$MODEL_DIR"
echo "model dir: $MODEL_DIR (${free_gb} GB free)"; df -h "$MODEL_DIR" | tail -1; free -g | sed -n 2p; nproc

# --- Model: download parts from the repo release, join, verify ---
t0=$(date +%s)
gh release download "$TAG" --repo "$REPO" --dir "$MODEL_DIR/parts" --pattern 'qwen3-30b-a3b-q3_k_m.gguf.part*' --pattern SHA256SUMS --clobber
echo "downloaded in $(( $(date +%s) - t0 ))s"
( cd "$MODEL_DIR/parts" && grep 'part' SHA256SUMS | sha256sum -c - ) || { echo "::error::a model part failed its checksum"; exit 1; }
cat "$MODEL_DIR"/parts/qwen3-30b-a3b-q3_k_m.gguf.part* > "$MODEL_DIR/$GGUF"
rm -rf "$MODEL_DIR/parts"
want=1f3792eec1bb8559bf6fb49fec159cd85bff97ec262c21b8b59a43e9e2b29859  # sha256 of the full GGUF (matches Hugging Face)
got=$(sha256sum "$MODEL_DIR/$GGUF" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then echo "::error::joined model hash mismatch"; exit 1; fi
echo "model ready ($(( $(date +%s) - t0 ))s total), sha256 ok"

# --- Self-test: one real generation, prints load time and tok/s into the log ---
THREADS=$(nproc)
if [ "${SELFTEST:-1}" = "1" ]; then
  echo "== self-test =="
  timeout 600 bin/bmoe-cli -m "$MODEL_DIR/$GGUF" --moe-stream --overlap --dense-weights anon \
    --cache-mb auto --cache-floor-mb 1500 --cache-ceil-mb 5000 --io-threads 4 -t "$THREADS" \
    -n 64 --chatml --no-think -p "Explain in two sentences why the sky is blue." 2>&1 | tail -25
fi

# --- Worker config ---
cat > worker-config-bmoe.json <<EOT
{
  "name": "actions-bigmoe-1",
  "gateway": "${TB_GATEWAY}",
  "token": "${TB_NODE_TOKEN_BMOE}",
  "private_jobs": true,
  "cloud_enabled": false,
  "storage_gb": 8,
  "bigmoe": {
    "exe": "$PWD/bin/bmoe-cli",
    "dll_dir": "$PWD/bin",
    "models": { "${MODEL_NAME}": "$MODEL_DIR/$GGUF" },
    "threads": ${THREADS},
    "ctx": 4096,
    "cache_ceil_mb": 5000,
    "cache_floor_mb": 1500,
    "io_threads": 4,
    "idle_unload_s": 1800,
    "extra_args": ["--overlap"]
  }
}
EOT

( timeout "${RUN_FOR}m" python -u -X faulthandler worker.py --config worker-config-bmoe.json --headless --multi 2>&1 \
    | tee /tmp/worker-bmoe.log | sed -u 's/^/[bmoe] /' ) &
WPID=$!

sleep 90
if ! grep -q "heartbeat ok" /tmp/worker-bmoe.log; then
  echo "::error::The gateway did not accept the node's heartbeat within 90s (revoked/invalid token, or gateway unreachable). Recent output:"
  tail -n 10 /tmp/worker-bmoe.log
  pkill -f worker.py || true
  exit 1
fi
echo "node online; serving ${MODEL_NAME} for up to ${RUN_FOR} minutes"
wait "$WPID"
echo "Worker window finished."
