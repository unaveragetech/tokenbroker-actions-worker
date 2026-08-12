# TokenBroker Actions Worker

A **standing compute node** for TokenBroker powered by GitHub Actions free
runners. Each workflow run installs Ollama on an `ubuntu-latest` runner and
runs the headless TokenBroker worker for the job window (~6h max per run). The
schedule re-fires every 5 hours, so the node comes back with only a short gap.

## Setup

1. Add two repository secrets:
   - `TB_GATEWAY` = `https://tokenbroker-edge.tokenbroker.workers.dev`
   - `TB_NODE_TOKEN` = the node token minted for this worker (shown once)
2. Push this repo. The scheduled workflow keeps the node standing; run
   `workflow_dispatch` manually to start it immediately.

## What it can serve

- CPU-only runner (2 vCPU / 7 GB RAM / 14 GB SSD) - small models (<= 4B Q4).
- The hub only assigns models the node can pull + fit (requirement matching).
- Models are pulled on demand and evicted after each job (ephemeral).

## Notes

- Free tier: unlimited minutes on public repos, 2000 min/month on private.
- The runner IP changes per run - the hub records it but does not bind the
  node to a single IP.
- `private_jobs` is off: this node never claims Hiro-encoded private jobs.
