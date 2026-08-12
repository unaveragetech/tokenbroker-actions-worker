# TokenBroker Actions Worker

**Three standing compute nodes** for TokenBroker powered by a single GitHub
Actions workflow. Each run installs Ollama on an `ubuntu-latest` runner and
launches **three worker instances that share one local Ollama server**
(multi-worker mode), so a single repo/run serves up to three jobs at once.
Models pulled by one worker are instantly available to the others, and an
Actions cache shares models across runs too.

The schedule re-fires every 5 hours (Actions jobs max ~6h), so the nodes come
back with only a short gap.

## Setup

1. Add two repository secrets:
   - `TB_GATEWAY` = `https://tokenbroker-edge.tokenbroker.workers.dev`
   - `TB_NODE_TOKEN` = the node token minted for this worker (shown once)
   - `TB_NODE_TOKEN_2`, `TB_NODE_TOKEN_3` = tokens for the 2nd and 3rd workers
2. Push this repo. The scheduled workflow keeps the node standing; run
   `workflow_dispatch` manually to start it immediately.

## What it can serve

- CPU-only runner (2 vCPU / 7 GB RAM / 14 GB SSD) - small models (<= 4B Q4).
- The hub only assigns models the node can pull + fit (requirement matching).
- Models are pulled on demand and evicted after each job (ephemeral).

## Notes

- Free tier: unlimited minutes on public repos, 2000 min/month on private.
- 3 worker processes per runner = 3 nodes online from one repo; the hub can
  assign up to 3 jobs concurrently to this run.
- `evict_after_job` is off here so models persist and are shared (the Actions
  cache + idle eviction keep the disk bounded).
- The runner IP changes per run - the hub records it but does not bind the
  node to a single IP.
- `private_jobs` is off: this node never claims Hiro-encoded private jobs.
