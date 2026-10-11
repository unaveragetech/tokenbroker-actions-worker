# TokenBroker Actions Worker

**Three standing compute nodes** for TokenBroker powered by a single GitHub
Actions workflow. Each run installs Ollama on an `ubuntu-latest` runner and
launches **three worker instances that share one local Ollama server**
(multi-worker mode), so a single repo/run serves up to three jobs at once.
Models pulled by one worker are instantly available to the others, and an
Actions cache shares models across runs too.

A run lasts ~5h50m and the schedule re-fires every 6 hours (Actions jobs max
~6h), so the nodes come back with only a short gap. A concurrency group stops
two runs from ever sharing the same node tokens.

## Setup

1. Add the repository secrets:
   - `TB_GATEWAY` = `https://tokenbroker.org`
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

## Troubleshooting

Worker output streams into the "Run 3 headless workers" step log, prefixed
`[w1]`/`[w2]`/`[w3]`. If the gateway rejects every node within 90s (revoked or
wrong token, gateway unreachable) the step fails with an `::error::` annotation
and the last lines of each worker log - a red run means the nodes are not
standing. Mint replacement tokens in the TokenBroker admin console and update
the `TB_NODE_TOKEN*` secrets.

GitHub disables scheduled workflows after 60 days without repository activity;
re-enable it from the Actions tab (or push any commit) if the nodes go quiet.
