---
name: deploy
description: Deploy the wimse-demo Worker to Cloudflare and verify the SPA health endpoint. Runs wrangler deploy, then hits /healthz to confirm the Worker is live. SPA deploys automatically via Cloudflare Pages GitHub integration — no action needed there.
when_to_use: When deploying a PR or release to Cloudflare. Run after all CI checks pass on main.
allowed-tools: Bash Read
effort: low
---

You are deploying wimse-demo to Cloudflare.

## Pre-flight

```bash
# Confirm you're on main and it's clean:
cd /Users/tatianetiago/claude-work/wimse-demo
git status
git log --oneline -3
```

## Deploy Worker

```bash
cd /Users/tatianetiago/claude-work/wimse-demo/worker
npm ci
npx wrangler deploy --env production
```

Requires `CLOUDFLARE_API_TOKEN` in the environment (or set in shell). In CI this comes from the `ci` GitHub Actions environment secret.

## Verify health

```bash
curl -sf https://wimse-demo-worker.YOUR_SUBDOMAIN.workers.dev/healthz | jq .
```

Expected response: `{ "status": "ok", ... }`

If the Worker URL has changed, check `worker/wrangler.toml` for the `routes` configuration.

## SPA

The SPA at `spa/index.html` is deployed automatically by Cloudflare Pages on every push to main. No manual step needed.

PR previews: `https://<PR-number>.wimse-demo.pages.dev`

To force a redeploy: push a whitespace change to any file in `spa/`.

## Rollback

If the deployed Worker is broken:
```bash
# List recent deployments:
npx wrangler deployments list

# Roll back to previous:
npx wrangler rollback <deployment-id>
```

## After deploy

Confirm in the SPA: open the production URL → click "Connect" → button should show "connected ✓".
