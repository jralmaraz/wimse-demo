# wimse-demo

A WIMSE identity demo built around a cross-cloud payment scenario. A single transaction triggers a full cryptographic identity chain: SPIFFE attestation → Workload Identity Token → Workload Authorization Grant → scoped access token → API calls across simulated AWS and Azure.

**Repo:** https://github.com/jralmaraz/wimse-demo  
**SPA:** https://wimse-demo.pages.dev (static; Fly.io backends scaled to zero — run locally to exercise the full flow)

> **Status:** Fly.io backends (`wimse-demo-platform`, `wimse-demo-workload`, `wimse-demo-apis`) are scaled to zero to avoid free-tier charges. The SPA and all code remain intact. See [Run locally](#run-locally) to spin everything up in Docker, or [Deploy to Fly.io](#deploy-to-flyio) to redeploy.

---

## Scenario

FinClear processes a payment. The `transaction-processor` workload runs on GCP. It must call a `fraud-api` (simulated AWS) and a `compliance-reporter` (simulated Azure). No pre-shared secrets. No passwords. Each hop proves identity with a fresh cryptographic token.

```
SPA (browser)
  → POST /transaction/run (workload :8083)
      → POST /wit/issue   (SPIRE :8081)  — workload identity token
      → POST /wag/issue   (SPIRE :8081)  — workload authorization grant
      → POST /token       (AS    :8082)  — exchange grant for access token
      → GET  /fraud/check (fraud :8084)  — Bearer + WPT proof
      → POST /compliance  (compliance :8085) — Bearer + WPT proof
```

---

## Architecture

Five logical services run on **three Fly.io VMs** (free-tier consolidation):

| Fly VM | App name | Services inside | Ports |
|---|---|---|---|
| VM 1 | `wimse-demo-platform` | SPIRE simulator + Auth Server | 8081 + 8082 |
| VM 2 | `wimse-demo-workload` | transaction-processor | 8083 |
| VM 3 | `wimse-demo-apis` | fraud-api + compliance-reporter | 8084 + 8085 |

**Why the consolidation?** Fly.io free tier allows 3 VMs. Running two lightweight HTTP servers inside one Go binary (different `net.Listener` goroutines, different ports) keeps costs at zero while still demonstrating realistic inter-service calling patterns. The README documents this so the architecture is not misleading — in production, SPIRE and the AS would be separate processes with a real SPIFFE workload attestor.

---

## Run locally

```bash
git clone https://github.com/jralmaraz/wimse-demo
cd wimse-demo
docker compose up
```

| Service | URL |
|---|---|
| SPIRE simulator | http://localhost:8081 |
| Auth Server | http://localhost:8082 |
| Transaction processor | http://localhost:8083 |
| Fraud API | http://localhost:8084 |
| Compliance reporter | http://localhost:8085 |
| SPA | http://localhost:3000 |

Point the SPA at local services:

```
http://localhost:3000?backend=http://localhost:8083&spire=http://localhost:8081&as=http://localhost:8082
```

Run without Docker (requires Go 1.26+):

```bash
export PATH=/opt/homebrew/bin:$PATH

# Terminal 1 — platform
cd services/platform/cmd && go run . 

# Terminal 2 — apis
cd services/apis/cmd && go run .

# Terminal 3 — workload (after platform + apis are up)
cd services/workload/cmd && go run .
```

---

## Tests

```bash
export PATH=/opt/homebrew/bin:$PATH
go test ./... -race -count=1
```

Test coverage includes:

- **Platform**: WIT round-trip, WAG issuance, token exchange, `jti` replay rejection, wrong grant type rejection, wrong key rejection
- **APIs**: Bearer token validation, wrong issuer, expired token, wrong typ claim, direct WAG usage blocked, fraud score thresholds
- **Workload**: transaction flow, missing amount, upstream error propagation

---

## Deploy to Fly.io

### Prerequisites

1. Install flyctl: https://fly.io/docs/hands-on/install-flyctl/
2. `flyctl auth login`
3. Create the three apps (one-time):

```bash
flyctl apps create wimse-demo-platform
flyctl apps create wimse-demo-workload
flyctl apps create wimse-demo-apis
```

### GitHub Actions secrets required

| Secret | Purpose |
|---|---|
| `FLY_API_TOKEN` | Deploy all three Fly.io apps |
| `CLOUDFLARE_API_TOKEN` | Deploy SPA to Cloudflare Pages |
| `CLOUDFLARE_ACCOUNT_ID` | Target Cloudflare account |

CI/CD pipeline (`.github/workflows/ci.yml`) runs on every push and PR:

1. **Test & Lint** — `go vet`, race detector, `govulncheck@v1.6.0`
2. **Docker Build** — builds all three images to verify Dockerfiles
3. **Security Scan** — SBOM (Syft) + Grype vulnerability scan (main branch only)
4. **Deploy to Fly.io** — deploys platform first, then apis, then workload (main branch only)
5. **Deploy SPA** — Cloudflare Pages wrangler deploy (main branch only)

### Redeploy from zero

The apps exist in Fly.io but have no machines. To redeploy:

```bash
flyctl deploy --config fly.platform.toml --remote-only
flyctl deploy --config fly.apis.toml --remote-only
flyctl deploy --config fly.workload.toml --remote-only
```

To scale back to zero again (stop billing):

```bash
flyctl scale count 0 --app wimse-demo-platform --yes
flyctl scale count 0 --app wimse-demo-workload --yes
flyctl scale count 0 --app wimse-demo-apis --yes
```

---

## Pre-push hook

The pre-push hook at `.git/hooks/pre-push` runs automatically before every push:

```
go mod verify
go vet ./...
go test ./... -race -count=1 -timeout 120s
govulncheck ./...
```

---

## Key WIMSE concepts

**WIT (Workload Identity Token)** — A JWT whose `sub` is a SPIFFE ID and whose `cnf.jwk` claim embeds the workload's public key, cryptographically binding the token to that key pair. Issued by SPIRE.

**WPT (Workload Proof Token)** — A DPoP-style proof JWT that binds a request to a specific URI. Signed with the workload's private key. Proves the caller holds the key referenced in the WIT.

**WAG (Workload Authorization Grant)** — `wag+jwt` token issued by SPIRE. Exchanged at the AS using `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`. The AS trusts SPIRE (registered once); individual workloads never need to register. `jti` claim prevents replay.

**Identity library:** `github.com/example/wimse-identity-fabric` — pkg/wit, pkg/wpt, pkg/wag, pkg/keys

---

## License

MIT
