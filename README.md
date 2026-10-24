# wimse-demo

A live WIMSE identity demo: two scenarios showing workload identity in multi-system environments.

**Live demo:** https://wimse-demo.pages.dev  
**Repo:** https://github.com/jralmaraz/wimse-demo

---

## Scenarios

### Multi-Cloud Microservices (default)

A `transaction-processor` workload calls three services across three clouds. Every hop proves identity cryptographically — no shared secrets, no sidecar proxy.

```
SPIRE               workload identity token (WIT) + workload authorization grant (WAG)
  → AS              WAG → access token, bound to workload's public key via cnf.jwk
    → Cloud A       fraud check   — Bearer AT + WPT proof
    → Cloud B       compliance    — Bearer AT + WPT proof (different aud)
    → Cloud C       settlement    — Bearer AT + WPT proof (different aud)
```

Token types: `wit+jwt` · `wag+jwt` · `at+jwt` · `application/wpt+jwt`

### B2B + OID-FED

Same WIMSE chain, but the AS and an external partner (RegulatoryHub) need to dynamically verify the WIT issuer before they accept it. OpenID Federation 1.0 provides the trust discovery layer.

Two runs: **Keycloak** (has `certified-idp` trust mark → approved) vs **Rogue IdP** (not in federation → rejected at AS, step 4).

---

## Architecture

### Cloudflare Worker (primary)

Self-contained TypeScript Worker. All key pairs generated at isolate cold-start. No external dependencies at runtime.

```
worker/
  src/crypto.ts      ES256 WebCrypto primitives
  src/federation.ts  OID-FED entities — dual key pairs per IdP (federation + protocol)
  src/wimse.ts       WIT / WAG / WPT / AT issuance + verification
  src/index.ts       Router + scenario logic
```

**Run locally:**
```bash
cd worker && npm install
npm run dev          # wrangler dev on :8787
# open spa/index.html?worker=http://localhost:8787
```

**Deploy:**
```bash
npm run deploy       # wrangler deploy --env production
```

### Go services (reference implementation)

Production-grade Go services for real deployments with SPIRE. Currently scaled to zero on Fly.io.

```
services/platform/   SPIRE simulator (:8081) + Authorization Server (:8082)
services/workload/   Transaction processor (:8083)
services/apis/       Fraud API (:8084) + Compliance API (:8085)
spa/                 fly.html — SPA for Go/Fly.io backend
```

**Redeploy to Fly.io:**
```bash
flyctl deploy --config fly.platform.toml --remote-only
flyctl deploy --config fly.apis.toml     --remote-only
flyctl deploy --config fly.workload.toml --remote-only
```

---

## SPA

`spa/index.html` — served at https://wimse-demo.pages.dev, connects to the Cloudflare Worker by default. Pass `?worker=http://localhost:8787` to target a local instance.

`spa/fly.html` — original SPA for the Go/Fly.io backend.

---

## Tests

```bash
# Go services
go test ./... -race -count=1 -timeout 120s

# Worker (26 tests)
cd worker && npm test
```

---

## CI

| Job | Trigger | What it does |
|---|---|---|
| Go — Test & Lint | all PRs + main | go test, go vet, govulncheck |
| Worker — Typecheck & Test | all PRs + main | tsc --noEmit, vitest |
| Docker Build | all PRs + main | verifies Go service images still build |
| Security Scan | main + manual | SBOM (Syft) + Grype container scan |
| Deploy Worker | main push | wrangler deploy --env production |
| Deploy SPA | main push, after Worker | wrangler pages deploy |

Secrets required in `ci` environment: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`.
