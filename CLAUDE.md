# CLAUDE.md — wimse-demo

## What this repo is

A self-contained WIMSE identity demo: three Go services + a static SPA. Every inter-service call uses real JWT-based authentication. Designed to run on Fly.io free tier (3 VMs) and Cloudflare Pages.

This is a **demo repo** — optimised for clarity and reproducibility, not production hardening. The SPIRE simulator is a stand-in for a real SPIRE deployment.

---

## Service map

| Directory | App | Ports | Notes |
|---|---|---|---|
| `services/platform/cmd/` | wimse-demo-platform | :8081 (SPIRE) :8082 (AS) | Two HTTP listeners in one binary |
| `services/workload/cmd/` | wimse-demo-workload | :8083 | Calls platform + apis |
| `services/apis/cmd/` | wimse-demo-apis | :8084 (fraud) :8085 (compliance) | Two HTTP listeners in one binary |
| `spa/` | Cloudflare Pages | — | Static HTML+JS, no build step |

---

## Go environment

```bash
export PATH=/opt/homebrew/bin:$PATH   # required before any go/govulncheck call
```

- Go: v1.26+ (`go.mod` declares minimum)
- govulncheck: **pinned at v1.6.0** — do not upgrade without checking CLAUDE.md in wimse-identity-fabric
- Module: `github.com/jralmaraz/wimse-demo`
- Identity library: `github.com/example/wimse-identity-fabric` — use the pseudo-version from `go.mod`, not `v1.1.0` (pkg/wag is not in v1.1.0)

---

## WIMSE API quick reference

### WIT

```go
issuer, _ := wit.NewIssuer(platformIssuer, privateKey, ttl)
token, _  := issuer.Issue(ctx, wit.IssueOptions{
    Subject:     "spiffe://finclear.io/workload/...",
    Audiences:   []string{"https://as.finclear.io"},
    WorkloadKey: workloadPubKey,  // *ecdsa.PublicKey
})
```

### WPT

```go
proof, _ := wpt.Generate(wpt.GenerateOptions{
    WIT:         witToken,
    TargetURI:   "https://api.example.com/path",
    WorkloadKey: privKey,  // *ecdsa.PrivateKey
})
```

### WAG

```go
issuer := wag.NewIssuer(wag.IssuerConfig{
    Issuer:     platformIssuer,
    PrivateKey: platformPrivKey,
    TTL:        5 * time.Minute,
})
grant, _ := issuer.Issue(ctx, wag.GrantOptions{
    Subject: "spiffe://finclear.io/workload/...",
    Scope:   "fraud:read compliance:write",
})
```

Exchange at AS with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`.

### JWT validation invariants

- `jwt.WithValidMethods([]string{"ES256"})` — always set this
- `jwt.WithAudience("https://...")` — singular, not slice
- Check `typ` claim manually: WIT is `wit+jwt`, WAG is `wag+jwt`, access token is `at+jwt`
- `jti` replay map: `sync.Map`, evict entries after token TTL

### Keys

```go
pub, _ := keys.PublicKeyToJWK(ecPubKey, "kid-string")
priv, _ := keys.GenerateKeyPair()
ecPub, _ := keys.JWKToPublicKey(&jwk)  // jwk is keys.JWK, not *joseJWK
```

---

## JWKS caching pattern

The apis service fetches the AS public key over HTTP. Cache it:

```go
var (
    cachedPub   *ecdsa.PublicKey
    cachedPubAt time.Time
    cachedPubMu sync.Mutex
)
const jwksCacheTTL = 5 * time.Minute
```

Refresh when `time.Since(cachedPubAt) > jwksCacheTTL`. There is no `jwt.NewCachingJWKSet` in jwt/v5.

---

## Fly.io free-tier consolidation

3 VMs for 5 logical services: platform (8081+8082) and apis (8084+8085) each run two `net.Listener` goroutines in the same binary. This is explicit in the README. In production, separate processes with separate attestation.

Fly app names: `wimse-demo-platform`, `wimse-demo-workload`, `wimse-demo-apis`  
Region: `sjc` (San Jose)  
Fly.io configs: `fly/platform.toml`, `fly/workload.toml`, `fly/apis.toml`

---

## SPA config

The SPA at `spa/index.html` reads backend URLs from query parameters:

| Param | Default |
|---|---|
| `?backend=` | `https://wimse-demo-workload.fly.dev` |
| `?spire=` | `https://wimse-demo-platform.fly.dev` |
| `?as=` | `https://wimse-demo-platform.fly.dev` |

Local dev: `http://localhost:3000?backend=http://localhost:8083&spire=http://localhost:8081&as=http://localhost:8082`

---

## Git workflow

Follow the global CLAUDE.md: never commit directly to main.

```bash
git checkout -b feat/short-description
# work…
git push -u origin feat/short-description
gh pr create --title "…" --body "…"
```

Branch naming: `feat/`, `fix/`, `chore/`, `docs/` + kebab-case.

---

## Tests

Every PR must pass all tests:

```bash
go test ./... -race -count=1 -timeout 120s
```

- Platform: 11 tests — WIT round-trip, WAG issuance, token exchange, jti replay, wrong grant type, wrong key
- APIs: 13 tests — Bearer validation, wrong issuer, expired, wrong typ, direct WAG blocked, fraud score thresholds
- Workload: tests in `services/workload/cmd/main_test.go` — transaction flow, error propagation

Security gate: `govulncheck@v1.6.0` runs in CI and in the pre-push hook.

---

## What NOT to do

- Do not commit `.env` files — all secrets via GitHub Actions secrets or Fly.io secrets
- Do not reference IBM or consulting context anywhere in code, comments, or PRs
- Do not bump the wimse-identity-fabric pseudo-version without checking if pkg/wag is available in the new tag
