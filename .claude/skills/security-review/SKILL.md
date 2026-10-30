---
name: security-review
description: Run a focused security review of the wimse-demo WIMSE token implementation — checks JWT validation logic, typ claim location, wth hash correctness, jti replay protection, TLS config, and secret hygiene.
when_to_use: Before merging any PR that touches services/, worker/src/, or go.mod. Also run after pulling a new version of wimse-identity-fabric.
allowed-tools: Read Grep Glob Bash
effort: high
agent: offensive-security
---

You are reviewing wimse-demo for security issues in the WIMSE token implementation.

## Scope

- `services/platform/` — WIT issuer, token exchange endpoint (AS), jti replay map
- `services/workload/` — WIT consumer, WPT generation, outbound HTTP clients
- `services/apis/` — Bearer (AT+WPT) validation, fraud/compliance handlers
- `worker/src/` — Worker JWT verification, fetch targets, secret usage

## Run govulncheck first

```bash
export PATH=/opt/homebrew/bin:$PATH
cd /Users/tatianetiago/claude-work/wimse-demo
go install golang.org/x/vuln/cmd/govulncheck@v1.6.0
govulncheck ./...
```

## JWT validation checklist

For each service that validates a JWT:

```
[ ] jwt.WithValidMethods(["ES256"]) set before ParseWithClaims
[ ] Audience validated (jwt.WithAudience with exact URI)
[ ] typ checked in header (token.Header["typ"]), NOT in payload claims
[ ] Issuer is pinned — not accepted from any issuer
[ ] jti checked in replay map before accepting
[ ] jti replay entries evicted after token TTL (not before, not never)
```

## WPT-specific checks

```
[ ] wth is SHA-256 of raw WIT bytes (the string), not decoded payload JSON
[ ] aud in WPT matches exact request URI (path + no trailing slash variants)
[ ] WPT signature verified against cnf.jwk in the AT (not just "a valid key")
[ ] WPT exp is ≤ 5 minutes from iat
```

## TLS checks

Grep for TLS config:
```bash
grep -rn "InsecureSkipVerify\|VersionTLS12\|MinVersion" services/ worker/
```

Expect: no `InsecureSkipVerify: true`, no `tls.VersionTLS12`. All HTTP clients should have `MinVersion: tls.VersionTLS13`.

## Secret hygiene

```bash
# Check for secrets in working tree:
git -C /Users/tatianetiago/claude-work/wimse-demo diff origin/main...HEAD -- '*.env' '*.key' '*.pem'
grep -rn "PRIVATE KEY\|secret\|password\|token" services/ --include="*.go" | grep -v "_test.go" | grep -v "\/\/"
```

Check `.gitignore` includes `.env`, `*.pem`, `*.key`.

## Output format

List findings as:
```
[Critical|High|Medium|Low] file:line
Issue: one sentence
Fix: one-line change
```

List passed checks as:
```
[OK] jwt.WithValidMethods enforced — services/platform/cmd/main.go:L143
```
