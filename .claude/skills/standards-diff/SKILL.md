---
name: standards-diff
description: Compare the wimse-demo implementation against the latest IETF WIMSE draft. Fetches the current draft-ietf-wimse-s2s-token-spec, extracts MUST/SHOULD requirements, and maps each to the corresponding code location.
when_to_use: When a new WIMSE draft is published, or before a release to verify compliance status. Also use when the identity fabric is upgraded to a new version.
argument-hint: "[draft-version]"
allowed-tools: Read Grep Glob Bash WebFetch
effort: medium
agent: internet-standards-researcher
---

You are comparing the wimse-demo implementation against the latest WIMSE IETF draft.

## Step 1 — Fetch the latest draft

```
WebFetch: https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-token-spec/
```

Note the latest version number (e.g., `-07`). If a specific version was passed as an argument, use that.

Fetch the plain text:
```
WebFetch: https://www.ietf.org/archive/id/draft-ietf-wimse-s2s-token-spec-NN.txt
```

## Step 2 — Extract normative requirements

From the draft, find every MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY statement. Group by section.

## Step 3 — Map to code

For each requirement, search the implementation:

```bash
# WIT issuance:
grep -rn "Issue\|WIT\|cnf\|jwk" /Users/tatianetiago/claude-work/wimse-demo/services/platform/

# WPT generation:
grep -rn "wth\|TargetURI\|aud" /Users/tatianetiago/claude-work/wimse-demo/services/workload/

# Token validation:
grep -rn "WithValidMethods\|WithAudience\|typ\|jti" /Users/tatianetiago/claude-work/wimse-demo/services/
```

Also check the identity fabric library:
```bash
find /Users/tatianetiago/claude-work/wimse-identity-fabric -name "*.go" | xargs grep -l "wth\|cnf\|wpt"
```

## Step 4 — Report

Use the Standards Tracker Report format from the internet-standards-researcher agent:

```
## Standards Tracker Report

Draft: draft-ietf-wimse-s2s-token-spec-NN
Fetched: YYYY-MM-DD

### MUST requirements
  ✓/✗/~/? §X.Y  requirement text
             → file:line function()

### SHOULD requirements
  ✓/? §X.Y  ...

### New in this version (if comparing to prior)
  ⚠️  §X.Y  changed from SHOULD to MUST

### Summary
  MUST violations: N
  SHOULD gaps: N
  New breaking changes: N

### Recommended actions
  1. [Critical] ...
```
