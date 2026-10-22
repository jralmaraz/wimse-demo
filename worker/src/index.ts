// wimse-demo Cloudflare Worker
//
// Simulates the full WIMSE identity chain for a B2B cross-cloud payment scenario:
//   FinClear transaction-processor calls:
//     /internal/fraud     — internal fraud check (WIT + WPT + Bearer)
//     /internal/compliance — internal compliance (same)
//     /partner/regulatoryhub/verify — external B2B API
//
// The B2B API performs OID-FED trust chain resolution before accepting the WIT:
//   1. extracts iss from WIT
//   2. calls /ta/federation/resolve → gets trust chain + jwks_uri
//   3. fetches jwks_uri to get WIT signing key
//   4. verifies WIT signature + checks certified-idp trust mark
//
// Scenario endpoint:
//   GET /api/scenario/b2b?idp=keycloak|rogue
//     runs the full flow atomically, returns step-by-step results

import { generateKeyPair, decodeJWT, importPublicJWK } from './crypto.js';
import {
  FederationState, LeafEntityID, TRUST_MARK, trustMarkRegistry,
  buildTAEntityConfig, buildKeycloakEntityConfig, buildOktaEntityConfig,
  buildEntraEntityConfig, buildRPEntityConfig,
  buildSubordinateStatement, buildResolveResponse, buildJWKS,
} from './federation.js';
import {
  WimseState,
  issueWIT, issueWAG, issueAccessToken, generateWPT,
  verifyWAG, verifyWIT, verifyWPT, verifyAccessToken,
  extractCnfJWK,
} from './wimse.js';

export interface Env { BASE_URL: string }

// ── Module-level state ────────────────────────────────────────────────────────
// Generated once per isolate cold-start. All JWTs within one isolate are key-consistent.

interface State {
  fed: FederationState;
  wim: WimseState;
}

let _state: State | null = null;

async function getState(base: string): Promise<State> {
  if (_state) return _state;

  const [taKey, kcFed, kcProt, oktaFed, oktaProt, entraFed, entraProt, rpFed, rpProt, spireKey, asKey, workloadKey] =
    await Promise.all([
      generateKeyPair('ta-1'),
      generateKeyPair('kc-fed-1'),  generateKeyPair('kc-prot-1'),
      generateKeyPair('okta-fed-1'), generateKeyPair('okta-prot-1'),
      generateKeyPair('entra-fed-1'), generateKeyPair('entra-prot-1'),
      generateKeyPair('rp-fed-1'),   generateKeyPair('rp-prot-1'),
      generateKeyPair('spire-1'),
      generateKeyPair('as-1'),
      generateKeyPair('workload-1'),
    ]);

  const fed: FederationState = {
    baseURL: base,
    taKey,
    entities: {
      ta:       { id: `${base}/ta` },
      keycloak: { id: `${base}/idp/keycloak`, keys: { federationKey: kcFed, protocolKey: kcProt } },
      okta:     { id: `${base}/idp/okta`,     keys: { federationKey: oktaFed, protocolKey: oktaProt } },
      entra:    { id: `${base}/idp/entra`,    keys: { federationKey: entraFed, protocolKey: entraProt } },
      rp:       { id: `${base}/rp/portal`,    keys: { federationKey: rpFed, protocolKey: rpProt } },
    },
  };

  const wim: WimseState = {
    baseURL: base,
    spire:   { issuer: `${base}/spire`, key: spireKey },
    as:      { issuer: `${base}/as`,    key: asKey },
    workload: {
      spiffeID: 'spiffe://finclear.io/workload/transaction-processor',
      key: workloadKey,
    },
    idp: {
      entityID:    fed.entities.keycloak.id,
      protocolKey: kcProt,
    },
  };

  _state = { fed, wim };
  return _state;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

function jwtResp(token: string, typ: string): Response {
  return new Response(token, {
    headers: { 'Content-Type': `application/${typ}`, 'Access-Control-Allow-Origin': '*' },
  });
}

const notFound   = (msg: string) => json({ error: msg }, 404);
const badRequest = (msg: string) => json({ error: msg }, 400);
const forbidden  = (msg: string) => json({ error: msg }, 403);

// ── Scenario: full B2B flow ───────────────────────────────────────────────────

interface ScenarioStep {
  step:   number;
  name:   string;
  status: 'ok' | 'rejected';
  detail: string;
  data?:  Record<string, unknown>;
}

async function runB2BScenario(
  s: State,
  idpMode: 'keycloak' | 'rogue',
): Promise<{ steps: ScenarioStep[]; outcome: 'approved' | 'rejected'; rejected_at?: number }> {
  const steps: ScenarioStep[] = [];
  const add = (step: number, name: string, status: 'ok' | 'rejected', detail: string, data?: Record<string, unknown>) => {
    steps.push({ step, name, status, detail, data });
  };

  const base = s.fed.baseURL;

  // ── Step 1: SPIRE issues WIT ─────────────────────────────────────────────
  let witToken: string;
  let witIss: string;
  if (idpMode === 'keycloak') {
    witToken = await issueWIT(s.wim);
    witIss   = s.wim.idp.entityID;
    const { payload } = decodeJWT(witToken);
    add(1, 'SPIRE: issue WIT (Keycloak IdP)', 'ok',
      `WIT issued. iss=${witIss}`,
      { iss: payload.iss, sub: payload.sub, typ: (payload as Record<string, unknown>).typ });
  } else {
    // Rogue IdP — not in the federation
    witIss = `${base}/idp/rogue-bank`;
    // Sign with a fresh random key that has no entry in the federation
    const rogueKey = await generateKeyPair('rogue-1');
    const { signJWT: sign } = await import('./crypto.js');
    const now = Math.floor(Date.now() / 1000);
    witToken = await sign({
      iss: witIss, sub: s.wim.workload.spiffeID,
      aud: [s.wim.as.issuer], iat: now, exp: now + 3600,
      jti: 'rogue-jti', cnf: { jwk: s.wim.workload.key.publicJWK },
    }, rogueKey.privateKey, rogueKey.kid, 'wit+jwt');
    add(1, 'SPIRE: issue WIT (Rogue IdP)', 'ok',
      `WIT issued by rogue IdP NOT in federation. iss=${witIss}`,
      { iss: witIss, sub: s.wim.workload.spiffeID, note: 'rogue — not registered in OID-FED' });
  }

  // ── Step 2: SPIRE issues WAG ─────────────────────────────────────────────
  const wagToken = await issueWAG(s.wim, witIss);
  const { payload: wagPayload } = decodeJWT(wagToken);
  add(2, 'SPIRE: issue WAG (Workload Authorization Grant)', 'ok',
    'WAG issued. Contains wit_iss so AS can perform federation check.',
    { iss: wagPayload.iss, sub: wagPayload.sub, scope: wagPayload.scope, wit_iss: wagPayload.wit_iss });

  // ── Step 3: AS validates WAG ─────────────────────────────────────────────
  const wagResult = await verifyWAG(wagToken, s.wim.spire.key.publicKey, s.wim.spire.issuer, s.wim.as.issuer);
  if (!wagResult.ok) {
    add(3, 'AS: validate WAG signature', 'rejected', wagResult.reason ?? 'WAG invalid');
    return { steps, outcome: 'rejected', rejected_at: 3 };
  }
  add(3, 'AS: validate WAG signature', 'ok', 'WAG signature valid. SPIRE is statically trusted by AS.');

  // ── Step 4: AS calls federation/resolve to verify WIT issuer ─────────────
  const taID = s.fed.entities.ta.id;
  const resolveResult = await federationResolveLeafByEntityID(s.fed, witIss);

  if (!resolveResult) {
    add(4, 'AS: OID-FED — federation/resolve for WIT issuer', 'rejected',
      `Entity not found in federation: ${witIss}. AS refuses to issue access token — the IdP that issued the WIT is not trusted.`,
      { queried: witIss, trust_anchor: taID });
    return { steps, outcome: 'rejected', rejected_at: 4 };
  }

  const { resolveJWT } = resolveResult;
  const { payload: rp } = decodeJWT(resolveJWT);

  // Check certified-idp trust mark in resolved metadata
  const certifiedIdPMark = TRUST_MARK.certifiedIdP(base);
  const registry = trustMarkRegistry(s.fed);
  const holdersCertified = registry[certifiedIdPMark] ?? [];
  const hasCertifiedIdP = holdersCertified.includes(witIss);

  if (!hasCertifiedIdP) {
    add(4, 'AS: OID-FED — check certified-idp trust mark', 'rejected',
      `Trust chain resolved but ${witIss} does not hold the certified-idp trust mark. AS requires it.`,
      { required_mark: certifiedIdPMark, entity: witIss, marks_held: Object.entries(registry).filter(([, h]) => h.includes(witIss)).map(([m]) => m) });
    return { steps, outcome: 'rejected', rejected_at: 4 };
  }

  add(4, 'AS: OID-FED — federation/resolve + trust mark check', 'ok',
    `Trust chain resolved. certified-idp trust mark confirmed. AS will issue access token.`,
    { sub: rp.sub, trust_anchor: rp.trust_anchor, trust_chain_length: (rp.trust_chain as string[]).length, certified_idp_mark: hasCertifiedIdP });

  // ── Step 5: AS issues access token ───────────────────────────────────────
  const cnfJWK = extractCnfJWK(witToken);
  if (!cnfJWK) {
    add(5, 'AS: issue access token', 'rejected', 'WIT missing cnf.jwk');
    return { steps, outcome: 'rejected', rejected_at: 5 };
  }
  const atToken = await issueAccessToken(s.wim, cnfJWK, wagPayload.scope as string);
  const { payload: atPayload } = decodeJWT(atToken);
  add(5, 'AS: issue access token', 'ok',
    'Access token issued. Contains cnf.jwk so APIs can bind WPT verification.',
    { iss: atPayload.iss, sub: atPayload.sub, scope: atPayload.scope });

  // ── Step 6: Fraud API — WIT + WPT + Bearer ────────────────────────────────
  const fraudURI = `${base}/internal/fraud/check`;
  const fraudWPT = await generateWPT(s.wim, fraudURI, witToken);
  const fraudATResult = await verifyAccessToken(atToken, s.wim.as.key.publicKey, s.wim.as.issuer, `${base}/internal`);
  if (!fraudATResult.ok) {
    add(6, 'Fraud API: validate Bearer token', 'rejected', fraudATResult.reason ?? 'AT invalid');
    return { steps, outcome: 'rejected', rejected_at: 6 };
  }
  const fraudWPTResult = await verifyWPT(fraudWPT, witToken, s.wim.workload.key.publicKey, fraudURI);
  if (!fraudWPTResult.ok) {
    add(6, 'Fraud API: validate WPT proof', 'rejected', fraudWPTResult.reason ?? 'WPT invalid');
    return { steps, outcome: 'rejected', rejected_at: 6 };
  }
  add(6, 'Fraud API: Bearer + WPT proof', 'ok',
    'Access token valid. WPT proof verifies workload controls cnf.jwk. Fraud score: 0.12 (below threshold).',
    { fraud_score: 0.12, threshold: 0.75, decision: 'PASS' });

  // ── Step 7: Compliance API — WIT + WPT + Bearer ───────────────────────────
  const compURI = `${base}/internal/compliance`;
  const compWPT = await generateWPT(s.wim, compURI, witToken);
  const compATResult = await verifyAccessToken(atToken, s.wim.as.key.publicKey, s.wim.as.issuer, `${base}/internal`);
  if (!compATResult.ok) {
    add(7, 'Compliance API: validate Bearer token', 'rejected', compATResult.reason ?? 'AT invalid');
    return { steps, outcome: 'rejected', rejected_at: 7 };
  }
  const compWPTResult = await verifyWPT(compWPT, witToken, s.wim.workload.key.publicKey, compURI);
  if (!compWPTResult.ok) {
    add(7, 'Compliance API: validate WPT proof', 'rejected', compWPTResult.reason ?? 'WPT invalid');
    return { steps, outcome: 'rejected', rejected_at: 7 };
  }
  add(7, 'Compliance API: Bearer + WPT proof', 'ok',
    'Internal compliance check passed.',
    { compliance_status: 'COMPLIANT', regulation: 'AML/KYC' });

  // ── Step 8: RegulatoryHub B2B API — full OID-FED verification ────────────
  const rhURI  = `${base}/partner/regulatoryhub/verify`;
  const rhWPT  = await generateWPT(s.wim, rhURI, witToken);

  // RegulatoryHub first resolves the WIT issuer in the federation
  const rhResolveResult = await federationResolveLeafByEntityID(s.fed, witIss);
  if (!rhResolveResult) {
    add(8, 'RegulatoryHub: OID-FED — resolve WIT issuer', 'rejected',
      `WIT issuer ${witIss} not found in shared federation. RegulatoryHub rejects request.`,
      { wit_iss: witIss, reason: 'entity not in federation' });
    return { steps, outcome: 'rejected', rejected_at: 8 };
  }

  // Extract jwks_uri from resolved metadata
  const resolvedMeta2 = rhResolveResult.resolvedMeta;
  const opMeta = (resolvedMeta2 as Record<string, Record<string, string>>).openid_provider;
  const jwksURI = opMeta?.jwks_uri;
  if (!jwksURI) {
    add(8, 'RegulatoryHub: extract jwks_uri', 'rejected',
      'Resolved metadata has no openid_provider.jwks_uri',
      { resolved_metadata: resolvedMeta2 });
    return { steps, outcome: 'rejected', rejected_at: 8 };
  }

  // Fetch the protocol JWKS (local endpoint in same isolate — no real HTTP needed)
  const jwksKey = await getProtocolJWKS(s.fed, witIss);
  if (!jwksKey) {
    add(8, 'RegulatoryHub: fetch jwks_uri', 'rejected',
      `jwks_uri ${jwksURI} returned no keys`,
      { jwks_uri: jwksURI });
    return { steps, outcome: 'rejected', rejected_at: 8 };
  }

  // Verify WIT signature using the key from jwks_uri
  const witVerifyResult = await verifyWIT(witToken, jwksKey, witIss);
  if (!witVerifyResult.ok) {
    add(8, 'RegulatoryHub: verify WIT signature (key from jwks_uri)', 'rejected',
      witVerifyResult.reason ?? 'WIT invalid');
    return { steps, outcome: 'rejected', rejected_at: 8 };
  }

  // Verify WPT proof
  const rhWPTResult = await verifyWPT(rhWPT, witToken, s.wim.workload.key.publicKey, rhURI);
  if (!rhWPTResult.ok) {
    add(8, 'RegulatoryHub: verify WPT proof', 'rejected', rhWPTResult.reason ?? 'WPT invalid');
    return { steps, outcome: 'rejected', rejected_at: 8 };
  }

  // Check certified-idp trust mark
  const rhCertifiedIdP = holdersCertified.includes(witIss);
  if (!rhCertifiedIdP) {
    add(8, 'RegulatoryHub: check certified-idp trust mark', 'rejected',
      `${witIss} does not hold certified-idp. RegulatoryHub requires it.`);
    return { steps, outcome: 'rejected', rejected_at: 8 };
  }

  add(8, 'RegulatoryHub: OID-FED verify + WIT sig + WPT proof', 'ok',
    'Trust chain resolved. WIT signature verified via jwks_uri. WPT proof valid. certified-idp confirmed.',
    {
      wit_iss:       witIss,
      jwks_uri:      jwksURI,
      trust_mark:    certifiedIdPMark,
      decision:      'ACCEPT',
    });

  // ── Step 9: Transaction approved ─────────────────────────────────────────
  add(9, 'Transaction verified', 'ok',
    'All checks passed. Payment cleared to RegulatoryHub.',
    { amount: '1250.00', currency: 'AUD', reference: `TXN-${Date.now()}` });

  return { steps, outcome: 'approved' };
}

// ── Scenario: multi-cloud microservices (pure WIMSE, no OID-FED) ─────────────
// Three internal services on different clouds each independently verify
// the workload's identity via WIT + WPT — no shared secrets between them.

async function runMicroservicesScenario(
  s: State,
): Promise<{ steps: ScenarioStep[]; outcome: 'approved' | 'rejected'; rejected_at?: number }> {
  const steps: ScenarioStep[] = [];
  const add = (step: number, name: string, status: 'ok' | 'rejected', detail: string, data?: Record<string, unknown>) => {
    steps.push({ step, name, status, detail, data });
  };

  const base = s.fed.baseURL;

  // Step 1: SPIRE attests workload → WIT
  const witToken = await issueWIT(s.wim);
  const { payload: witPayload } = decodeJWT(witToken);
  add(1, 'SPIRE: workload attestation → WIT', 'ok',
    `SPIRE attests the workload and issues a WIT. The IdP (${s.wim.idp.entityID}) signs it. cnf.jwk binds the workload's own public key — no other party holds the private key.`,
    { iss: witPayload.iss, sub: witPayload.sub, typ: 'wit+jwt', cnf: 'EC P-256 workload key' });

  // Step 2: SPIRE issues WAG
  const wagToken = await issueWAG(s.wim, s.wim.idp.entityID);
  const { payload: wagPayload } = decodeJWT(wagToken);
  add(2, 'SPIRE: issue WAG (Workload Authorization Grant)', 'ok',
    'SPIRE issues a scoped grant. The workload presents this to the AS to exchange for an access token. Scopes declare what services it may call.',
    { iss: wagPayload.iss, sub: wagPayload.sub, scope: wagPayload.scope, typ: 'wag+jwt' });

  // Step 3: AS validates WAG → issues AT (IdP is statically trusted — no OID-FED needed)
  const wagResult = await verifyWAG(wagToken, s.wim.spire.key.publicKey, s.wim.spire.issuer, s.wim.as.issuer);
  if (!wagResult.ok) {
    add(3, 'AS: WAG validation failed', 'rejected', wagResult.reason ?? 'WAG invalid');
    return { steps, outcome: 'rejected', rejected_at: 3 };
  }
  const cnfJWK = extractCnfJWK(witToken);
  if (!cnfJWK) {
    add(3, 'AS: issue access token', 'rejected', 'WIT missing cnf.jwk');
    return { steps, outcome: 'rejected', rejected_at: 3 };
  }
  const atToken = await issueAccessToken(s.wim, cnfJWK, wagPayload.scope as string);
  const { payload: atPayload } = decodeJWT(atToken);
  add(3, 'AS: WAG → Access Token', 'ok',
    'SPIRE is statically trusted. The AS verifies the WAG signature and issues an AT with cnf.jwk — the access token is cryptographically bound to the workload\'s public key.',
    { iss: atPayload.iss, sub: atPayload.sub, scope: atPayload.scope, typ: 'at+jwt', cnf_bound: true });

  // Step 4: Fraud Detection — Cloud A (US-East)
  const fraudURI  = `${base}/internal/fraud/check`;
  const fraudWPT  = await generateWPT(s.wim, fraudURI, witToken);
  const fraudAT   = await verifyAccessToken(atToken, s.wim.as.key.publicKey, s.wim.as.issuer, `${base}/internal`);
  if (!fraudAT.ok) {
    add(4, 'Fraud Detection (Cloud A): AT verify', 'rejected', fraudAT.reason ?? 'AT invalid');
    return { steps, outcome: 'rejected', rejected_at: 4 };
  }
  const fraudWPTR = await verifyWPT(fraudWPT, witToken, s.wim.workload.key.publicKey, fraudURI);
  if (!fraudWPTR.ok) {
    add(4, 'Fraud Detection (Cloud A): WPT verify', 'rejected', fraudWPTR.reason ?? 'WPT invalid');
    return { steps, outcome: 'rejected', rejected_at: 4 };
  }
  add(4, 'Fraud Detection — Cloud A / US-East', 'ok',
    'AT valid. WPT proves the caller holds cnf.jwk. The Fraud API shares no secret with the AS or the workload — it only needs the AS public key to verify the AT.',
    { cloud: 'Cloud A / US-East', fraud_score: 0.08, threshold: 0.75, decision: 'PASS', secrets_shared: 0 });

  // Step 5: Compliance Engine — Cloud B (EU-West)
  const compURI  = `${base}/internal/compliance`;
  const compWPT  = await generateWPT(s.wim, compURI, witToken);
  const compAT   = await verifyAccessToken(atToken, s.wim.as.key.publicKey, s.wim.as.issuer, `${base}/internal`);
  if (!compAT.ok) {
    add(5, 'Compliance Engine (Cloud B): AT verify', 'rejected', compAT.reason ?? 'AT invalid');
    return { steps, outcome: 'rejected', rejected_at: 5 };
  }
  const compWPTR = await verifyWPT(compWPT, witToken, s.wim.workload.key.publicKey, compURI);
  if (!compWPTR.ok) {
    add(5, 'Compliance Engine (Cloud B): WPT verify', 'rejected', compWPTR.reason ?? 'WPT invalid');
    return { steps, outcome: 'rejected', rejected_at: 5 };
  }
  add(5, 'Compliance Engine — Cloud B / EU-West', 'ok',
    'Independent verification on Cloud B. Same AT, fresh WPT with a different aud (this endpoint\'s URI). Compliance Engine has zero knowledge of Fraud Detection.',
    { cloud: 'Cloud B / EU-West', compliance: 'AML/KYC PASS', regulation: 'EU 2023/1114', wpt_aud: 'per-endpoint binding' });

  // Step 6: Settlement Gateway — Cloud C (APAC)
  const settlementURI  = `${base}/internal/settlement`;
  const settlementWPT  = await generateWPT(s.wim, settlementURI, witToken);
  const settlementAT   = await verifyAccessToken(atToken, s.wim.as.key.publicKey, s.wim.as.issuer, `${base}/internal`);
  if (!settlementAT.ok) {
    add(6, 'Settlement Gateway (Cloud C): AT verify', 'rejected', settlementAT.reason ?? 'AT invalid');
    return { steps, outcome: 'rejected', rejected_at: 6 };
  }
  const settlementWPTR = await verifyWPT(settlementWPT, witToken, s.wim.workload.key.publicKey, settlementURI);
  if (!settlementWPTR.ok) {
    add(6, 'Settlement Gateway (Cloud C): WPT verify', 'rejected', settlementWPTR.reason ?? 'WPT invalid');
    return { steps, outcome: 'rejected', rejected_at: 6 };
  }
  add(6, 'Settlement Gateway — Cloud C / APAC', 'ok',
    'Third independent verification. Each cloud receives the same AT but a unique WPT bound to its own endpoint URI. No cloud can replay the WPT to impersonate calls to another.',
    { cloud: 'Cloud C / APAC', settlement: 'CLEARED', amount: '1250.00', currency: 'AUD' });

  // Step 7: Complete
  add(7, 'Transaction complete', 'ok',
    '3 services across 3 clouds verified workload identity independently. Every hop has cryptographic proof. No shared secrets. No sidecar proxy. No internal CA.',
    { clouds: 3, services: 3, hops_verified: 3, shared_secrets: 0, mechanism: 'WIT + WPT + AT' });

  return { steps, outcome: 'approved' };
}

// ── Federation helpers (in-process, no HTTP) ──────────────────────────────────

async function federationResolveLeafByEntityID(
  fed: FederationState,
  entityID: string,
): Promise<{ resolveJWT: string; resolvedMeta: unknown } | null> {
  const leafMap: Record<string, LeafEntityID> = {
    [fed.entities.keycloak.id]: 'keycloak',
    [fed.entities.okta.id]:     'okta',
    [fed.entities.entra.id]:    'entra',
    [fed.entities.rp.id]:       'rp',
  };
  const leafID = leafMap[entityID];
  if (!leafID) return null;

  const builders: Record<LeafEntityID, (f: FederationState) => Promise<string>> = {
    keycloak: buildKeycloakEntityConfig,
    okta:     buildOktaEntityConfig,
    entra:    buildEntraEntityConfig,
    rp:       buildRPEntityConfig,
  };

  const ecJWT     = await builders[leafID](fed);
  const subStmt   = await buildSubordinateStatement(fed, leafID);
  const taEC      = await buildTAEntityConfig(fed);
  const { payload: ecPayload } = decodeJWT(ecJWT);
  const resolvedMeta = (ecPayload as Record<string, unknown>).metadata ?? {};
  const resolveJWT = await buildResolveResponse(fed, leafID, ecJWT, subStmt, taEC, resolvedMeta as Record<string, unknown>);
  return { resolveJWT, resolvedMeta };
}

async function getProtocolJWKS(fed: FederationState, entityID: string): Promise<CryptoKey | null> {
  const e = Object.values(fed.entities).find(ent => 'keys' in ent && (ent as { id: string }).id === entityID) as
    { id: string; keys: { federationKey: import('./crypto.js').KeyPair; protocolKey: import('./crypto.js').KeyPair } } | undefined;
  if (!e || !('keys' in e)) return null;
  return e.keys.protocolKey.publicKey;
}

// ── Router ────────────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env, _ctx?: ExecutionContext): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin':  '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, Workload-Identity-Token, Workload-Proof-Token',
        },
      });
    }

    const url  = new URL(request.url);
    const path = url.pathname;
    const s    = await getState(env.BASE_URL);
    const fed  = s.fed;

    // ── Healthcheck ───────────────────────────────────────────────────────
    if (path === '/healthz')
      return json({ status: 'ok', service: 'wimse-demo-worker' });

    // ── Scenario endpoints ────────────────────────────────────────────────
    if (path === '/api/scenario/microservices') {
      const result = await runMicroservicesScenario(s);
      return json(result);
    }

    if (path === '/api/scenario/b2b') {
      const idpParam = url.searchParams.get('idp') ?? 'keycloak';
      if (idpParam !== 'keycloak' && idpParam !== 'rogue')
        return badRequest('idp must be "keycloak" or "rogue"');
      const result = await runB2BScenario(s, idpParam);
      return json(result);
    }

    // ── State snapshot ────────────────────────────────────────────────────
    if (path === '/api/state') {
      const registry = trustMarkRegistry(fed);
      return json({
        federation: {
          trust_anchor: { id: fed.entities.ta.id },
          idps: [
            { id: fed.entities.keycloak.id, name: 'Keycloak',     marks: registry },
            { id: fed.entities.okta.id,     name: 'Okta',         marks: registry },
            { id: fed.entities.entra.id,    name: 'Entra (Azure)', marks: registry },
          ],
          rp: { id: fed.entities.rp.id, name: 'FinClear Portal' },
        },
        wimse: {
          spire_issuer:    s.wim.spire.issuer,
          as_issuer:       s.wim.as.issuer,
          workload_spiffe: s.wim.workload.spiffeID,
          idp_entity_id:   s.wim.idp.entityID,
        },
        trust_marks: registry,
      });
    }

    // ── OID-FED: Entity Configuration endpoints ───────────────────────────
    if (path === '/ta/.well-known/openid-federation')
      return jwtResp(await buildTAEntityConfig(fed), 'entity-statement+jwt');

    if (path === '/idp/keycloak/.well-known/openid-federation')
      return jwtResp(await buildKeycloakEntityConfig(fed), 'entity-statement+jwt');

    if (path === '/idp/okta/.well-known/openid-federation')
      return jwtResp(await buildOktaEntityConfig(fed), 'entity-statement+jwt');

    if (path === '/idp/entra/.well-known/openid-federation')
      return jwtResp(await buildEntraEntityConfig(fed), 'entity-statement+jwt');

    if (path === '/rp/portal/.well-known/openid-federation')
      return jwtResp(await buildRPEntityConfig(fed), 'entity-statement+jwt');

    // ── Protocol JWKS (WIT signing keys, separate from federation keys) ───
    if (path === '/idp/keycloak/protocol/openid-connect/certs')
      return json(buildJWKS(fed.entities.keycloak.keys.protocolKey.publicJWK));

    if (path === '/idp/okta/v1/keys')
      return json(buildJWKS(fed.entities.okta.keys.protocolKey.publicJWK));

    if (path === '/idp/entra/discovery/v2.0/keys')
      return json(buildJWKS(fed.entities.entra.keys.protocolKey.publicJWK));

    if (path === '/rp/portal/jwks.json')
      return json(buildJWKS(fed.entities.rp.keys.protocolKey.publicJWK));

    // ── OID-FED: Federation API ───────────────────────────────────────────
    if (path === '/ta/federation/fetch') {
      const sub    = url.searchParams.get('sub');
      const leafMap: Record<string, LeafEntityID> = {
        [fed.entities.keycloak.id]: 'keycloak',
        [fed.entities.okta.id]:     'okta',
        [fed.entities.entra.id]:    'entra',
        [fed.entities.rp.id]:       'rp',
      };
      const leafID = sub ? leafMap[sub] : undefined;
      if (!leafID) return notFound(`entity not found: ${sub}`);
      return jwtResp(await buildSubordinateStatement(fed, leafID), 'entity-statement+jwt');
    }

    if (path === '/ta/federation/list') {
      const typeFilter = url.searchParams.get('entity_type');
      const all = [
        { id: fed.entities.keycloak.id, entity_type: 'openid_provider' },
        { id: fed.entities.okta.id,     entity_type: 'openid_provider' },
        { id: fed.entities.entra.id,    entity_type: 'openid_provider' },
        { id: fed.entities.rp.id,       entity_type: 'openid_relying_party' },
      ];
      const filtered = typeFilter ? all.filter(e => e.entity_type === typeFilter) : all;
      return json({ iss: fed.entities.ta.id, iat: Math.floor(Date.now() / 1000), entities: filtered.map(e => e.id), entity_details: filtered });
    }

    if (path === '/ta/federation/resolve') {
      const sub         = url.searchParams.get('sub');
      const trustAnchor = url.searchParams.get('trust_anchor');
      if (!sub)         return badRequest('sub parameter required');
      if (!trustAnchor) return badRequest('trust_anchor parameter required');
      if (trustAnchor !== fed.entities.ta.id) return badRequest(`unknown trust_anchor: ${trustAnchor}`);
      const result = await federationResolveLeafByEntityID(fed, sub);
      if (!result) return notFound(`entity not found: ${sub}`);
      return jwtResp(result.resolveJWT, 'resolve-response+jwt');
    }

    if (path === '/ta/trust_mark_status') {
      const sub    = url.searchParams.get('sub');
      const markID = url.searchParams.get('trust_mark_id');
      if (!sub)    return badRequest('sub parameter required');
      if (!markID) return badRequest('trust_mark_id parameter required');
      const holders = trustMarkRegistry(fed)[markID] ?? [];
      return json({ active: holders.includes(sub), sub, trust_mark_id: markID, iss: fed.entities.ta.id, iat: Math.floor(Date.now() / 1000) });
    }

    if (path === '/ta/trust_mark_list') {
      const markID = url.searchParams.get('trust_mark_id');
      if (!markID) return badRequest('trust_mark_id parameter required');
      return json({ trust_mark_id: markID, iss: fed.entities.ta.id, iat: Math.floor(Date.now() / 1000), entities: trustMarkRegistry(fed)[markID] ?? [] });
    }

    // ── WIMSE: SPIRE endpoints ────────────────────────────────────────────
    if (path === '/spire/wit/issue' && request.method === 'POST') {
      const wit = await issueWIT(s.wim);
      return json({ token: wit, decoded: decodeJWT(wit) });
    }

    if (path === '/spire/wag/issue' && request.method === 'POST') {
      const wag = await issueWAG(s.wim, s.wim.idp.entityID);
      return json({ token: wag, decoded: decodeJWT(wag) });
    }

    // ── WIMSE: Authorization Server ───────────────────────────────────────
    if (path === '/as/token' && request.method === 'POST') {
      let body: Record<string, string>;
      try { body = await request.json() as Record<string, string>; }
      catch { return badRequest('invalid JSON body'); }

      const grantType = body['grant_type'];
      if (grantType !== 'urn:ietf:params:oauth:grant-type:jwt-bearer')
        return badRequest(`unsupported grant_type: ${grantType}`);

      const assertion = body['assertion'];
      if (!assertion) return badRequest('assertion required');

      const wagResult = await verifyWAG(assertion, s.wim.spire.key.publicKey, s.wim.spire.issuer, s.wim.as.issuer);
      if (!wagResult.ok) return forbidden(`WAG invalid: ${wagResult.reason}`);

      const witIss = wagResult.payload?.['wit_iss'] as string | undefined;
      if (!witIss) return badRequest('WAG missing wit_iss claim');

      const resolveResult = await federationResolveLeafByEntityID(fed, witIss);
      if (!resolveResult) return forbidden(`WIT issuer not in federation: ${witIss}`);

      const registry   = trustMarkRegistry(fed);
      const hasMark    = (registry[TRUST_MARK.certifiedIdP(fed.baseURL)] ?? []).includes(witIss);
      if (!hasMark) return forbidden(`WIT issuer ${witIss} does not hold certified-idp trust mark`);

      const cnfJWK = s.wim.workload.key.publicJWK;
      const at     = await issueAccessToken(s.wim, cnfJWK, wagResult.payload?.['scope'] as string ?? '');
      return json({ access_token: at, token_type: 'Bearer', expires_in: 3600, decoded: decodeJWT(at) });
    }

    // ── WIMSE: Internal APIs ──────────────────────────────────────────────
    if (path === '/internal/fraud/check') {
      const authHdr = request.headers.get('Authorization') ?? '';
      const atToken = authHdr.startsWith('Bearer ') ? authHdr.slice(7) : '';
      const witToken = request.headers.get('Workload-Identity-Token') ?? '';
      const wptToken = request.headers.get('Workload-Proof-Token') ?? '';

      if (!atToken)  return badRequest('Authorization: Bearer required');
      if (!witToken) return badRequest('Workload-Identity-Token required');
      if (!wptToken) return badRequest('Workload-Proof-Token required');

      const atResult = await verifyAccessToken(atToken, s.wim.as.key.publicKey, s.wim.as.issuer, `${s.wim.baseURL}/internal`);
      if (!atResult.ok) return forbidden(`AT: ${atResult.reason}`);

      const wptResult = await verifyWPT(wptToken, witToken, s.wim.workload.key.publicKey, request.url);
      if (!wptResult.ok) return forbidden(`WPT: ${wptResult.reason}`);

      return json({ fraud_score: 0.12, threshold: 0.75, decision: 'PASS' });
    }

    if (path === '/internal/compliance' && request.method === 'POST') {
      const authHdr  = request.headers.get('Authorization') ?? '';
      const atToken  = authHdr.startsWith('Bearer ') ? authHdr.slice(7) : '';
      const witToken = request.headers.get('Workload-Identity-Token') ?? '';
      const wptToken = request.headers.get('Workload-Proof-Token') ?? '';

      if (!atToken || !witToken || !wptToken)
        return badRequest('Authorization, Workload-Identity-Token, Workload-Proof-Token required');

      const atResult  = await verifyAccessToken(atToken, s.wim.as.key.publicKey, s.wim.as.issuer, `${s.wim.baseURL}/internal`);
      if (!atResult.ok) return forbidden(`AT: ${atResult.reason}`);

      const wptResult = await verifyWPT(wptToken, witToken, s.wim.workload.key.publicKey, request.url);
      if (!wptResult.ok) return forbidden(`WPT: ${wptResult.reason}`);

      return json({ compliance_status: 'COMPLIANT', regulation: 'AML/KYC' });
    }

    // ── WIMSE: RegulatoryHub B2B Partner API ──────────────────────────────
    if (path === '/partner/regulatoryhub/verify' && request.method === 'POST') {
      const witToken = request.headers.get('Workload-Identity-Token') ?? '';
      const wptToken = request.headers.get('Workload-Proof-Token') ?? '';
      if (!witToken) return badRequest('Workload-Identity-Token required');
      if (!wptToken) return badRequest('Workload-Proof-Token required');

      // Resolve the WIT issuer in the federation
      const { payload: witPayload } = decodeJWT(witToken);
      const witIss = witPayload.iss as string;

      const resolveResult = await federationResolveLeafByEntityID(fed, witIss);
      if (!resolveResult) return forbidden(`WIT issuer not in federation: ${witIss}`);

      // Get protocol JWKS for WIT verification
      const protocolKey = await getProtocolJWKS(fed, witIss);
      if (!protocolKey) return forbidden(`No protocol key for ${witIss}`);

      const witResult = await verifyWIT(witToken, protocolKey, witIss);
      if (!witResult.ok) return forbidden(`WIT: ${witResult.reason}`);

      // Verify WPT
      const cnfJWK = extractCnfJWK(witToken);
      if (!cnfJWK) return badRequest('WIT missing cnf.jwk');
      const cnfKey = await importPublicJWK(cnfJWK);
      const wptResult = await verifyWPT(wptToken, witToken, cnfKey, request.url);
      if (!wptResult.ok) return forbidden(`WPT: ${wptResult.reason}`);

      // Check trust mark
      const registry = trustMarkRegistry(fed);
      const hasMark  = (registry[TRUST_MARK.certifiedIdP(fed.baseURL)] ?? []).includes(witIss);
      if (!hasMark) return forbidden(`${witIss} does not hold certified-idp trust mark`);

      return json({ decision: 'APPROVED', sub: witPayload.sub, idp: witIss });
    }

    return notFound(`no route for ${path}`);
  },
};
