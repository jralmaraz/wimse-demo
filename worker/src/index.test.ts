import { describe, it, expect } from 'vitest';
import worker from './index.js';

const BASE_URL = 'http://localhost:8787';
const env = { BASE_URL };

function req(path: string, method = 'GET', body?: unknown): Request {
  return new Request(`${BASE_URL}${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function getJSON(path: string) {
  const r = await worker.fetch(req(path), env, {} as ExecutionContext);
  return r.json();
}

async function getText(path: string) {
  const r = await worker.fetch(req(path), env, {} as ExecutionContext);
  return { status: r.status, text: await r.text(), ct: r.headers.get('content-type') };
}

function decodePayload(jwt: string) {
  return JSON.parse(atob(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
}

// ── Health ────────────────────────────────────────────────────────────────────

describe('healthz', () => {
  it('returns ok', async () => {
    const d = await getJSON('/healthz') as { status: string };
    expect(d.status).toBe('ok');
  });
});

// ── OID-FED Entity Configurations ────────────────────────────────────────────

describe('Entity Configuration endpoints', () => {
  it('TA EC is entity-statement+jwt', async () => {
    const { ct, text } = await getText('/ta/.well-known/openid-federation');
    expect(ct).toContain('entity-statement');
    expect(text.split('.')).toHaveLength(3);
  });

  it('TA EC declares all federation API endpoints', async () => {
    const { text } = await getText('/ta/.well-known/openid-federation');
    const p = decodePayload(text);
    const fe = p.metadata?.federation_entity;
    expect(fe.federation_fetch_endpoint).toContain('/federation/fetch');
    expect(fe.federation_resolve_endpoint).toContain('/federation/resolve');
    expect(fe.trust_mark_status_endpoint).toContain('/trust_mark_status');
  });

  it('Keycloak EC declares certified-idp trust mark', async () => {
    const { text } = await getText('/idp/keycloak/.well-known/openid-federation');
    const p = decodePayload(text);
    expect(p.trust_marks?.[0]?.id).toContain('certified-idp');
    expect(p.metadata?.openid_provider?.jwks_uri).toContain('/certs');
  });

  it('Entra EC declares treasury-approved trust mark', async () => {
    const { text } = await getText('/idp/entra/.well-known/openid-federation');
    const p = decodePayload(text);
    expect(p.trust_marks?.[0]?.id).toContain('treasury-approved');
  });
});

// ── Protocol JWKS (two-key architecture) ─────────────────────────────────────

describe('Protocol JWKS — separate from federation keys', () => {
  it('Keycloak protocol JWKS returns ES256 key', async () => {
    const d = await getJSON('/idp/keycloak/protocol/openid-connect/certs') as { keys: { kty: string; crv: string }[] };
    expect(d.keys).toHaveLength(1);
    expect(d.keys[0].kty).toBe('EC');
    expect(d.keys[0].crv).toBe('P-256');
  });

  it('Keycloak federation key differs from protocol key', async () => {
    const ecText = (await getText('/idp/keycloak/.well-known/openid-federation')).text;
    const fedJWK = decodePayload(ecText).jwks?.keys?.[0];
    const protJWKS = await getJSON('/idp/keycloak/protocol/openid-connect/certs') as { keys: { kid: string }[] };
    expect(fedJWK.kid).not.toBe(protJWKS.keys[0].kid);
  });
});

// ── Federation API ────────────────────────────────────────────────────────────

describe('Federation API — fetch + list + resolve', () => {
  it('fetch returns SubStmt for keycloak', async () => {
    const state = await getJSON('/api/state') as { federation: { idps: { id: string }[] } };
    const kcID = state.federation.idps[0].id;
    const { ct, text } = await getText(`/ta/federation/fetch?sub=${encodeURIComponent(kcID)}`);
    expect(ct).toContain('entity-statement');
    expect(decodePayload(text).sub).toBe(kcID);
  });

  it('list returns 4 entities', async () => {
    const d = await getJSON('/ta/federation/list') as { entities: string[] };
    expect(d.entities).toHaveLength(4);
  });

  it('list filtered by openid_provider returns 3', async () => {
    const d = await getJSON('/ta/federation/list?entity_type=openid_provider') as { entities: string[] };
    expect(d.entities).toHaveLength(3);
  });

  it('resolve returns resolve-response+jwt for keycloak', async () => {
    const state = await getJSON('/api/state') as { federation: { idps: { id: string }[]; trust_anchor: { id: string } } };
    const sub = state.federation.idps[0].id;
    const ta  = state.federation.trust_anchor.id;
    const { ct, text } = await getText(`/ta/federation/resolve?sub=${encodeURIComponent(sub)}&trust_anchor=${encodeURIComponent(ta)}`);
    expect(ct).toContain('resolve-response');
    const p = decodePayload(text);
    expect(p.sub).toBe(sub);
    expect((p.trust_chain as string[]).length).toBe(3);
    expect(p.metadata).toBeTruthy();
  });

  it('resolve 400 without trust_anchor', async () => {
    const state = await getJSON('/api/state') as { federation: { idps: { id: string }[] } };
    const { status } = await getText(`/ta/federation/resolve?sub=${encodeURIComponent(state.federation.idps[0].id)}`);
    expect(status).toBe(400);
  });

  it('resolve 404 for unknown entity', async () => {
    const state = await getJSON('/api/state') as { federation: { trust_anchor: { id: string } } };
    const ta = state.federation.trust_anchor.id;
    const { status } = await getText(`/ta/federation/resolve?sub=https://unknown.example.com&trust_anchor=${encodeURIComponent(ta)}`);
    expect(status).toBe(404);
  });
});

// ── Trust Mark API ────────────────────────────────────────────────────────────

describe('Trust Mark API', () => {
  it('trust_mark_status active for Keycloak certified-idp', async () => {
    const state = await getJSON('/api/state') as { federation: { idps: { id: string }[] }; trust_marks: Record<string, string[]> };
    const sub    = state.federation.idps[0].id;
    const markID = Object.keys(state.trust_marks).find(k => k.includes('certified-idp'))!;
    const d = await getJSON(`/ta/trust_mark_status?sub=${encodeURIComponent(sub)}&trust_mark_id=${encodeURIComponent(markID)}`) as { active: boolean };
    expect(d.active).toBe(true);
  });

  it('trust_mark_status inactive for Entra certified-idp', async () => {
    const state = await getJSON('/api/state') as { federation: { idps: { id: string }[] }; trust_marks: Record<string, string[]> };
    const entraID = state.federation.idps[2].id;
    const markID  = Object.keys(state.trust_marks).find(k => k.includes('certified-idp'))!;
    const d = await getJSON(`/ta/trust_mark_status?sub=${encodeURIComponent(entraID)}&trust_mark_id=${encodeURIComponent(markID)}`) as { active: boolean };
    expect(d.active).toBe(false);
  });
});

// ── WIMSE SPIRE + AS ──────────────────────────────────────────────────────────

describe('WIMSE: SPIRE + AS', () => {
  it('SPIRE issues a valid WIT with cnf.jwk', async () => {
    const d = await (await worker.fetch(req('/spire/wit/issue', 'POST'), env, {} as ExecutionContext)).json() as { decoded: { payload: { iss: string; cnf: { jwk: object } } } };
    expect(d.decoded.payload.iss).toContain('/idp/keycloak');
    expect(d.decoded.payload.cnf?.jwk).toBeTruthy();
  });

  it('SPIRE issues a WAG with wit_iss claim', async () => {
    const d = await (await worker.fetch(req('/spire/wag/issue', 'POST'), env, {} as ExecutionContext)).json() as { decoded: { payload: { wit_iss: string } } };
    expect(d.decoded.payload.wit_iss).toContain('/idp/keycloak');
  });

  it('AS token exchange succeeds with valid WAG + trusted IdP', async () => {
    const wag = await (await worker.fetch(req('/spire/wag/issue', 'POST'), env, {} as ExecutionContext)).json() as { token: string };
    const r = await worker.fetch(req('/as/token', 'POST', {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion:  wag.token,
    }), env, {} as ExecutionContext);
    expect(r.status).toBe(200);
    const d = await r.json() as { access_token: string; decoded: { payload: { iss: string } } };
    expect(d.access_token).toBeTruthy();
    expect(d.decoded.payload.iss).toContain('/as');
  });

  it('AS rejects unknown grant_type', async () => {
    const r = await worker.fetch(req('/as/token', 'POST', { grant_type: 'client_credentials' }), env, {} as ExecutionContext);
    expect(r.status).toBe(400);
  });
});

// ── Scenario endpoint ─────────────────────────────────────────────────────────

describe('Scenario: B2B payment flow', () => {
  it('Keycloak scenario: all 9 steps pass, outcome = approved', async () => {
    const d = await getJSON('/api/scenario/b2b?idp=keycloak') as {
      steps: { step: number; status: string }[];
      outcome: string;
    };
    expect(d.outcome).toBe('approved');
    expect(d.steps).toHaveLength(9);
    d.steps.forEach(s => expect(s.status).toBe('ok'));
  });

  it('Rogue IdP scenario: rejected at AS (step 4), outcome = rejected', async () => {
    const d = await getJSON('/api/scenario/b2b?idp=rogue') as {
      steps: { step: number; status: string }[];
      outcome: string;
      rejected_at?: number;
    };
    expect(d.outcome).toBe('rejected');
    expect(d.rejected_at).toBe(4);
    // Steps 1–3 are ok, step 4 is the rejection
    const step4 = d.steps.find(s => s.step === 4);
    expect(step4?.status).toBe('rejected');
  });

  it('invalid idp param returns 400', async () => {
    const { status } = await getText('/api/scenario/b2b?idp=unknown');
    expect(status).toBe(400);
  });
});

// ── CORS + 404 ────────────────────────────────────────────────────────────────

describe('CORS + 404', () => {
  it('OPTIONS returns CORS headers', async () => {
    const r = await worker.fetch(
      new Request(`${BASE_URL}/api/state`, { method: 'OPTIONS' }),
      env, {} as ExecutionContext,
    );
    expect(r.headers.get('access-control-allow-origin')).toBe('*');
  });

  it('unknown route returns 404', async () => {
    const { status } = await getText('/does-not-exist');
    expect(status).toBe(404);
  });
});
