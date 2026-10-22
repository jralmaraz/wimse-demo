// WIMSE token issuance and verification:
//   WIT  — Workload Identity Token  (typ: wit+jwt)
//   WAG  — Workload Authorization Grant (typ: wag+jwt)
//   WPT  — Workload Proof Token     (typ: application/wpt+jwt)
//   AT   — Access Token             (typ: at+jwt)
//
// WIT is signed by the IdP's protocol key (not the federation key).
// WPT is signed by the workload's own key (cnf.jwk in the WIT).

import { KeyPair, JWK, signJWT, decodeJWT, verifyJWT, sha256b64url, randomJTI } from './crypto.js';

const now = () => Math.floor(Date.now() / 1000);
const TTL_WIT = 3600;
const TTL_WAG = 300;
const TTL_WPT = 300;
const TTL_AT  = 3600;

export interface WimseState {
  baseURL: string;
  spire: {
    issuer:   string;
    key:      KeyPair;
  };
  as: {
    issuer:   string;
    key:      KeyPair;
  };
  // The workload (transaction-processor) has its own key pair.
  // cnf.jwk in the WIT embeds the workload public key.
  // The workload signs WPTs with its private key.
  workload: {
    spiffeID: string;   // spiffe://finclear.io/workload/transaction-processor
    key:      KeyPair;
  };
  // Reference to the Keycloak IdP protocol key — SPIRE uses it to issue WITs.
  idp: {
    entityID:    string;
    protocolKey: KeyPair;
  };
}

// ── WIT ───────────────────────────────────────────────────────────────────────
// Issued by the IdP (Keycloak). Contains cnf.jwk = workload public key.
// The WIT iss identifies the federation entity whose jwks_uri holds the signing key.

export async function issueWIT(s: WimseState): Promise<string> {
  return signJWT({
    iss:    s.idp.entityID,
    sub:    s.workload.spiffeID,
    aud:    [s.as.issuer],
    iat:    now(),
    exp:    now() + TTL_WIT,
    jti:    randomJTI(),
    cnf:    { jwk: s.workload.key.publicJWK },
  }, s.idp.protocolKey.privateKey, s.idp.protocolKey.kid, 'wit+jwt');
}

// ── WAG ───────────────────────────────────────────────────────────────────────
// Issued by SPIRE. References the WIT's issuer so the AS can do a federation check.

export async function issueWAG(s: WimseState, witIss: string): Promise<string> {
  return signJWT({
    iss:     s.spire.issuer,
    sub:     s.workload.spiffeID,
    aud:     [s.as.issuer],
    iat:     now(),
    exp:     now() + TTL_WAG,
    jti:     randomJTI(),
    scope:   'fraud:read compliance:write partner:verify',
    // wit_iss tells the AS which IdP issued the WIT for this workload,
    // so the AS can call federation/resolve before issuing the access token.
    wit_iss: witIss,
  }, s.spire.key.privateKey, s.spire.key.kid, 'wag+jwt');
}

// ── Access Token ──────────────────────────────────────────────────────────────
// Issued by the AS after validating the WAG and the OID-FED trust chain.
// Embeds cnf.jwk so APIs can bind WPT verification to the access token.

export async function issueAccessToken(
  s: WimseState,
  workloadCnfJWK: JWK,
  scope: string,
): Promise<string> {
  return signJWT({
    iss:   s.as.issuer,
    sub:   s.workload.spiffeID,
    aud:   [s.baseURL + '/internal', s.baseURL + '/partner'],
    iat:   now(),
    exp:   now() + TTL_AT,
    jti:   randomJTI(),
    scope,
    cnf:   { jwk: workloadCnfJWK },
  }, s.as.key.privateKey, s.as.key.kid, 'at+jwt');
}

// ── WPT ───────────────────────────────────────────────────────────────────────
// Signed by the workload's private key. Proves the workload controls cnf.jwk.

export async function generateWPT(
  s: WimseState,
  targetURI: string,
  witToken: string,
): Promise<string> {
  const wth = await sha256b64url(witToken);
  return signJWT({
    aud: [targetURI],
    iat: now(),
    exp: now() + TTL_WPT,
    jti: randomJTI(),
    wth,
  }, s.workload.key.privateKey, s.workload.key.kid, 'application/wpt+jwt');
}

// ── Validation helpers ────────────────────────────────────────────────────────

export function extractCnfJWK(token: string): JWK | null {
  try {
    const { payload } = decodeJWT(token);
    const cnf = payload.cnf as { jwk?: JWK } | undefined;
    return cnf?.jwk ?? null;
  } catch { return null; }
}

export async function verifyWAG(
  token: string,
  spirePublicKey: CryptoKey,
  spireIssuer: string,
  asIssuer: string,
): Promise<{ ok: boolean; reason?: string; payload?: Record<string, unknown> }> {
  const { header, payload } = decodeJWT(token);
  if (payload.iss !== spireIssuer) return { ok: false, reason: `wrong iss: ${payload.iss}` };
  if (!Array.isArray(payload.aud) || !(payload.aud as string[]).includes(asIssuer))
    return { ok: false, reason: 'aud does not include AS issuer' };
  const t = header.typ as string | undefined;
  if (t !== 'wag+jwt') return { ok: false, reason: `wrong typ: ${t}` };
  const exp = payload.exp as number;
  if (exp < now()) return { ok: false, reason: 'WAG expired' };
  const valid = await verifyJWT(token, spirePublicKey);
  if (!valid) return { ok: false, reason: 'WAG signature invalid' };
  return { ok: true, payload };
}

export async function verifyWIT(
  token: string,
  idpPublicKey: CryptoKey,
  expectedIss: string,
): Promise<{ ok: boolean; reason?: string; payload?: Record<string, unknown> }> {
  const { header, payload } = decodeJWT(token);
  if (payload.iss !== expectedIss) return { ok: false, reason: `wrong iss: ${payload.iss}` };
  const t = header.typ as string | undefined;
  if (t !== 'wit+jwt') return { ok: false, reason: `wrong typ: ${t}` };
  const exp = payload.exp as number;
  if (exp < now()) return { ok: false, reason: 'WIT expired' };
  const valid = await verifyJWT(token, idpPublicKey);
  if (!valid) return { ok: false, reason: 'WIT signature invalid' };
  return { ok: true, payload };
}

export async function verifyWPT(
  wptToken: string,
  witToken: string,
  workloadPublicKey: CryptoKey,
  targetURI: string,
): Promise<{ ok: boolean; reason?: string }> {
  const { header, payload } = decodeJWT(wptToken);
  const t = header.typ as string | undefined;
  if (t !== 'application/wpt+jwt') return { ok: false, reason: `wrong typ: ${t}` };
  const exp = payload.exp as number;
  if (exp < now()) return { ok: false, reason: 'WPT expired' };
  // aud check
  const aud = payload.aud as string[] | string;
  const audList = Array.isArray(aud) ? aud : [aud];
  if (!audList.includes(targetURI)) return { ok: false, reason: `WPT aud mismatch: ${audList.join(',')}` };
  // wth check
  const expectedWth = await sha256b64url(witToken);
  if (payload.wth !== expectedWth) return { ok: false, reason: 'wth mismatch' };
  // sig
  const valid = await verifyJWT(wptToken, workloadPublicKey);
  if (!valid) return { ok: false, reason: 'WPT signature invalid' };
  return { ok: true };
}

export async function verifyAccessToken(
  token: string,
  asPublicKey: CryptoKey,
  asIssuer: string,
  requiredAudPrefix: string,
): Promise<{ ok: boolean; reason?: string; payload?: Record<string, unknown> }> {
  const { header, payload } = decodeJWT(token);
  if (payload.iss !== asIssuer) return { ok: false, reason: `wrong iss: ${payload.iss}` };
  const t = header.typ as string | undefined;
  if (t !== 'at+jwt') return { ok: false, reason: `wrong typ: ${t}` };
  const exp = payload.exp as number;
  if (exp < now()) return { ok: false, reason: 'AT expired' };
  const aud = payload.aud as string[];
  if (!aud.some(a => a.startsWith(requiredAudPrefix)))
    return { ok: false, reason: 'aud does not include required audience' };
  const valid = await verifyJWT(token, asPublicKey);
  if (!valid) return { ok: false, reason: 'AT signature invalid' };
  return { ok: true, payload };
}
