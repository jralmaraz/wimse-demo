// OpenID Federation 1.0 entities for the wimse-demo.
//
// Each IdP has TWO key pairs:
//   federationKey — signs Entity Configurations and Subordinate Statements
//   protocolKey   — signs WITs (OIDC tokens); served at jwks_uri
//
// This mirrors real deployments: the OID-FED layer uses federation keys to
// establish trust; the WIMSE/OIDC layer uses protocol keys to issue/verify tokens.

import { KeyPair, JWK, signJWT } from './crypto.js';

const now = () => Math.floor(Date.now() / 1000);
const TTL = 3600;

export interface EntityKeys {
  federationKey: KeyPair;
  protocolKey:   KeyPair;
}

export interface FederationState {
  baseURL:   string;
  taKey:     KeyPair;
  entities: {
    ta:       { id: string };
    keycloak: { id: string; keys: EntityKeys };
    okta:     { id: string; keys: EntityKeys };
    entra:    { id: string; keys: EntityKeys };
    rp:       { id: string; keys: EntityKeys };
  };
}

export type LeafEntityID = 'keycloak' | 'okta' | 'entra' | 'rp';

export const TRUST_MARK = {
  certifiedIdP:     (base: string) => `${base}/ta/trust-mark/certified-idp`,
  treasuryApproved: (base: string) => `${base}/ta/trust-mark/treasury-approved`,
  verifiedRP:       (base: string) => `${base}/ta/trust-mark/verified-rp`,
};

// Trust mark registry — keyed by mark ID, value is entity IDs that hold the mark.
export function trustMarkRegistry(s: FederationState): Record<string, string[]> {
  return {
    [TRUST_MARK.certifiedIdP(s.baseURL)]:     [s.entities.keycloak.id, s.entities.okta.id],
    [TRUST_MARK.treasuryApproved(s.baseURL)]: [s.entities.entra.id],
    [TRUST_MARK.verifiedRP(s.baseURL)]:       [s.entities.rp.id],
  };
}

// ── Trust Mark JWT ────────────────────────────────────────────────────────────

export async function buildTrustMark(
  s: FederationState,
  entityID: string,
  markID: string,
): Promise<string> {
  return signJWT(
    { iss: s.entities.ta.id, sub: entityID, id: markID, iat: now(), exp: now() + TTL },
    s.taKey.privateKey, s.taKey.kid, 'trust-mark+jwt',
  );
}

// ── Entity Configuration builders ────────────────────────────────────────────

export async function buildTAEntityConfig(s: FederationState): Promise<string> {
  const iss = s.entities.ta.id;
  return signJWT({
    iss, sub: iss, iat: now(), exp: now() + TTL,
    jwks: { keys: [s.taKey.publicJWK] },
    metadata: {
      federation_entity: {
        organization_name: 'FinClear Federation Authority',
        federation_fetch_endpoint:   `${iss}/federation/fetch`,
        federation_list_endpoint:    `${iss}/federation/list`,
        federation_resolve_endpoint: `${iss}/federation/resolve`,
        trust_mark_status_endpoint:  `${iss}/trust_mark_status`,
        trust_mark_list_endpoint:    `${iss}/trust_mark_list`,
        trust_mark_issuers: {
          [TRUST_MARK.certifiedIdP(s.baseURL)]:     [iss],
          [TRUST_MARK.treasuryApproved(s.baseURL)]: [iss],
          [TRUST_MARK.verifiedRP(s.baseURL)]:       [iss],
        },
      },
    },
  }, s.taKey.privateKey, s.taKey.kid, 'federation+jwt');
}

export async function buildKeycloakEntityConfig(s: FederationState): Promise<string> {
  const iss  = s.entities.keycloak.id;
  const keys = s.entities.keycloak.keys;
  const markID   = TRUST_MARK.certifiedIdP(s.baseURL);
  const trustMark = await buildTrustMark(s, iss, markID);
  return signJWT({
    iss, sub: iss, iat: now(), exp: now() + TTL,
    jwks:            { keys: [keys.federationKey.publicJWK] },
    authority_hints: [s.entities.ta.id],
    trust_marks:     [{ id: markID, trust_mark: trustMark }],
    metadata: {
      openid_provider: {
        issuer: iss,
        authorization_endpoint: `${iss}/protocol/openid-connect/auth`,
        token_endpoint:         `${iss}/protocol/openid-connect/token`,
        jwks_uri:               `${iss}/protocol/openid-connect/certs`,
        id_token_signing_alg_values_supported: ['ES256'],
        organization_name: 'FinClear Internal IdP (Keycloak)',
      },
      federation_entity: { organization_name: 'FinClear Internal IdP (Keycloak)' },
    },
  }, keys.federationKey.privateKey, keys.federationKey.kid, 'federation+jwt');
}

export async function buildOktaEntityConfig(s: FederationState): Promise<string> {
  const iss  = s.entities.okta.id;
  const keys = s.entities.okta.keys;
  const markID   = TRUST_MARK.certifiedIdP(s.baseURL);
  const trustMark = await buildTrustMark(s, iss, markID);
  return signJWT({
    iss, sub: iss, iat: now(), exp: now() + TTL,
    jwks:            { keys: [keys.federationKey.publicJWK] },
    authority_hints: [s.entities.ta.id],
    trust_marks:     [{ id: markID, trust_mark: trustMark }],
    metadata: {
      openid_provider: {
        issuer: iss,
        authorization_endpoint: `${iss}/v1/authorize`,
        token_endpoint:         `${iss}/v1/token`,
        jwks_uri:               `${iss}/v1/keys`,
        organization_name: 'FinClear Partner Network (Okta)',
      },
      federation_entity: { organization_name: 'FinClear Partner Network (Okta)' },
    },
  }, keys.federationKey.privateKey, keys.federationKey.kid, 'federation+jwt');
}

export async function buildEntraEntityConfig(s: FederationState): Promise<string> {
  const iss  = s.entities.entra.id;
  const keys = s.entities.entra.keys;
  const markID   = TRUST_MARK.treasuryApproved(s.baseURL);
  const trustMark = await buildTrustMark(s, iss, markID);
  return signJWT({
    iss, sub: iss, iat: now(), exp: now() + TTL,
    jwks:            { keys: [keys.federationKey.publicJWK] },
    authority_hints: [s.entities.ta.id],
    trust_marks:     [{ id: markID, trust_mark: trustMark }],
    metadata: {
      openid_provider: {
        issuer: iss,
        authorization_endpoint: `${iss}/oauth2/v2.0/authorize`,
        token_endpoint:         `${iss}/oauth2/v2.0/token`,
        jwks_uri:               `${iss}/discovery/v2.0/keys`,
        organization_name: 'FinClear Treasury (Entra)',
      },
      federation_entity: { organization_name: 'FinClear Treasury (Entra)' },
    },
  }, keys.federationKey.privateKey, keys.federationKey.kid, 'federation+jwt');
}

export async function buildRPEntityConfig(s: FederationState): Promise<string> {
  const iss  = s.entities.rp.id;
  const keys = s.entities.rp.keys;
  const markID   = TRUST_MARK.verifiedRP(s.baseURL);
  const trustMark = await buildTrustMark(s, iss, markID);
  return signJWT({
    iss, sub: iss, iat: now(), exp: now() + TTL,
    jwks:            { keys: [keys.federationKey.publicJWK] },
    authority_hints: [s.entities.ta.id],
    trust_marks:     [{ id: markID, trust_mark: trustMark }],
    metadata: {
      openid_relying_party: {
        client_name:    'FinClear Portal',
        redirect_uris:  [`${iss}/callback`],
        response_types: ['code'],
        jwks_uri:       `${iss}/jwks.json`,
      },
      federation_entity: { organization_name: 'FinClear Portal' },
    },
  }, keys.federationKey.privateKey, keys.federationKey.kid, 'federation+jwt');
}

// ── Subordinate Statement ────────────────────────────────────────────────────

export async function buildSubordinateStatement(
  s: FederationState,
  leafID: LeafEntityID,
): Promise<string> {
  const sub   = s.entities[leafID].id;
  const fedKey = s.entities[leafID].keys.federationKey;
  return signJWT({
    iss: s.entities.ta.id, sub,
    iat: now(), exp: now() + TTL,
    jwks: { keys: [fedKey.publicJWK] },
    metadata_policy: {},
    source_endpoint: `${s.entities.ta.id}/federation/fetch`,
  }, s.taKey.privateKey, s.taKey.kid, 'federation+jwt');
}

// ── Resolve Response ─────────────────────────────────────────────────────────

export async function buildResolveResponse(
  s: FederationState,
  leafID: LeafEntityID,
  ecJWT: string,
  subStmtJWT: string,
  taEC: string,
  resolvedMetadata: Record<string, unknown>,
): Promise<string> {
  return signJWT({
    iss: s.entities.ta.id,
    sub: s.entities[leafID].id,
    iat: now(), exp: now() + TTL,
    trust_anchor: s.entities.ta.id,
    trust_chain: [ecJWT, subStmtJWT, taEC],
    metadata: resolvedMetadata,
  }, s.taKey.privateKey, s.taKey.kid, 'resolve-response+jwt');
}

// ── Protocol JWKS ────────────────────────────────────────────────────────────

export function buildJWKS(key: JWK): { keys: JWK[] } {
  return { keys: [key] };
}
