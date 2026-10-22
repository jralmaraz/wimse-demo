// Cryptographic primitives — ES256 over P-256, Web Crypto API.

export type JWK = JsonWebKey & { kid: string };

export interface KeyPair {
  privateKey: CryptoKey;
  publicKey:  CryptoKey;
  publicJWK:  JWK;
  kid:        string;
}

function b64url(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function encodeText(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export async function generateKeyPair(kid: string): Promise<KeyPair> {
  const raw = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'],
  ) as CryptoKeyPair;
  const jwkRaw = await crypto.subtle.exportKey('jwk', raw.publicKey) as JsonWebKey;
  const publicJWK: JWK = { ...jwkRaw, kid, use: 'sig', alg: 'ES256' };
  return { privateKey: raw.privateKey, publicKey: raw.publicKey, publicJWK, kid };
}

export async function signJWT(
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
  kid: string,
  typ = 'JWT',
): Promise<string> {
  const header = { alg: 'ES256', typ, kid };
  const h = b64url(encodeText(JSON.stringify(header)).buffer as ArrayBuffer);
  const p = b64url(encodeText(JSON.stringify(payload)).buffer as ArrayBuffer);
  const sigBuf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    encodeText(`${h}.${p}`),
  );
  return `${h}.${p}.${b64url(sigBuf)}`;
}

export function decodeJWT(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const [h, p] = token.split('.');
  const dec = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/')));
  return { header: dec(h), payload: dec(p) };
}

export async function verifyJWT(token: string, publicKey: CryptoKey): Promise<boolean> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const data    = encodeText(`${parts[0]}.${parts[1]}`);
    const sigBytes = Uint8Array.from(
      atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')),
      c => c.charCodeAt(0),
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sigBytes,
      data,
    );
  } catch { return false; }
}

export async function importPublicJWK(jwk: JWK): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, ['verify'],
  );
}

export async function sha256b64url(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', encodeText(s));
  return b64url(buf);
}

export function randomJTI(): string {
  return b64url(crypto.getRandomValues(new Uint8Array(16)).buffer as ArrayBuffer);
}
