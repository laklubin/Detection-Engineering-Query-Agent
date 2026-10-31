/**
 * Authentication and authorisation for inference requests.
 *
 * Two mechanisms, both header based:
 *
 *   1. Browser sessions — the frontend calls POST /api/v1/session and receives
 *      a short-lived HMAC-signed bearer token plus a bound CSRF value. The
 *      token is opaque, carries no privileges beyond "may call generate", and
 *      expires. It is held in memory by the SPA, never in a cookie, so
 *      cross-site request forgery is structurally impossible; the CSRF header
 *      is still required as defence in depth.
 *
 *   2. Shared API keys — optional machine-to-machine access via X-API-Key,
 *      compared in constant time against the configured allowlist.
 *
 * No mechanism ever exposes the Hugging Face token or any other secret.
 */

import type { RuntimeConfig } from './env.js';

const TOKEN_VERSION = 'v1';
const encoder = new TextEncoder();

export interface SessionClaims {
  /** Opaque session identifier used as the rate-limit and quota subject. */
  readonly sid: string;
  /** Issued-at, seconds since epoch. */
  readonly iat: number;
  /** Expiry, seconds since epoch. */
  readonly exp: number;
}

export interface IssuedSession {
  readonly token: string;
  readonly csrfToken: string;
  readonly expiresAt: string;
  readonly sessionId: string;
}

export type AuthFailure =
  | 'missing_credentials'
  | 'malformed_token'
  | 'bad_signature'
  | 'expired'
  | 'csrf_mismatch'
  | 'unknown_api_key'
  | 'server_misconfigured';

export interface AuthSuccess {
  readonly ok: true;
  /** Rate-limit / quota subject. */
  readonly subject: string;
  readonly kind: 'session' | 'api_key';
}

export interface AuthRejection {
  readonly ok: false;
  readonly reason: AuthFailure;
}

export type AuthResult = AuthSuccess | AuthRejection;

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlEncodeString(value: string): string {
  return base64UrlEncode(encoder.encode(value));
}

function base64UrlDecodeString(value: string): string | null {
  try {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

/** Length-independent comparison to avoid leaking a prefix match. */
export function constantTimeEquals(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const length = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;
  for (let i = 0; i < length; i += 1) {
    diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  }
  return diff === 0;
}

async function importKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
}

async function hmac(secret: string, message: string): Promise<string> {
  const key = await importKey(secret);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return base64UrlEncode(new Uint8Array(signature));
}

export function randomId(byteLength = 16): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

// ---------------------------------------------------------------------------
// Session issuing / verification
// ---------------------------------------------------------------------------

export async function issueSession(config: RuntimeConfig, now = Date.now()): Promise<IssuedSession | null> {
  if (!config.sessionSigningKey) return null;

  const issuedAt = Math.floor(now / 1000);
  const claims: SessionClaims = {
    sid: randomId(18),
    iat: issuedAt,
    exp: issuedAt + config.sessionTtlSeconds,
  };
  const payload = base64UrlEncodeString(JSON.stringify(claims));
  const signature = await hmac(config.sessionSigningKey, `${TOKEN_VERSION}.${payload}`);
  const csrfToken = await hmac(config.sessionSigningKey, `csrf.${claims.sid}`);

  return {
    token: `${TOKEN_VERSION}.${payload}.${signature}`,
    csrfToken,
    expiresAt: new Date(claims.exp * 1000).toISOString(),
    sessionId: claims.sid,
  };
}

export async function verifySessionToken(
  token: string,
  config: RuntimeConfig,
  now = Date.now(),
): Promise<{ ok: true; claims: SessionClaims } | { ok: false; reason: AuthFailure }> {
  if (!config.sessionSigningKey) return { ok: false, reason: 'server_misconfigured' };

  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== TOKEN_VERSION) return { ok: false, reason: 'malformed_token' };
  const [, payload, signature] = parts as [string, string, string];

  const expected = await hmac(config.sessionSigningKey, `${TOKEN_VERSION}.${payload}`);
  if (!constantTimeEquals(signature, expected)) return { ok: false, reason: 'bad_signature' };

  const decoded = base64UrlDecodeString(payload);
  if (decoded === null) return { ok: false, reason: 'malformed_token' };

  let claims: SessionClaims;
  try {
    const parsed: unknown = JSON.parse(decoded);
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      typeof (parsed as SessionClaims).sid !== 'string' ||
      typeof (parsed as SessionClaims).exp !== 'number' ||
      typeof (parsed as SessionClaims).iat !== 'number'
    ) {
      return { ok: false, reason: 'malformed_token' };
    }
    claims = parsed as SessionClaims;
  } catch {
    return { ok: false, reason: 'malformed_token' };
  }

  if (claims.exp * 1000 <= now) return { ok: false, reason: 'expired' };
  return { ok: true, claims };
}

/**
 * Authorise a request. Returns the rate-limit subject on success.
 */
export async function authenticate(
  request: Request,
  config: RuntimeConfig,
  now = Date.now(),
): Promise<AuthResult> {
  const apiKey = request.headers.get('x-api-key');
  if (apiKey !== null && apiKey.length > 0) {
    if (config.apiAccessKeys.length === 0) return { ok: false, reason: 'unknown_api_key' };
    const matched = config.apiAccessKeys.some((candidate) => constantTimeEquals(candidate, apiKey));
    if (!matched) return { ok: false, reason: 'unknown_api_key' };
    // Subject is derived from the key so one key cannot exhaust another's quota,
    // and the key itself is never used as a log or storage identifier.
    const digest = await hmac(config.sessionSigningKey ?? 'unsigned', `apikey.${apiKey}`);
    return { ok: true, subject: `key:${digest.slice(0, 24)}`, kind: 'api_key' };
  }

  const authorization = request.headers.get('authorization') ?? '';
  const bearer = /^Bearer\s+(.+)$/i.exec(authorization.trim());
  if (!bearer?.[1]) return { ok: false, reason: 'missing_credentials' };

  const verified = await verifySessionToken(bearer[1], config, now);
  if (!verified.ok) return { ok: false, reason: verified.reason };

  if (!config.sessionSigningKey) return { ok: false, reason: 'server_misconfigured' };
  const expectedCsrf = await hmac(config.sessionSigningKey, `csrf.${verified.claims.sid}`);
  const presented = request.headers.get('x-dfai-csrf') ?? '';
  if (!constantTimeEquals(presented, expectedCsrf)) return { ok: false, reason: 'csrf_mismatch' };

  return { ok: true, subject: `sid:${verified.claims.sid}`, kind: 'session' };
}
