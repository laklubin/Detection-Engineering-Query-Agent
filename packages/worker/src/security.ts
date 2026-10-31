/**
 * HTTP security: CORS allowlisting, response headers and Content Security
 * Policy for the API surface.
 */

import type { RuntimeConfig } from './env.js';

/** API responses are JSON only; the CSP locks the response context down hard. */
const API_CSP = [
  "default-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'Content-Security-Policy': API_CSP,
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Resource-Policy': 'same-site',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'geolocation=(), camera=(), microphone=(), payment=(), usb=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Cache-Control': 'no-store, no-cache, must-revalidate',
  Pragma: 'no-cache',
};

export const CSRF_HEADER = 'x-dfai-csrf';
export const REQUEST_ID_HEADER = 'x-dfai-request-id';

/**
 * Exact-match origin allowlist. No wildcards and no suffix matching, so a
 * look-alike origin such as `https://evil-laklubin.github.io` cannot pass.
 */
export function isOriginAllowed(origin: string | null, config: RuntimeConfig): boolean {
  if (origin === null) return true; // non-browser client (curl, server-to-server)
  return config.allowedOrigins.includes(origin);
}

export function corsHeaders(origin: string | null, config: RuntimeConfig): Record<string, string> {
  const headers: Record<string, string> = {
    Vary: 'Origin',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': `Content-Type, Authorization, X-API-Key, ${CSRF_HEADER}`,
    'Access-Control-Max-Age': '600',
    'Access-Control-Expose-Headers': `${REQUEST_ID_HEADER}, Retry-After`,
  };
  if (origin !== null && config.allowedOrigins.includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    // No credentials are used: auth travels in an Authorization header, so
    // cookies are never attached and CSRF is structurally not applicable.
    headers['Access-Control-Allow-Credentials'] = 'false';
  }
  return headers;
}

export function withSecurityHeaders(
  response: Response,
  origin: string | null,
  config: RuntimeConfig,
  requestId: string,
): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) headers.set(key, value);
  for (const [key, value] of Object.entries(corsHeaders(origin, config))) headers.set(key, value);
  headers.set(REQUEST_ID_HEADER, requestId);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
