/**
 * DetectionForge AI — API layer (Cloudflare Worker).
 *
 * Responsibilities, in order, for every inference request:
 *   1. CORS allowlist + security headers
 *   2. body size limit
 *   3. authentication (session bearer token or shared API key) + CSRF header
 *   4. per-subject sliding-window rate limit
 *   5. per-subject daily cost quota
 *   6. hand off to the core pipeline, which sanitises, applies guardrails,
 *      calls Hugging Face, validates output and renders all seven formats
 *   7. safe error mapping — no stack traces, no upstream bodies, no secrets
 *
 * The Hugging Face token exists only in this Worker's environment. It is never
 * placed in a response body, a log line, or an error message.
 */

import {
  APP_NAME,
  APP_SUBTITLE,
  COMMERCIAL_NOTICE,
  GenerationError,
  LIMITS,
  LOG_SOURCES,
  MAX_USE_CASES_PER_REQUEST,
  OFF_TOPIC_REJECTION_MESSAGE,
  PLATFORMS,
  PLATFORM_IDS,
  SEVERITIES,
  SYSTEM_PROMPT_VERSION,
  VALIDATION_DISCLAIMER,
  VALIDATION_STATUSES,
  VALIDATION_STATUS_LABEL,
  VENDORS,
  generateDetections,
  type ErrorCode,
} from '@detectionforge/core';
import { readConfig, type Env, type RuntimeConfig } from './env.js';
import { authenticate, issueSession, randomId, type AuthFailure } from './auth.js';
import { Limiter } from './ratelimit.js';
import { log } from './log.js';
import { REQUEST_ID_HEADER, isOriginAllowed, withSecurityHeaders } from './security.js';
import { API_PREFIX, ROUTES } from './routes.js';

const HTTP_STATUS: Readonly<Record<ErrorCode, number>> = {
  bad_request: 400,
  off_topic: 422,
  unsafe_input: 422,
  payload_too_large: 413,
  unauthorized: 401,
  forbidden_origin: 403,
  rate_limited: 429,
  quota_exceeded: 429,
  model_unavailable: 503,
  credits_exhausted: 503,
  upstream_timeout: 504,
  invalid_model_output: 502,
  missing_credentials: 503,
  internal_error: 500,
};

function jsonResponse(body: unknown, status: number, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders },
  });
}

function errorResponse(
  code: ErrorCode,
  message: string,
  requestId: string,
  options: { details?: readonly string[]; retryAfterSeconds?: number } = {},
): Response {
  const headers: Record<string, string> = {};
  if (options.retryAfterSeconds !== undefined) headers['Retry-After'] = String(options.retryAfterSeconds);
  return jsonResponse(
    {
      ok: false,
      code,
      message,
      requestId,
      ...(options.details && options.details.length > 0 ? { details: [...options.details] } : {}),
      ...(options.retryAfterSeconds !== undefined ? { retryAfterSeconds: options.retryAfterSeconds } : {}),
    },
    HTTP_STATUS[code],
    headers,
  );
}

const AUTH_MESSAGES: Readonly<Record<AuthFailure, string>> = {
  missing_credentials: 'A session token is required. Call POST /api/v1/session first.',
  malformed_token: 'The session token is malformed. Request a new session.',
  bad_signature: 'The session token signature is invalid. Request a new session.',
  expired: 'The session token has expired. Request a new session.',
  csrf_mismatch: 'The request is missing a valid X-DFAI-CSRF header for this session.',
  unknown_api_key: 'The supplied API key is not recognised.',
  server_misconfigured:
    'The API is not configured for authenticated requests: SESSION_SIGNING_KEY is not set on the backend.',
};

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

function handleHealth(config: RuntimeConfig, limiter: Limiter, requestId: string): Response {
  return jsonResponse(
    {
      ok: true,
      application: APP_NAME,
      status: 'operational',
      // Deployment posture is reported honestly: "demo" means no token is set
      // and responses come from a labelled synthetic fixture.
      mode: config.mode,
      model: config.publicModelName,
      promptVersion: SYSTEM_PROMPT_VERSION,
      authenticationConfigured: config.sessionSigningKey !== undefined,
      apiKeyAuthEnabled: config.apiAccessKeys.length > 0,
      rateLimitDurable: limiter.durable,
      corsAllowlistConfigured: config.allowedOrigins.length > 0,
      supportedPlatforms: PLATFORM_IDS.length,
      maxUseCasesPerRequest: MAX_USE_CASES_PER_REQUEST,
      requestId,
    },
    200,
  );
}

function handleCatalog(requestId: string): Response {
  return jsonResponse(
    {
      ok: true,
      requestId,
      application: { name: APP_NAME, subtitle: APP_SUBTITLE, promptVersion: SYSTEM_PROMPT_VERSION },
      vendors: VENDORS,
      logSources: LOG_SOURCES,
      platforms: PLATFORM_IDS.map((id) => ({
        id,
        product: PLATFORMS[id].product,
        language: PLATFORMS[id].language,
        highlight: PLATFORMS[id].highlight,
        fileExtension: PLATFORMS[id].fileExtension,
        standaloneQueryIsDeployable: PLATFORMS[id].standaloneQueryIsDeployable,
        notes: PLATFORMS[id].notes,
      })),
      severities: SEVERITIES,
      validationStatuses: VALIDATION_STATUSES.map((id) => ({ id, label: VALIDATION_STATUS_LABEL[id] })),
      limits: {
        requirementMinChars: LIMITS.requirementMinChars,
        requirementMaxChars: LIMITS.requirementMaxChars,
        maxUseCasesPerRequest: MAX_USE_CASES_PER_REQUEST,
      },
      notices: {
        commercial: COMMERCIAL_NOTICE,
        offTopicRejection: OFF_TOPIC_REJECTION_MESSAGE,
        validationDisclaimer: VALIDATION_DISCLAIMER,
      },
    },
    200,
  );
}

async function handleSession(config: RuntimeConfig, requestId: string): Promise<Response> {
  const session = await issueSession(config);
  if (session === null) {
    log('error', 'session.misconfigured', { requestId });
    return errorResponse(
      'missing_credentials',
      AUTH_MESSAGES.server_misconfigured,
      requestId,
    );
  }
  return jsonResponse(
    {
      ok: true,
      requestId,
      token: session.token,
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt,
      tokenType: 'Bearer',
      mode: config.mode,
    },
    201,
  );
}

async function handleGenerate(
  request: Request,
  config: RuntimeConfig,
  limiter: Limiter,
  requestId: string,
): Promise<Response> {
  // --- body size limit ------------------------------------------------------
  const declaredLength = Number.parseInt(request.headers.get('content-length') ?? '', 10);
  if (Number.isFinite(declaredLength) && declaredLength > LIMITS.maxRequestBytes) {
    return errorResponse('payload_too_large', 'The request body is too large.', requestId);
  }

  const contentType = request.headers.get('content-type') ?? '';
  if (!contentType.toLowerCase().includes('application/json')) {
    return errorResponse('bad_request', 'Content-Type must be application/json.', requestId);
  }

  const rawBody = await request.text();
  if (rawBody.length > LIMITS.maxRequestBytes) {
    return errorResponse('payload_too_large', 'The request body is too large.', requestId);
  }

  // --- authentication -------------------------------------------------------
  const auth = await authenticate(request, config);
  if (!auth.ok) {
    log('warn', 'auth.rejected', { requestId, reason: auth.reason });
    const code: ErrorCode = auth.reason === 'server_misconfigured' ? 'missing_credentials' : 'unauthorized';
    return errorResponse(code, AUTH_MESSAGES[auth.reason], requestId);
  }

  // --- rate limit -----------------------------------------------------------
  const rate = await limiter.checkRate(auth.subject);
  if (!rate.allowed) {
    log('warn', 'ratelimit.exceeded', { requestId, kind: auth.kind, limit: rate.limit });
    return errorResponse(
      'rate_limited',
      `Rate limit exceeded: at most ${rate.limit} generations per ${config.rateLimit.windowSeconds} seconds. ` +
        'Please wait and try again.',
      requestId,
      { retryAfterSeconds: rate.retryAfterSeconds },
    );
  }

  // --- daily cost quota -----------------------------------------------------
  const quota = await limiter.checkQuota(auth.subject);
  if (!quota.allowed) {
    log('warn', 'quota.exceeded', { requestId, kind: auth.kind, limit: quota.limit });
    return errorResponse(
      'quota_exceeded',
      `Daily generation quota of ${quota.limit} requests has been used for this session. ` +
        `The quota resets at ${quota.resetsAt}.`,
      requestId,
    );
  }

  // --- parse body -----------------------------------------------------------
  let payload: unknown;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return errorResponse('bad_request', 'The request body is not valid JSON.', requestId);
  }

  // --- generate -------------------------------------------------------------
  try {
    const outcome = await generateDetections(
      payload,
      { mode: config.mode, huggingFace: config.huggingFace },
      { requestId },
    );

    log('info', 'generate.ok', {
      requestId,
      mode: outcome.telemetry.mode,
      model: outcome.telemetry.model,
      attempts: outcome.telemetry.attempts,
      usedFallback: outcome.telemetry.usedFallback,
      useCases: outcome.response.useCases.length,
      truncated: outcome.response.truncatedUseCases,
      clarified: outcome.response.clarifyingQuestion !== null,
      // Counts only: raw requirement text is never logged.
      redactions: outcome.telemetry.redactionCount,
      quotaUsed: quota.used,
    });

    return jsonResponse(outcome.response, 200, {
      'X-DFAI-RateLimit-Remaining': String(rate.remaining),
      'X-DFAI-Quota-Remaining': String(Math.max(0, quota.limit - quota.used)),
    });
  } catch (error) {
    if (error instanceof GenerationError) {
      log(error.code === 'off_topic' ? 'info' : 'warn', 'generate.rejected', {
        requestId,
        code: error.code,
        guardrail: error.guardrailCategory ?? null,
      });
      return errorResponse(error.code, error.message, requestId, {
        details: error.details,
        ...(error.retryAfterSeconds !== undefined ? { retryAfterSeconds: error.retryAfterSeconds } : {}),
      });
    }
    // Unknown failures are logged (redacted) but never surfaced in detail.
    log('error', 'generate.unhandled', {
      requestId,
      message: error instanceof Error ? error.message : 'non-error thrown',
    });
    return errorResponse('internal_error', 'An unexpected error occurred while generating the detection.', requestId);
  }
}

// ---------------------------------------------------------------------------
// Worker entry point
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const config = readConfig(env);
    const limiter = new Limiter(
      { ...config.rateLimit, dailyQuota: config.dailyQuota },
      env.RATE_LIMIT_KV,
    );
    const requestId = request.headers.get(REQUEST_ID_HEADER)?.replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64) || randomId(12);
    const origin = request.headers.get('origin');
    const url = new URL(request.url);

    const finish = (response: Response): Response => withSecurityHeaders(response, origin, config, requestId);

    // Preflight.
    if (request.method === 'OPTIONS') {
      if (!isOriginAllowed(origin, config)) {
        return finish(new Response(null, { status: 403 }));
      }
      return finish(new Response(null, { status: 204 }));
    }

    // Origin allowlist for every cross-origin browser call.
    if (!isOriginAllowed(origin, config)) {
      log('warn', 'cors.rejected', { requestId, path: url.pathname });
      return finish(
        errorResponse('forbidden_origin', 'This origin is not permitted to call the API.', requestId),
      );
    }

    try {
      if (request.method === 'GET' && url.pathname === ROUTES.health) {
        return finish(handleHealth(config, limiter, requestId));
      }
      if (request.method === 'GET' && url.pathname === ROUTES.catalog) {
        return finish(handleCatalog(requestId));
      }
      if (request.method === 'POST' && url.pathname === ROUTES.session) {
        return finish(await handleSession(config, requestId));
      }
      if (request.method === 'POST' && url.pathname === ROUTES.generate) {
        return finish(await handleGenerate(request, config, limiter, requestId));
      }
      if (url.pathname === '/' || url.pathname === `${API_PREFIX}`) {
        return finish(
          jsonResponse(
            {
              ok: true,
              application: APP_NAME,
              subtitle: APP_SUBTITLE,
              endpoints: [
                `GET ${ROUTES.health}`,
                `GET ${ROUTES.catalog}`,
                `POST ${ROUTES.session}`,
                `POST ${ROUTES.generate}`,
              ],
              requestId,
            },
            200,
          ),
        );
      }
      return finish(errorResponse('bad_request', 'Unknown endpoint.', requestId));
    } catch (error) {
      log('error', 'router.unhandled', {
        requestId,
        message: error instanceof Error ? error.message : 'non-error thrown',
      });
      return finish(errorResponse('internal_error', 'An unexpected error occurred.', requestId));
    }
  },
};
