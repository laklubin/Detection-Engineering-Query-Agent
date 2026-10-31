/**
 * Environment binding parsing.
 *
 * Secrets are read from the Worker environment and never leave this module in
 * raw form. Nothing here is echoed into a response body, a log line, or an
 * error message.
 */

import type { HuggingFaceConfig } from '@detectionforge/core';

export interface Env {
  // --- secrets (Worker secrets / .dev.vars) --------------------------------
  HF_TOKEN?: string;
  SESSION_SIGNING_KEY?: string;
  API_ACCESS_KEYS?: string;

  // --- non-secret vars ----------------------------------------------------
  HF_MODEL?: string;
  HF_MODEL_FALLBACKS?: string;
  HF_PROVIDER?: string;
  HF_BASE_URL?: string;
  HF_TIMEOUT_MS?: string;
  HF_MAX_RETRIES?: string;
  HF_MAX_OUTPUT_TOKENS?: string;
  HF_TEMPERATURE?: string;
  ALLOWED_ORIGINS?: string;
  RATE_LIMIT_REQUESTS?: string;
  RATE_LIMIT_WINDOW_SECONDS?: string;
  DAILY_QUOTA_PER_SESSION?: string;
  SESSION_TTL_SECONDS?: string;

  // --- optional bindings ---------------------------------------------------
  RATE_LIMIT_KV?: KVNamespace;
}

export interface RuntimeConfig {
  readonly mode: 'live' | 'demo';
  readonly huggingFace: HuggingFaceConfig | undefined;
  readonly allowedOrigins: readonly string[];
  readonly rateLimit: { readonly requests: number; readonly windowSeconds: number };
  readonly dailyQuota: number;
  readonly sessionTtlSeconds: number;
  readonly sessionSigningKey: string | undefined;
  readonly apiAccessKeys: readonly string[];
  /** Public, non-secret model identifier for the health endpoint. */
  readonly publicModelName: string | null;
}

function intVar(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(value ?? '', 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function floatVar(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseFloat(value ?? '');
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function csv(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
}

const DEFAULT_MODEL = 'meta-llama/Llama-3.3-70B-Instruct';
const DEFAULT_BASE_URL = 'https://router.huggingface.co/v1';

export function readConfig(env: Env): RuntimeConfig {
  const token = (env.HF_TOKEN ?? '').trim();
  const model = (env.HF_MODEL ?? '').trim() || DEFAULT_MODEL;
  const live = token.length > 0;

  const huggingFace: HuggingFaceConfig | undefined = live
    ? {
        token,
        model,
        fallbackModels: csv(env.HF_MODEL_FALLBACKS),
        baseUrl: (env.HF_BASE_URL ?? '').trim() || DEFAULT_BASE_URL,
        timeoutMs: intVar(env.HF_TIMEOUT_MS, 45_000, 5_000, 120_000),
        maxRetries: intVar(env.HF_MAX_RETRIES, 2, 0, 5),
        maxOutputTokens: intVar(env.HF_MAX_OUTPUT_TOKENS, 4096, 512, 16_384),
        temperature: floatVar(env.HF_TEMPERATURE, 0.15, 0, 1),
        provider: (env.HF_PROVIDER ?? '').trim() || 'auto',
      }
    : undefined;

  return {
    mode: live ? 'live' : 'demo',
    huggingFace,
    allowedOrigins: csv(env.ALLOWED_ORIGINS),
    rateLimit: {
      requests: intVar(env.RATE_LIMIT_REQUESTS, 10, 1, 1000),
      windowSeconds: intVar(env.RATE_LIMIT_WINDOW_SECONDS, 300, 10, 86_400),
    },
    dailyQuota: intVar(env.DAILY_QUOTA_PER_SESSION, 40, 1, 100_000),
    sessionTtlSeconds: intVar(env.SESSION_TTL_SECONDS, 3600, 60, 86_400),
    sessionSigningKey: (env.SESSION_SIGNING_KEY ?? '').trim() || undefined,
    apiAccessKeys: csv(env.API_ACCESS_KEYS),
    publicModelName: live ? model : null,
  };
}
