/**
 * Hugging Face Inference Providers client.
 *
 * Uses the official OpenAI-compatible Inference Providers router
 * (`POST {baseUrl}/chat/completions`), which is the currently supported entry
 * point for serverless chat completions on Hugging Face. No deprecated
 * endpoint is used and no model availability is hardcoded: the primary model
 * and its fallbacks are supplied by backend configuration.
 *
 * Operational guarantees:
 *   - hard request timeout via AbortController
 *   - bounded retries with exponential backoff and jitter
 *   - explicit, distinguishable error codes (quota, credits, unavailable, ...)
 *   - prompt content is never logged
 *   - never fabricates a completion when inference fails
 */

import type { ErrorCode } from '../schemas.js';

export interface ChatMessage {
  readonly role: 'system' | 'user';
  readonly content: string;
}

export interface HuggingFaceConfig {
  /** Backend-only secret. Never returned to a client. */
  readonly token: string;
  readonly model: string;
  readonly fallbackModels: readonly string[];
  readonly baseUrl: string;
  readonly timeoutMs: number;
  readonly maxRetries: number;
  readonly maxOutputTokens: number;
  readonly temperature: number;
  /** Optional provider pin; "auto" lets Hugging Face route. */
  readonly provider?: string | undefined;
}

export interface InferenceResult {
  readonly content: string;
  /** Model that actually produced the completion. */
  readonly model: string;
  readonly attempts: number;
  readonly usedFallback: boolean;
}

export class InferenceError extends Error {
  readonly code: ErrorCode;
  readonly retryAfterSeconds?: number;
  readonly httpStatus?: number;

  constructor(code: ErrorCode, message: string, options: { retryAfterSeconds?: number; httpStatus?: number } = {}) {
    super(message);
    this.name = 'InferenceError';
    this.code = code;
    if (options.retryAfterSeconds !== undefined) this.retryAfterSeconds = options.retryAfterSeconds;
    if (options.httpStatus !== undefined) this.httpStatus = options.httpStatus;
  }
}

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface ClientDeps {
  readonly fetchImpl?: FetchLike;
  readonly sleep?: (ms: number) => Promise<void>;
  /** Injectable jitter source for deterministic tests. */
  readonly random?: () => number;
}

const DEFAULT_SLEEP = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Error text patterns that identify an exhausted free credit allowance. */
const CREDITS_PATTERNS = [
  /exceeded your (?:monthly )?(?:included )?credits/i,
  /monthly (?:included )?credits/i,
  /payment required/i,
  /quota exceeded/i,
  /insufficient (?:credits|balance|funds)/i,
  /billing/i,
];

const MODEL_UNAVAILABLE_PATTERNS = [
  /model .*(?:not found|does not exist|is not supported)/i,
  /no provider.*available/i,
  /not supported (?:for|by) .*provider/i,
  /currently loading/i,
  /model is overloaded/i,
  /service unavailable/i,
];

function classifyHttp(status: number, body: string): { code: ErrorCode; retryable: boolean; tryFallback: boolean } {
  if (status === 401 || status === 403) {
    return { code: 'unauthorized', retryable: false, tryFallback: false };
  }
  if (status === 402) {
    return { code: 'credits_exhausted', retryable: false, tryFallback: false };
  }
  if (status === 404 || status === 400) {
    // A 400 from the router most often means the model/provider pair is invalid.
    const unavailable = MODEL_UNAVAILABLE_PATTERNS.some((re) => re.test(body)) || status === 404;
    return { code: unavailable ? 'model_unavailable' : 'bad_request', retryable: false, tryFallback: unavailable };
  }
  if (status === 429) {
    if (CREDITS_PATTERNS.some((re) => re.test(body))) {
      return { code: 'credits_exhausted', retryable: false, tryFallback: false };
    }
    return { code: 'rate_limited', retryable: true, tryFallback: false };
  }
  if (status === 503 || status === 502 || status === 504) {
    return { code: 'model_unavailable', retryable: true, tryFallback: true };
  }
  if (status >= 500) {
    return { code: 'model_unavailable', retryable: true, tryFallback: false };
  }
  return { code: 'internal_error', retryable: false, tryFallback: false };
}

interface ChatCompletionChoice {
  message?: { content?: unknown };
  finish_reason?: unknown;
}
interface ChatCompletionBody {
  choices?: ChatCompletionChoice[];
  model?: unknown;
  error?: unknown;
}

function extractContent(payload: unknown): { content: string; model: string | null; finishReason: string | null } {
  if (typeof payload !== 'object' || payload === null) {
    throw new InferenceError('invalid_model_output', 'Inference response was not a JSON object.');
  }
  const body = payload as ChatCompletionBody;
  const choice = Array.isArray(body.choices) ? body.choices[0] : undefined;
  const content = choice?.message?.content;
  if (typeof content !== 'string' || content.trim().length === 0) {
    throw new InferenceError('invalid_model_output', 'Inference response contained no completion text.');
  }
  return {
    content,
    model: typeof body.model === 'string' ? body.model : null,
    finishReason: typeof choice?.finish_reason === 'string' ? choice.finish_reason : null,
  };
}

function backoffMs(attempt: number, random: () => number): number {
  const base = Math.min(8000, 500 * 2 ** attempt);
  return Math.round(base * (0.7 + random() * 0.6));
}

/**
 * Perform a chat completion. Throws `InferenceError` with a precise code on
 * every failure path; it never returns synthetic content.
 */
export async function createChatCompletion(
  config: HuggingFaceConfig,
  messages: readonly ChatMessage[],
  deps: ClientDeps = {},
): Promise<InferenceResult> {
  if (!config.token || config.token.trim().length === 0) {
    throw new InferenceError('missing_credentials', 'No Hugging Face token is configured on the backend.');
  }

  const doFetch: FetchLike = deps.fetchImpl ?? ((input, init) => fetch(input, init));
  const sleep = deps.sleep ?? DEFAULT_SLEEP;
  const random = deps.random ?? Math.random;

  const candidates = [config.model, ...config.fallbackModels].filter(
    (m, i, arr) => typeof m === 'string' && m.length > 0 && arr.indexOf(m) === i,
  );
  const url = `${config.baseUrl.replace(/\/+$/, '')}/chat/completions`;

  let attempts = 0;
  let lastError: InferenceError | null = null;

  for (const [modelIndex, model] of candidates.entries()) {
    let useJsonMode = true;

    for (let attempt = 0; attempt <= config.maxRetries; attempt += 1) {
      attempts += 1;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), config.timeoutMs);

      try {
        const requestBody: Record<string, unknown> = {
          model: config.provider && config.provider !== 'auto' ? `${model}:${config.provider}` : model,
          messages: messages.map((m) => ({ role: m.role, content: m.content })),
          max_tokens: config.maxOutputTokens,
          temperature: config.temperature,
          stream: false,
        };
        if (useJsonMode) requestBody['response_format'] = { type: 'json_object' };

        const response = await doFetch(url, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${config.token}`,
            'Content-Type': 'application/json',
            Accept: 'application/json',
            'X-Client-Name': 'detectionforge-ai',
          },
          body: JSON.stringify(requestBody),
          signal: controller.signal,
        });

        if (!response.ok) {
          const raw = await response.text().catch(() => '');
          const snippet = raw.slice(0, 600);
          const { code, retryable, tryFallback } = classifyHttp(response.status, snippet);

          // Some providers reject JSON mode; retry once without it.
          if (useJsonMode && response.status === 400 && /response_format|json_object|json_schema/i.test(snippet)) {
            useJsonMode = false;
            attempt -= 1;
            continue;
          }

          const retryAfterHeader = response.headers.get('retry-after');
          const retryAfterSeconds = retryAfterHeader ? Number.parseInt(retryAfterHeader, 10) : undefined;
          lastError = new InferenceError(code, describeUpstream(code, response.status), {
            httpStatus: response.status,
            ...(Number.isFinite(retryAfterSeconds) ? { retryAfterSeconds: retryAfterSeconds as number } : {}),
          });

          if (retryable && attempt < config.maxRetries) {
            await sleep(backoffMs(attempt, random));
            continue;
          }
          if (tryFallback && modelIndex < candidates.length - 1) break;
          throw lastError;
        }

        const payload: unknown = await response.json().catch(() => null);
        const { content, model: servedModel, finishReason } = extractContent(payload);
        if (finishReason === 'length') {
          throw new InferenceError(
            'invalid_model_output',
            'The model hit the output token limit before completing a valid response. ' +
              'Reduce the scope of the requirement and try again.',
          );
        }
        return {
          content,
          model: servedModel ?? model,
          attempts,
          usedFallback: modelIndex > 0,
        };
      } catch (error) {
        if (error instanceof InferenceError) {
          lastError = error;
          if (error.code === 'invalid_model_output' && attempt < config.maxRetries) {
            await sleep(backoffMs(attempt, random));
            continue;
          }
          if (error.code === 'model_unavailable' && modelIndex < candidates.length - 1) break;
          throw error;
        }
        const aborted =
          (error as { name?: string }).name === 'AbortError' || (error as { name?: string }).name === 'TimeoutError';
        // A transport failure is not the service reporting a problem: nothing
        // was received at all. Reporting it as "model unavailable" sends the
        // caller looking at the model when the real cause is connectivity, a
        // blocked cross-origin request, or an intercepting proxy.
        lastError = aborted
          ? new InferenceError(
              'upstream_timeout',
              `The inference request exceeded the ${Math.round(config.timeoutMs / 1000)}s timeout.`,
            )
          : new InferenceError('upstream_unreachable', 'The inference service could not be reached.');
        if (attempt < config.maxRetries) {
          await sleep(backoffMs(attempt, random));
          continue;
        }
        if (modelIndex < candidates.length - 1) break;
        throw lastError;
      } finally {
        clearTimeout(timer);
      }
    }
  }

  throw lastError ?? new InferenceError('internal_error', 'Inference failed for an unknown reason.');
}

/** User-facing description per error code. Contains no upstream body text. */
function describeUpstream(code: ErrorCode, status: number): string {
  switch (code) {
    case 'unauthorized':
      return 'The backend Hugging Face token was rejected. It is missing, expired or lacks the Inference Providers permission.';
    case 'credits_exhausted':
      return 'The Hugging Face inference credits for this deployment are exhausted. Detection generation is paused until the allowance resets or billing is enabled.';
    case 'rate_limited':
      return 'Hugging Face is rate limiting this deployment. Please retry shortly.';
    case 'model_unavailable':
      return 'The configured inference model is not currently available through Hugging Face Inference Providers.';
    case 'bad_request':
      return `The inference provider rejected the request (HTTP ${status}).`;
    default:
      return `The inference provider returned HTTP ${status}.`;
  }
}

/**
 * Extract the first balanced JSON object from model text.
 *
 * Models sometimes wrap JSON in prose or code fences even when told not to.
 * This is a scanner, not an evaluator: nothing is executed, and the result is
 * still schema-validated by the caller.
 */
export function extractJsonObject(text: string): string {
  const trimmed = text.trim();
  const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(trimmed);
  const candidate = fenced?.[1]?.trim() ?? trimmed;

  const start = candidate.indexOf('{');
  if (start === -1) {
    throw new InferenceError('invalid_model_output', 'The model response contained no JSON object.');
  }

  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < candidate.length; i += 1) {
    const ch = candidate[i] as string;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (inString) {
      if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return candidate.slice(start, i + 1);
    }
  }
  throw new InferenceError('invalid_model_output', 'The model response contained an unterminated JSON object.');
}
