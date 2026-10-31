/**
 * Bring-your-own-key inference.
 *
 * Lets a visitor supply their own Hugging Face token so the page produces live
 * model output with no backend at all. This is the only safe way a static,
 * world-readable bundle can do live inference: the key belongs to the person
 * using it, is held in their browser, and is never sent to this project.
 *
 * Non-negotiable properties, enforced here rather than left to the caller:
 *
 *   - `BASE_URL` is a hardcoded constant. The token is attached to exactly one
 *     destination, huggingface.co. A user-supplied endpoint would turn this
 *     field into a way to talk someone into posting their own credential to an
 *     attacker's server, so the endpoint is not configurable.
 *   - Nothing is persisted unless the visitor explicitly asks. The default is
 *     memory only, which dies with the tab.
 *   - The token is never logged, never rendered, and never attached to any
 *     request to this origin.
 */

import type { HuggingFaceConfig } from '@detectionforge/core';

/** Fixed destination. The token can reach nowhere else. */
export const BASE_URL = 'https://router.huggingface.co/v1';

const STORAGE_KEY = 'dfai.byok';

export interface InferenceSettings {
  /** The visitor's own Hugging Face token. */
  readonly token: string;
  /** Any model Hugging Face can route to, optionally suffixed `:provider`. */
  readonly model: string;
  /** Persist for this tab only. Default false: memory, lost on close. */
  readonly remember: boolean;
}

export const DEFAULT_MODEL = 'meta-llama/Llama-3.3-70B-Instruct';

/**
 * Suggested models. Hugging Face routes these to whichever provider serves
 * them, so "any cloud LLM" is a matter of typing its id — the list is a
 * starting point, not a restriction.
 */
export const SUGGESTED_MODELS: readonly { id: string; label: string; note: string }[] = [
  {
    id: 'meta-llama/Llama-3.3-70B-Instruct',
    label: 'Llama 3.3 70B Instruct',
    note: 'Strong instruction following; good default for structured output.',
  },
  {
    id: 'Qwen/Qwen2.5-72B-Instruct',
    label: 'Qwen2.5 72B Instruct',
    note: 'Reliable JSON adherence.',
  },
  {
    id: 'deepseek-ai/DeepSeek-V3',
    label: 'DeepSeek V3',
    note: 'Strong reasoning on multi-stage correlation.',
  },
  {
    id: 'mistralai/Mistral-Small-24B-Instruct-2501',
    label: 'Mistral Small 24B Instruct',
    note: 'Smaller and cheaper; may need a simpler requirement.',
  },
  {
    id: 'Qwen/Qwen2.5-7B-Instruct',
    label: 'Qwen2.5 7B Instruct',
    note: 'Lowest cost; schema adherence is less reliable.',
  },
];

/** Hugging Face user access tokens are `hf_` followed by alphanumerics. */
const TOKEN_SHAPE = /^hf_[A-Za-z0-9]{10,}$/;
/** `owner/model`, optionally `:provider`. */
const MODEL_SHAPE = /^[A-Za-z0-9][\w.-]*\/[\w.-]+(?::[\w-]+)?$/;

export type SettingsProblem = 'token_missing' | 'token_shape' | 'model_missing' | 'model_shape';

export const PROBLEM_MESSAGE: Readonly<Record<SettingsProblem, string>> = {
  token_missing: 'Enter a Hugging Face access token.',
  token_shape:
    'That does not look like a Hugging Face access token. They begin with "hf_". Create one at huggingface.co/settings/tokens with the "Make calls to Inference Providers" permission.',
  model_missing: 'Choose or enter a model id.',
  model_shape: 'A model id looks like "owner/model", optionally with ":provider" to pin a provider.',
};

export function validateSettings(settings: Pick<InferenceSettings, 'token' | 'model'>): SettingsProblem[] {
  const problems: SettingsProblem[] = [];
  const token = settings.token.trim();
  const model = settings.model.trim();

  if (token.length === 0) problems.push('token_missing');
  else if (!TOKEN_SHAPE.test(token)) problems.push('token_shape');

  if (model.length === 0) problems.push('model_missing');
  else if (!MODEL_SHAPE.test(model)) problems.push('model_shape');

  return problems;
}

/**
 * Build the inference configuration the core pipeline consumes.
 *
 * `baseUrl` is the module constant, not a parameter: the call site cannot
 * redirect the token somewhere else.
 */
export function buildConfig(settings: Pick<InferenceSettings, 'token' | 'model'>): HuggingFaceConfig {
  const model = settings.model.trim();
  const [id, provider] = model.split(':');
  return {
    token: settings.token.trim(),
    model: id ?? DEFAULT_MODEL,
    fallbackModels: [],
    baseUrl: BASE_URL,
    timeoutMs: 60_000,
    maxRetries: 1,
    maxOutputTokens: 4096,
    temperature: 0.15,
    provider: provider ?? 'auto',
  };
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

interface StoredSettings {
  token: string;
  model: string;
}

/**
 * sessionStorage, not localStorage: a credential that outlives the tab on a
 * shared machine is a liability, and the visitor opted in to convenience for
 * this session, not to indefinite storage.
 */
export function loadRemembered(): StoredSettings | null {
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      typeof (parsed as StoredSettings).token !== 'string' ||
      typeof (parsed as StoredSettings).model !== 'string'
    ) {
      return null;
    }
    return { token: (parsed as StoredSettings).token, model: (parsed as StoredSettings).model };
  } catch {
    // Private browsing, blocked storage, or corrupt data: behave as if empty.
    return null;
  }
}

export function remember(settings: StoredSettings): void {
  try {
    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  } catch {
    // Storage unavailable. The in-memory copy still works for this session.
  }
}

export function forget(): void {
  try {
    window.sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing to do.
  }
}

/** Render a token for display without revealing it. */
export function maskToken(token: string): string {
  const trimmed = token.trim();
  if (trimmed.length <= 10) return '•'.repeat(Math.max(trimmed.length, 4));
  return `${trimmed.slice(0, 6)}${'•'.repeat(12)}${trimmed.slice(-3)}`;
}

/**
 * Turn a failed browser-side inference call into something actionable.
 *
 * A direct browser call has failure modes a server call does not — most
 * notably the browser refusing the cross-origin request — and a bare "network
 * error" would send someone hunting for the wrong problem.
 */
export function describeBrowserInferenceFailure(code: string, message: string): string {
  switch (code) {
    case 'unauthorized':
      return 'Hugging Face rejected the token. Check that it is current and that it carries the "Make calls to Inference Providers" permission.';
    case 'credits_exhausted':
      return 'This token has no Inference Providers credit left. Wait for the monthly allowance to reset, or add billing to the account.';
    case 'model_unavailable':
      return 'No provider is currently serving that model. Try another model id, or pin a provider with "model:provider".';
    case 'rate_limited':
      return 'Hugging Face is rate limiting this token. Wait a moment and try again.';
    case 'upstream_timeout':
      return 'The model did not respond in time. A smaller model usually answers faster.';
    case 'invalid_model_output':
      return 'The model replied, but not with the structured detection specification this application requires. Larger instruction-following models hold the schema far more reliably.';
    case 'upstream_unreachable':
    case 'network_error':
      return (
        'The browser could not reach Hugging Face. This is usually the cross-origin request being blocked, ' +
        'or an extension or network filter intercepting it. Deploying the API Worker avoids browser-side ' +
        'calls entirely.'
      );
    default:
      return message;
  }
}
