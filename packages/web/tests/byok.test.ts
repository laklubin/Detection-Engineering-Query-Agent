import { afterEach, describe, expect, it } from 'vitest';
import {
  BASE_URL,
  DEFAULT_MODEL,
  SUGGESTED_MODELS,
  buildConfig,
  describeBrowserInferenceFailure,
  forget,
  loadRemembered,
  maskToken,
  remember,
  validateSettings,
} from '../src/lib/byok.js';

const GOOD_TOKEN = 'hf_AbCdEfGhIjKlMnOpQrStUvWx0123';

afterEach(() => {
  window.sessionStorage.clear();
  window.localStorage.clear();
});

describe('validateSettings', () => {
  it('accepts a well-formed token and model', () => {
    expect(validateSettings({ token: GOOD_TOKEN, model: DEFAULT_MODEL })).toEqual([]);
  });

  it('accepts a provider-pinned model', () => {
    expect(validateSettings({ token: GOOD_TOKEN, model: `${DEFAULT_MODEL}:together` })).toEqual([]);
  });

  it('reports a missing token', () => {
    expect(validateSettings({ token: '   ', model: DEFAULT_MODEL })).toEqual(['token_missing']);
  });

  it('reports a token that is not Hugging Face shaped', () => {
    expect(validateSettings({ token: 'sk-not-a-hf-token-value', model: DEFAULT_MODEL })).toEqual(['token_shape']);
  });

  it('reports a malformed model id', () => {
    for (const model of ['notowner', 'owner/model/extra', 'owner model', '../../etc']) {
      expect(validateSettings({ token: GOOD_TOKEN, model }), model).toContain('model_shape');
    }
  });

  it('reports a missing model', () => {
    expect(validateSettings({ token: GOOD_TOKEN, model: '' })).toEqual(['model_missing']);
  });

  it('suggests only well-formed model ids', () => {
    for (const suggestion of SUGGESTED_MODELS) {
      expect(validateSettings({ token: GOOD_TOKEN, model: suggestion.id }), suggestion.id).toEqual([]);
    }
  });
});

describe('buildConfig', () => {
  it('pins the destination so the token cannot be redirected', () => {
    const config = buildConfig({ token: GOOD_TOKEN, model: DEFAULT_MODEL });
    expect(config.baseUrl).toBe(BASE_URL);
    expect(config.baseUrl.startsWith('https://router.huggingface.co')).toBe(true);
  });

  it('splits a provider suffix out of the model id', () => {
    const config = buildConfig({ token: GOOD_TOKEN, model: 'owner/model:together' });
    expect(config.model).toBe('owner/model');
    expect(config.provider).toBe('together');
  });

  it('defaults the provider to auto', () => {
    expect(buildConfig({ token: GOOD_TOKEN, model: 'owner/model' }).provider).toBe('auto');
  });

  it('trims surrounding whitespace from the token', () => {
    expect(buildConfig({ token: `  ${GOOD_TOKEN}  `, model: DEFAULT_MODEL }).token).toBe(GOOD_TOKEN);
  });

  it('carries a bounded timeout and retry budget', () => {
    const config = buildConfig({ token: GOOD_TOKEN, model: DEFAULT_MODEL });
    expect(config.timeoutMs).toBeGreaterThan(0);
    expect(config.timeoutMs).toBeLessThanOrEqual(120_000);
    expect(config.maxRetries).toBeLessThanOrEqual(2);
    expect(config.fallbackModels).toEqual([]);
  });
});

describe('storage', () => {
  it('round-trips a remembered key through session storage only', () => {
    remember({ token: GOOD_TOKEN, model: DEFAULT_MODEL });
    expect(loadRemembered()).toEqual({ token: GOOD_TOKEN, model: DEFAULT_MODEL });
    // Never local storage: that would outlive the tab on a shared machine.
    expect(window.localStorage.length).toBe(0);
  });

  it('returns null when nothing is stored', () => {
    expect(loadRemembered()).toBeNull();
  });

  it('returns null for corrupt stored data rather than throwing', () => {
    window.sessionStorage.setItem('dfai.byok', '{not json');
    expect(loadRemembered()).toBeNull();
    window.sessionStorage.setItem('dfai.byok', JSON.stringify({ token: 42 }));
    expect(loadRemembered()).toBeNull();
  });

  it('forgets on request', () => {
    remember({ token: GOOD_TOKEN, model: DEFAULT_MODEL });
    forget();
    expect(loadRemembered()).toBeNull();
  });
});

describe('maskToken', () => {
  it('never reveals the middle of a token', () => {
    const masked = maskToken(GOOD_TOKEN);
    expect(masked).not.toBe(GOOD_TOKEN);
    expect(masked).not.toContain(GOOD_TOKEN.slice(8, 20));
    expect(masked).toContain('•');
  });

  it('fully masks a short value', () => {
    expect(maskToken('hf_abc')).toMatch(/^•+$/);
  });
});

describe('describeBrowserInferenceFailure', () => {
  it('explains a blocked cross-origin call rather than saying "network error"', () => {
    const message = describeBrowserInferenceFailure('network_error', 'Failed to fetch');
    expect(message).toMatch(/cross-origin/i);
    expect(message).toMatch(/Worker/);
  });

  it('gives actionable text for each known code', () => {
    for (const code of [
      'unauthorized',
      'credits_exhausted',
      'model_unavailable',
      'rate_limited',
      'upstream_timeout',
      'invalid_model_output',
    ]) {
      expect(describeBrowserInferenceFailure(code, 'raw').length, code).toBeGreaterThan(30);
    }
  });

  it('falls back to the raw message for an unknown code', () => {
    expect(describeBrowserInferenceFailure('something_else', 'raw message')).toBe('raw message');
  });
});
