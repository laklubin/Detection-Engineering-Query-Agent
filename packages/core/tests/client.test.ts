import { describe, expect, it, vi } from 'vitest';
import {
  InferenceError,
  createChatCompletion,
  extractJsonObject,
  type FetchLike,
  type HuggingFaceConfig,
} from '../src/llm/client.js';

const CONFIG: HuggingFaceConfig = {
  token: 'hf_test_token_value_placeholder',
  model: 'primary/model',
  fallbackModels: ['fallback/model'],
  baseUrl: 'https://router.huggingface.co/v1',
  timeoutMs: 1000,
  maxRetries: 2,
  maxOutputTokens: 1024,
  temperature: 0.1,
  provider: 'auto',
};

const MESSAGES = [
  { role: 'system' as const, content: 'system instructions' },
  { role: 'user' as const, content: 'user data' },
];

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function textResponse(body: string, status: number, headers: Record<string, string> = {}): Response {
  return new Response(body, { status, headers });
}

function completion(content: string, model = 'primary/model'): Response {
  return jsonResponse({ model, choices: [{ message: { content }, finish_reason: 'stop' }] });
}

const noSleep = { sleep: async () => {}, random: () => 0.5 };

describe('createChatCompletion — success paths', () => {
  it('calls the official Inference Providers chat-completions route', async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
      calls.push({ url, init });
      return completion('{"status":"ok"}');
    };

    const result = await createChatCompletion(CONFIG, MESSAGES, { fetchImpl, ...noSleep });

    expect(result.content).toBe('{"status":"ok"}');
    expect(result.usedFallback).toBe(false);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('https://router.huggingface.co/v1/chat/completions');
    expect(calls[0]?.init.method).toBe('POST');
  });

  it('sends the bearer token only in the Authorization header', async () => {
    let captured: RequestInit | undefined;
    const fetchImpl: FetchLike = async (_url, init) => {
      captured = init;
      return completion('{}');
    };
    await createChatCompletion(CONFIG, MESSAGES, { fetchImpl, ...noSleep });

    const headers = captured?.headers as Record<string, string>;
    expect(headers['Authorization']).toBe(`Bearer ${CONFIG.token}`);
    expect(String(captured?.body)).not.toContain(CONFIG.token);
  });

  it('requests JSON mode and honours the output token budget', async () => {
    let body: Record<string, unknown> = {};
    const fetchImpl: FetchLike = async (_url, init) => {
      body = JSON.parse(String(init.body)) as Record<string, unknown>;
      return completion('{}');
    };
    await createChatCompletion(CONFIG, MESSAGES, { fetchImpl, ...noSleep });

    expect(body['response_format']).toEqual({ type: 'json_object' });
    expect(body['max_tokens']).toBe(1024);
    expect(body['stream']).toBe(false);
  });

  it('pins the provider when one is configured', async () => {
    let body: Record<string, unknown> = {};
    const fetchImpl: FetchLike = async (_url, init) => {
      body = JSON.parse(String(init.body)) as Record<string, unknown>;
      return completion('{}');
    };
    await createChatCompletion({ ...CONFIG, provider: 'together' }, MESSAGES, { fetchImpl, ...noSleep });
    expect(body['model']).toBe('primary/model:together');
  });
});

describe('createChatCompletion — credential and quota failures', () => {
  it('refuses to call out when no token is configured', async () => {
    const fetchImpl = vi.fn();
    await expect(
      createChatCompletion({ ...CONFIG, token: '' }, MESSAGES, { fetchImpl: fetchImpl as unknown as FetchLike }),
    ).rejects.toMatchObject({ code: 'missing_credentials' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('maps 401 to unauthorized without retrying', async () => {
    let calls = 0;
    const fetchImpl: FetchLike = async () => {
      calls += 1;
      return textResponse('Invalid credentials', 401);
    };
    await expect(createChatCompletion(CONFIG, MESSAGES, { fetchImpl, ...noSleep })).rejects.toMatchObject({
      code: 'unauthorized',
    });
    expect(calls).toBe(1);
  });

  it('maps 402 to credits_exhausted with an actionable message', async () => {
    const fetchImpl: FetchLike = async () => textResponse('Payment Required', 402);
    const error = await createChatCompletion(CONFIG, MESSAGES, { fetchImpl, ...noSleep }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(InferenceError);
    expect((error as InferenceError).code).toBe('credits_exhausted');
    expect((error as InferenceError).message).toMatch(/credits/i);
  });

  it('treats a 429 that mentions credits as exhausted, not as throttling', async () => {
    const fetchImpl: FetchLike = async () =>
      textResponse('You have exceeded your monthly included credits for Inference Providers', 429);
    await expect(createChatCompletion(CONFIG, MESSAGES, { fetchImpl, ...noSleep })).rejects.toMatchObject({
      code: 'credits_exhausted',
    });
  });

  it('retries a plain 429 up to the bound and surfaces retry-after', async () => {
    let calls = 0;
    const fetchImpl: FetchLike = async () => {
      calls += 1;
      return textResponse('Too Many Requests', 429, { 'Retry-After': '12' });
    };
    const error = await createChatCompletion(CONFIG, MESSAGES, { fetchImpl, ...noSleep }).catch((e: unknown) => e);
    expect(calls).toBe(CONFIG.maxRetries + 1);
    expect((error as InferenceError).code).toBe('rate_limited');
    expect((error as InferenceError).retryAfterSeconds).toBe(12);
  });

  it('succeeds after a transient 429', async () => {
    let calls = 0;
    const fetchImpl: FetchLike = async () => {
      calls += 1;
      return calls === 1 ? textResponse('Too Many Requests', 429) : completion('{"status":"ok"}');
    };
    const result = await createChatCompletion(CONFIG, MESSAGES, { fetchImpl, ...noSleep });
    expect(result.content).toBe('{"status":"ok"}');
    expect(result.attempts).toBe(2);
  });
});

describe('createChatCompletion — availability failures', () => {
  it('falls back to the next configured model on 404', async () => {
    const models: string[] = [];
    const fetchImpl: FetchLike = async (_url, init) => {
      const body = JSON.parse(String(init.body)) as { model: string };
      models.push(body.model);
      return body.model.startsWith('primary')
        ? textResponse('Model primary/model does not exist', 404)
        : completion('{"status":"ok"}', 'fallback/model');
    };
    const result = await createChatCompletion(CONFIG, MESSAGES, { fetchImpl, ...noSleep });
    expect(models).toEqual(['primary/model', 'fallback/model']);
    expect(result.usedFallback).toBe(true);
    expect(result.model).toBe('fallback/model');
  });

  it('reports model_unavailable when every candidate fails', async () => {
    const fetchImpl: FetchLike = async () => textResponse('Service Unavailable', 503);
    await expect(
      createChatCompletion({ ...CONFIG, maxRetries: 0 }, MESSAGES, { fetchImpl, ...noSleep }),
    ).rejects.toMatchObject({ code: 'model_unavailable' });
  });

  it('distinguishes a transport failure from the service reporting a problem', async () => {
    // Nothing was received at all. Calling this "model unavailable" would send
    // the caller looking at the model instead of at connectivity, a blocked
    // cross-origin request, or an intercepting proxy.
    const fetchImpl: FetchLike = async () => {
      throw new TypeError('Failed to fetch');
    };
    const error = await createChatCompletion({ ...CONFIG, maxRetries: 0, fallbackModels: [] }, MESSAGES, {
      fetchImpl,
      ...noSleep,
    }).catch((e: unknown) => e);
    expect((error as InferenceError).code).toBe('upstream_unreachable');
    expect((error as InferenceError).code).not.toBe('model_unavailable');
  });

  it('maps an aborted request to upstream_timeout', async () => {
    const fetchImpl: FetchLike = async () => {
      const error = new Error('aborted');
      error.name = 'AbortError';
      throw error;
    };
    await expect(
      createChatCompletion({ ...CONFIG, maxRetries: 0, fallbackModels: [] }, MESSAGES, { fetchImpl, ...noSleep }),
    ).rejects.toMatchObject({ code: 'upstream_timeout' });
  });

  it('aborts a request that exceeds the configured timeout', async () => {
    const fetchImpl: FetchLike = (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => {
          const error = new Error('aborted');
          error.name = 'AbortError';
          reject(error);
        });
      });
    await expect(
      createChatCompletion({ ...CONFIG, timeoutMs: 20, maxRetries: 0, fallbackModels: [] }, MESSAGES, {
        fetchImpl,
        ...noSleep,
      }),
    ).rejects.toMatchObject({ code: 'upstream_timeout' });
  });

  it('retries without JSON mode when the provider rejects response_format', async () => {
    const bodies: Record<string, unknown>[] = [];
    const fetchImpl: FetchLike = async (_url, init) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      bodies.push(body);
      if (body['response_format']) {
        return textResponse('response_format json_object is not supported by this provider', 400);
      }
      return completion('{"status":"ok"}');
    };
    const result = await createChatCompletion(CONFIG, MESSAGES, { fetchImpl, ...noSleep });
    expect(result.content).toBe('{"status":"ok"}');
    expect(bodies[0]).toHaveProperty('response_format');
    expect(bodies[1]).not.toHaveProperty('response_format');
  });
});

describe('createChatCompletion — malformed upstream output', () => {
  it('rejects a response with no completion text', async () => {
    const fetchImpl: FetchLike = async () => jsonResponse({ choices: [] });
    await expect(
      createChatCompletion({ ...CONFIG, maxRetries: 0, fallbackModels: [] }, MESSAGES, { fetchImpl, ...noSleep }),
    ).rejects.toMatchObject({ code: 'invalid_model_output' });
  });

  it('rejects a truncated completion rather than using partial output', async () => {
    const fetchImpl: FetchLike = async () =>
      jsonResponse({ model: 'primary/model', choices: [{ message: { content: '{"status":"o' }, finish_reason: 'length' }] });
    const error = await createChatCompletion({ ...CONFIG, maxRetries: 0, fallbackModels: [] }, MESSAGES, {
      fetchImpl,
      ...noSleep,
    }).catch((e: unknown) => e);
    expect((error as InferenceError).code).toBe('invalid_model_output');
    expect((error as InferenceError).message).toMatch(/token limit/i);
  });

  it('never returns fabricated content on failure', async () => {
    const fetchImpl: FetchLike = async () => textResponse('boom', 500);
    const result = await createChatCompletion({ ...CONFIG, maxRetries: 0, fallbackModels: [] }, MESSAGES, {
      fetchImpl,
      ...noSleep,
    }).catch(() => null);
    expect(result).toBeNull();
  });
});

describe('extractJsonObject', () => {
  it('returns a bare JSON object unchanged', () => {
    expect(extractJsonObject('{"a":1}')).toBe('{"a":1}');
  });

  it('unwraps a fenced code block', () => {
    expect(extractJsonObject('```json\n{"a":1}\n```')).toBe('{"a":1}');
  });

  it('strips surrounding prose', () => {
    expect(extractJsonObject('Here you go:\n{"a":{"b":2}}\nHope that helps!')).toBe('{"a":{"b":2}}');
  });

  it('respects braces inside string literals', () => {
    const json = '{"regex":"^\\\\{.*\\\\}$","n":1}';
    expect(extractJsonObject(`noise ${json} noise`)).toBe(json);
  });

  it('throws when there is no object', () => {
    expect(() => extractJsonObject('I cannot help with that.')).toThrow(InferenceError);
  });

  it('throws on an unterminated object', () => {
    expect(() => extractJsonObject('{"a":1')).toThrow(/unterminated/i);
  });
});
