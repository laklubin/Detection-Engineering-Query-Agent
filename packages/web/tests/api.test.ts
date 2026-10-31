import { describe, expect, it, vi } from 'vitest';
import { ApiError, DetectionForgeApi } from '../src/lib/api.js';

const BASE = 'https://api.example.test';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

const SESSION = { token: 'v1.payload.signature', csrfToken: 'csrf-value', expiresAt: new Date(Date.now() + 3_600_000).toISOString() };

describe('DetectionForgeApi', () => {
  it('reports whether a backend is configured', () => {
    expect(new DetectionForgeApi('').configured).toBe(false);
    expect(new DetectionForgeApi(BASE).configured).toBe(true);
  });

  it('obtains a session then sends the bearer and CSRF headers', async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const fetchImpl = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith('/api/v1/session')) return json(SESSION, 201);
      return json({ ok: true, useCases: [] });
    });

    const api = new DetectionForgeApi(BASE, fetchImpl as unknown as typeof fetch);
    await api.generate({ requirement: 'Detect failed logon bursts in Windows security logs' });

    expect(calls[0]?.url).toBe(`${BASE}/api/v1/session`);
    expect(calls[1]?.url).toBe(`${BASE}/api/v1/generate`);
    const headers = calls[1]?.init?.headers as Record<string, string>;
    expect(headers['Authorization']).toBe(`Bearer ${SESSION.token}`);
    expect(headers['X-DFAI-CSRF']).toBe(SESSION.csrfToken);
  });

  it('reuses a live session instead of requesting a new one per call', async () => {
    let sessionCalls = 0;
    const fetchImpl = vi.fn(async (url: RequestInfo | URL) => {
      if (String(url).endsWith('/api/v1/session')) {
        sessionCalls += 1;
        return json(SESSION, 201);
      }
      return json({ ok: true });
    });
    const api = new DetectionForgeApi(BASE, fetchImpl as unknown as typeof fetch);
    await api.generate({ requirement: 'Detect failed logon bursts in Windows security logs' });
    await api.generate({ requirement: 'Detect failed logon bursts in Windows security logs' });
    expect(sessionCalls).toBe(1);
  });

  it('re-authenticates once when the session is rejected mid-flight', async () => {
    let generateCalls = 0;
    const fetchImpl = vi.fn(async (url: RequestInfo | URL) => {
      if (String(url).endsWith('/api/v1/session')) return json(SESSION, 201);
      generateCalls += 1;
      if (generateCalls === 1) return json({ ok: false, code: 'unauthorized', message: 'expired' }, 401);
      return json({ ok: true, useCases: [] });
    });
    const api = new DetectionForgeApi(BASE, fetchImpl as unknown as typeof fetch);
    await api.generate({ requirement: 'Detect failed logon bursts in Windows security logs' });
    expect(generateCalls).toBe(2);
  });

  it('surfaces structured API errors with code and details', async () => {
    const fetchImpl = vi.fn(async (url: RequestInfo | URL) => {
      if (String(url).endsWith('/api/v1/session')) return json(SESSION, 201);
      return json({ ok: false, code: 'off_topic', message: 'rejected', details: ['why'] }, 422);
    });
    const api = new DetectionForgeApi(BASE, fetchImpl as unknown as typeof fetch);
    const error = await api
      .generate({ requirement: 'Build me a website with a login form' })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe('off_topic');
    expect((error as ApiError).httpStatus).toBe(422);
    expect((error as ApiError).details).toEqual(['why']);
  });

  it('maps a network failure to an actionable message', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new TypeError('Failed to fetch');
    });
    const api = new DetectionForgeApi(BASE, fetchImpl as unknown as typeof fetch);
    const error = await api.health().catch((e: unknown) => e);
    expect((error as ApiError).code).toBe('network_error');
    expect((error as ApiError).message).toMatch(/CORS allowlist/i);
  });

  it('maps an aborted request to a timeout', async () => {
    const fetchImpl = vi.fn(async () => {
      const error = new Error('aborted');
      error.name = 'AbortError';
      throw error;
    });
    const api = new DetectionForgeApi(BASE, fetchImpl as unknown as typeof fetch);
    const error = await api.health().catch((e: unknown) => e);
    expect((error as ApiError).code).toBe('upstream_timeout');
  });

  it('keeps the session token out of persistent browser storage', async () => {
    const fetchImpl = vi.fn(async (url: RequestInfo | URL) =>
      String(url).endsWith('/api/v1/session') ? json(SESSION, 201) : json({ ok: true }),
    );
    const api = new DetectionForgeApi(BASE, fetchImpl as unknown as typeof fetch);
    await api.generate({ requirement: 'Detect failed logon bursts in Windows security logs' });

    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    expect(document.cookie).toBe('');
  });

  it('drops the credential when the session is forgotten', async () => {
    let sessionCalls = 0;
    const fetchImpl = vi.fn(async (url: RequestInfo | URL) => {
      if (String(url).endsWith('/api/v1/session')) {
        sessionCalls += 1;
        return json(SESSION, 201);
      }
      return json({ ok: true });
    });
    const api = new DetectionForgeApi(BASE, fetchImpl as unknown as typeof fetch);
    await api.generate({ requirement: 'Detect failed logon bursts in Windows security logs' });
    api.forgetSession();
    await api.generate({ requirement: 'Detect failed logon bursts in Windows security logs' });
    expect(sessionCalls).toBe(2);
  });
});
